//! Encrypted binary keyring format.

use std::{
    collections::HashMap,
    io::{self, Cursor, Read},
};

use endi::{Endian, ReadBytes};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(any(feature = "unstable", test))]
use super::super::EncryptedItem;
use super::{FILE_HEADER, FILE_HEADER_LEN, item_type_schema};
#[cfg(any(feature = "unstable", test))]
use crate::{
    Mac,
    file::{Item, LockedItem},
};
use crate::{
    Secret, XDG_SCHEMA_ATTRIBUTE, crypto,
    file::{Error, UnlockedItem},
};

pub const MAJOR_VERSION: u8 = 0;
pub const MINOR_VERSION: u8 = 0;

/// An item of the cleartext attribute section of the keyring file.
#[derive(Debug)]
struct HashedItem {
    item_type: u32,
    #[cfg_attr(not(feature = "unstable"), allow(dead_code))]
    attributes: HashMap<String, String>,
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct Keyring {
    salt: Vec<u8>,
    iteration_count: u32,
    encrypted_content: Vec<u8>,
    // In the same order as the encrypted items
    #[zeroize(skip)]
    hashed_items: Vec<HashedItem>,
}

impl Keyring {
    pub fn decrypt_items(self, secret: &Secret) -> Result<Vec<UnlockedItem>, Error> {
        let content = self.decrypt_content(secret)?;
        self.read_items(&content)
    }

    /// Check whether the secret can decrypt this keyring.
    #[cfg(any(feature = "unstable", test))]
    pub fn validate_secret(&self, secret: &Secret) -> Result<bool, Error> {
        match self.decrypt_content(secret) {
            Ok(_) => Ok(true),
            Err(Error::ChecksumMismatch) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Decrypt the keyring content, verifying its checksum.
    fn decrypt_content(&self, secret: &Secret) -> Result<Vec<u8>, Error> {
        let (key, iv) = crypto::legacy_derive_key_and_iv(
            &**secret,
            &self.salt,
            self.iteration_count.try_into().unwrap(),
        )?;
        let decrypted = crypto::decrypt_no_padding(&self.encrypted_content, &key, iv)?;
        if decrypted.len() < 16 {
            return Err(Error::NoData);
        }
        let (digest, content) = decrypted.split_at(16);
        if !crypto::verify_checksum_md5(digest, content) {
            return Err(Error::ChecksumMismatch);
        }
        Ok(content.to_vec())
    }

    fn read_attributes<'a>(
        cursor: &mut Cursor<&'a [u8]>,
        count: usize,
    ) -> Result<HashMap<&'a str, String>, Error> {
        let mut result = HashMap::new();
        for _ in 0..count {
            let name = Self::read_string(cursor)?.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "empty attribute name")
            })?;
            let value = match cursor.read_u32(Endian::Big)? {
                0 => Self::read_string(cursor)?
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "empty attribute value")
                    })?
                    .to_string(),
                1 => cursor.read_u32(Endian::Big)?.to_string(),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "unknown attribute type",
                    )
                    .into());
                }
            };
            result.insert(name, value);
        }
        Ok(result)
    }

    /// The items of the keyring, locked.
    ///
    /// The items have no label nor secret until the keyring is migrated
    /// and unlocked; they only carry the cleartext attributes of the
    /// keyring file.
    #[cfg(any(feature = "unstable", test))]
    pub fn items(&self) -> Vec<Item> {
        self.hashed_items
            .iter()
            .map(|item| {
                Item::Locked(LockedItem {
                    inner: EncryptedItem {
                        hashed_attributes: item
                            .attributes
                            .iter()
                            .map(|(key, value)| (key.clone(), Mac::new(value.as_bytes().to_vec())))
                            .collect(),
                        // The secret is only available once decrypted
                        blob: Vec::new(),
                    },
                })
            })
            .collect()
    }

    fn read_items(self, decrypted: &[u8]) -> Result<Vec<UnlockedItem>, Error> {
        let mut cursor = Cursor::new(decrypted);
        let mut items = Vec::with_capacity(self.hashed_items.len());
        for hashed_item in &self.hashed_items {
            let item_type = hashed_item.item_type;
            let display_name = Self::read_string(&mut cursor)?.unwrap_or_else(|| {
                #[cfg(feature = "tracing")]
                tracing::warn!("Item has no label, defaulting to empty");
                ""
            });
            let secret = Self::read_byte_array(&mut cursor)?.unwrap_or_else(|| {
                #[cfg(feature = "tracing")]
                tracing::warn!("Item '{display_name}' has no secret, defaulting to empty");
                &[]
            });
            let _created_time = Self::read_time(&mut cursor)?;
            let _modified_time = Self::read_time(&mut cursor)?;
            let _reserved = Self::read_string(&mut cursor)?;
            for _ in 0..4 {
                let _ = cursor.read_u32(Endian::Big)?;
            }
            let attribute_count = cursor.read_u32(Endian::Big)? as usize;
            let mut attributes = Self::read_attributes(&mut cursor, attribute_count)?;
            if !attributes.contains_key(XDG_SCHEMA_ATTRIBUTE)
                && let Some(schema) = item_type_schema(item_type)
            {
                attributes.insert(XDG_SCHEMA_ATTRIBUTE, schema.to_owned());
            }
            items.push(UnlockedItem::new(display_name, &attributes, secret));
            let acl_count = cursor.read_u32(Endian::Big)? as usize;
            Self::skip_acls(&mut cursor, acl_count)?;
        }
        Ok(items)
    }

    fn read_byte_array<'a>(cursor: &mut Cursor<&'a [u8]>) -> Result<Option<&'a [u8]>, Error> {
        let len = cursor.read_u32(Endian::Big)? as usize;
        if len == 0xffffffff {
            Ok(None)
        } else if len >= 0x7fffffff {
            Err(io::Error::new(io::ErrorKind::OutOfMemory, "").into())
        } else if len > cursor.get_ref().len() {
            Err(Error::NoData)
        } else {
            let pos = cursor.position() as usize;
            let bytes = &cursor.get_ref()[pos..pos + len];
            cursor.set_position((pos + len) as u64);
            Ok(Some(bytes))
        }
    }

    fn read_string<'a>(cursor: &mut Cursor<&'a [u8]>) -> Result<Option<&'a str>, Error> {
        match Self::read_byte_array(cursor) {
            Ok(Some(bytes)) => Ok(Some(std::str::from_utf8(bytes)?)),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn read_time(cursor: &mut Cursor<&[u8]>) -> Result<u64, Error> {
        let hi = cursor.read_u32(Endian::Big)? as u64;
        let lo = cursor.read_u32(Endian::Big)? as u64;
        Ok((hi << 32) | lo)
    }

    fn read_hashed_items(
        cursor: &mut Cursor<&[u8]>,
        count: usize,
    ) -> Result<Vec<HashedItem>, Error> {
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            let _id = cursor.read_u32(Endian::Big)?;
            let item_type = cursor.read_u32(Endian::Big)?;
            let num_attributes = cursor.read_u32(Endian::Big)? as usize;
            let mut attributes = HashMap::with_capacity(num_attributes);
            for _ in 0..num_attributes {
                let name = Self::read_string(cursor)?.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "empty attribute name")
                })?;
                let value = match cursor.read_u32(Endian::Big)? {
                    0 => Self::read_string(cursor)?
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidInput, "empty attribute value")
                        })?
                        .to_string(),
                    1 => cursor.read_u32(Endian::Big)?.to_string(),
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "unknown attribute type",
                        )
                        .into());
                    }
                };
                attributes.insert(name.to_string(), value);
            }
            // Mirror the schema synthesis applied to the decrypted items,
            // so schema based searches match the migrated items
            if !attributes.contains_key(XDG_SCHEMA_ATTRIBUTE)
                && let Some(schema) = item_type_schema(item_type)
            {
                attributes.insert(XDG_SCHEMA_ATTRIBUTE.to_owned(), crypto::md5_hex(schema));
            }
            items.push(HashedItem {
                item_type,
                attributes,
            });
        }
        Ok(items)
    }

    fn skip_acls(cursor: &mut Cursor<&[u8]>, count: usize) -> Result<(), Error> {
        for _ in 0..count {
            let _flags = cursor.read_u32(Endian::Big)?;
            let _display_name = Self::read_string(cursor)?;
            let _path = Self::read_string(cursor)?;
            let _reserved0 = Self::read_string(cursor)?;
            let _reserved1 = cursor.read_u32(Endian::Big)?;
        }
        Ok(())
    }

    fn parse(data: &[u8]) -> Result<Self, Error> {
        let mut cursor = Cursor::new(data);
        let crypto = cursor.read_u8(Endian::Big)?;
        if crypto != 0 {
            return Err(Error::AlgorithmMismatch(crypto));
        }
        let hash = cursor.read_u8(Endian::Big)?;
        if hash != 0 {
            return Err(Error::AlgorithmMismatch(hash));
        }
        let _display_name = Self::read_string(&mut cursor)?;
        let _created_time = Self::read_time(&mut cursor)?;
        let _modified_time = Self::read_time(&mut cursor)?;
        let _flags = cursor.read_u32(Endian::Big)?;
        let _lock_timeout = cursor.read_u32(Endian::Big)?;
        let iteration_count = cursor.read_u32(Endian::Big)?;
        let mut salt = vec![0; 8];
        cursor.read_exact(salt.as_mut_slice())?;
        for _ in 0..4 {
            let _ = cursor.read_u32(Endian::Big)?;
        }
        let item_count = cursor.read_u32(Endian::Big)? as usize;
        let hashed_items = Self::read_hashed_items(&mut cursor, item_count)?;
        let mut size = cursor.read_u32(Endian::Big)? as usize;
        let pos = cursor.position() as usize;
        if size > cursor.get_ref()[pos..].len() {
            return Err(Error::NoData);
        }
        if !size.is_multiple_of(16) {
            size = (size / 16) * 16;
        }
        let encrypted_content = Vec::from(&cursor.get_ref()[pos..pos + size]);

        Ok(Self {
            salt,
            iteration_count,
            encrypted_content,
            hashed_items,
        })
    }
}

impl TryFrom<&[u8]> for Keyring {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Error> {
        let header = value.get(..FILE_HEADER.len());
        if header != Some(FILE_HEADER) {
            return Err(Error::FileHeaderMismatch(
                header.map(|x| String::from_utf8_lossy(x).to_string()),
            ));
        }

        let version = value.get(FILE_HEADER_LEN..(FILE_HEADER_LEN + 2));
        if version != Some(&[MAJOR_VERSION, MINOR_VERSION]) {
            return Err(Error::VersionMismatch(version.map(|x| x.to_vec())));
        }

        if let Some(data) = value.get((FILE_HEADER_LEN + 2)..) {
            Self::parse(data)
        } else {
            Err(Error::NoData)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn decrypt_empty_content_is_an_error() {
        // A crafted keyring file can declare an empty encrypted content
        let keyring = Keyring {
            salt: vec![0; 8],
            iteration_count: 100000,
            encrypted_content: Vec::new(),
            hashed_items: Vec::new(),
        };
        assert!(matches!(
            keyring.decrypt_items(&Secret::from("test")),
            Err(Error::NoData)
        ));
    }

    #[test]
    fn legacy_decrypt() -> Result<(), Error> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("legacy.keyring");
        let blob = std::fs::read(path)?;
        let keyring = Keyring::try_from(blob.as_slice())?;
        let secret = Secret::blob("test");
        let items = keyring.decrypt_items(&secret)?;

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label(), "foo");
        assert_eq!(items[0].secret(), Secret::blob("foo"));
        let attributes = items[0].attributes();
        assert_eq!(attributes.len(), 2); // also content-type
        assert_eq!(
            attributes
                .get(crate::XDG_SCHEMA_ATTRIBUTE)
                .map(|v| v.as_ref()),
            Some("org.gnome.keyring.Note")
        );

        Ok(())
    }

    #[test]
    fn legacy_decrypt_schema_from_item_type() -> Result<(), Error> {
        // Written by gnome-keyring 48 for an item stored without a schema
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("legacy-no-schema.keyring");
        let blob = std::fs::read(path)?;
        let keyring = Keyring::try_from(blob.as_slice())?;
        let items = keyring.decrypt_items(&Secret::blob("test"))?;

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label(), "Unlock password for: user@example.com");
        assert_eq!(items[0].secret(), Secret::blob("my-ssh-passphrase"));
        let attributes = items[0].attributes();
        assert_eq!(attributes.len(), 3); // also content-type
        assert_eq!(
            attributes.get("unique").map(|v| v.as_ref()),
            Some("ssh-store:/fake/id_rsa")
        );
        assert_eq!(
            attributes
                .get(crate::XDG_SCHEMA_ATTRIBUTE)
                .map(|v| v.as_ref()),
            Some(crate::GENERIC_SCHEMA)
        );

        Ok(())
    }
}
