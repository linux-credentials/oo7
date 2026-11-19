//! Legacy GNOME Keyring file format low level API.
//!
//! gnome-keyring stores a keyring either in an encrypted binary format, or as a
//! plain-text key file when the keyring password is empty.

mod encrypted;
mod plain;

pub use encrypted::MAJOR_VERSION;

#[cfg(any(feature = "unstable", test))]
use crate::file::Item;
use crate::{
    Secret,
    file::{Error, UnlockedItem},
};

const FILE_HEADER: &[u8] = b"GnomeKeyring\n\r\0\n";
const FILE_HEADER_LEN: usize = FILE_HEADER.len();

/// The schema gnome-keyring exposes for items without an `xdg:schema`
/// attribute, derived from their type (`gkm_secret_compat_format_item_type`).
/// Adding it keeps schema based lookups matching the migrated items.
fn item_type_schema(item_type: u32) -> Option<&'static str> {
    match item_type & 0xffff {
        0 => Some(crate::GENERIC_SCHEMA),
        1 => Some("org.gnome.keyring.NetworkPassword"),
        2 => Some("org.gnome.keyring.Note"),
        3 => Some("org.gnome.keyring.ChainedKeyring"),
        4 => Some("org.gnome.keyring.EncryptionKey"),
        0x100 => Some("org.gnome.keyring.PkStorage"),
        _ => None,
    }
}

#[derive(Debug)]
pub enum Keyring {
    Encrypted(encrypted::Keyring),
    Plain(plain::Keyring),
}

impl Keyring {
    /// Whether this keyring is stored in the encrypted binary format.
    #[cfg(any(feature = "unstable", test))]
    pub fn is_encrypted(&self) -> bool {
        matches!(self, Self::Encrypted(_))
    }

    /// Retrieve the keyring items.
    ///
    /// The secret is ignored for plain keyrings.
    pub fn decrypt_items(self, secret: &Secret) -> Result<Vec<UnlockedItem>, Error> {
        match self {
            Self::Encrypted(keyring) => keyring.decrypt_items(secret),
            Self::Plain(keyring) => Ok(keyring.into_items()),
        }
    }

    /// Check whether the secret can decrypt this keyring.
    ///
    /// Plain keyrings are not encrypted and accept any secret.
    #[cfg(any(feature = "unstable", test))]
    pub fn validate_secret(&self, secret: &Secret) -> Result<bool, Error> {
        match self {
            Self::Encrypted(keyring) => keyring.validate_secret(secret),
            Self::Plain(_) => Ok(true),
        }
    }

    /// The items of the keyring.
    ///
    /// Items of an encrypted keyring are locked: they carry no label nor
    /// secret until the keyring is migrated and unlocked, only the
    /// cleartext attributes of the keyring file. Items of a plain
    /// keyring are unlocked and carry their data.
    #[cfg(any(feature = "unstable", test))]
    pub fn items(&self) -> Vec<Item> {
        match self {
            Self::Encrypted(keyring) => keyring.items(),
            Self::Plain(keyring) => keyring.items(),
        }
    }
}

impl TryFrom<&[u8]> for Keyring {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Error> {
        // Same as gnome-keyring, anything without the binary header is
        // attempted as a plain keyring.
        if value.starts_with(FILE_HEADER) {
            encrypted::Keyring::try_from(value).map(Self::Encrypted)
        } else {
            plain::Keyring::try_from(value).map(Self::Plain)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join(name);
        std::fs::read(path).unwrap()
    }

    #[test]
    fn encrypted_keyring() {
        let keyring = Keyring::try_from(fixture("legacy.keyring").as_slice()).unwrap();
        assert!(keyring.is_encrypted());

        assert!(
            keyring
                .validate_secret(&Secret::from("test"))
                .expect("validation should not fail")
        );
        assert!(
            !keyring
                .validate_secret(&Secret::from("wrong-password"))
                .expect("validation should not fail")
        );

        // The cleartext attributes are searchable without the secret,
        // values are stored as their MD5 digests
        let items = keyring.items();
        assert_eq!(items.len(), 1);
        assert!(items[0].is_locked());
        assert!(items[0].matches_attributes(
            &[(
                crate::XDG_SCHEMA_ATTRIBUTE,
                crate::crypto::md5_hex("org.gnome.keyring.Note")
            )],
            None
        ));
        assert!(!items[0].matches_attributes(&[("unique", "nope")], None));

        let items = keyring
            .decrypt_items(&Secret::from("test"))
            .expect("decryption should not fail");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label(), "foo");
    }

    #[test]
    fn plain_keyring() {
        let keyring = Keyring::try_from(fixture("plain.keyring").as_slice()).unwrap();
        assert!(!keyring.is_encrypted());

        // Plain keyrings accept any secret
        assert!(
            keyring
                .validate_secret(&Secret::from("anything"))
                .expect("validation should not fail")
        );

        // The items are unlocked and carry their data
        let items = keyring.items();
        assert_eq!(items.len(), 3);
        assert!(items.iter().all(|item| !item.is_locked()));
        assert!(items.iter().any(|item| {
            item.matches_attributes(
                &[(crate::XDG_SCHEMA_ATTRIBUTE, "org.remmina.Password")],
                None,
            )
        }));
    }
}
