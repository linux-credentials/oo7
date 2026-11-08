//! Legacy GNOME Keyring file format low level API.
//!
//! gnome-keyring stores a keyring either in an encrypted binary format, or as a
//! plain-text key file when the keyring password is empty.

mod encrypted;
mod plain;

pub use encrypted::MAJOR_VERSION;

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
    /// Retrieve the keyring items.
    ///
    /// The secret is ignored for plain keyrings.
    pub fn decrypt_items(self, secret: &Secret) -> Result<Vec<UnlockedItem>, Error> {
        match self {
            Self::Encrypted(keyring) => keyring.decrypt_items(secret),
            Self::Plain(keyring) => Ok(keyring.into_items()),
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
