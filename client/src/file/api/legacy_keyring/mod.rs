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
