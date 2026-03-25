use std::fmt;

use crate::format::{CipherType, HashType};

#[derive(Debug)]
pub enum Error {
    InvalidMagic,
    UnsupportedVersion(u8, u8),
    UnsupportedCipher(CipherType),
    UnsupportedHash(HashType),
    UnknownCipher(u8),
    UnknownHash(u8),
    FileTooSmall(usize),
    InvalidSalt,
    DecryptionFailed,
    HashValidationFailed,
    InvalidDataStructure,
    Io(std::io::Error),
    Utf8(std::string::FromUtf8Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "Invalid magic bytes"),
            Self::UnsupportedVersion(major, minor) => {
                write!(
                    f,
                    "Unsupported wallet version: major={major}, minor={minor}"
                )
            }
            Self::UnsupportedCipher(cipher) => write!(f, "Unsupported cipher type: {cipher:?}"),
            Self::UnsupportedHash(hash) => write!(f, "Unsupported hash type: {hash:?}"),
            Self::UnknownCipher(value) => write!(f, "Unknown cipher type: {value}"),
            Self::UnknownHash(value) => write!(f, "Unknown hash type: {value}"),
            Self::FileTooSmall(size) => write!(f, "File too small: {size} bytes (minimum 60)"),
            Self::InvalidSalt => write!(f, "Salt file not found or invalid"),
            Self::DecryptionFailed => write!(f, "Decryption failed"),
            Self::HashValidationFailed => write!(f, "Hash validation failed"),
            Self::InvalidDataStructure => write!(f, "Invalid data structure"),
            Self::Io(err) => write!(f, "IO error: {err}"),
            Self::Utf8(err) => write!(f, "UTF-8 error: {err}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Utf8(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Self::Utf8(err)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
