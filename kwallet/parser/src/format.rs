use std::io::Read;

use crate::error::{Error, Result};

pub const KWMAGIC: &[u8; 12] = b"KWALLET\n\r\0\r\n";

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherType {
    BlowfishECB = 0,
    /// Unsupported - removed from KWallet, no implementation exists
    TripleDESCBC = 1,
    /// Unsupported - requires GPG integration
    GPG = 2,
    BlowfishCBC = 3,
}

impl std::fmt::Display for CipherType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BlowfishECB => write!(f, "Blowfish-ECB"),
            Self::TripleDESCBC => write!(f, "3DES-CBC"),
            Self::GPG => write!(f, "GPG"),
            Self::BlowfishCBC => write!(f, "Blowfish-CBC"),
        }
    }
}

impl TryFrom<u8> for CipherType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::BlowfishECB),
            1 => Ok(Self::TripleDESCBC),
            2 => Ok(Self::GPG),
            3 => Ok(Self::BlowfishCBC),
            _ => Err(Error::UnknownCipher(value)),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashType {
    /// Legacy SHA-1 hash (2000 iterations)
    SHA1 = 0,
    /// Unsupported - deprecated since KDE 4.13 (2013), no implementation exists
    /// in modern KWallet
    MD5 = 1,
    /// Modern PBKDF2-SHA512 (50000 iterations, default since KDE 4.13)
    PBKDF2SHA512 = 2,
}

impl std::fmt::Display for HashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SHA1 => write!(f, "SHA-1"),
            Self::MD5 => write!(f, "MD5"),
            Self::PBKDF2SHA512 => write!(f, "PBKDF2-SHA512"),
        }
    }
}

impl TryFrom<u8> for HashType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::SHA1),
            1 => Ok(Self::MD5),
            2 => Ok(Self::PBKDF2SHA512),
            _ => Err(Error::UnknownHash(value)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WalletHeader {
    version_major: u8,
    version_minor: u8,
    cipher_type: CipherType,
    hash_type: HashType,
}

impl WalletHeader {
    pub fn version(&self) -> (u8, u8) {
        (self.version_major, self.version_minor)
    }

    pub fn cipher_type(&self) -> CipherType {
        self.cipher_type
    }

    pub fn hash_type(&self) -> HashType {
        self.hash_type
    }

    pub fn read<R: Read>(reader: &mut R) -> Result<Self> {
        let mut magic = [0u8; 12];
        reader.read_exact(&mut magic)?;

        if &magic != KWMAGIC {
            return Err(Error::InvalidMagic);
        }

        let mut version = [0u8; 4];
        reader.read_exact(&mut version)?;

        let cipher_type = CipherType::try_from(version[2])?;
        let hash_type = HashType::try_from(version[3])?;

        let header = WalletHeader {
            version_major: version[0],
            version_minor: version[1],
            cipher_type,
            hash_type,
        };

        header.validate()?;
        Ok(header)
    }

    fn validate(&self) -> Result<()> {
        if self.version_major != 0 {
            return Err(Error::UnsupportedVersion(
                self.version_major,
                self.version_minor,
            ));
        }

        match (self.version_minor, self.cipher_type, self.hash_type) {
            (0, CipherType::BlowfishECB, HashType::SHA1) => Ok(()),
            (1, CipherType::BlowfishCBC, HashType::PBKDF2SHA512) => Ok(()),
            _ => {
                if self.version_minor != 0 && self.version_minor != 1 {
                    Err(Error::UnsupportedVersion(
                        self.version_major,
                        self.version_minor,
                    ))
                } else if self.cipher_type != CipherType::BlowfishECB
                    && self.cipher_type != CipherType::BlowfishCBC
                {
                    Err(Error::UnsupportedCipher(self.cipher_type))
                } else {
                    Err(Error::UnsupportedHash(self.hash_type))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn test_valid_header() {
        let mut data = Vec::new();
        data.extend_from_slice(KWMAGIC);
        data.extend_from_slice(&[
            0,
            1,
            CipherType::BlowfishCBC as u8,
            HashType::PBKDF2SHA512 as u8,
        ]);

        let header = WalletHeader::read(&mut Cursor::new(data)).unwrap();

        assert_eq!(header.version_major, 0);
        assert_eq!(header.version_minor, 1);
        assert_eq!(header.cipher_type, CipherType::BlowfishCBC);
        assert_eq!(header.hash_type, HashType::PBKDF2SHA512);
    }

    #[test]
    fn test_invalid_magic() {
        let mut data = Vec::new();
        data.extend_from_slice(b"INVALID_MAG!");
        data.extend_from_slice(&[0, 1, 3, 2]);

        let result = WalletHeader::read(&mut Cursor::new(data));

        assert!(matches!(result, Err(Error::InvalidMagic)));
    }
}
