//! Read-only parser for KWallet file format
//!
//! This crate provides parsing support for KWallet wallet files:
//!
//! ## Modern Format (version 0.1)
//! - Blowfish-CBC encryption
//! - PBKDF2-SHA512 password hashing
//!
//! ## Legacy Format (version 0.0)
//! - Blowfish-ECB encryption
//! - SHA1-based password hashing (2000 iterations)
//!
//! # Example
//!
//! ```no_run
//! use kwallet_parser::{EntryType, KWalletFile};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let wallet = KWalletFile::open("~/.local/share/kwalletd/kdewallet.kwl", b"password")?;
//!
//! for (folder_name, folder) in wallet.wallet() {
//!     println!("{}:", folder_name);
//!
//!     for (key, entry) in folder {
//!         match entry.entry_type() {
//!             EntryType::Password => {
//!                 if let Ok(password) = entry.as_password() {
//!                     println!("  {}: {}", key, password);
//!                 }
//!             }
//!             EntryType::Map => {
//!                 if let Ok(map) = entry.as_map() {
//!                     println!("  {} (map):", key);
//!                     for (k, v) in map {
//!                         println!("    {}: {}", k, v);
//!                     }
//!                 }
//!             }
//!             EntryType::Stream => {
//!                 println!("  {}: {} bytes", key, entry.as_stream().len());
//!             }
//!             EntryType::Unknown => {}
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```

mod crypto;
mod error;
mod format;
mod qdata;
pub mod secret_service;
mod wallet;

use std::{fs, io::Cursor, path::Path};

pub use error::{Error, Result};
pub use format::{CipherType, HashType};
pub use secret_service::{SecretServiceEntry, convert_entry};
pub use wallet::{Entry, EntryType, Folder, Wallet};

/// A parsed KWallet file
#[derive(Debug, Clone)]
pub struct KWalletFile {
    header: format::WalletHeader,
    wallet: Wallet,
}

impl KWalletFile {
    pub fn version(&self) -> (u8, u8) {
        self.header.version()
    }

    pub fn cipher_type(&self) -> CipherType {
        self.header.cipher_type()
    }

    pub fn hash_type(&self) -> HashType {
        self.header.hash_type()
    }

    pub fn wallet(&self) -> &Wallet {
        &self.wallet
    }

    /// Open and parse a KWallet file
    pub fn open<P: AsRef<Path>>(path: P, password: &[u8]) -> Result<Self> {
        let path = path.as_ref();
        let wallet_data = fs::read(path)?;

        if wallet_data.len() < 60 {
            return Err(Error::FileTooSmall(wallet_data.len()));
        }

        let mut cursor = Cursor::new(&wallet_data);
        let header = format::WalletHeader::read(&mut cursor)?;

        let key = match header.hash_type() {
            HashType::PBKDF2SHA512 => {
                pub const PBKDF2_SHA512_SALTSIZE: usize = 56;
                let salt_path = path.with_extension("salt");
                let salt = fs::read(&salt_path).map_err(|_| Error::InvalidSalt)?;

                if salt.len() != PBKDF2_SHA512_SALTSIZE {
                    return Err(Error::InvalidSalt);
                }

                crypto::derive_key_pbkdf2_sha512(password, &salt).to_vec()
            }
            HashType::SHA1 => crypto::derive_key_legacy(password),
            HashType::MD5 => return Err(Error::UnsupportedHash(header.hash_type())),
        };

        let remaining_data = &wallet_data[16..];

        let mut cursor = Cursor::new(remaining_data);
        let mut hash_reader = qdata::QDataStreamReader::new(&mut cursor);
        let folder_count = hash_reader.read_u32()?;

        let mut folder_hashes = Vec::new();
        for _ in 0..folder_count {
            let mut folder_hash = [0u8; 16];
            hash_reader.read_raw(&mut folder_hash)?;
            let entry_count = hash_reader.read_u32()?;

            let mut entry_hashes = Vec::new();
            for _ in 0..entry_count {
                let mut entry_hash = [0u8; 16];
                hash_reader.read_raw(&mut entry_hash)?;
                entry_hashes.push(entry_hash);
            }
            folder_hashes.push((folder_hash, entry_hashes));
        }

        let hash_section_size = cursor.position() as usize;
        let encrypted_data = &remaining_data[hash_section_size..];

        let wallet_data = match header.cipher_type() {
            CipherType::BlowfishCBC => {
                let decrypted = crypto::decrypt_blowfish_cbc(&key, encrypted_data)?;
                crypto::extract_wallet_data(&decrypted)?
            }
            CipherType::BlowfishECB => {
                let switched = crypto::switch_endianness(encrypted_data)?;
                let decrypted = crypto::decrypt_blowfish_ecb(&key, &switched)?;
                let restored = crypto::switch_endianness(&decrypted)?;

                if restored.len() < 12 {
                    return Err(Error::InvalidDataStructure);
                }
                let size =
                    u32::from_be_bytes([restored[8], restored[9], restored[10], restored[11]])
                        as usize;

                if restored.len() < 12 + size {
                    return Err(Error::InvalidDataStructure);
                }

                restored[12..12 + size].to_vec()
            }
            _ => return Err(Error::UnsupportedCipher(header.cipher_type())),
        };

        let wallet = Wallet::parse(&wallet_data)?;

        validate_hashes(&wallet, &folder_hashes)?;

        Ok(Self { header, wallet })
    }

    /// Get the wallet file path for a given wallet name in
    /// `$XDG_DATA_HOME/kwalletd/`
    pub fn get_wallet_path(wallet_name: &str) -> Option<std::path::PathBuf> {
        let data_home = std::env::var("XDG_DATA_HOME").ok().or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|home| format!("{}/.local/share", home))
        })?;

        let wallet_dir = Path::new(&data_home).join("kwalletd");
        Some(wallet_dir.join(format!("{}.kwl", wallet_name)))
    }
}

fn validate_hashes(wallet: &Wallet, folder_hashes: &[([u8; 16], Vec<[u8; 16]>)]) -> Result<()> {
    // Build a map of folder_hash -> (folder_name, entry_hashes)
    let mut folder_hash_map = std::collections::HashMap::new();

    for (folder_name, folder) in wallet.iter() {
        let folder_hash = crypto::compute_md5(folder_name.as_bytes());

        let mut entry_hashes = Vec::new();
        for (entry_key, _entry) in folder {
            let entry_hash = crypto::compute_md5(entry_key.as_bytes());
            entry_hashes.push(entry_hash);
        }

        folder_hash_map.insert(folder_hash, (folder_name, entry_hashes));
    }

    // Validate against expected hashes
    for (expected_folder_hash, expected_entry_hashes) in folder_hashes.iter() {
        let Some((_folder_name, computed_entry_hashes)) = folder_hash_map.get(expected_folder_hash)
        else {
            return Err(Error::HashValidationFailed);
        };

        // Entry hashes also need to be matched by hash, not by order
        if computed_entry_hashes.len() != expected_entry_hashes.len() {
            return Err(Error::HashValidationFailed);
        }

        // Check that all expected entry hashes are present
        for expected_entry_hash in expected_entry_hashes {
            if !computed_entry_hashes.contains(expected_entry_hash) {
                return Err(Error::HashValidationFailed);
            }
        }
    }

    Ok(())
}
