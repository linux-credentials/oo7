//! Keyring migration support for legacy formats

use std::path::PathBuf;

use oo7::{Secret, file::UnlockedKeyring};

use crate::error::Error;

/// Pending keyring migration
#[derive(Clone)]
pub enum PendingMigration {
    /// Legacy v0 keyring format
    V0 {
        name: String,
        path: PathBuf,
        label: String,
        alias: String,
    },
    /// KWallet keyring format
    #[cfg(feature = "kwallet_migration")]
    KWallet {
        name: String,
        path: PathBuf,
        label: String,
        alias: String,
    },
}

impl PendingMigration {
    /// Attempt to migrate this keyring with the provided secret
    pub async fn migrate(
        &self,
        data_dir: &PathBuf,
        secret: Option<&Secret>,
    ) -> Result<UnlockedKeyring, Error> {
        match self {
            Self::V0 { path, name, .. } => {
                tracing::debug!("Migrating v0 keyring: {}", name);

                let unlocked = UnlockedKeyring::open_at(data_dir, name, secret.cloned()).await?;

                // Write migrated keyring
                unlocked.write().await?;
                tracing::info!("Wrote migrated keyring '{}' to disk", name);

                // Cleanup old file
                if let Err(e) = tokio::fs::remove_file(path).await {
                    tracing::warn!("Failed to remove v0 keyring at {:?}: {}", path, e);
                } else {
                    tracing::info!("Removed v0 keyring file at {:?}", path);
                }

                tracing::info!("Successfully migrated v0 keyring '{}'", name);
                Ok(unlocked)
            }
            #[cfg(feature = "kwallet_migration")]
            Self::KWallet { path, name, .. } => {
                tracing::debug!("Migrating KWallet keyring: {}", name);

                let secret = secret.ok_or_else(|| {
                    Error::IO(std::io::Error::other("KWallet migration requires a secret"))
                })?;

                // Parse KWallet file in blocking task
                let path_clone = path.clone();
                let password = secret.to_vec();
                let wallet = tokio::task::spawn_blocking(move || {
                    kwallet_parser::KWalletFile::open(&path_clone, &password)
                })
                .await
                .map_err(|e| {
                    Error::IO(std::io::Error::other(format!("Task join error: {}", e)))
                })??;

                tracing::info!("Parsed KWallet file '{}'", name);

                // Create new oo7 keyring
                let unlocked =
                    UnlockedKeyring::open_at(data_dir, name, Some(secret.clone())).await?;

                // Convert KWallet entries to oo7 items
                let mut items = Vec::new();
                for (folder_name, folder) in wallet.wallet() {
                    for (entry_key, entry) in folder {
                        match kwallet_parser::convert_entry(folder_name, entry_key, entry) {
                            Ok(ss_entry) => {
                                items.push((
                                    ss_entry.label().to_owned(),
                                    ss_entry.attributes().to_owned(),
                                    Secret::blob(ss_entry.secret()),
                                    true,
                                ));
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Skipping entry {}/{}: {}",
                                    folder_name,
                                    entry_key,
                                    e
                                );
                            }
                        }
                    }
                }
                unlocked.create_items(items).await?;

                tracing::info!("Migrated KWallet entries to oo7 format for '{}'", name);

                // Cleanup old files
                if let Err(e) = tokio::fs::remove_file(path).await {
                    tracing::warn!("Failed to remove KWallet file at {:?}: {}", path, e);
                } else {
                    tracing::info!("Removed KWallet file at {:?}", path);
                }

                // Try to remove salt file if it exists
                let salt_path = path.with_extension("salt");
                if salt_path.exists() {
                    if let Err(e) = tokio::fs::remove_file(&salt_path).await {
                        tracing::warn!(
                            "Failed to remove KWallet salt file at {:?}: {}",
                            salt_path,
                            e
                        );
                    } else {
                        tracing::info!("Removed KWallet salt file at {:?}", salt_path);
                    }
                }

                tracing::info!("Successfully migrated KWallet keyring '{}'", name);
                Ok(unlocked)
            }
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::V0 { name, .. } => name,
            #[cfg(feature = "kwallet_migration")]
            Self::KWallet { name, .. } => name,
        }
    }

    pub fn label(&self) -> &str {
        match self {
            Self::V0 { label, .. } => label,
            #[cfg(feature = "kwallet_migration")]
            Self::KWallet { label, .. } => label,
        }
    }

    pub fn alias(&self) -> &str {
        match self {
            Self::V0 { alias, .. } => alias,
            #[cfg(feature = "kwallet_migration")]
            Self::KWallet { alias, .. } => alias,
        }
    }

    pub fn path(&self) -> &PathBuf {
        match self {
            Self::V0 { path, .. } => path,
            #[cfg(feature = "kwallet_migration")]
            Self::KWallet { path, .. } => path,
        }
    }
}
