//! Keyring migration support for legacy formats

use std::path::PathBuf;

use oo7::{Secret, file::UnlockedKeyring};

use crate::error::Error;

/// Pending keyring migration
#[derive(Clone, Debug)]
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
        name: &str,
        secret: &Secret,
    ) -> Result<UnlockedKeyring, Error> {
        match self {
            Self::V0 { path, .. } => {
                tracing::debug!("Migrating v0 keyring: {}", name);

                let unlocked = UnlockedKeyring::open_at(data_dir, name, secret.clone()).await?;

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
            Self::KWallet { path, .. } => {
                tracing::debug!("Migrating KWallet keyring: {}", name);

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
                let unlocked = UnlockedKeyring::open_at(data_dir, name, secret.clone()).await?;

                // Convert KWallet entries to oo7 items
                for (folder_name, folder) in wallet.wallet() {
                    for (entry_key, entry) in folder {
                        let mut attributes = std::collections::HashMap::new();
                        attributes.insert("kwallet_folder".to_string(), folder_name.clone());
                        attributes.insert("kwallet_key".to_string(), entry_key.clone());

                        let label = format!("{}/{}", folder_name, entry_key);

                        match entry.entry_type() {
                            kwallet_parser::EntryType::Password => {
                                if let Ok(password) = entry.as_password() {
                                    attributes.insert("type".to_string(), "password".to_string());
                                    unlocked
                                        .create_item(
                                            &label,
                                            &attributes,
                                            Secret::text(password),
                                            true,
                                        )
                                        .await?;
                                }
                            }
                            kwallet_parser::EntryType::Map => {
                                if let Ok(map) = entry.as_map() {
                                    attributes.insert("type".to_string(), "map".to_string());
                                    for (k, v) in map {
                                        attributes.insert(k.clone(), v.clone());
                                    }
                                    unlocked
                                        .create_item(&label, &attributes, Secret::text(""), true)
                                        .await?;
                                }
                            }
                            kwallet_parser::EntryType::Stream => {
                                attributes.insert("type".to_string(), "stream".to_string());
                                unlocked
                                    .create_item(
                                        &label,
                                        &attributes,
                                        Secret::blob(entry.as_stream()),
                                        true,
                                    )
                                    .await?;
                            }
                            kwallet_parser::EntryType::Unknown => {
                                tracing::warn!(
                                    "Skipping unknown entry type: {}/{}",
                                    folder_name,
                                    entry_key
                                );
                            }
                        }
                    }
                }

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
