use std::path::PathBuf;

use oo7::{
    Secret,
    file::{Keyring, LockedKeyring},
};

use crate::{
    error::Error,
    migration::{self, PendingMigration},
};

const LOGIN_ALIAS: &str = "login";

pub(crate) struct LoadedKeyring {
    pub name: String,
    pub label: String,
    pub alias: String,
    pub keyring: Keyring,
    pub pending_migration: Option<PendingMigration>,
}

fn capitalize(name: &str) -> String {
    let mut chars = name.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

/// Discover existing keyrings in the data directory
pub(crate) async fn discover_keyrings(
    data_dir: &PathBuf,
    secret: Option<Secret>,
) -> Result<Vec<LoadedKeyring>, Error> {
    let mut discovered = Vec::new();

    let keyrings_dir = data_dir.join("keyrings");

    // Scan for v1 keyrings first
    let v1_dir = keyrings_dir.join("v1");
    if v1_dir.exists() {
        tracing::debug!("Scanning for v1 keyrings in {}", v1_dir.display());
        if let Ok(mut entries) = tokio::fs::read_dir(&v1_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();

                // Skip directories and non-.keyring files
                if path.is_dir() || path.extension() != Some(std::ffi::OsStr::new("keyring")) {
                    continue;
                }

                if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                    tracing::debug!("Found v1 keyring: {name}");

                    // Try to load the keyring
                    match load_keyring(data_dir, &path, name, secret.as_ref()).await {
                        Ok(loaded) => discovered.push(loaded),
                        Err(e) => tracing::warn!("Failed to load keyring {:?}: {}", path, e),
                    }
                }
            }
        }
    }

    // Scan for v0 keyrings
    if keyrings_dir.exists() {
        tracing::debug!("Scanning for v0 keyrings in {}", keyrings_dir.display());
        if let Ok(mut entries) = tokio::fs::read_dir(&keyrings_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();

                // Skip directories and non-.keyring files
                if path.is_dir() || path.extension() != Some(std::ffi::OsStr::new("keyring")) {
                    continue;
                }

                if migration::stamp_path(&path).exists() {
                    continue;
                }

                if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                    tracing::debug!("Found v0 keyring: {name}");

                    // Try to load the keyring
                    match load_keyring(data_dir, &path, name, secret.as_ref()).await {
                        Ok(loaded) => discovered.push(loaded),
                        Err(e) => tracing::warn!("Failed to load keyring {:?}: {}", path, e),
                    }
                }
            }
        }
    }

    // Discover KWallet keyrings for migration
    #[cfg(feature = "kwallet_migration")]
    discover_kwallet_keyrings(data_dir, secret.as_ref(), &mut discovered).await;

    let pending_count = discovered
        .iter()
        .filter(|d| d.pending_migration.is_some())
        .count();

    if discovered.is_empty() && pending_count == 0 {
        tracing::info!("No keyrings discovered in data directory");
    } else {
        tracing::info!(
            "Discovered {} keyring(s), {pending_count} pending migration(s)",
            discovered.len(),
        );
    }

    Ok(discovered)
}

/// Load a single keyring from a file path
async fn load_keyring(
    data_dir: &PathBuf,
    path: &std::path::Path,
    name: &str,
    secret: Option<&Secret>,
) -> Result<LoadedKeyring, Error> {
    let alias = if name.eq_ignore_ascii_case(LOGIN_ALIAS) {
        oo7::dbus::Service::DEFAULT_COLLECTION.to_owned()
    } else {
        name.to_owned().to_lowercase()
    };

    // Use name as label (capitalized for consistency with Login)
    let label = capitalize(name);

    // Try to load the keyring
    let (keyring, pending_migration) = match LockedKeyring::load(path).await {
        Ok(locked_keyring) => {
            // Successfully loaded as v1 keyring
            if let Some(secret) = secret {
                match locked_keyring.unlock(secret.clone()).await {
                    Ok(unlocked) => {
                        tracing::info!("Unlocked keyring '{}' from {:?}", name, path);
                        (Keyring::Unlocked(unlocked), None)
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to unlock keyring '{}' with provided secret: {}. Keeping it locked.",
                            name,
                            e
                        );
                        // Reload as locked since unlock consumed it
                        (Keyring::Locked(LockedKeyring::load(path).await?), None)
                    }
                }
            } else {
                tracing::debug!("No secret provided, keeping keyring '{}' locked", name);
                (Keyring::Locked(locked_keyring), None)
            }
        }
        Err(oo7::file::Error::VersionMismatch(Some(version))) if version.first() == Some(&0) =>
        // v0 is the legacy version
        {
            // This is a v0 keyring that needs migration
            tracing::info!(
                "Found legacy v0 keyring '{name}' at {}, registering for migration",
                path.display()
            );

            let migration = PendingMigration::V0 {
                name: name.to_owned(),
                path: path.to_path_buf(),
                label: label.clone(),
                alias: alias.clone(),
            };

            tracing::debug!("Attempting immediate migration of v0 keyring '{name}'",);
            match migration.migrate(data_dir, secret).await {
                Ok(unlocked) => {
                    tracing::info!("Successfully migrated v0 keyring '{name}' to v1",);
                    return Ok(LoadedKeyring {
                        name: name.to_owned(),
                        label,
                        alias,
                        keyring: Keyring::Unlocked(unlocked),
                        pending_migration: None,
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to migrate v0 keyring '{name}': {e}. Creating locked placeholder collection.",
                    );
                }
            }

            // Migration failed - create locked placeholder and register for
            // pending migration
            tracing::debug!(
                "Creating locked placeholder for v0 keyring '{}', will migrate on unlock",
                name
            );

            let locked = LockedKeyring::open_at(data_dir, name).await?;
            (Keyring::Locked(locked), Some(migration))
        }
        // Plain legacy keyrings, written by gnome-keyring for an empty
        // password, don't have the binary file header. Their migration
        // doesn't need a secret, so if it fails this isn't a keyring.
        Err(oo7::file::Error::FileHeaderMismatch(_)) => {
            tracing::info!(
                "Found legacy plain keyring '{name}' at {}, migrating",
                path.display()
            );

            let migration = PendingMigration::V0 {
                name: name.to_owned(),
                path: path.to_path_buf(),
                label: label.clone(),
                alias: alias.clone(),
            };
            (
                Keyring::Unlocked(migration.migrate(data_dir, secret).await?),
                None,
            )
        }
        Err(e) => {
            return Err(e.into());
        }
    };

    Ok(LoadedKeyring {
        name: name.to_owned(),
        label,
        alias,
        keyring,
        pending_migration,
    })
}

/// Discover KWallet keyrings for migration
#[cfg(feature = "kwallet_migration")]
async fn discover_kwallet_keyrings(
    data_dir: &PathBuf,
    secret: Option<&Secret>,
    discovered: &mut Vec<LoadedKeyring>,
) {
    let kwallet_dir = data_dir.join("kwalletd");

    if !kwallet_dir.exists() {
        tracing::debug!("No kwalletd directory found, skipping KWallet discovery");
        return;
    }

    tracing::debug!("Scanning for KWallet files in {}", kwallet_dir.display());

    let Ok(mut entries) = tokio::fs::read_dir(&kwallet_dir).await else {
        tracing::warn!("Failed to read kwalletd directory");
        return;
    };

    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();

        // Only process .kwl files
        if path.extension().is_none_or(|ext| ext != "kwl") {
            continue;
        }

        if migration::stamp_path(&path).exists() {
            continue;
        }

        let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };

        tracing::debug!("Found KWallet file: {name}");

        // Use lowercased name as alias
        let alias = name.to_lowercase();

        let label = capitalize(name);

        let migration = PendingMigration::KWallet {
            name: name.to_owned(),
            path: path.clone(),
            label: label.clone(),
            alias: alias.clone(),
        };

        if let Some(secret) = secret {
            tracing::debug!("Attempting immediate migration of KWallet keyring '{name}'",);
            match migration.migrate(data_dir, Some(secret)).await {
                Ok(unlocked) => {
                    tracing::info!("Successfully migrated KWallet keyring '{name}' to oo7",);
                    discovered.push(LoadedKeyring {
                        name: name.to_owned(),
                        label,
                        alias,
                        keyring: Keyring::Unlocked(unlocked),
                        pending_migration: None,
                    });
                    continue;
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to migrate KWallet keyring '{name}' at {}: {e}. Creating locked placeholder collection.",
                        migration.path().display()
                    );
                }
            }
        }

        // Migration failed or no secret - create locked placeholder and
        // register for pending migration
        tracing::debug!(
            "Creating locked placeholder for KWallet keyring '{name}', will migrate on unlock",
        );

        match LockedKeyring::open_at(data_dir, name).await {
            Ok(locked) => {
                tracing::debug!(
                    "Created locked placeholder for '{name}', adding to pending migrations",
                );
                discovered.push(LoadedKeyring {
                    name: name.to_owned(),
                    label,
                    alias,
                    keyring: Keyring::Locked(locked),
                    pending_migration: Some(migration),
                });
            }
            Err(e) => {
                tracing::error!("Failed to create placeholder keyring for '{name}': {e}");
            }
        }
    }
}
