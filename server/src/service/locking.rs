use oo7::{Secret, dbus::ServiceError, file::Keyring};
use zbus::{
    proxy::Defaults,
    wire::{ObjectPath, OwnedObjectPath},
};

use super::Service;
use crate::{collection::Collection, error::custom_service_error, migration::PendingMigration};

impl Service {
    pub async fn set_locked(
        &self,
        locked: bool,
        objects: &[OwnedObjectPath],
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), ServiceError> {
        let mut without_prompt = Vec::new();
        let mut with_prompt = Vec::new();
        let snapshot = self.sorted_collections().await;

        for object in objects {
            let resolved = Self::resolve_alias(&snapshot, object)
                .await
                .unwrap_or_else(|| object.clone());
            let mut found = false;
            for collection in &snapshot {
                let collection_locked = collection.is_locked().await;
                if resolved.as_str() == collection.path().as_str() {
                    found = true;
                    if collection_locked == locked {
                        tracing::debug!(
                            "Collection: {} is already {}.",
                            resolved,
                            if locked { "locked" } else { "unlocked" }
                        );
                        without_prompt.push(resolved.clone());
                    } else if locked {
                        // Locking never requires a prompt
                        collection.set_locked(true, None).await?;
                        without_prompt.push(resolved.clone());
                    } else {
                        // Unlocking may require a prompt
                        with_prompt.push(resolved.clone());
                    }
                    break;
                } else if let Some(item) = collection.item_from_path(&resolved).await {
                    found = true;
                    // If collection is locked, can't perform any item
                    // lock/unlock operations
                    if collection_locked {
                        // Unlocking an item when collection is locked requires
                        // unlocking collection
                        if !locked {
                            with_prompt.push(resolved.clone());
                        } else {
                            // Can't lock an item when collection is locked
                            return Err(ServiceError::IsLocked(format!(
                                "Cannot lock item {} when collection is locked",
                                resolved
                            )));
                        }
                    } else if locked == item.is_locked().await {
                        tracing::debug!(
                            "Item: {} is already {}.",
                            resolved,
                            if locked { "locked" } else { "unlocked" }
                        );
                        without_prompt.push(resolved.clone());
                    } else {
                        let keyring = collection.keyring.read().await;
                        match keyring.as_ref() {
                            Some(k) if !k.is_locked() => {
                                item.set_locked(locked, k.as_unlocked()).await?;
                                without_prompt.push(resolved.clone());
                            }
                            _ => {
                                if locked {
                                    return Err(ServiceError::IsLocked(format!(
                                        "Cannot lock item {} when collection is locked",
                                        resolved
                                    )));
                                } else {
                                    with_prompt.push(resolved.clone());
                                }
                            }
                        }
                    }
                    break;
                }
            }
            if !found {
                tracing::warn!("Object: {} does not exist.", object);
            }
        }

        Ok((without_prompt, with_prompt))
    }

    pub(crate) async fn collection_for_objects(
        &self,
        objects: &[OwnedObjectPath],
    ) -> Option<Collection> {
        for object in objects {
            if let Some(collection) = self.collection_from_path(object).await {
                return Some(collection);
            }
        }

        // Fall back to the parent path of the first item
        let parent = objects.first()?.as_str().rsplit_once('/')?.0;
        self.collection_from_path(&ObjectPath::try_from(parent).ok()?)
            .await
    }

    /// Unlock a collection with a secret, completing its pending legacy
    /// keyring migration, if any.
    ///
    /// Unlike [`Collection::set_locked`], this migrates the legacy keyring
    /// registered for the collection instead of unlocking the empty
    /// placeholder backing it, and fails if the secret cannot decrypt it.
    pub(crate) async fn unlock_collection(
        &self,
        collection: &Collection,
        secret: Option<Secret>,
    ) -> Result<(), ServiceError> {
        let migration = {
            let pending = self.pending_migrations.lock().await;
            pending.get(collection.name()).cloned()
        };

        let Some(migration) = migration else {
            return collection.set_locked(false, secret).await;
        };

        let name = migration.name().to_owned();
        tracing::debug!("Attempting migration for '{name}' during unlock");
        match migration.migrate(&self.data_dir, secret.as_ref()).await {
            Ok(unlocked) => {
                tracing::info!("Successfully migrated '{name}' during unlock");

                collection
                    .apply_migrated_keyring(Keyring::Unlocked(unlocked))
                    .await
                    .map_err(|e| {
                        custom_service_error(&format!(
                            "Failed to dispatch items of migrated keyring '{name}': {e}"
                        ))
                    })?;

                self.pending_migrations.lock().await.remove(&name);
                Ok(())
            }
            Err(e) => Err(custom_service_error(&format!(
                "Failed to migrate keyring '{name}': {e}"
            ))),
        }
    }

    /// Whether a legacy keyring awaits migration under this collection's
    /// name.
    pub(crate) async fn has_pending_migration(&self, name: &str) -> bool {
        self.pending_migrations.lock().await.contains_key(name)
    }

    pub(crate) async fn perform_unlock(&self, objects: &[OwnedObjectPath], secret: Option<Secret>) {
        for object in objects {
            let collection = {
                let collections = self.collections.lock().await;
                collections.get(object).cloned()
            };

            if let Some(collection) = collection {
                if let Err(e) = self.unlock_collection(&collection, secret.clone()).await {
                    tracing::warn!("Failed to unlock collection {}: {}", collection.path(), e);
                }
            } else {
                // Try to find as item within collections
                let collections = self.collections.lock().await;
                let mut found_collection = None;
                for collection in collections.values() {
                    if let Some(item) = collection.item_from_path(object).await {
                        found_collection = Some((
                            collection.clone(),
                            item.clone(),
                            collection.is_locked().await,
                        ));
                        break;
                    }
                }
                drop(collections);

                if let Some((collection, item, is_locked)) = found_collection {
                    if is_locked {
                        if let Err(e) = self.unlock_collection(&collection, secret.clone()).await {
                            tracing::warn!(
                                "Failed to unlock collection {}: {}",
                                collection.path(),
                                e
                            );
                        }
                    } else {
                        let keyring = collection.keyring.read().await;
                        match keyring.as_ref() {
                            Some(k) if !k.is_locked() => {
                                let _ = item.set_locked(false, k.as_unlocked()).await;
                            }
                            _ => {
                                drop(keyring);
                                if let Err(e) =
                                    self.unlock_collection(&collection, secret.clone()).await
                                {
                                    tracing::warn!(
                                        "Failed to unlock collection {}: {}",
                                        collection.path(),
                                        e
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut pending = self.pending_unlocks.lock().await;
        for obj in objects {
            pending.remove(obj);
        }
    }

    pub async fn migrate_pending_keyrings(&self, secret: &Secret) -> Vec<String> {
        let mut migrated = Vec::new();
        // Migrating reads files and derives keys, don't hold the lock for it
        let migrations: Vec<PendingMigration> = self
            .pending_migrations
            .lock()
            .await
            .values()
            .cloned()
            .collect();
        let mut to_remove = Vec::new();

        for migration in &migrations {
            let name = migration.name();
            tracing::debug!("Attempting to migrate pending keyring: {name}");

            match migration.migrate(&self.data_dir, Some(secret)).await {
                Ok(unlocked) => {
                    // Look for the placeholder collection that was registered
                    // at startup.
                    let placeholder = {
                        let collections = self.collections.lock().await;
                        collections.values().find(|c| c.name() == name).cloned()
                    };

                    if let Some(collection) = placeholder {
                        if let Err(e) = collection
                            .apply_migrated_keyring(Keyring::Unlocked(unlocked))
                            .await
                        {
                            tracing::error!(
                                "Failed to dispatch items for migrated keyring '{name}': {e}",
                            );
                            continue;
                        }

                        if let Ok(signal_emitter) =
                            self.signal_emitter(oo7::dbus::api::Service::PATH.as_ref().unwrap())
                        {
                            let _ = self.collections_changed(&signal_emitter).await;
                        }

                        tracing::info!(
                            "Replaced placeholder for keyring '{name}' with migrated data",
                        );
                    } else {
                        let label = migration.label();
                        let alias = migration.alias();

                        let collection = match self
                            .register_collection(name, label, alias, Keyring::Unlocked(unlocked))
                            .await
                        {
                            Ok((_, collection)) => collection,
                            Err(e) => {
                                tracing::error!(
                                    "Failed to register migrated collection '{name}': {e}",
                                );
                                continue;
                            }
                        };

                        if let Err(e) = collection.dispatch_items().await {
                            tracing::error!(
                                "Failed to dispatch items for migrated collection '{name}': {e}",
                            );
                        }
                    }

                    migrated.push(name.to_owned());
                    to_remove.push(name.to_owned());
                }
                Err(e) => {
                    tracing::debug!(
                        "Failed to migrate keyring '{name}' found at {} with provided secret: {e}",
                        migration.path().display()
                    );
                }
            }
        }

        let mut pending = self.pending_migrations.lock().await;
        for name in &to_remove {
            pending.remove(name);
        }

        migrated
    }
}
