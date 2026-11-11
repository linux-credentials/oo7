use std::collections::HashMap;

use oo7::{Secret, dbus::ServiceError, file::Keyring};
use zbus::{
    proxy::Defaults,
    wire::{ObjectPath, OwnedObjectPath},
};

use super::Service;
use crate::collection::Collection;

impl Service {
    pub async fn set_locked(
        &self,
        locked: bool,
        objects: &[OwnedObjectPath],
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), ServiceError> {
        let mut without_prompt = Vec::new();
        let mut with_prompt = Vec::new();
        let snapshot: HashMap<OwnedObjectPath, Collection> = self.collections.lock().await.clone();

        for object in objects {
            let resolved = Self::resolve_alias(&snapshot, object)
                .await
                .unwrap_or_else(|| object.clone());
            let mut found = false;
            for (path, collection) in snapshot.iter() {
                let collection_locked = collection.is_locked().await;
                if resolved == *path {
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

    pub(crate) async fn perform_unlock(&self, objects: &[OwnedObjectPath], secret: Option<Secret>) {
        // First, check for pending migrations (without holding collections
        // lock)
        for object in objects {
            let collection = {
                let collections = self.collections.lock().await;
                collections.get(object).cloned()
            };

            if let Some(collection) = collection {
                // Check if this collection has a pending migration by name
                let migration_opt = {
                    let pending = self.pending_migrations.lock().await;
                    pending.get(collection.name()).cloned()
                };

                if let Some(migration) = migration_opt {
                    let migration_name = migration.name();
                    tracing::debug!(
                        "Attempting migration for '{}' during unlock",
                        migration_name
                    );

                    // Attempt migration with the provided secret (no locks
                    // held)
                    match migration.migrate(&self.data_dir, secret.as_ref()).await {
                        Ok(unlocked_keyring) => {
                            tracing::info!(
                                "Successfully migrated '{}' during unlock",
                                migration_name
                            );

                            // Replace the keyring in the collection
                            let mut keyring_guard = collection.keyring.write().await;
                            *keyring_guard = Some(Keyring::Unlocked(unlocked_keyring));
                            drop(keyring_guard);

                            // Dispatch items from the migrated keyring
                            if let Err(e) = collection.dispatch_items().await {
                                tracing::error!("Failed to dispatch items after migration: {}", e);
                            }

                            // Remove from pending migrations
                            self.pending_migrations.lock().await.remove(migration_name);
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to migrate '{}' during unlock: {}",
                                migration_name,
                                e
                            );
                            let _ = collection.set_locked(false, secret.clone()).await;
                        }
                    }
                } else {
                    // Normal unlock
                    let _ = collection.set_locked(false, secret.clone()).await;
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
                        let _ = collection.set_locked(false, secret.clone()).await;
                    } else {
                        let keyring = collection.keyring.read().await;
                        match keyring.as_ref() {
                            Some(k) if !k.is_locked() => {
                                let _ = item.set_locked(false, k.as_unlocked()).await;
                            }
                            _ => {
                                drop(keyring);
                                let _ = collection.set_locked(false, secret.clone()).await;
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
        let mut pending = self.pending_migrations.lock().await;
        let mut to_remove = Vec::new();

        for (name, migration) in pending.iter() {
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
                        *collection.keyring.write().await = Some(Keyring::Unlocked(unlocked));

                        if let Err(e) = collection.dispatch_items().await {
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

                    migrated.push(name.clone());
                    to_remove.push(name.clone());
                }
                Err(e) => {
                    tracing::debug!(
                        "Failed to migrate keyring '{name}' found at {} with provided secret: {e}",
                        migration.path().display()
                    );
                }
            }
        }

        for name in &to_remove {
            pending.remove(name);
        }

        migrated
    }
}
