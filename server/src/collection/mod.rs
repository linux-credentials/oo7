// org.freedesktop.Secret.Collection

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

use oo7::{
    Secret,
    dbus::{
        ServiceError,
        api::{DBusSecretInner, Properties},
    },
    file::Keyring,
};
use tokio::sync::{Mutex, RwLock};
use zbus::{interface, object_server::SignalEmitter, proxy::Defaults, zvariant};
use zvariant::{ObjectPath, OwnedObjectPath};

use crate::{
    Service,
    error::{Error, custom_service_error},
    item,
};

#[derive(Debug, Clone)]
pub struct Collection {
    // Properties
    items: Arc<Mutex<Vec<item::Item>>>,
    label: Arc<Mutex<String>>,
    created: Duration,
    modified: Arc<Mutex<Duration>>,
    // Other attributes
    alias: Arc<Mutex<String>>,
    pub(crate) keyring: Arc<RwLock<Option<Keyring>>>,
    service: Service,
    item_index: Arc<RwLock<u32>>,
    path: OwnedObjectPath,
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    #[zbus(out_args("prompt"))]
    pub async fn delete(&self) -> Result<OwnedObjectPath, ServiceError> {
        // Check if collection is locked
        if self.is_locked().await {
            // Create a prompt to unlock and delete the collection
            let prompt = crate::prompt::Prompt::new(
                self.service.clone(),
                crate::prompt::PromptRole::Unlock,
                self.label().await,
                Some(self.clone()),
            )
            .await;
            let prompt_path = OwnedObjectPath::from(prompt.path().clone());

            let collection = self.clone();
            let action =
                crate::prompt::PromptAction::new(move |unlock_secret: Secret| async move {
                    // Unlock the collection
                    collection.set_locked(false, Some(unlock_secret)).await?;

                    collection.delete_unlocked().await?;

                    Ok(zvariant::Value::new(OwnedObjectPath::default())
                        .try_into_owned()
                        .unwrap())
                });

            prompt.set_action(action).await;

            self.service
                .register_prompt(prompt_path.clone(), prompt.clone())
                .await;

            self.service
                .object_server()
                .at(&prompt_path, prompt)
                .await?;

            tracing::debug!(
                "Delete prompt created at `{}` for locked collection `{}`",
                prompt_path,
                self.path
            );

            return Ok(prompt_path);
        }

        self.delete_unlocked().await?;
        Ok(OwnedObjectPath::default())
    }

    async fn delete_unlocked(&self) -> Result<(), ServiceError> {
        let keyring = self.keyring.read().await;
        let keyring = keyring.as_ref().unwrap().as_unlocked();

        let object_server = self.service.object_server();

        // Remove all items from the object server
        let items = self.items.lock().await;
        for item in items.iter() {
            object_server.remove::<item::Item, _>(item.path()).await?;
        }
        drop(items);

        // Delete the keyring file if it's persistent
        if let Some(path) = keyring.path() {
            tokio::fs::remove_file(&path).await.map_err(|err| {
                custom_service_error(&format!("Failed to delete keyring file: {err}"))
            })?;
            tracing::debug!("Deleted keyring file: {}", path.display());
        }

        // Emit CollectionDeleted signal before removing from object server
        let service_path = oo7::dbus::api::Service::PATH.as_ref().unwrap();
        let signal_emitter = self.service.signal_emitter(service_path)?;
        Service::collection_deleted(&signal_emitter, &self.path).await?;

        // Remove collection from object server
        object_server.remove::<Collection, _>(&self.path).await?;

        // Notify service to remove from collections list
        self.service.remove_collection(&self.path).await;

        tracing::info!("Collection `{}` deleted.", self.path);

        Ok(())
    }

    #[zbus(out_args("results"))]
    pub async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<Vec<OwnedObjectPath>, ServiceError> {
        let results = self
            .search_inner_items(&attributes)
            .await?
            .iter()
            .map(|item| item.path().clone().into())
            .collect::<Vec<OwnedObjectPath>>();

        if results.is_empty() {
            tracing::debug!(
                "Items with attributes {:?} does not exist in collection: {}.",
                attributes,
                self.path
            );
        } else {
            tracing::debug!(
                "Items with attributes {:?} found in collection: {}.",
                attributes,
                self.path
            );
        }

        Ok(results)
    }

    #[zbus(out_args("item", "prompt"))]
    pub async fn create_item(
        &self,
        properties: Properties,
        secret: DBusSecretInner,
        replace: bool,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), ServiceError> {
        if self.is_locked().await {
            // Create a prompt to unlock the collection and create the item
            let prompt = crate::prompt::Prompt::new(
                self.service.clone(),
                crate::prompt::PromptRole::Unlock,
                self.label().await,
                Some(self.clone()),
            )
            .await;
            let prompt_path = OwnedObjectPath::from(prompt.path().clone());

            let collection = self.clone();
            let action =
                crate::prompt::PromptAction::new(move |unlock_secret: Secret| async move {
                    collection.set_locked(false, Some(unlock_secret)).await?;

                    let item_path = collection
                        .create_item_unlocked(properties, secret, replace)
                        .await?;

                    Ok(zvariant::Value::new(item_path).try_into_owned().unwrap())
                });

            prompt.set_action(action).await;

            self.service
                .register_prompt(prompt_path.clone(), prompt.clone())
                .await;

            self.service
                .object_server()
                .at(&prompt_path, prompt)
                .await?;

            tracing::debug!(
                "CreateItem prompt created at `{}` for locked collection `{}`",
                prompt_path,
                self.path
            );

            return Ok((OwnedObjectPath::default(), prompt_path));
        }

        let item_path = self
            .create_item_unlocked(properties, secret, replace)
            .await?;

        Ok((item_path, OwnedObjectPath::default()))
    }

    async fn create_item_unlocked(
        &self,
        properties: Properties,
        secret: DBusSecretInner,
        replace: bool,
    ) -> Result<OwnedObjectPath, ServiceError> {
        let keyring = self.keyring.read().await;
        let keyring = keyring.as_ref().unwrap().as_unlocked();

        let DBusSecretInner(session_path, iv, secret_bytes, content_type) = secret;
        let label = properties.label();
        // Safe to unwrap as an item always has attributes
        let mut attributes = properties.attributes().unwrap().to_owned();

        let Some(session) = self.service.session(&session_path).await else {
            tracing::error!("The session `{}` does not exist.", session_path);
            return Err(ServiceError::NoSession(format!(
                "The session `{session_path}` does not exist."
            )));
        };

        let secret = match session.aes_key() {
            Some(key) => oo7::crypto::decrypt(secret_bytes, &key, &iv)
                .map_err(|err| custom_service_error(&format!("Failed to decrypt secret {err}.")))?,
            None => zeroize::Zeroizing::new(secret_bytes),
        };

        // Ensure content-type attribute is stored
        if !attributes.contains_key(oo7::CONTENT_TYPE_ATTRIBUTE) {
            attributes.insert(
                oo7::CONTENT_TYPE_ATTRIBUTE.to_owned(),
                content_type.as_str().to_owned(),
            );
        }

        let item = keyring
            .create_item(label, &attributes, secret, replace)
            .await
            .map_err(|err| custom_service_error(&format!("Failed to create a new item {err}.")))?;

        let n_items = *self.item_index.read().await;
        let item_path = OwnedObjectPath::try_from(format!("{}/{n_items}", self.path)).unwrap();

        let item = item::Item::new(
            item,
            self.service.clone(),
            self.path.clone(),
            item_path.clone(),
        );
        *self.item_index.write().await = n_items + 1;

        let object_server = self.service.object_server();
        let signal_emitter = self.service.signal_emitter(&self.path)?;

        // Remove any existing items with the same attributes
        if replace {
            let existing_items = self.search_inner_items(&attributes).await?;
            if !existing_items.is_empty() {
                let mut items = self.items.lock().await;
                for existing in &existing_items {
                    let existing_path = existing.path();

                    items.retain(|i| i.path() != existing_path);
                    object_server.remove::<item::Item, _>(existing_path).await?;
                    Self::item_deleted(&signal_emitter, existing_path).await?;

                    tracing::debug!("Replaced item `{}`", existing_path);
                }
                drop(items);
            }
        }

        self.items.lock().await.push(item.clone());

        object_server.at(&item_path, item).await?;

        self.update_modified().await?;

        Self::item_created(&signal_emitter, &item_path).await?;
        self.items_changed(&signal_emitter).await?;

        tracing::info!("Item `{item_path}` created.");

        Ok(item_path)
    }

    #[zbus(property, name = "Items")]
    pub async fn items(&self) -> Vec<OwnedObjectPath> {
        self.items
            .lock()
            .await
            .iter()
            .map(|i| i.path().to_owned().into())
            .collect()
    }

    #[zbus(property, name = "Label")]
    pub async fn label(&self) -> String {
        self.label.lock().await.clone()
    }

    #[zbus(property, name = "Label")]
    pub async fn set_label(&self, label: &str) -> Result<(), zbus::Error> {
        if self.is_locked().await {
            tracing::error!("Cannot set label of a locked collection `{}`", self.path);
            return Err(zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(
                format!("Cannot set label of a locked collection `{}`.", self.path),
            ))));
        }

        *self.label.lock().await = label.to_owned();

        self.update_modified()
            .await
            .map_err(|err| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(err.to_string()))))?;

        let service_path = oo7::dbus::api::Service::PATH.as_ref().unwrap();
        let signal_emitter = self
            .service
            .signal_emitter(service_path)
            .map_err(|err| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(err.to_string()))))?;
        Service::collection_changed(&signal_emitter, &self.path).await?;

        let signal_emitter = self
            .service
            .signal_emitter(&self.path)
            .map_err(|err| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(err.to_string()))))?;
        self.label_changed(&signal_emitter).await?;

        Ok(())
    }

    #[zbus(property, name = "Locked")]
    pub async fn is_locked(&self) -> bool {
        self.keyring
            .read()
            .await
            .as_ref()
            .map(|k| k.is_locked())
            .unwrap_or(true)
    }

    #[zbus(property, name = "Created")]
    pub fn created_at(&self) -> u64 {
        self.created.as_secs()
    }

    #[zbus(property, name = "Modified")]
    pub async fn modified_at(&self) -> u64 {
        self.modified.lock().await.as_secs()
    }

    #[zbus(signal, name = "ItemCreated")]
    async fn item_created(
        signal_emitter: &SignalEmitter<'_>,
        item: &ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal, name = "ItemDeleted")]
    pub async fn item_deleted(
        signal_emitter: &SignalEmitter<'_>,
        item: &ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal, name = "ItemChanged")]
    pub async fn item_changed(
        signal_emitter: &SignalEmitter<'_>,
        item: &ObjectPath<'_>,
    ) -> zbus::Result<()>;
}

impl Collection {
    pub async fn new(label: &str, alias: &str, service: Service, keyring: Keyring) -> Self {
        let modified = keyring.modified_time().await;
        let created = keyring.created_time().await.unwrap_or(modified);

        let sanitized_label = label
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect::<String>();

        Self {
            items: Default::default(),
            label: Arc::new(Mutex::new(label.to_owned())),
            modified: Arc::new(Mutex::new(modified)),
            alias: Arc::new(Mutex::new(alias.to_owned())),
            item_index: Arc::new(RwLock::new(0)),
            path: OwnedObjectPath::try_from(format!(
                "/org/freedesktop/secrets/collection/{sanitized_label}"
            ))
            .expect("Sanitized label should always produce valid object path"),
            created,
            service,
            keyring: Arc::new(RwLock::new(Some(keyring))),
        }
    }

    pub fn path(&self) -> &ObjectPath<'_> {
        &self.path
    }

    pub async fn set_alias(&self, alias: &str) {
        *self.alias.lock().await = alias.to_owned();
    }

    pub async fn alias(&self) -> String {
        self.alias.lock().await.clone()
    }

    pub async fn search_inner_items(
        &self,
        attributes: &HashMap<String, String>,
    ) -> Result<Vec<item::Item>, ServiceError> {
        // If collection is locked, we can't search
        if self.is_locked().await {
            return Ok(Vec::new());
        }

        let keyring_guard = self.keyring.read().await;
        let keyring = keyring_guard.as_ref().unwrap().as_unlocked();

        let key = keyring
            .key()
            .await
            .map_err(|err| custom_service_error(&format!("Failed to derive key: {err}")))?;

        let mut matching_items = Vec::new();
        let items = self.items.lock().await;

        for item_wrapper in items.iter() {
            let inner = item_wrapper.inner.lock().await;
            let file_item = inner.as_ref().unwrap();

            // Use the oo7::file::Item's matches_attributes method
            if file_item.matches_attributes(attributes, &key) {
                matching_items.push(item_wrapper.clone());
            }
        }

        Ok(matching_items)
    }

    pub async fn item_from_path(&self, path: &ObjectPath<'_>) -> Option<item::Item> {
        let items = self.items.lock().await;

        items.iter().find(|i| i.path() == path).cloned()
    }

    pub async fn set_locked(
        &self,
        locked: bool,
        secret: Option<Secret>,
    ) -> Result<(), ServiceError> {
        let mut keyring_guard = self.keyring.write().await;

        if let Some(old_keyring) = keyring_guard.take() {
            let new_keyring = match (old_keyring, locked) {
                (Keyring::Unlocked(unlocked), true) => {
                    let items = self.items.lock().await;
                    for item in items.iter() {
                        item.set_locked(locked, &unlocked).await?;
                    }
                    drop(items);

                    Keyring::Locked(unlocked.lock())
                }
                (Keyring::Locked(locked_kr), false) => {
                    let secret = secret.ok_or_else(|| {
                        custom_service_error("Cannot unlock collection without a secret")
                    })?;

                    let keyring_path = locked_kr.path().map(|p| p.to_path_buf());

                    let unlocked = match locked_kr.unlock(secret).await {
                        Ok(unlocked) => unlocked,
                        Err(err) => {
                            // Reload the locked keyring from disk before returning error
                            if let Some(path) = keyring_path
                                && let Ok(reloaded) = oo7::file::LockedKeyring::load(&path).await
                            {
                                *keyring_guard = Some(Keyring::Locked(reloaded));
                            }
                            return Err(custom_service_error(&format!(
                                "Failed to unlock keyring: {err}"
                            )));
                        }
                    };

                    let items = self.items.lock().await;
                    for item in items.iter() {
                        item.set_locked(locked, &unlocked).await?;
                    }
                    drop(items);

                    Keyring::Unlocked(unlocked)
                }
                (other, _) => other,
            };
            *keyring_guard = Some(new_keyring);
        }

        drop(keyring_guard);

        // Emit signals
        let signal_emitter = self.service.signal_emitter(&self.path)?;
        self.locked_changed(&signal_emitter).await?;

        let service_path = oo7::dbus::api::Service::PATH.as_ref().unwrap();
        let signal_emitter = self.service.signal_emitter(service_path)?;
        Service::collection_changed(&signal_emitter, &self.path).await?;

        tracing::debug!(
            "Collection: {} is {}.",
            self.path,
            if locked { "locked" } else { "unlocked" }
        );

        Ok(())
    }

    pub async fn dispatch_items(&self) -> Result<(), Error> {
        let keyring_guard = self.keyring.read().await;
        let keyring = keyring_guard.as_ref().unwrap();

        let keyring_items = keyring.items().await?;
        let mut items = self.items.lock().await;
        let object_server = self.service.object_server();
        let mut n_items = 1;

        for keyring_item in keyring_items {
            let item_path = OwnedObjectPath::try_from(format!("{}/{n_items}", self.path)).unwrap();
            let item = item::Item::new(
                keyring_item.map_err(Error::InvalidItem)?,
                self.service.clone(),
                self.path.clone(),
                item_path.clone(),
            );
            n_items += 1;

            items.push(item.clone());
            object_server.at(item_path, item).await?;
        }

        *self.item_index.write().await = n_items;

        Ok(())
    }

    pub async fn delete_item(&self, path: &ObjectPath<'_>) -> Result<(), ServiceError> {
        let Some(item) = self.item_from_path(path).await else {
            return Err(ServiceError::NoSuchObject(format!(
                "Item `{path}` does not exist."
            )));
        };

        if item.is_locked().await {
            return Err(ServiceError::IsLocked(format!(
                "Cannot delete a locked item `{path}`"
            )));
        }

        if self.is_locked().await {
            return Err(ServiceError::IsLocked(format!(
                "Cannot delete an item `{path}`  in a locked collection "
            )));
        }

        let attributes = item.attributes().await.map_err(|err| {
            custom_service_error(&format!("Failed to read item attributes {err}"))
        })?;

        let keyring = self.keyring.read().await;
        let keyring = keyring.as_ref().unwrap().as_unlocked();

        keyring
            .delete(&attributes)
            .await
            .map_err(|err| custom_service_error(&format!("Failed to deleted item {err}.")))?;

        let mut items = self.items.lock().await;
        items.retain(|item| item.path() != path);
        drop(items);

        self.update_modified().await?;

        let signal_emitter = self.service.signal_emitter(&self.path)?;
        self.items_changed(&signal_emitter).await?;

        Ok(())
    }

    /// Update the modified timestamp and emit the PropertiesChanged signal
    async fn update_modified(&self) -> Result<(), ServiceError> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        *self.modified.lock().await = now;

        let signal_emitter = self.service.signal_emitter(&self.path)?;
        self.modified_changed(&signal_emitter).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests;
