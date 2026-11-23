// org.freedesktop.Secret.Item

use std::{collections::HashMap, sync::Arc};

use oo7::{
    dbus::{ServiceError, api::DBusSecretInner},
    file::{Keyring, UnlockedItem},
};
use tokio::sync::Mutex;
use zbus::wire::{ObjectPath, OwnedObjectPath};

use crate::{Service, collection::Collection, error::custom_service_error, storage::Record};

#[derive(Clone)]
pub struct Item {
    // Properties
    pub(super) inner: Arc<Mutex<Record>>,
    // Other attributes
    service: Service,
    collection_path: OwnedObjectPath,
    path: OwnedObjectPath,
}

#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    #[zbus(out_args("Prompt"))]
    pub async fn delete(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<OwnedObjectPath, ServiceError> {
        let caller = if let Some(sender) = header.sender() {
            self.service.peer_display_name(sender).await
        } else {
            "unknown".to_string()
        };
        let collection = self.collection().await?;

        // Deleting a stand-in item would migrate the legacy keyring and
        // throw the item away
        if self.service.has_pending_migration(collection.name()).await {
            return Err(ServiceError::IsLocked(format!(
                "Item `{}` belongs to a collection holding a keyring awaiting \
                 migration, unlock the collection first.",
                self.path
            )));
        }

        // Check if item or collection is locked
        if self.is_locked().await || collection.is_locked().await {
            // Create a prompt to unlock and delete the item
            let prompt = crate::prompt::Prompt::new(
                self.service.clone(),
                crate::prompt::PromptRole::Unlock,
                collection.label().await,
                Some(collection.clone()),
            )
            .await;
            let prompt_path = OwnedObjectPath::from(prompt.path().clone());

            let item_self = self.clone();
            let coll = collection.clone();
            let service = self.service.clone();
            let caller = caller.to_owned();
            let action = crate::prompt::PromptAction::new(
                move |unlock_secret: Option<oo7::Secret>| async move {
                    service.unlock_collection(&coll, unlock_secret).await?;

                    // The migration replaced the placeholder items
                    let item = coll
                        .item_from_path(item_self.path())
                        .await
                        .ok_or_else(|| ServiceError::NoSuchObject(item_self.path().to_string()))?;

                    // Now delete the item
                    item.delete_unlocked(&coll, &caller).await?;

                    Ok(zbus::wire::Variant::new(OwnedObjectPath::default())
                        .try_into_owned()
                        .unwrap())
                },
            );

            prompt.set_action(action).await;

            // Register the prompt
            self.service
                .register_prompt(prompt_path.clone(), prompt.clone())
                .await;

            self.service
                .object_server()
                .at(&prompt_path, prompt)
                .await?;

            tracing::debug!(
                "Delete prompt created at `{}` for locked item `{}`",
                prompt_path,
                self.path
            );

            return Ok(prompt_path);
        }

        // Item and collection are unlocked, proceed directly
        self.delete_unlocked(&collection, &caller).await?;
        Ok(OwnedObjectPath::default())
    }

    #[zbus(out_args("secret"))]
    pub async fn get_secret(
        &self,
        session: OwnedObjectPath,
    ) -> Result<(DBusSecretInner,), ServiceError> {
        let Some(session) = self.service.session(&session).await else {
            tracing::error!("The session `{}` does not exist.", session);
            return Err(ServiceError::NoSession(format!(
                "The session `{session}` does not exist."
            )));
        };

        let inner = self.require_unlocked().await?;
        let secret = inner.unlocked().secret();
        let content_type = secret.content_type();

        tracing::debug!("Secret retrieved from the item: {}.", self.path);

        match session.aes_key() {
            Some(key) => {
                let iv = oo7::crypto::generate_iv().map_err(|err| {
                    custom_service_error(&format!("Failed to generate iv {err}."))
                })?;
                let encrypted = oo7::crypto::encrypt(secret, &key, &iv).map_err(|err| {
                    custom_service_error(&format!("Failed to encrypt secret {err}."))
                })?;

                Ok((DBusSecretInner(
                    session.path().clone().into(),
                    iv,
                    encrypted,
                    content_type,
                ),))
            }
            None => Ok((DBusSecretInner(
                session.path().clone().into(),
                Vec::new(),
                secret.to_vec(),
                content_type,
            ),)),
        }
    }

    pub async fn set_secret(&self, secret: DBusSecretInner) -> Result<(), ServiceError> {
        let DBusSecretInner(ref session, ref iv, ref secret, ref content_type) = secret;

        let Some(session) = self.service.session(session).await else {
            tracing::error!("The session `{}` does not exist.", session);
            return Err(ServiceError::NoSession(format!(
                "The session `{session}` does not exist."
            )));
        };

        let collection = self.collection().await?;
        {
            let keyring = collection.keyring.write().await;
            let mut inner = self.require_unlocked().await?;

            let mut item = inner.unlocked().clone();
            match session.aes_key() {
                Some(key) => {
                    let decrypted = oo7::crypto::decrypt(secret, &key, iv).map_err(|err| {
                        custom_service_error(&format!("Failed to decrypt secret {err}."))
                    })?;
                    item.set_secret(decrypted);
                }
                None => {
                    item.set_secret(secret);
                }
            }

            // Ensure content-type attribute is stored
            let mut attributes = item.attributes().clone();
            if !attributes.contains_key(oo7::CONTENT_TYPE_ATTRIBUTE) {
                attributes.insert(
                    oo7::CONTENT_TYPE_ATTRIBUTE.to_owned(),
                    content_type.as_str().into(),
                );
            } else {
                attributes
                    .entry(oo7::CONTENT_TYPE_ATTRIBUTE.to_string())
                    .and_modify(|v| *v = content_type.as_str().into());
            }
            item.set_attributes(&attributes);

            self.write(keyring.as_ref(), &mut inner, item).await?;
        }

        let signal_emitter = self.service.signal_emitter(&self.collection_path)?;
        Collection::item_changed(&signal_emitter, &self.path).await?;

        if let Ok(signal_emitter) = self.service.signal_emitter(&self.path)
            && let Err(err) = self.modified_changed(&signal_emitter).await
        {
            tracing::error!(
                "Failed to emit PropertiesChanged signal for Modified: {}",
                err
            );
        }

        tracing::debug!("Secret updated for item: {}.", self.path);

        Ok(())
    }

    #[zbus(property, name = "Locked")]
    pub async fn is_locked(&self) -> bool {
        self.inner.lock().await.is_locked()
    }

    #[zbus(property, name = "Attributes")]
    pub async fn attributes(&self) -> Result<HashMap<String, String>, ServiceError> {
        let inner = self.require_unlocked().await?;
        Ok(inner
            .unlocked()
            .attributes()
            .iter()
            .map(|(k, v)| (k.to_owned(), v.to_string()))
            .collect())
    }

    #[zbus(property, name = "Attributes")]
    pub async fn set_attributes(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<(), ServiceError> {
        let collection = self.collection().await?;
        {
            let keyring = collection.keyring.write().await;
            let mut inner = self.require_unlocked().await?;

            let mut item = inner.unlocked().clone();
            item.set_attributes(&attributes);
            self.write(keyring.as_ref(), &mut inner, item).await?;
        }

        let signal_emitter = self.service.signal_emitter(&self.collection_path)?;
        Collection::item_changed(&signal_emitter, &self.path).await?;

        let signal_emitter = self.service.signal_emitter(&self.path)?;
        self.attributes_changed(&signal_emitter).await?;
        self.modified_changed(&signal_emitter).await?;

        tracing::debug!("Attributes updated for item `{}`.", self.path);
        Ok(())
    }

    #[zbus(property, name = "Label")]
    pub async fn label(&self) -> Result<String, ServiceError> {
        let inner = self.require_unlocked().await?;
        Ok(inner.unlocked().label().to_owned())
    }

    #[zbus(property, name = "Label")]
    pub async fn set_label(&self, label: &str) -> Result<(), ServiceError> {
        let collection = self.collection().await?;
        {
            let keyring = collection.keyring.write().await;
            let mut inner = self.require_unlocked().await?;

            let mut item = inner.unlocked().clone();
            item.set_label(label);
            self.write(keyring.as_ref(), &mut inner, item).await?;
        }

        let signal_emitter = self.service.signal_emitter(&self.collection_path)?;
        Collection::item_changed(&signal_emitter, &self.path).await?;

        let signal_emitter = self.service.signal_emitter(&self.path)?;
        self.label_changed(&signal_emitter).await?;
        self.modified_changed(&signal_emitter).await?;

        tracing::debug!("Label updated for item `{}`.", self.path);
        Ok(())
    }

    #[zbus(property, name = "Created")]
    pub async fn created_at(&self) -> Result<u64, ServiceError> {
        let inner = self.require_unlocked().await?;
        Ok(inner.unlocked().created().as_secs())
    }

    #[zbus(property, name = "Modified")]
    pub async fn modified_at(&self) -> Result<u64, ServiceError> {
        let inner = self.require_unlocked().await?;
        Ok(inner.unlocked().modified().as_secs())
    }
}

impl Item {
    pub(crate) fn new(
        item: Record,
        service: Service,
        collection_path: OwnedObjectPath,
        path: OwnedObjectPath,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(item)),
            path,
            collection_path,
            service,
        }
    }

    pub fn path(&self) -> &ObjectPath<'_> {
        &self.path
    }

    async fn require_unlocked(&self) -> Result<tokio::sync::MutexGuard<'_, Record>, ServiceError> {
        let guard = self.inner.lock().await;
        if guard.is_locked() {
            return Err(ServiceError::IsLocked(format!(
                "Object `{}` is locked.",
                self.path
            )));
        }
        Ok(guard)
    }

    async fn collection(&self) -> Result<Collection, ServiceError> {
        self.service
            .collection_from_path(&self.collection_path)
            .await
            .ok_or_else(|| {
                ServiceError::NoSuchObject(format!(
                    "Collection `{}` does not exist.",
                    self.collection_path
                ))
            })
    }

    async fn write(
        &self,
        keyring: Option<&Keyring>,
        record: &mut Record,
        new: UnlockedItem,
    ) -> Result<(), ServiceError> {
        let Some(Keyring::Unlocked(keyring)) = keyring else {
            return Err(ServiceError::IsLocked(format!(
                "Cannot write item `{}` to a locked keyring.",
                self.path
            )));
        };

        if !record
            .replace(keyring, new)
            .await
            .map_err(|err| custom_service_error(&format!("Failed to write item: {err}")))?
        {
            return Err(ServiceError::NoSuchObject(format!(
                "Item `{}` is not in the keyring.",
                self.path
            )));
        }
        Ok(())
    }

    pub(crate) async fn set_locked(
        &self,
        locked: bool,
        keyring: &oo7::file::UnlockedKeyring,
    ) -> Result<(), ServiceError> {
        if let Some((mut current, next)) = self.prepare_lock_state(locked, keyring).await? {
            *current = next;
        }
        self.notify_lock_state(locked).await
    }

    pub(crate) async fn prepare_lock_state(
        &self,
        locked: bool,
        keyring: &oo7::file::UnlockedKeyring,
    ) -> Result<Option<(tokio::sync::MutexGuard<'_, Record>, Record)>, ServiceError> {
        let current = self.inner.lock().await;
        let next = current
            .with_lock_state(locked, keyring)
            .await
            .map_err(|err| {
                let action = if locked { "lock" } else { "unlock" };
                custom_service_error(&format!("Failed to {action} item: {err}"))
            })?;
        Ok(next.map(|next| (current, next)))
    }

    pub(crate) async fn notify_lock_state(&self, locked: bool) -> Result<(), ServiceError> {
        let signal_emitter = self.service.signal_emitter(&self.path)?;
        self.locked_changed(&signal_emitter).await?;

        let signal_emitter = self.service.signal_emitter(&self.collection_path)?;
        Collection::item_changed(&signal_emitter, &self.path).await?;

        tracing::debug!(
            "Item: {} is {}.",
            self.path,
            if locked { "locked" } else { "unlocked" }
        );

        Ok(())
    }

    async fn delete_unlocked(
        &self,
        collection: &Collection,
        caller: &str,
    ) -> Result<(), ServiceError> {
        // Delete from keyring and collection's items list
        collection.delete_item(&self.path).await?;

        // Remove from object server
        self.service
            .object_server()
            .remove::<Item, _>(&self.path)
            .await?;

        // Emit ItemDeleted signal
        let signal_emitter = self.service.signal_emitter(&self.collection_path)?;
        Collection::item_deleted(&signal_emitter, &self.path).await?;

        tracing::info!("Item `{}` deleted by {caller}.", &self.path);

        Ok(())
    }
}

#[cfg(test)]
mod tests;
