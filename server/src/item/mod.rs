// org.freedesktop.Secret.Item

use std::{collections::HashMap, sync::Arc};

use oo7::dbus::{ServiceError, api::DBusSecretInner};
use tokio::sync::Mutex;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use crate::{Service, collection::Collection, error::custom_service_error};

#[derive(Debug, Clone)]
pub struct Item {
    // Properties
    pub(super) inner: Arc<Mutex<Option<oo7::file::Item>>>,
    // Other attributes
    service: Service,
    collection_path: OwnedObjectPath,
    path: OwnedObjectPath,
}

#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    #[zbus(out_args("Prompt"))]
    pub async fn delete(&self) -> Result<OwnedObjectPath, ServiceError> {
        let Some(collection) = self
            .service
            .collection_from_path(&self.collection_path)
            .await
        else {
            return Err(ServiceError::NoSuchObject(format!(
                "Collection `{}` does not exist.",
                &self.collection_path
            )));
        };

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
            let action =
                crate::prompt::PromptAction::new(move |unlock_secret: oo7::Secret| async move {
                    // Unlock the collection
                    coll.set_locked(false, Some(unlock_secret)).await?;

                    // Now delete the item
                    item_self.delete_unlocked(&coll).await?;

                    Ok(zbus::zvariant::Value::new(OwnedObjectPath::default())
                        .try_into_owned()
                        .unwrap())
                });

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
        self.delete_unlocked(&collection).await?;
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

        if self.is_locked().await {
            tracing::error!("Cannot get secret of a locked object `{}`", self.path);
            return Err(ServiceError::IsLocked(format!(
                "Cannot get secret of a locked object `{}`.",
                self.path
            )));
        }

        let inner = self.inner.lock().await;
        let inner = inner.as_ref().unwrap();
        let secret = inner.as_unlocked().secret();
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
        let DBusSecretInner(session, iv, secret, content_type) = secret;

        let Some(session) = self.service.session(&session).await else {
            tracing::error!("The session `{}` does not exist.", session);
            return Err(ServiceError::NoSession(format!(
                "The session `{session}` does not exist."
            )));
        };

        if self.is_locked().await {
            tracing::error!("Cannot set secret of a locked object `{}`", self.path);
            return Err(ServiceError::IsLocked(format!(
                "Cannot set secret of a locked object `{}`.",
                self.path
            )));
        }

        {
            let mut inner = self.inner.lock().await;
            let inner = inner.as_mut().unwrap();

            match session.aes_key() {
                Some(key) => {
                    let decrypted = oo7::crypto::decrypt(secret, &key, &iv).map_err(|err| {
                        custom_service_error(&format!("Failed to decrypt secret {err}."))
                    })?;
                    inner.as_mut_unlocked().set_secret(decrypted);
                }
                None => {
                    inner.as_mut_unlocked().set_secret(secret);
                }
            }

            // Ensure content-type attribute is stored
            let mut attributes = inner.as_unlocked().attributes().clone();
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
            inner.as_mut_unlocked().set_attributes(&attributes);
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

        Ok(())
    }

    #[zbus(property, name = "Locked")]
    pub async fn is_locked(&self) -> bool {
        self.inner.lock().await.as_ref().unwrap().is_locked()
    }

    #[zbus(property, name = "Attributes")]
    pub async fn attributes(&self) -> zbus::fdo::Result<HashMap<String, String>> {
        if self.is_locked().await {
            return Err(zbus::fdo::Error::Failed(format!(
                "Cannot get attributes of a locked object `{}`.",
                self.path
            )));
        }

        Ok(self
            .inner
            .lock()
            .await
            .as_ref()
            .unwrap()
            .as_unlocked()
            .attributes()
            .iter()
            .map(|(k, v)| (k.to_owned(), v.to_string()))
            .collect())
    }

    #[zbus(property, name = "Attributes")]
    pub async fn set_attributes(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<(), zbus::Error> {
        if self.is_locked().await {
            tracing::error!("Cannot set attributes of a locked object `{}`", self.path);
            return Err(zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(
                format!("Cannot set attributes of a locked object `{}`.", self.path),
            ))));
        }

        {
            let mut inner = self.inner.lock().await;
            inner
                .as_mut()
                .unwrap()
                .as_mut_unlocked()
                .set_attributes(&attributes);
        }

        let signal_emitter = self
            .service
            .signal_emitter(&self.collection_path)
            .map_err(|err| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(err.to_string()))))?;
        Collection::item_changed(&signal_emitter, &self.path).await?;

        let signal_emitter = self
            .service
            .signal_emitter(&self.path)
            .map_err(|err| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(err.to_string()))))?;
        self.attributes_changed(&signal_emitter).await?;
        self.modified_changed(&signal_emitter).await?;
        Ok(())
    }

    #[zbus(property, name = "Label")]
    pub async fn label(&self) -> zbus::fdo::Result<String> {
        if self.is_locked().await {
            return Err(zbus::fdo::Error::Failed(format!(
                "Cannot get label of a locked object `{}`.",
                self.path
            )));
        }

        Ok(self
            .inner
            .lock()
            .await
            .as_ref()
            .unwrap()
            .as_unlocked()
            .label()
            .to_owned())
    }

    #[zbus(property, name = "Label")]
    pub async fn set_label(&self, label: &str) -> Result<(), zbus::Error> {
        if self.is_locked().await {
            tracing::error!("Cannot set label of a locked object `{}`", self.path);
            return Err(zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(
                format!("Cannot set label of a locked object `{}`.", self.path),
            ))));
        }
        {
            let mut inner = self.inner.lock().await;
            inner.as_mut().unwrap().as_mut_unlocked().set_label(label);
        }

        let signal_emitter = self
            .service
            .signal_emitter(&self.collection_path)
            .map_err(|err| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(err.to_string()))))?;
        Collection::item_changed(&signal_emitter, &self.path).await?;

        let signal_emitter = self
            .service
            .signal_emitter(&self.path)
            .map_err(|err| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(err.to_string()))))?;
        self.label_changed(&signal_emitter).await?;
        self.modified_changed(&signal_emitter).await?;

        Ok(())
    }

    #[zbus(property, name = "Created")]
    pub async fn created_at(&self) -> zbus::fdo::Result<u64> {
        if self.is_locked().await {
            return Err(zbus::fdo::Error::Failed(format!(
                "Cannot get created timestamp of a locked object `{}`.",
                self.path
            )));
        }

        Ok(self
            .inner
            .lock()
            .await
            .as_ref()
            .unwrap()
            .as_unlocked()
            .created()
            .as_secs())
    }

    #[zbus(property, name = "Modified")]
    pub async fn modified_at(&self) -> zbus::fdo::Result<u64> {
        if self.is_locked().await {
            return Err(zbus::fdo::Error::Failed(format!(
                "Cannot get modified timestamp of a locked object `{}`.",
                self.path
            )));
        }

        Ok(self
            .inner
            .lock()
            .await
            .as_ref()
            .unwrap()
            .as_unlocked()
            .modified()
            .as_secs())
    }
}

impl Item {
    pub fn new(
        item: oo7::file::Item,
        service: Service,
        collection_path: OwnedObjectPath,
        path: OwnedObjectPath,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(item))),
            path,
            collection_path,
            service,
        }
    }

    pub fn path(&self) -> &ObjectPath<'_> {
        &self.path
    }

    pub(crate) async fn set_locked(
        &self,
        locked: bool,
        keyring: &oo7::file::UnlockedKeyring,
    ) -> Result<(), ServiceError> {
        let mut inner_guard = self.inner.lock().await;

        if let Some(old_item) = inner_guard.take() {
            let new_item = match (old_item, locked) {
                (oo7::file::Item::Unlocked(unlocked), true) => {
                    let locked_item = keyring.lock_item(unlocked).await.map_err(|err| {
                        custom_service_error(&format!("Failed to lock item: {err}"))
                    })?;
                    oo7::file::Item::Locked(locked_item)
                }
                (oo7::file::Item::Locked(locked_item), false) => {
                    let unlocked = keyring.unlock_item(locked_item).await.map_err(|err| {
                        custom_service_error(&format!("Failed to unlock item: {err}"))
                    })?;
                    oo7::file::Item::Unlocked(unlocked)
                }
                (other, _) => other,
            };
            *inner_guard = Some(new_item);
        }

        drop(inner_guard);

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

    async fn delete_unlocked(&self, collection: &Collection) -> Result<(), ServiceError> {
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

        tracing::info!("Item `{}` deleted.", &self.path);

        Ok(())
    }
}

#[cfg(test)]
mod tests;
