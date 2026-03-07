// Backward compatibility interface for GNOME Keyring.
// This allows creating/unlocking collections without user prompts.

use oo7::{
    Secret,
    dbus::{
        ServiceError,
        api::{DBusSecret, DBusSecretInner, Properties},
    },
    file::Keyring,
};
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue};

use crate::{
    error::custom_service_error,
    prompt::{Prompt, PromptAction, PromptRole},
    service::Service,
};

pub const INTERNAL_INTERFACE_PATH: &str =
    "/org/gnome/keyring/InternalUnsupportedGuiltRiddenInterface";

#[derive(Debug, Clone)]
pub struct InternalInterface {
    service: Service,
}

impl InternalInterface {
    pub fn new(service: Service) -> Self {
        Self { service }
    }

    async fn decrypt_secret(&self, secret: DBusSecretInner) -> Result<oo7::Secret, ServiceError> {
        let session_path = &secret.0;

        let Some(session) = self.service.session(session_path).await else {
            return Err(ServiceError::NoSession(format!(
                "The session `{session_path}` does not exist."
            )));
        };

        let secret = DBusSecret::from_inner(self.service.connection(), secret)
            .await
            .map_err(|err| {
                custom_service_error(&format!("Failed to create session object {err}"))
            })?;

        secret
            .decrypt(session.aes_key().as_ref())
            .map_err(|err| custom_service_error(&format!("Failed to decrypt secret {err}")))
    }
}

#[zbus::interface(name = "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface")]
impl InternalInterface {
    /// Create a collection with a master password without prompting the user.
    #[zbus(name = "CreateWithMasterPassword")]
    async fn create_with_master_password(
        &self,
        properties: Properties,
        master: DBusSecretInner,
    ) -> Result<OwnedObjectPath, ServiceError> {
        let label = properties.label().to_owned();
        let secret = self.decrypt_secret(master).await?;

        let collection_path = self
            .service
            .create_collection_with_secret(&label, "", secret)
            .await?;

        tracing::info!(
            "Collection `{}` created with label '{}' via InternalUnsupportedGuiltRiddenInterface",
            collection_path,
            label
        );

        Ok(collection_path)
    }

    /// Unlock a collection with a master password.
    #[zbus(name = "UnlockWithMasterPassword")]
    async fn unlock_with_master_password(
        &self,
        collection: ObjectPath<'_>,
        master: DBusSecretInner,
    ) -> Result<(), ServiceError> {
        let secret = self.decrypt_secret(master).await?;

        let collection_obj = self
            .service
            .collection_from_path(&collection)
            .await
            .ok_or_else(|| ServiceError::NoSuchObject(collection.to_string()))?;

        collection_obj.set_locked(false, Some(secret)).await?;

        tracing::info!(
            "Collection `{}` unlocked via InternalUnsupportedGuiltRiddenInterface",
            collection
        );

        Ok(())
    }

    /// Change collection password with a master password.
    #[zbus(name = "ChangeWithMasterPassword")]
    async fn change_with_master_password(
        &self,
        collection: ObjectPath<'_>,
        original: DBusSecretInner,
        master: DBusSecretInner,
    ) -> Result<(), ServiceError> {
        let original_secret = self.decrypt_secret(original).await?;
        let new_secret = self.decrypt_secret(master).await?;

        let collection_obj = self
            .service
            .collection_from_path(&collection)
            .await
            .ok_or_else(|| ServiceError::NoSuchObject(collection.to_string()))?;

        collection_obj
            .set_locked(false, Some(original_secret))
            .await?;

        let keyring_guard = collection_obj.keyring.read().await;
        if let Some(Keyring::Unlocked(unlocked)) = keyring_guard.as_ref() {
            unlocked
                .change_secret(new_secret)
                .await
                .map_err(|err| custom_service_error(&format!("Failed to change secret: {err}")))?;
        } else {
            return Err(custom_service_error("Collection is not unlocked"));
        }

        tracing::info!(
            "Collection `{}` password changed via InternalUnsupportedGuiltRiddenInterface",
            collection
        );

        Ok(())
    }

    /// Change collection password with a prompt.
    #[zbus(name = "ChangeWithPrompt")]
    async fn change_with_prompt(
        &self,
        collection: ObjectPath<'_>,
    ) -> Result<OwnedObjectPath, ServiceError> {
        let collection_obj = self
            .service
            .collection_from_path(&collection)
            .await
            .ok_or_else(|| ServiceError::NoSuchObject(collection.to_string()))?;

        let label = collection_obj.label().await;

        let prompt = Prompt::new(
            self.service.clone(),
            PromptRole::ChangePassword,
            label,
            None,
        )
        .await;
        let prompt_path: OwnedObjectPath = prompt.path().to_owned().into();

        let service = self.service.clone();
        let collection_path = collection.to_owned();
        let action = PromptAction::new(move |new_secret: Secret| {
            let service = service.clone();
            let collection_path = collection_path.clone();
            async move {
                let collection = service
                    .collection_from_path(&collection_path)
                    .await
                    .ok_or_else(|| ServiceError::NoSuchObject(collection_path.to_string()))?;

                let keyring_guard = collection.keyring.read().await;
                if let Some(Keyring::Unlocked(unlocked)) = keyring_guard.as_ref() {
                    unlocked.change_secret(new_secret).await.map_err(|err| {
                        custom_service_error(&format!("Failed to change secret: {err}"))
                    })?;
                } else {
                    return Err(custom_service_error(
                        "Collection must be unlocked to change password",
                    ));
                }

                tracing::info!(
                    "Collection `{}` password changed via prompt",
                    collection_path
                );

                Ok(OwnedValue::from(ObjectPath::from_str_unchecked("/")))
            }
        });

        prompt.set_action(action).await;

        self.service
            .object_server()
            .at(prompt.path(), prompt.clone())
            .await?;

        self.service
            .register_prompt(prompt_path.clone(), prompt)
            .await;

        tracing::info!(
            "Created password change prompt for collection `{}`",
            collection
        );

        Ok(prompt_path)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use oo7::{Secret, dbus};
    use zbus::zvariant::{ObjectPath, OwnedObjectPath};

    use crate::tests::TestServiceSetup;

    /// Proxy for the InternalUnsupportedGuiltRiddenInterface
    #[zbus::proxy(
        interface = "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface",
        default_service = "org.freedesktop.secrets",
        default_path = "/org/gnome/keyring/InternalUnsupportedGuiltRiddenInterface",
        gen_blocking = false
    )]
    trait InternalInterfaceProxy {
        #[zbus(name = "CreateWithMasterPassword")]
        fn create_with_master_password(
            &self,
            properties: dbus::api::Properties,
            master: dbus::api::DBusSecretInner,
        ) -> zbus::Result<OwnedObjectPath>;

        #[zbus(name = "UnlockWithMasterPassword")]
        fn unlock_with_master_password(
            &self,
            collection: &ObjectPath<'_>,
            master: dbus::api::DBusSecretInner,
        ) -> zbus::Result<()>;

        #[zbus(name = "ChangeWithMasterPassword")]
        fn change_with_master_password(
            &self,
            collection: &ObjectPath<'_>,
            original: dbus::api::DBusSecretInner,
            master: dbus::api::DBusSecretInner,
        ) -> zbus::Result<()>;

        #[zbus(name = "ChangeWithPrompt")]
        fn change_with_prompt(&self, collection: &ObjectPath<'_>) -> zbus::Result<OwnedObjectPath>;
    }

    #[tokio::test]
    async fn test_create_with_master_password() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::encrypted_session(false).await?;

        // Create proxy to the InternalInterface
        let internal_proxy = InternalInterfaceProxyProxy::builder(&setup.client_conn)
            .build()
            .await?;

        // Prepare properties for collection creation
        let label = "TestCollection";
        let properties = oo7::dbus::api::Properties::for_collection(label);

        // Prepare the master password secret
        let master_secret = Secret::text("my-master-password");
        let aes_key = setup.aes_key.as_ref().unwrap();
        let dbus_secret = oo7::dbus::api::DBusSecret::new_encrypted(
            Arc::clone(&setup.session),
            master_secret,
            aes_key,
        )?;
        let dbus_secret_inner = dbus_secret.into();

        // Call CreateWithMasterPassword via D-Bus
        let collection_path = internal_proxy
            .create_with_master_password(properties, dbus_secret_inner)
            .await?;

        // Verify the collection was created
        assert!(
            !collection_path.as_str().is_empty(),
            "Collection path should not be empty"
        );

        // Verify we can access the newly created collection via D-Bus
        let collection =
            oo7::dbus::api::Collection::new(&setup.client_conn, collection_path.clone()).await?;
        let label = collection.label().await?;
        assert_eq!(
            label, "TestCollection",
            "Collection should have the correct label"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_unlock_with_master_password() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::encrypted_session(true).await?;
        let internal_proxy = InternalInterfaceProxyProxy::builder(&setup.client_conn)
            .build()
            .await?;

        // Get the default collection
        let default_collection = setup.default_collection().await?;
        let collection_path: zbus::zvariant::OwnedObjectPath =
            default_collection.inner().path().to_owned().into();

        // Lock the collection
        setup
            .service_api
            .lock(&[collection_path.clone()], None)
            .await?;

        // Verify it's locked
        assert!(
            default_collection.is_locked().await?,
            "Collection should be locked"
        );

        // Prepare the unlock secret (use the keyring secret)
        let unlock_secret = setup.keyring_secret.clone().unwrap();
        let aes_key = setup.aes_key.as_ref().unwrap();
        let dbus_secret = oo7::dbus::api::DBusSecret::new_encrypted(
            Arc::clone(&setup.session),
            unlock_secret,
            aes_key,
        )?;
        let dbus_secret_inner = dbus_secret.into();

        // Call UnlockWithMasterPassword via D-Bus
        internal_proxy
            .unlock_with_master_password(&collection_path.as_ref(), dbus_secret_inner)
            .await?;

        // Verify it's unlocked
        assert!(
            !default_collection.is_locked().await?,
            "Collection should be unlocked"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_change_with_master_password() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::encrypted_session(true).await?;
        let internal_proxy = InternalInterfaceProxyProxy::builder(&setup.client_conn)
            .build()
            .await?;

        let default_collection = setup.default_collection().await?;
        let collection_path: zbus::zvariant::OwnedObjectPath =
            default_collection.inner().path().to_owned().into();

        // Prepare original and new secrets
        let original_secret = setup.keyring_secret.clone().unwrap();
        let new_secret = Secret::text("new-master-password");

        let aes_key = setup.aes_key.as_ref().unwrap();
        let original_dbus = dbus::api::DBusSecret::new_encrypted(
            Arc::clone(&setup.session),
            original_secret,
            aes_key,
        )?;
        let new_dbus = dbus::api::DBusSecret::new_encrypted(
            Arc::clone(&setup.session),
            new_secret.clone(),
            aes_key,
        )?;

        // Call ChangeWithMasterPassword via D-Bus
        internal_proxy
            .change_with_master_password(
                &collection_path.as_ref(),
                original_dbus.into(),
                new_dbus.into(),
            )
            .await?;

        // Verify the password was changed by locking and unlocking with new password
        setup
            .service_api
            .lock(&[collection_path.clone()], None)
            .await?;
        assert!(
            default_collection.is_locked().await?,
            "Collection should be locked"
        );

        // Unlock with new password via D-Bus
        let unlock_dbus =
            dbus::api::DBusSecret::new_encrypted(Arc::clone(&setup.session), new_secret, aes_key)?;
        internal_proxy
            .unlock_with_master_password(&collection_path.as_ref(), unlock_dbus.into())
            .await?;

        assert!(
            !default_collection.is_locked().await?,
            "Collection should be unlocked with new password"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_change_with_prompt() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::encrypted_session(true).await?;
        let internal_proxy = InternalInterfaceProxyProxy::builder(&setup.client_conn)
            .build()
            .await?;

        let default_collection = setup.default_collection().await?;
        let collection_path: zbus::zvariant::OwnedObjectPath =
            default_collection.inner().path().to_owned().into();

        // Call ChangeWithPrompt via D-Bus
        let prompt_path = internal_proxy
            .change_with_prompt(&collection_path.as_ref())
            .await?;

        // Verify prompt was created
        assert!(
            !prompt_path.as_str().is_empty(),
            "Prompt path should not be empty"
        );

        // Verify the prompt exists and is accessible via D-Bus
        let _prompt_proxy = dbus::api::Prompt::new(&setup.client_conn, prompt_path).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_unlock_with_wrong_password() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::encrypted_session(true).await?;
        let internal_proxy = InternalInterfaceProxyProxy::builder(&setup.client_conn)
            .build()
            .await?;

        let default_collection = setup.default_collection().await?;
        let collection_path: zbus::zvariant::OwnedObjectPath =
            default_collection.inner().path().to_owned().into();

        // Create an item first so that the unlock validation has something to validate
        let aes_key = setup.aes_key.as_ref().unwrap();
        let item_secret = Secret::text("item-secret");
        let dbus_secret =
            dbus::api::DBusSecret::new_encrypted(Arc::clone(&setup.session), item_secret, aes_key)?;

        let mut attributes = std::collections::HashMap::new();
        attributes.insert("test".to_string(), "value".to_string());

        default_collection
            .create_item("Test Item", &attributes, &dbus_secret, false, None)
            .await?;

        // Lock the collection
        setup
            .service_api
            .lock(&[collection_path.clone()], None)
            .await?;

        // Verify it's locked before attempting unlock
        assert!(
            default_collection.is_locked().await?,
            "Collection should be locked before unlock attempt"
        );

        // Try to unlock with wrong password via D-Bus
        let wrong_secret = Secret::text("wrong-password");
        let wrong_dbus_secret = dbus::api::DBusSecret::new_encrypted(
            Arc::clone(&setup.session),
            wrong_secret,
            aes_key,
        )?;

        let result = internal_proxy
            .unlock_with_master_password(&collection_path.as_ref(), wrong_dbus_secret.into())
            .await;

        // Should fail
        assert!(result.is_err(), "Unlocking with wrong password should fail");

        // Collection should remain locked
        assert!(
            default_collection.is_locked().await?,
            "Collection should remain locked after failed unlock"
        );

        Ok(())
    }
}
