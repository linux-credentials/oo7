// org.freedesktop.Secret.Prompt

use std::{future::Future, pin::Pin, str::FromStr, sync::Arc};

use oo7::{Secret, dbus::ServiceError};
use tokio::sync::{Mutex, OnceCell};
use zbus::{
    interface,
    object_server::SignalEmitter,
    zvariant::{ObjectPath, Optional, OwnedObjectPath, OwnedValue},
};

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
use crate::gnome::prompter::{GNOMEPrompterCallback, GNOMEPrompterProxy};
#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
use crate::plasma::prompter::{PlasmaPrompterCallback, in_plasma_environment};
use crate::{error::custom_service_error, service::Service};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptRole {
    Unlock,
    CreateCollection,
    ChangePassword,
}

/// A boxed future that represents the action to be taken when a prompt
/// completes
pub type PromptActionFuture =
    Pin<Box<dyn Future<Output = Result<OwnedValue, ServiceError>> + Send + 'static>>;

/// Represents the action to be taken when a prompt completes
pub struct PromptAction {
    /// The async function to execute when the prompt is accepted
    action: Box<dyn FnOnce(Secret) -> PromptActionFuture + Send>,
}

impl PromptAction {
    /// Create a new prompt action from a closure that takes an optional secret
    /// and returns a future
    pub fn new<F, Fut>(f: F) -> Self
    where
        F: FnOnce(Secret) -> Fut + Send + 'static,
        Fut: Future<Output = Result<OwnedValue, ServiceError>> + Send + 'static,
    {
        Self {
            action: Box::new(move |secret| Box::pin(f(secret))),
        }
    }

    /// Execute the action with the provided secret
    pub async fn execute(self, secret: Secret) -> Result<OwnedValue, ServiceError> {
        (self.action)(secret).await
    }
}

#[derive(Clone)]
pub struct Prompt {
    service: Service,
    role: PromptRole,
    path: OwnedObjectPath,
    /// The label of the collection/keyring being prompted for
    label: String,
    /// The collection for Unlock prompts (needed for secret validation)
    collection: Option<crate::collection::Collection>,
    /// GNOME Specific
    #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
    gnome_callback: Arc<OnceCell<GNOMEPrompterCallback>>,
    /// KDE Plasma Specific
    #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
    plasma_callback: Arc<OnceCell<PlasmaPrompterCallback>>,
    /// The action to execute when the prompt completes
    action: Arc<Mutex<Option<PromptAction>>>,
}

// Manual impl because OnceCell doesn't impl Debug
impl std::fmt::Debug for Prompt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prompt")
            .field("service", &self.service)
            .field("role", &self.role)
            .field("path", &self.path)
            .field("label", &self.label)
            .field("collection", &self.collection)
            .finish()
    }
}

#[cfg(any(
    feature = "gnome_openssl_crypto",
    feature = "gnome_native_crypto",
    feature = "plasma_native_crypto",
    feature = "plasma_openssl_crypto"
))] // User has to enable at least one prompt backend
#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    pub async fn prompt(&self, window_id: Optional<&str>) -> Result<(), ServiceError> {
        let window_id = (*window_id).and_then(|w| ashpd::WindowIdentifierType::from_str(w).ok());
        #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
        if in_plasma_environment(self.service.connection()).await {
            if self.plasma_callback.get().is_some() {
                return Err(custom_service_error(
                    "A prompt callback is ongoing already.",
                ));
            }

            let callback =
                PlasmaPrompterCallback::new(self.service.clone(), self.path.clone()).await;
            let path = OwnedObjectPath::from(callback.path().clone());

            self.plasma_callback
                .set(callback.clone())
                .expect("A prompt callback is only set once");
            self.service
                .object_server()
                .at(&path, callback.clone())
                .await?;
            tracing::debug!("Prompt `{}` created.", self.path);

            return callback.start(&self.role, window_id, &self.label).await;
        }

        #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
        {
            if self.gnome_callback.get().is_some() {
                return Err(custom_service_error(
                    "A GNOME prompt callback is ongoing already.",
                ));
            };

            let callback =
                GNOMEPrompterCallback::new(window_id, self.service.clone(), self.path.clone())
                    .await
                    .map_err(|err| {
                        custom_service_error(&format!(
                            "Failed to create GNOMEPrompterCallback {err}."
                        ))
                    })?;

            let path = OwnedObjectPath::from(callback.path().clone());

            self.gnome_callback
                .set(callback.clone())
                .expect("A prompt callback is only set once");

            self.service.object_server().at(&path, callback).await?;
            tracing::debug!("Prompt `{}` created.", self.path);

            // Starts GNOME System Prompting.
            // Spawned separately to avoid blocking the early return of the current
            // execution.
            let prompter = GNOMEPrompterProxy::new(self.service.connection()).await?;
            tokio::spawn(async move { prompter.begin_prompting(&path).await });

            return Ok(());
        }

        #[allow(unreachable_code)]
        Err(custom_service_error(
            "No prompt backend available in the current environment.",
        ))
    }

    pub async fn dismiss(&self) -> Result<(), ServiceError> {
        #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
        if let Some(callback) = self.plasma_callback.get() {
            let emitter = SignalEmitter::from_parts(
                self.service.connection().clone(),
                callback.path().clone(),
            );
            PlasmaPrompterCallback::dismiss(&emitter).await?;
        }

        #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
        if let Some(_callback) = self.gnome_callback.get() {
            // TODO: figure out if we should destroy the un-export the callback
            // here?
        }

        self.service
            .object_server()
            .remove::<Self, _>(&self.path)
            .await?;
        self.service.remove_prompt(&self.path).await;

        Ok(())
    }

    #[zbus(signal, name = "Completed")]
    pub async fn completed(
        signal_emitter: &SignalEmitter<'_>,
        dismissed: bool,
        result: OwnedValue,
    ) -> zbus::Result<()>;
}

impl Prompt {
    pub async fn new(
        service: Service,
        role: PromptRole,
        label: String,
        collection: Option<crate::collection::Collection>,
    ) -> Self {
        let index = service.prompt_index().await;
        Self {
            path: OwnedObjectPath::try_from(format!("/org/freedesktop/secrets/prompt/p{index}"))
                .unwrap(),
            service,
            role,
            label,
            collection,
            #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
            gnome_callback: Default::default(),
            #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
            plasma_callback: Default::default(),
            action: Arc::new(Mutex::new(None)),
        }
    }

    pub fn path(&self) -> &ObjectPath<'_> {
        &self.path
    }

    pub fn role(&self) -> PromptRole {
        self.role
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    fn collection(&self) -> Option<&crate::collection::Collection> {
        self.collection.as_ref()
    }

    /// Set the action to execute when the prompt completes
    pub async fn set_action(&self, action: PromptAction) {
        *self.action.lock().await = Some(action);
    }

    /// Take the action, consuming it so it can only be executed once
    async fn take_action(&self) -> Option<PromptAction> {
        self.action.lock().await.take()
    }

    pub async fn on_unlock_collection(&self, secret: Secret) -> Result<bool, ServiceError> {
        debug_assert_eq!(self.role, PromptRole::Unlock);

        // Get the collection to validate the secret
        let collection = self.collection().expect("Unlock requires a collection");
        let label = self.label();

        // Validate the secret using the already-open keyring
        let keyring_guard = collection.keyring.read().await;
        let is_valid = keyring_guard
            .as_ref()
            .unwrap()
            .validate_secret(&secret)
            .await
            .map_err(|err| {
                custom_service_error(&format!(
                    "Failed to validate secret for {label} keyring: {err}."
                ))
            })?;
        drop(keyring_guard);

        if is_valid {
            tracing::debug!("Keyring secret matches for {label}.");

            let Some(action) = self.take_action().await else {
                return Err(custom_service_error(
                    "Prompt action was already executed or not set",
                ));
            };

            // Execute the unlock action after successful validation
            let result_value = action.execute(secret).await?;

            let prompt_path = self.path().to_owned();
            let signal_emitter = self.service.signal_emitter(&prompt_path)?;
            tokio::spawn(async move {
                tracing::debug!("Unlock prompt completed.");
                let _ = Prompt::completed(&signal_emitter, false, result_value).await;
            });
            Ok(true)
        } else {
            tracing::error!("Keyring {label} failed to unlock, incorrect secret.");

            Ok(false)
        }
    }

    pub async fn on_create_collection(&self, secret: Secret) -> Result<(), ServiceError> {
        debug_assert_eq!(self.role, PromptRole::CreateCollection);

        let Some(action) = self.take_action().await else {
            return Err(custom_service_error(
                "Prompt action was already executed or not set",
            ));
        };

        // Execute the collection creation action with the secret
        match action.execute(secret).await {
            Ok(collection_path_value) => {
                tracing::info!("CreateCollection action completed successfully");

                let signal_emitter = self.service.signal_emitter(self.path().to_owned())?;

                tokio::spawn(async move {
                    tracing::debug!("CreateCollection prompt completed.");
                    let _ = Prompt::completed(&signal_emitter, false, collection_path_value).await;
                });
                Ok(())
            }
            Err(err) => Err(custom_service_error(&format!(
                "Failed to create collection: {err}."
            ))),
        }
    }

    pub async fn on_change_password(&self, secret: Secret) -> Result<(), ServiceError> {
        debug_assert_eq!(self.role, PromptRole::ChangePassword);

        let Some(action) = self.take_action().await else {
            return Err(custom_service_error(
                "Prompt action was already executed or not set",
            ));
        };

        // Execute the change password action with the new secret
        match action.execute(secret).await {
            Ok(result) => {
                tracing::info!("ChangePassword action completed successfully");

                let signal_emitter = self.service.signal_emitter(self.path().to_owned())?;

                tokio::spawn(async move {
                    tracing::debug!("ChangePassword prompt completed.");
                    let _ = Prompt::completed(&signal_emitter, false, result).await;
                });
                Ok(())
            }
            Err(err) => Err(custom_service_error(&format!(
                "Failed to change password: {err}."
            ))),
        }
    }
}

#[cfg(test)]
mod tests;
