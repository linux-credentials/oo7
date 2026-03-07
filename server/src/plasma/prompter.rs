// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Harald Sitter <sitter@kde.org>

use std::{env, os::fd::AsFd};

use ashpd::WindowIdentifierType;
use gettextrs::gettext;
use oo7::{Secret, dbus::ServiceError};
use serde::Serialize;
use tokio::io::AsyncReadExt;
use zbus::{
    object_server::SignalEmitter,
    zvariant::{self, ObjectPath, OwnedFd, OwnedObjectPath, Type},
};

use crate::{
    prompt::{Prompt, PromptRole},
    service::Service,
};

#[repr(i32)]
#[derive(Debug, Type, Serialize)]
pub enum CallbackAction {
    Dismiss = 0,
    Keep = 1,
}

#[must_use]
pub async fn in_plasma_environment(_connection: &zbus::Connection) -> bool {
    #[cfg(test)]
    return match env::var("OO7_DAEMON_PROMPTER_TEST").map(|v| v.to_lowercase() == "plasma") {
        Ok(_) => true,
        Err(_) => false,
    };

    #[cfg(not(test))]
    {
        static IS_PLASMA: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        if let Some(cached_value) = IS_PLASMA.get() {
            return *cached_value;
        }

        let is_plasma = async {
            match env::var("XDG_CURRENT_DESKTOP").map(|v| v.to_lowercase() == "kde") {
                Ok(_) => (),
                Err(_) => return false,
            };

            let proxy = match zbus::fdo::DBusProxy::new(_connection).await {
                Ok(proxy) => proxy,
                Err(_) => return false,
            };
            let activatable_names = match proxy.list_activatable_names().await {
                Ok(names) => names,
                Err(_) => return false,
            };
            activatable_names
                .iter()
                .any(|name| name.as_str() == "org.kde.secretprompter")
        }
        .await;

        *IS_PLASMA.get_or_init(|| is_plasma)
    }
}

#[zbus::proxy(
    default_service = "org.kde.secretprompter",
    interface = "org.kde.secretprompter",
    default_path = "/SecretPrompter",
    gen_blocking = false
)]
pub trait PlasmaPrompter {
    fn unlock_collection_prompt(
        &self,
        request: &ObjectPath<'_>,
        window_id: &str,
        activation_token: &str,
        collection_name: &str,
    ) -> Result<(), ServiceError>;
    fn create_collection_prompt(
        &self,
        request: &ObjectPath<'_>,
        window_id: &str,
        activation_token: &str,
        collection_name: &str,
    ) -> Result<(), ServiceError>;
}

#[derive(Debug, Clone)]
pub struct PlasmaPrompterCallback {
    service: Service,
    prompt_path: OwnedObjectPath,
    path: OwnedObjectPath,
}

#[zbus::interface(name = "org.kde.secretprompter.request")]
impl PlasmaPrompterCallback {
    pub async fn accepted(&self, result_fd: OwnedFd) -> Result<CallbackAction, ServiceError> {
        let prompt_path = &self.prompt_path;
        let Some(prompt) = self.service.prompt(prompt_path).await else {
            return Err(ServiceError::NoSuchObject(format!(
                "Prompt '{prompt_path}' does not exist."
            )));
        };

        tracing::debug!("User accepted the prompt.");

        let secret = {
            let borrowed_fd = result_fd.as_fd();
            let std_stream = std::os::unix::net::UnixStream::from(
                borrowed_fd
                    .try_clone_to_owned()
                    .expect("Failed to clone fd"),
            );
            let mut stream = tokio::net::UnixStream::from_std(std_stream)
                .expect("Failed to create Tokio UnixStream");
            let mut buffer = String::new();
            stream
                .read_to_string(&mut buffer)
                .await
                .expect("error reading secret");
            tracing::debug!("Read secret from fd, length {}", buffer.len());
            oo7::Secret::from(buffer)
        };

        self.on_reply(&prompt, secret).await
    }

    pub async fn rejected(&self) -> Result<CallbackAction, ServiceError> {
        tracing::debug!("User rejected the prompt.");
        self.prompter_dismissed(self.prompt_path.clone()).await?;
        Ok(CallbackAction::Dismiss) // simply dismiss without further action
    }

    pub async fn dismissed(&self) -> Result<(), ServiceError> {
        // This is only does check if the prompt is tracked on Service
        let path = &self.prompt_path;
        if let Some(_prompt) = self.service.prompt(path).await {
            self.service
                .object_server()
                .remove::<Prompt, _>(path)
                .await?;
            self.service.remove_prompt(path).await;
        }
        self.service
            .object_server()
            .remove::<Self, _>(&self.path)
            .await?;

        Ok(())
    }

    #[zbus(signal)]
    pub async fn retry(signal_emitter: &SignalEmitter<'_>, reason: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn dismiss(signal_emitter: &SignalEmitter<'_>) -> zbus::Result<()>;
}

impl PlasmaPrompterCallback {
    pub async fn new(service: Service, prompt_path: OwnedObjectPath) -> Self {
        let index = service.prompt_index().await;
        Self {
            path: OwnedObjectPath::try_from(format!("/org/plasma/keyring/Prompt/p{index}"))
                .unwrap(),
            service,
            prompt_path,
        }
    }

    pub fn path(&self) -> &ObjectPath<'_> {
        &self.path
    }

    pub async fn start(
        &self,
        role: &PromptRole,
        window_id: Option<WindowIdentifierType>,
        collection_name: &str,
    ) -> Result<(), ServiceError> {
        let path = self.path.clone();
        let prompter = PlasmaPrompterProxy::new(self.service.connection()).await?;
        let window_id = match window_id {
            Some(id) => id.to_string(),
            None => String::new(),
        };
        let collection_name = collection_name.to_string();

        match role {
            PromptRole::Unlock => {
                tokio::spawn(async move {
                    prompter
                        .unlock_collection_prompt(&path, &window_id, "", collection_name.as_str())
                        .await
                });
            }
            PromptRole::CreateCollection => {
                tokio::spawn(async move {
                    prompter
                        .create_collection_prompt(&path, &window_id, "", collection_name.as_str())
                        .await
                });
            }
            PromptRole::ChangePassword => {
                tokio::spawn(async move {
                    prompter
                        .unlock_collection_prompt(&path, &window_id, "", collection_name.as_str())
                        .await
                });
            }
        }

        Ok(())
    }

    async fn on_reply(
        &self,
        prompt: &Prompt,
        secret: Secret,
    ) -> Result<CallbackAction, ServiceError> {
        // Handle each role differently based on what validation/preparation is needed
        match prompt.role() {
            PromptRole::Unlock => {
                if prompt.on_unlock_collection(secret).await? {
                    Ok(CallbackAction::Dismiss)
                } else {
                    tracing::debug!("Unlock failed, sending retry signal.");
                    let emitter = SignalEmitter::from_parts(
                        self.service.connection().clone(),
                        self.path().clone(),
                    );
                    PlasmaPrompterCallback::retry(
                        &emitter,
                        &gettext("The unlock password was incorrect"),
                    )
                    .await?;

                    Ok(CallbackAction::Keep) // we retry
                }
            }
            PromptRole::CreateCollection => {
                prompt.on_create_collection(secret).await?;
                Ok(CallbackAction::Dismiss)
            }
            PromptRole::ChangePassword => {
                prompt.on_change_password(secret).await?;
                Ok(CallbackAction::Dismiss)
            }
        }
    }

    async fn prompter_dismissed(&self, prompt_path: OwnedObjectPath) -> Result<(), ServiceError> {
        let signal_emitter = self.service.signal_emitter(prompt_path)?;
        let result = zvariant::Value::new::<Vec<OwnedObjectPath>>(vec![])
            .try_into_owned()
            .unwrap();

        tokio::spawn(async move { Prompt::completed(&signal_emitter, true, result).await });
        Ok(())
    }
}
