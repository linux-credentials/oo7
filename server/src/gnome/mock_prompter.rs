use std::{collections::HashMap, sync::Arc};

use base64::Engine;
use oo7::{Secret, crypto};
use zbus::wire::{ObjectPath, Optional, Variant};

use super::{
    prompter::{PromptType, Properties, Reply},
    secret_exchange,
};

/// Mock implementation of org.gnome.keyring.internal.Prompter
///
/// This simulates the GNOME System Prompter for testing without requiring
/// the actual GNOME keyring prompter service to be running.
#[derive(Clone)]
pub(crate) struct MockPrompterServiceGNOME {
    /// The password to use for unlock prompts (simulates user input)
    unlock_password: Arc<tokio::sync::Mutex<Option<Secret>>>,
    /// Whether to accept (true) or dismiss (false) prompts
    should_accept: Arc<tokio::sync::Mutex<bool>>,
    /// Queue of passwords to use for for testing retry logic
    password_queue: Arc<tokio::sync::Mutex<Vec<Secret>>>,
}

#[allow(unused)]
impl MockPrompterServiceGNOME {
    pub fn new() -> Self {
        Self {
            unlock_password: Arc::new(tokio::sync::Mutex::new(Some(Secret::from(
                "test-password-long-enough",
            )))),
            should_accept: Arc::new(tokio::sync::Mutex::new(true)),
            password_queue: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }

    /// Set whether prompts should be accepted or dismissed
    pub async fn set_accept(&self, accept: bool) {
        *self.should_accept.lock().await = accept;
    }

    pub async fn set_password_queue(&self, passwords: Vec<Secret>) {
        *self.password_queue.lock().await = passwords;
    }
}

#[allow(unused)]
#[zbus::interface(name = "org.gnome.keyring.internal.Prompter")]
impl MockPrompterServiceGNOME {
    async fn begin_prompting(
        &self,
        callback: ObjectPath<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        tracing::debug!("MockPrompter: begin_prompting called for {}", callback);
        let callback_path = callback.to_owned();
        let connection = connection.clone();

        // Spawn a task to send the initial prompt_ready call
        tokio::spawn(async move {
            tracing::debug!("MockPrompter: spawned task starting");
            // Small delay to ensure callback is fully registered
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

            // Call PromptReady directly without building a proxy (avoids
            // introspection issues in p2p)
            tracing::debug!(
                "MockPrompter: calling PromptReady with None on {}",
                callback_path
            );
            let properties: HashMap<String, Variant> = HashMap::new();
            let empty_exchange = "";

            connection
                .call_method(
                    None::<()>, // No destination in p2p
                    &callback_path,
                    Some("org.gnome.keyring.internal.Prompter.Callback"),
                    "PromptReady",
                    &(Optional::<Reply>::from(None), properties, empty_exchange),
                )
                .await?;

            tracing::debug!("MockPrompter: PromptReady(None) completed");
            Ok::<_, zbus::Error>(())
        });

        Ok(())
    }

    async fn perform_prompt(
        &self,
        callback: ObjectPath<'_>,
        type_: PromptType,
        _properties: Properties,
        exchange: &str,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        tracing::debug!(
            "MockPrompter: perform_prompt called for {}, type={:?}",
            callback,
            type_
        );
        // This is called by GNOMEPrompterCallback.prompter_init() with the
        // server's exchange
        let callback_path = callback.to_owned();
        let unlock_password = self.unlock_password.clone();
        let should_accept = self.should_accept.clone();
        let password_queue = self.password_queue.clone();
        let exchange = exchange.to_owned();
        let connection = connection.clone();

        // Spawn a task to simulate user interaction and send final response
        tokio::spawn(async move {
            tracing::debug!("MockPrompter: perform_prompt task starting");
            // Small delay to simulate user interaction
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

            let accept = *should_accept.lock().await;
            let properties: HashMap<String, Variant> = HashMap::new();

            if !accept {
                tracing::debug!("MockPrompter: dismissing prompt");
                // Dismiss the prompt
                connection
                    .call_method(
                        None::<()>, // No destination in p2p
                        &callback_path,
                        Some("org.gnome.keyring.internal.Prompter.Callback"),
                        "PromptReady",
                        &(Reply::No, properties, ""),
                    )
                    .await?;
                tracing::debug!("MockPrompter: PromptReady(no) completed");

                return Ok(());
            } else if type_ == PromptType::Password {
                tracing::debug!("MockPrompter: performing unlock (password prompt)");
                // Unlock prompt - perform secret exchange

                let mut queue = password_queue.lock().await;
                let password = if !queue.is_empty() {
                    let pwd = queue.remove(0);
                    tracing::debug!(
                        "MockPrompter: using password from queue (length: {}, queue remaining: {})",
                        pwd.as_str().unwrap_or("<binary>"),
                        queue.len()
                    );
                    pwd
                } else {
                    let pwd = unlock_password.lock().await.clone().unwrap();
                    tracing::debug!(
                        "MockPrompter: using default password (length: {})",
                        pwd.as_str().unwrap_or("<binary>")
                    );
                    pwd
                };
                drop(queue);

                // Generate our own key pair
                let private_key = oo7::Key::generate_private_key().unwrap();
                let public_key = super::crypto::generate_public_key(&private_key).unwrap();

                // Handshake with server's exchange to get AES key
                let aes_key = secret_exchange::handshake(&private_key, &exchange).unwrap();

                // Encrypt the password
                let iv = crypto::generate_iv().unwrap();
                let encrypted = crypto::encrypt(password.as_bytes(), &aes_key, &iv).unwrap();

                // Create final exchange with encrypted secret
                let final_exchange = format!(
                    "[sx-aes-1]\npublic={}\nsecret={}\niv={}",
                    base64::prelude::BASE64_STANDARD.encode(public_key.as_ref()),
                    base64::prelude::BASE64_STANDARD.encode(&encrypted),
                    base64::prelude::BASE64_STANDARD.encode(&iv)
                );

                tracing::debug!("MockPrompter: calling PromptReady with yes");
                connection
                    .call_method(
                        None::<()>, // No destination in p2p
                        &callback_path,
                        Some("org.gnome.keyring.internal.Prompter.Callback"),
                        "PromptReady",
                        &(Reply::Yes, properties, final_exchange.as_str()),
                    )
                    .await?;
                tracing::debug!("MockPrompter: PromptReady(yes) with secret exchange completed");
            } else {
                tracing::debug!("MockPrompter: accepting confirm prompt");
                // Lock/confirm prompt - just accept
                connection
                    .call_method(
                        None::<()>, // No destination in p2p
                        &callback_path,
                        Some("org.gnome.keyring.internal.Prompter.Callback"),
                        "PromptReady",
                        &(Reply::Yes, properties, ""),
                    )
                    .await?;
                tracing::debug!("MockPrompter: PromptReady(yes) completed");
            }

            Ok::<_, zbus::Error>(())
        });

        Ok(())
    }

    async fn stop_prompting(
        &self,
        callback: ObjectPath<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        tracing::debug!("MockPrompter: stop_prompting called for {}", callback);
        let callback_path = callback.to_owned();
        let connection = connection.clone();

        tokio::spawn(async move {
            tracing::debug!("MockPrompter: calling PromptDone for {}", callback_path);
            let result = connection
                .call_method(
                    None::<()>,
                    &callback_path,
                    Some("org.gnome.keyring.internal.Prompter.Callback"),
                    "PromptDone",
                    &(),
                )
                .await;

            if let Err(err) = result {
                tracing::debug!("MockPrompter: PromptDone failed: {}", err);
            } else {
                tracing::debug!("MockPrompter: PromptDone completed for {}", callback_path);
            }
        });

        Ok(())
    }
}
