use std::{io::Write, os::unix::net::UnixStream, sync::Arc};

use oo7::Secret;
use tokio_stream::StreamExt;
use zbus::wire::{Fd, ObjectPath};

/// Mock implementation of org.kde.secretprompter
///
/// This simulates the Plasma System Prompter for testing without requiring
/// the actual service to be running.
#[derive(Clone)]
pub(crate) struct MockPrompterServicePlasma {
    /// The password to use for unlock prompts (simulates user input)
    unlock_password: Arc<tokio::sync::Mutex<Option<Secret>>>,
    /// Whether to accept (true) or dismiss (false) prompts
    should_accept: Arc<tokio::sync::Mutex<bool>>,
    /// Queue of passwords to use for for testing retry logic
    password_queue: Arc<tokio::sync::Mutex<Vec<Secret>>>,
}

#[allow(unused)]
impl MockPrompterServicePlasma {
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

    pub async fn send_secret(
        connection: &zbus::Connection,
        callback_path: &ObjectPath<'_>,
        secret: &Secret,
    ) -> zbus::fdo::Result<()> {
        let callback_path = callback_path.to_owned();
        let connection = connection.clone();
        let secret = secret.clone();

        // Accepted case
        tokio::spawn(async move {
            tracing::debug!(
                "MockPrompterServicePlasma: calling Accepted on {}",
                callback_path
            );

            let (read_end, mut write_end) =
                UnixStream::pair().expect("Failed to create socketpair");
            read_end.set_nonblocking(true).unwrap();
            write_end.set_nonblocking(true).unwrap();
            write_end.write_all(secret.as_bytes()).unwrap();
            drop(write_end); // Close write end to signal EOF

            connection
                .call_method(
                    None::<()>, // No destination in p2p
                    &callback_path,
                    Some("org.kde.secretprompter.request"),
                    "Accepted",
                    &(Fd::Owned(read_end.into())),
                )
                .await?;

            tracing::debug!(
                "MockPrompterServicePlasma: Accepted completed for {}",
                callback_path
            );
            Ok::<_, zbus::Error>(())
        });

        Ok(())
    }
}

#[allow(unused)]
#[zbus::interface(name = "org.kde.secretprompter")]
impl MockPrompterServicePlasma {
    async fn unlock_collection_prompt(
        &self,
        request: ObjectPath<'_>,
        _window_id: &str,
        _activation_token: &str,
        _collection_name: &str,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        tracing::debug!(
            "MockPrompterServicePlasma: unlock_collection_prompt called for {}",
            request
        );

        let callback_path = request.to_owned();
        let connection = connection.clone();

        // Reject case
        if !*self.should_accept.lock().await {
            tokio::spawn(async move {
                tracing::debug!(
                    "MockPrompterServicePlasma: dismissing prompt for {}",
                    callback_path
                );

                connection
                    .call_method(
                        None::<()>, // No destination in p2p
                        &callback_path,
                        Some("org.kde.secretprompter.request"),
                        "Rejected",
                        &(),
                    )
                    .await
                    .unwrap();

                tracing::debug!(
                    "MockPrompterServicePlasma: Dismissed completed for {}",
                    callback_path
                );
            });
            return Ok(());
        }

        let mut queue = self.password_queue.lock().await.clone();
        self.password_queue.lock().await.clear();
        if !queue.is_empty() {
            tokio::spawn(async move {
                let proxy: zbus::proxy::Proxy<'_> = zbus::proxy::Builder::new(&connection)
                    .destination("org.kde.client") // apparently unused but still required for p2p
                    .path(callback_path.clone())
                    .interface("org.kde.secretprompter.request")
                    .build()
                    .await
                    .unwrap();
                let mut signal_stream = proxy.receive_signal("Retry").await.unwrap();

                loop {
                    let secret = queue.remove(0);
                    MockPrompterServicePlasma::send_secret(&connection, &callback_path, &secret)
                        .await
                        .unwrap();

                    if queue.is_empty() {
                        break;
                    }

                    // Wait for Retry signal before sending next secret from the
                    // queue
                    signal_stream.next().await;
                }
            });
        } else {
            let pwd = self.unlock_password.lock().await.clone().unwrap();
            tracing::debug!(
                "MockPrompterServicePlasma: using default password (length: {})",
                pwd.as_str().unwrap_or("<binary>")
            );
            MockPrompterServicePlasma::send_secret(&connection, &callback_path, &pwd).await?;
        };

        Ok(())
    }

    async fn create_collection_prompt(
        &self,
        request: ObjectPath<'_>,
        window_id: &str,
        activation_token: &str,
        collection_name: &str,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        tracing::debug!(
            "MockPrompterServicePlasma: create_collection_prompt called for {}",
            request
        );
        // Behavior is identical for both prompts. Visualization would be
        // different.
        self.unlock_collection_prompt(
            request,
            window_id,
            activation_token,
            collection_name,
            connection,
        )
        .await?;
        Ok(())
    }
}
