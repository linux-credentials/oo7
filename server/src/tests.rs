use std::{collections::HashMap, fs::File, io::Write, sync::Arc};

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
use base64::Engine;
use oo7::{Secret, crypto, dbus};
use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};
use tokio_stream::StreamExt;
use zbus::zvariant::{Fd, ObjectPath, Optional, Value};

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
use crate::gnome::{
    prompter::{PromptType, Properties, Reply},
    secret_exchange,
};
use crate::service::{PrompterType, Service};

/// Helper to create a peer-to-peer connection pair using Unix socket
async fn create_p2p_connection()
-> Result<(zbus::Connection, zbus::Connection), Box<dyn std::error::Error>> {
    let guid = zbus::Guid::generate();
    let (p0, p1) = tokio::net::UnixStream::pair()?;

    let (client_conn, server_conn) = tokio::try_join!(
        // Client
        zbus::connection::Builder::unix_stream(p0).p2p().build(),
        // Server
        zbus::connection::Builder::unix_stream(p1)
            .server(guid)?
            .p2p()
            .build(),
    )?;

    Ok((server_conn, client_conn))
}

pub struct TestServiceSetup {
    pub server: Service,
    pub client_conn: zbus::Connection,
    pub service_api: dbus::api::Service,
    pub session: Arc<dbus::api::Session>,
    pub collections: Vec<dbus::api::Collection>,
    pub server_public_key: Option<oo7::Key>,
    pub keyring_secret: Option<oo7::Secret>,
    pub aes_key: Option<Arc<oo7::Key>>,
    #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
    pub(crate) mock_prompter: MockPrompterService,
    #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
    pub(crate) mock_prompter_plasma: MockPrompterServicePlasma,
    // Keep temp dir alive for duration of test
    _temp_dir: tempfile::TempDir,
}

impl TestServiceSetup {
    /// Get the default/Login collection
    pub async fn default_collection(
        &self,
    ) -> Result<&dbus::api::Collection, Box<dyn std::error::Error>> {
        for collection in &self.collections {
            let label = collection.label().await?;
            if label == "Login" {
                return Ok(collection);
            }
        }
        Err("Default collection not found".into())
    }

    pub async fn plain_session(
        with_default_collection: bool,
    ) -> Result<TestServiceSetup, Box<dyn std::error::Error>> {
        let (server_conn, client_conn) = create_p2p_connection().await?;

        let secret = if with_default_collection {
            Some(Secret::from("test-password-long-enough"))
        } else {
            None
        };

        let temp_dir = tempfile::TempDir::new()?;
        let server = Service::run_with_connection(
            server_conn.clone(),
            temp_dir.path().to_path_buf(),
            None,
            secret.clone(),
        )
        .await?;
        server.set_prompter_type(PrompterType::GNOME).await;

        // Create and serve the mock prompter
        #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
        let mock_prompter = {
            let mock_prompter = MockPrompterService::new();
            client_conn
                .object_server()
                .at("/org/gnome/keyring/Prompter", mock_prompter.clone())
                .await?;
            mock_prompter
        };
        #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
        let mock_prompter_plasma = {
            let mock_prompter_plasma = MockPrompterServicePlasma::new();
            client_conn
                .object_server()
                .at("/SecretPrompter", mock_prompter_plasma.clone())
                .await?;
            mock_prompter_plasma
        };

        // Give the server a moment to fully initialize
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let service_api = dbus::api::Service::new(&client_conn).await?;

        let (server_public_key, session) = service_api.open_session(None).await?;
        let session = Arc::new(session);

        let collections = service_api.collections().await?;

        Ok(TestServiceSetup {
            server,
            keyring_secret: secret,
            client_conn,
            service_api,
            session,
            collections,
            server_public_key,
            aes_key: None,
            #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
            mock_prompter,
            #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
            mock_prompter_plasma,
            _temp_dir: temp_dir,
        })
    }

    pub async fn encrypted_session(
        with_default_collection: bool,
    ) -> Result<TestServiceSetup, Box<dyn std::error::Error>> {
        let (server_conn, client_conn) = create_p2p_connection().await?;

        let secret = if with_default_collection {
            Some(Secret::from("test-password-long-enough"))
        } else {
            None
        };

        let temp_dir = tempfile::TempDir::new()?;
        let server = Service::run_with_connection(
            server_conn.clone(),
            temp_dir.path().to_path_buf(),
            None,
            secret.clone(),
        )
        .await?;
        server.set_prompter_type(PrompterType::GNOME).await;

        // Create and serve the mock prompter
        #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
        let mock_prompter = {
            let mock_prompter = MockPrompterService::new();
            client_conn
                .object_server()
                .at("/org/gnome/keyring/Prompter", mock_prompter.clone())
                .await?;
            mock_prompter
        };

        #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
        let mock_prompter_plasma = {
            let mock_prompter_plasma = MockPrompterServicePlasma::new();
            client_conn
                .object_server()
                .at("/SecretPrompter", mock_prompter_plasma.clone())
                .await?;
            mock_prompter_plasma
        };

        // Give the server a moment to fully initialize
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let service_api = dbus::api::Service::new(&client_conn).await?;

        // Generate client key pair for encrypted session
        let client_private_key = oo7::Key::generate_private_key()?;
        let client_public_key = oo7::Key::generate_public_key(&client_private_key)?;

        let (server_public_key, session) =
            service_api.open_session(Some(client_public_key)).await?;
        let session = Arc::new(session);

        let aes_key =
            oo7::Key::generate_aes_key(&client_private_key, server_public_key.as_ref().unwrap())?;

        let collections = service_api.collections().await?;

        Ok(Self {
            server,
            keyring_secret: secret,
            client_conn,
            service_api,
            session,
            collections,
            server_public_key,
            aes_key: Some(Arc::new(aes_key)),
            #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
            mock_prompter,
            #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
            mock_prompter_plasma,
            _temp_dir: temp_dir,
        })
    }

    /// Create a test setup that discovers keyrings from disk
    /// This is useful for PAM tests that need to create keyrings on disk first
    pub(crate) async fn with_disk_keyrings(
        data_dir: std::path::PathBuf,
        pam_socket: Option<std::path::PathBuf>,
        secret: Option<Secret>,
    ) -> Result<TestServiceSetup, Box<dyn std::error::Error>> {
        use zbus::proxy::Defaults;

        let (server_conn, client_conn) = create_p2p_connection().await?;

        let temp_dir = tempfile::TempDir::new()?;
        let service = crate::Service::new(data_dir, pam_socket);

        server_conn
            .object_server()
            .at(
                oo7::dbus::api::Service::PATH.as_deref().unwrap(),
                service.clone(),
            )
            .await?;

        let discovered = service.discover_keyrings(secret.clone()).await?;
        service
            .initialize(server_conn, discovered, secret.clone(), false)
            .await?;
        service.set_prompter_type(PrompterType::GNOME).await;

        #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
        let mock_prompter = {
            let mock_prompter = MockPrompterService::new();
            client_conn
                .object_server()
                .at("/org/gnome/keyring/Prompter", mock_prompter.clone())
                .await?;
            mock_prompter
        };

        #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
        let mock_prompter_plasma = {
            let mock_prompter_plasma = MockPrompterServicePlasma::new();
            client_conn
                .object_server()
                .at("/SecretPrompter", mock_prompter_plasma.clone())
                .await?;
            mock_prompter_plasma
        };

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let service_api = dbus::api::Service::new(&client_conn).await?;

        let (server_public_key, session) = service_api.open_session(None).await?;
        let session = Arc::new(session);

        let collections = service_api.collections().await?;

        Ok(TestServiceSetup {
            server: service,
            keyring_secret: secret,
            client_conn,
            service_api,
            session,
            collections,
            server_public_key,
            aes_key: None,
            #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
            mock_prompter,
            #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
            mock_prompter_plasma,
            _temp_dir: temp_dir,
        })
    }

    pub(crate) async fn set_password_accept(&self, accept: bool) {
        #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
        self.mock_prompter.set_accept(accept).await;
        #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
        self.mock_prompter_plasma.set_accept(accept).await;
    }

    pub(crate) async fn set_password_queue(&self, passwords: Vec<oo7::Secret>) {
        #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
        self.mock_prompter
            .set_password_queue(passwords.clone())
            .await;
        #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
        self.mock_prompter_plasma
            .set_password_queue(passwords)
            .await;
    }

    /// Helper to create a DBusSecret
    ///
    /// Automatically handles plain vs encrypted based on whether aes_key is
    /// set.
    pub(crate) fn create_dbus_secret(
        &self,
        secret: impl Into<Secret>,
    ) -> Result<dbus::api::DBusSecret, Box<dyn std::error::Error>> {
        let secret = secret.into();
        let dbus_secret = if let Some(ref aes_key) = self.aes_key {
            dbus::api::DBusSecret::new_encrypted(Arc::clone(&self.session), secret, aes_key)?
        } else {
            dbus::api::DBusSecret::new(Arc::clone(&self.session), secret)
        };
        Ok(dbus_secret)
    }

    /// Helper to create a test item in the default collection (index 0)
    ///
    /// Automatically handles plain vs encrypted sessions based on whether
    /// aes_key is set.
    pub(crate) async fn create_item(
        &self,
        label: &str,
        attributes: &impl oo7::AsAttributes,
        secret: impl Into<Secret>,
        replace: bool,
    ) -> Result<dbus::api::Item, Box<dyn std::error::Error>> {
        let dbus_secret = self.create_dbus_secret(secret)?;

        let item = self.collections[0]
            .create_item(label, attributes, &dbus_secret, replace, None)
            .await?;

        Ok(item)
    }

    /// Helper to lock a collection
    ///
    /// Gets the server-side collection and locks it with the keyring secret.
    pub(crate) async fn lock_collection(
        &self,
        collection: &dbus::api::Collection,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let server_collection = self
            .server
            .collection_from_path(collection.inner().path())
            .await
            .expect("Collection should exist");
        server_collection
            .set_locked(true, self.keyring_secret.clone())
            .await?;
        Ok(())
    }

    /// Helper to unlock a collection
    ///
    /// Gets the server-side collection and unlocks it with the keyring secret.
    pub(crate) async fn unlock_collection(
        &self,
        collection: &dbus::api::Collection,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let server_collection = self
            .server
            .collection_from_path(collection.inner().path())
            .await
            .expect("Collection should exist");
        server_collection
            .set_locked(false, self.keyring_secret.clone())
            .await?;
        Ok(())
    }

    /// Helper to lock an item
    ///
    /// Gets the server-side collection and item, then locks the item.
    pub(crate) async fn lock_item(
        &self,
        item: &dbus::api::Item,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let collection = self
            .server
            .collection_from_path(self.collections[0].inner().path())
            .await
            .expect("Collection should exist");

        let keyring = collection.keyring.read().await;
        let unlocked_keyring = keyring.as_ref().unwrap().as_unlocked();

        let server_item = collection
            .item_from_path(item.inner().path())
            .await
            .unwrap();
        server_item.set_locked(true, unlocked_keyring).await?;
        Ok(())
    }
}

/// Mock implementation of org.gnome.keyring.internal.Prompter
///
/// This simulates the GNOME System Prompter for testing without requiring
/// the actual GNOME keyring prompter service to be running.
#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[derive(Clone)]
pub(crate) struct MockPrompterService {
    /// The password to use for unlock prompts (simulates user input)
    unlock_password: Arc<tokio::sync::Mutex<Option<oo7::Secret>>>,
    /// Whether to accept (true) or dismiss (false) prompts
    should_accept: Arc<tokio::sync::Mutex<bool>>,
    /// Queue of passwords to use for for testing retry logic
    password_queue: Arc<tokio::sync::Mutex<Vec<oo7::Secret>>>,
}

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
impl MockPrompterService {
    pub fn new() -> Self {
        Self {
            unlock_password: Arc::new(tokio::sync::Mutex::new(Some(oo7::Secret::from(
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

    pub async fn set_password_queue(&self, passwords: Vec<oo7::Secret>) {
        *self.password_queue.lock().await = passwords;
    }
}

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[zbus::interface(name = "org.gnome.keyring.internal.Prompter")]
impl MockPrompterService {
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

            // Call PromptReady directly without building a proxy (avoids introspection
            // issues in p2p)
            tracing::debug!(
                "MockPrompter: calling PromptReady with None on {}",
                callback_path
            );
            let properties: HashMap<String, Value> = HashMap::new();
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
        // This is called by GNOMEPrompterCallback.prompter_init() with the server's
        // exchange
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
            let properties: HashMap<String, Value> = HashMap::new();

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
                        std::str::from_utf8(pwd.as_bytes()).unwrap_or("<binary>"),
                        queue.len()
                    );
                    pwd
                } else {
                    let pwd = unlock_password.lock().await.clone().unwrap();
                    tracing::debug!(
                        "MockPrompter: using default password (length: {})",
                        std::str::from_utf8(pwd.as_bytes()).unwrap_or("<binary>")
                    );
                    pwd
                };
                drop(queue);

                // Generate our own key pair
                let private_key = oo7::Key::generate_private_key().unwrap();
                let public_key = crate::gnome::crypto::generate_public_key(&private_key).unwrap();

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

/// Mock implementation of org.kde.secretprompter
///
/// This simulates the Plasma System Prompter for testing without requiring
/// the actual service to be running.
#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
#[derive(Clone)]
pub(crate) struct MockPrompterServicePlasma {
    /// The password to use for unlock prompts (simulates user input)
    unlock_password: Arc<tokio::sync::Mutex<Option<oo7::Secret>>>,
    /// Whether to accept (true) or dismiss (false) prompts
    should_accept: Arc<tokio::sync::Mutex<bool>>,
    /// Queue of passwords to use for for testing retry logic
    password_queue: Arc<tokio::sync::Mutex<Vec<oo7::Secret>>>,
}

#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
impl MockPrompterServicePlasma {
    pub fn new() -> Self {
        Self {
            unlock_password: Arc::new(tokio::sync::Mutex::new(Some(oo7::Secret::from(
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

    pub async fn set_password_queue(&self, passwords: Vec<oo7::Secret>) {
        *self.password_queue.lock().await = passwords;
    }

    pub async fn send_secret(
        connection: &zbus::Connection,
        callback_path: &ObjectPath<'_>,
        secret: &oo7::Secret,
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

            let (read_fd, write_fd) = socketpair(
                AddressFamily::UNIX,
                SocketType::STREAM,
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
                None,
            )
            .expect("Failed to create socketpair");
            let mut file = File::from(write_fd);
            file.write_all(secret.as_bytes()).unwrap();
            drop(file); // Close write end to signal EOF

            connection
                .call_method(
                    None::<()>, // No destination in p2p
                    &callback_path,
                    Some("org.kde.secretprompter.request"),
                    "Accepted",
                    &(Fd::Owned(read_fd)),
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

#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
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
                    .unwrap()
                    .path(callback_path.clone())
                    .unwrap()
                    .interface("org.kde.secretprompter.request")
                    .unwrap()
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

                    // Wait for Retry signal before sending next secret from the queue
                    signal_stream.next().await;
                }
            });
        } else {
            let pwd = self.unlock_password.lock().await.clone().unwrap();
            tracing::debug!(
                "MockPrompterServicePlasma: using default password (length: {})",
                std::str::from_utf8(pwd.as_bytes()).unwrap_or("<binary>")
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
        // Behavior is identical for both prompts. Visualization would be different.
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
