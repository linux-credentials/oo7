use std::{os::unix::net::UnixStream, sync::Arc};

use oo7::{Secret, dbus, file::UnlockedKeyring};
use tokio_stream::StreamExt;

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
use crate::gnome::mock_prompter::MockPrompterServiceGNOME;
#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
use crate::plasma::mock_prompter::MockPrompterServicePlasma;
use crate::service::{PrompterType, Service};

pub(crate) async fn assert_next_signal<T>(
    stream: &mut (impl tokio_stream::Stream<Item = T> + Unpin),
) -> T {
    let result = tokio::time::timeout(tokio::time::Duration::from_secs(1), stream.next()).await;
    assert!(result.is_ok(), "Signal not received within timeout");
    let signal = result.unwrap();
    assert!(signal.is_some(), "Signal stream ended unexpectedly");
    signal.unwrap()
}

/// Helper to create a peer-to-peer connection pair using Unix socket
pub(crate) async fn create_p2p_connection()
-> Result<(zbus::Connection, zbus::Connection), Box<dyn std::error::Error>> {
    let guid = zbus::Guid::generate();
    let (p0, p1) = UnixStream::pair()?;

    let (client_conn, server_conn) = tokio::try_join!(
        // Client
        zbus::connection::Builder::unix_stream(p0).p2p().build(),
        // Server
        zbus::connection::Builder::unix_stream(p1)
            .server(guid)
            .p2p()
            .build(),
    )?;

    Ok((server_conn, client_conn))
}

struct MockPrompters {
    #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
    gnome: MockPrompterServiceGNOME,
    #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
    plasma: MockPrompterServicePlasma,
}

impl MockPrompters {
    async fn register(
        conn: &zbus::Connection,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
        let gnome = {
            let prompter = MockPrompterServiceGNOME::new();
            conn.object_server()
                .at("/org/gnome/keyring/Prompter", prompter.clone())
                .await?;
            prompter
        };
        #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
        let plasma = {
            let prompter = MockPrompterServicePlasma::new();
            conn.object_server()
                .at("/SecretPrompter", prompter.clone())
                .await?;
            prompter
        };
        Ok(Self {
            #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
            gnome,
            #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
            plasma,
        })
    }
}

struct ServerSetup {
    server: Service,
    client_conn: zbus::Connection,
    service_api: dbus::api::Service,
    #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
    mock_prompter: MockPrompterServiceGNOME,
    #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
    mock_prompter_plasma: MockPrompterServicePlasma,
    temp_dir: tempfile::TempDir,
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
    pub(crate) mock_prompter: MockPrompterServiceGNOME,
    #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
    pub(crate) mock_prompter_plasma: MockPrompterServicePlasma,
    // Keep temp dir alive for duration of test
    temp_dir: tempfile::TempDir,
}

impl Drop for TestServiceSetup {
    fn drop(&mut self) {
        self.server.release_connection();
    }
}

impl TestServiceSetup {
    async fn setup_server(
        secret: Option<Secret>,
        encrypted_supported: bool,
    ) -> Result<ServerSetup, Box<dyn std::error::Error>> {
        let (server_conn, client_conn) = create_p2p_connection().await?;

        let temp_dir = tempfile::TempDir::new()?;
        let server = Service::run_with_connection(
            server_conn.clone(),
            temp_dir.path().to_path_buf(),
            None,
            secret,
            encrypted_supported,
        )
        .await?;
        server.set_prompter_type(PrompterType::GNOME).await;

        let prompters = MockPrompters::register(&client_conn).await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let service_api = dbus::api::Service::new(&client_conn).await?;

        Ok(ServerSetup {
            server,
            client_conn,
            service_api,
            #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
            mock_prompter: prompters.gnome,
            #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
            mock_prompter_plasma: prompters.plasma,
            temp_dir,
        })
    }

    pub async fn plain_session(
        with_default_collection: bool,
    ) -> Result<TestServiceSetup, Box<dyn std::error::Error>> {
        let secret = if with_default_collection {
            Some(Secret::from("test-password-long-enough"))
        } else {
            None
        };

        let s = Self::setup_server(secret.clone(), true).await?;

        let (server_public_key, session) = s.service_api.open_session(None).await?;
        let mut collections = s.service_api.collections().await?;
        collections.sort_by(|a, b| a.inner().path().cmp(b.inner().path()));

        Ok(TestServiceSetup {
            server: s.server,
            keyring_secret: secret,
            client_conn: s.client_conn,
            service_api: s.service_api,
            session: Arc::new(session),
            collections,
            server_public_key,
            aes_key: None,
            #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
            mock_prompter: s.mock_prompter,
            #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
            mock_prompter_plasma: s.mock_prompter_plasma,
            temp_dir: s.temp_dir,
        })
    }

    #[allow(unused)]
    pub async fn plain_session_no_encrypted() -> Result<TestServiceSetup, Box<dyn std::error::Error>>
    {
        let secret = Some(Secret::from("test-password-long-enough"));

        let s = Self::setup_server(secret.clone(), false).await?;

        let (server_public_key, session) = s.service_api.open_session(None).await?;
        let mut collections = s.service_api.collections().await?;
        collections.sort_by(|a, b| a.inner().path().cmp(b.inner().path()));

        Ok(TestServiceSetup {
            server: s.server,
            keyring_secret: secret,
            client_conn: s.client_conn,
            service_api: s.service_api,
            session: Arc::new(session),
            collections,
            server_public_key,
            aes_key: None,
            #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
            mock_prompter: s.mock_prompter,
            #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
            mock_prompter_plasma: s.mock_prompter_plasma,
            temp_dir: s.temp_dir,
        })
    }

    pub async fn encrypted_session(
        with_default_collection: bool,
    ) -> Result<TestServiceSetup, Box<dyn std::error::Error>> {
        let secret = if with_default_collection {
            Some(Secret::from("test-password-long-enough"))
        } else {
            None
        };

        let s = Self::setup_server(secret.clone(), true).await?;

        let client_private_key = oo7::Key::generate_private_key()?;
        let client_public_key = oo7::Key::generate_public_key(&client_private_key)?;

        let (server_public_key, session) =
            s.service_api.open_session(Some(client_public_key)).await?;

        let aes_key =
            oo7::Key::generate_aes_key(&client_private_key, server_public_key.as_ref().unwrap())?;

        let mut collections = s.service_api.collections().await?;
        collections.sort_by(|a, b| a.inner().path().cmp(b.inner().path()));

        Ok(Self {
            server: s.server,
            keyring_secret: secret,
            client_conn: s.client_conn,
            service_api: s.service_api,
            session: Arc::new(session),
            collections,
            server_public_key,
            aes_key: Some(Arc::new(aes_key)),
            #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
            mock_prompter: s.mock_prompter,
            #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
            mock_prompter_plasma: s.mock_prompter_plasma,
            temp_dir: s.temp_dir,
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
        let service = crate::Service::new(data_dir, pam_socket, true);

        server_conn
            .object_server()
            .at(
                oo7::dbus::api::Service::PATH.as_deref().unwrap(),
                service.clone(),
            )
            .await?;

        #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
        server_conn
            .object_server()
            .at(
                oo7::dbus::api::Service::PATH.as_deref().unwrap(),
                crate::gnome::internal::InternalInterface::new(service.clone()),
            )
            .await?;

        let discovered = service.discover_keyrings(secret.clone()).await?;
        service
            .initialize(server_conn, discovered, secret.clone(), false)
            .await?;
        service.set_prompter_type(PrompterType::GNOME).await;

        let prompters = MockPrompters::register(&client_conn).await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let service_api = dbus::api::Service::new(&client_conn).await?;

        let (server_public_key, session) = service_api.open_session(None).await?;
        let session = Arc::new(session);

        let mut collections = service_api.collections().await?;
        collections.sort_by(|a, b| a.inner().path().cmp(b.inner().path()));

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
            mock_prompter: prompters.gnome,
            #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
            mock_prompter_plasma: prompters.plasma,
            temp_dir,
        })
    }

    /// Create a test setup with an empty Login keyring stored on disk
    pub(crate) async fn with_login_keyring(
        secret: Secret,
    ) -> Result<TestServiceSetup, Box<dyn std::error::Error>> {
        let temp_dir = tempfile::TempDir::new()?;
        UnlockedKeyring::open_at(temp_dir.path(), "login", Some(secret.clone()))
            .await?
            .write()
            .await?;

        let mut setup =
            Self::with_disk_keyrings(temp_dir.path().to_path_buf(), None, Some(secret)).await?;
        setup.temp_dir = temp_dir;
        Ok(setup)
    }

    /// Load the Login keyring of [`Self::with_login_keyring`] from disk
    pub(crate) async fn login_keyring(
        &self,
    ) -> Result<UnlockedKeyring, Box<dyn std::error::Error>> {
        let keyring =
            UnlockedKeyring::open_at(self.temp_dir.path(), "login", self.keyring_secret.clone())
                .await?;
        Ok(keyring)
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
