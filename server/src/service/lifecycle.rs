use oo7::{
    Secret,
    file::{Keyring, LockedKeyring, UnlockedKeyring},
};
use tokio_stream::StreamExt;
use zbus::{
    fdo::{RequestNameFlags, RequestNameReply},
    names::UniqueName,
    proxy::Defaults,
    wire::Optional,
};

use super::{Service, discovery, naming};
#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
use crate::gnome::internal::InternalInterface;
use crate::{collection::Collection, error::Error};

impl Service {
    pub async fn run(
        secret: Option<Secret>,
        request_replacement: bool,
    ) -> Result<zbus::Connection, Error> {
        // Compute data directory from environment variables
        let data_dir = std::env::var_os("XDG_DATA_HOME")
            .filter(|h| !h.is_empty())
            .map(std::path::PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| {
                std::env::var_os("HOME")
                    .filter(|h| !h.is_empty())
                    .map(std::path::PathBuf::from)
                    .map(|p| p.join(".local/share"))
            })
            .ok_or_else(|| {
                Error::IO(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No data directory found (XDG_DATA_HOME or HOME)",
                ))
            })?;

        // Compute PAM socket path from environment variable
        let pam_socket = std::env::var_os("OO7_PAM_SOCKET").map(std::path::PathBuf::from);

        let service = Self::new(data_dir, pam_socket, true);

        // Start PAM listener early so it can buffer secrets arriving before
        // D-Bus is ready (e.g. during PAM-initiated login startup).
        tracing::info!("Starting PAM listener");
        let pam_listener = crate::pam_listener::PamListener::new(service.clone());
        let pam_listener_replay = pam_listener.clone();
        tokio::spawn(async move {
            if let Err(e) = pam_listener.start().await {
                tracing::error!("PAM listener error: {}", e);
            }
        });

        // The name is requested only once the service is initialized
        let connection = zbus::connection::Builder::session()
            .serve_at(
                oo7::dbus::api::Service::PATH.as_deref().unwrap(),
                service.clone(),
            )
            .build()
            .await?;

        #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
        connection
            .object_server()
            .at(
                oo7::dbus::api::Service::PATH.as_deref().unwrap(),
                InternalInterface::new(service.clone()),
            )
            .await?;

        // Discover existing keyrings
        let discovered_keyrings = service.discover_keyrings(secret.clone()).await?;

        let connection_clone = connection.clone();
        service
            .initialize(connection, discovered_keyrings, secret, true)
            .await?;

        let mut flags = RequestNameFlags::ALLOW_REPLACEMENT | RequestNameFlags::DO_NOT_QUEUE;
        if request_replacement {
            flags |= RequestNameFlags::REPLACE_EXISTING;
        }
        match connection_clone
            .request_name_with_flags(
                oo7::dbus::api::Service::DESTINATION.as_deref().unwrap(),
                flags,
            )
            .await?
        {
            RequestNameReply::PrimaryOwner | RequestNameReply::AlreadyOwner => {}
            RequestNameReply::Exists | RequestNameReply::InQueue => {
                return Err(Error::Zbus(zbus::Error::NameTaken));
            }
        }

        // Replay any secrets that the PAM listener buffered during startup
        pam_listener_replay.replay_buffered_secrets().await;

        Ok(connection_clone)
    }

    #[cfg(any(test, feature = "test-util"))]
    #[allow(dead_code)]
    pub async fn run_with_connection(
        connection: zbus::Connection,
        data_dir: std::path::PathBuf,
        pam_socket: Option<std::path::PathBuf>,
        secret: Option<Secret>,
        encrypted_supported: bool,
    ) -> Result<Self, Error> {
        let service = Self::new(data_dir, pam_socket, encrypted_supported);

        // Serve the service at the standard path
        connection
            .object_server()
            .at(
                oo7::dbus::api::Service::PATH.as_deref().unwrap(),
                service.clone(),
            )
            .await?;

        #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
        connection
            .object_server()
            .at(
                oo7::dbus::api::Service::PATH.as_deref().unwrap(),
                InternalInterface::new(service.clone()),
            )
            .await?;

        let default_keyring = if let Some(secret) = secret.clone() {
            vec![discovery::LoadedKeyring {
                name: "default".to_owned(),
                label: "Login".to_owned(),
                alias: oo7::dbus::Service::DEFAULT_COLLECTION.to_owned(),
                keyring: Keyring::Unlocked(UnlockedKeyring::temporary(secret).await?),
                pending_migration: None,
            }]
        } else {
            vec![]
        };

        service
            .initialize(connection, default_keyring, secret, false)
            .await?;
        Ok(service)
    }

    pub(crate) async fn discover_keyrings(
        &self,
        secret: Option<Secret>,
    ) -> Result<Vec<discovery::LoadedKeyring>, Error> {
        let mut loaded = discovery::discover_keyrings(&self.data_dir, secret).await?;
        let mut pending = self.pending_migrations.lock().await;
        for item in &mut loaded {
            if let Some(migration) = item.pending_migration.take() {
                pending.insert(item.name.clone(), migration);
            }
        }
        Ok(loaded)
    }

    pub(crate) async fn initialize(
        &self,
        connection: zbus::Connection,
        mut discovered_keyrings: Vec<discovery::LoadedKeyring>,
        secret: Option<Secret>,
        auto_create_default: bool,
    ) -> Result<(), Error> {
        *self.connection.write().unwrap() = Some(connection.clone());

        let object_server = connection.object_server();
        let mut collections = self.collections.lock().await;

        // Check if we have a default collection
        let has_default = discovered_keyrings.iter().any(|dk| {
            dk.alias == oo7::dbus::Service::DEFAULT_COLLECTION || dk.alias == Self::LOGIN_ALIAS
        });

        if !has_default && auto_create_default {
            tracing::info!("No default collection found, creating 'Login' keyring");

            let keyring = if let Some(secret) = secret {
                UnlockedKeyring::open_at(&self.data_dir, Self::LOGIN_ALIAS, Some(secret))
                    .await
                    .map(Keyring::Unlocked)
            } else {
                LockedKeyring::open_at(&self.data_dir, Self::LOGIN_ALIAS)
                    .await
                    .map(Keyring::Locked)
            };

            let keyring = keyring.inspect_err(|e| {
                tracing::error!("Failed to create default Login keyring: {}", e);
            })?;

            let is_locked = if keyring.is_locked() {
                "locked"
            } else {
                "unlocked"
            };
            discovered_keyrings.push(discovery::LoadedKeyring {
                name: Self::LOGIN_ALIAS.to_owned(),
                label: "Login".to_owned(),
                alias: oo7::dbus::Service::DEFAULT_COLLECTION.to_owned(),
                keyring,
                pending_migration: None,
            });

            tracing::info!("Created default 'Login' collection ({})", is_locked);
        }

        // Sort so the login keyring is processed first
        discovered_keyrings.sort_by(|a, b| {
            let a_is_login = a.name.eq_ignore_ascii_case(Self::LOGIN_ALIAS);
            let b_is_login = b.name.eq_ignore_ascii_case(Self::LOGIN_ALIAS);
            b_is_login.cmp(&a_is_login)
        });

        // Build all collections under the lock, then register on D-Bus after
        // releasing it to avoid deadlocks with incoming calls.
        let mut built_collections: Vec<(Collection, String)> = Vec::new();

        for dk in discovered_keyrings {
            tracing::info!("Setting up collection '{}' (alias: {}).", dk.name, dk.alias);
            let (unique_label, unique_alias) =
                naming::make_unique_label_and_alias(&collections, &dk.label, &dk.alias).await;
            let collection = Collection::new(
                &dk.name,
                &unique_label,
                &unique_alias,
                self.clone(),
                dk.keyring,
            )
            .await;
            collections.insert(collection.path().to_owned().into(), collection.clone());
            built_collections.push((collection, unique_alias));
        }

        // Always create session collection (always temporary)
        let session_collection = Collection::new(
            "session",
            "session",
            oo7::dbus::Service::SESSION_COLLECTION,
            self.clone(),
            Keyring::Unlocked(UnlockedKeyring::temporary(Secret::random().unwrap()).await?),
        )
        .await;
        collections.insert(
            session_collection.path().to_owned().into(),
            session_collection.clone(),
        );

        drop(collections);

        // Now register on D-Bus and dispatch items without holding the lock
        for (collection, alias) in &built_collections {
            collection.dispatch_items().await?;
            object_server
                .at(collection.path(), collection.clone())
                .await?;
            collection.serve_alias_path(alias).await;
        }

        let session_path = session_collection.path().to_owned();
        object_server
            .at(&session_path, session_collection.clone())
            .await?;
        session_collection
            .serve_alias_path(oo7::dbus::Service::SESSION_COLLECTION)
            .await;

        // Spawn client disconnect handler
        let service = self.clone();
        tokio::spawn(async move { service.on_client_disconnect().await });

        // Spawn stale session cleanup task
        let service = self.clone();
        tokio::spawn(async move { service.cleanup_stale_sessions().await });

        Ok(())
    }

    pub(crate) async fn on_client_disconnect(&self) -> zbus::Result<()> {
        let rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender("org.freedesktop.DBus")
            .interface("org.freedesktop.DBus")
            .member("NameOwnerChanged")
            .arg(2, "")
            .build()?;
        let mut stream =
            zbus::MessageStream::for_match_rule(rule, &self.connection(), None).await?;
        while let Some(message) = stream.try_next().await? {
            let body = message.body();
            let Ok((name, old_owner, new_owner)) =
                body.deserialize::<(&str, Optional<UniqueName<'_>>, Optional<UniqueName<'_>>)>()
            else {
                continue;
            };
            debug_assert!(new_owner.is_none()); // We enforce that in the matching rule
            let old_owner = old_owner
                .as_ref()
                .expect("A disconnected client requires an old_owner");
            if name != old_owner.as_str() {
                continue; // a well-known name was released, the client is still connected
            }
            if let Some(session) = self.session_from_sender(old_owner).await {
                let client_name = match session.peer_info() {
                    Some(info) => format!("{old_owner} ({info})"),
                    None => old_owner.to_string(),
                };
                session.mark_stale().await;
                tracing::info!(
                    "Client {} disconnected. Session: {} marked for cleanup.",
                    client_name,
                    session.path()
                );
            }
        }
        Ok(())
    }

    pub(crate) async fn cleanup_stale_sessions(&self) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let stale_paths: Vec<_> = {
                let sessions = self.sessions.lock().await;
                let mut paths = Vec::new();
                for (path, session) in sessions.iter() {
                    if session.is_stale().await {
                        paths.push(path.clone());
                    }
                }
                paths
            };
            for path in stale_paths {
                if let Some(session) = self.session(&path).await {
                    match session.close().await {
                        Ok(_) => tracing::info!("Stale session {} cleaned up.", path),
                        Err(err) => {
                            tracing::error!("Failed to clean up stale session {}: {}", path, err)
                        }
                    }
                }
            }
        }
    }
}
