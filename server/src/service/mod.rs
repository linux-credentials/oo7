// org.freedesktop.Secret.Service

mod discovery;

use std::{
    collections::HashMap,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU32, Ordering},
    },
};

use oo7::{
    Key, Secret,
    dbus::{
        Algorithm, ServiceError,
        api::{DBusSecretInner, Properties},
    },
    file::{Keyring, LockedKeyring, UnlockedKeyring},
};
use tokio::sync::Mutex;
use tokio_stream::StreamExt;
use zbus::{
    fdo::{RequestNameFlags, RequestNameReply},
    names::UniqueName,
    object_server::SignalEmitter,
    proxy::Defaults,
    wire::{ObjectPath, Optional, OwnedObjectPath, OwnedVariant, Variant},
};

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
pub use crate::gnome::internal::InternalInterface;
#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
use crate::plasma::prompter::in_plasma_environment;
use crate::{
    collection::Collection,
    error::{Error, custom_service_error},
    migration::PendingMigration,
    prompt::{Prompt, PromptAction, PromptRole},
    session::{PeerInfo, Session},
};

#[cfg(any(test, feature = "test-util"))]
pub(crate) const P2P_TEST_SENDER: &str = ":p2p.test";

/// Prompter type
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PrompterType {
    #[allow(clippy::upper_case_acronyms)]
    GNOME,
    Plasma,
    Cli,
}

#[derive(Clone)]
pub struct Service {
    // Properties
    pub(crate) collections: Arc<Mutex<HashMap<OwnedObjectPath, Collection>>>,
    // Other attributes
    connection: Arc<RwLock<Option<zbus::Connection>>>,
    // sessions mapped to their corresponding object path on the bus
    sessions: Arc<Mutex<HashMap<OwnedObjectPath, Session>>>,
    session_index: Arc<AtomicU32>,
    // prompts mapped to their corresponding object path on the bus
    prompts: Arc<Mutex<HashMap<OwnedObjectPath, Prompt>>>,
    prompt_index: Arc<AtomicU32>,
    // pending collection creations: prompt_path -> (label, alias)
    pending_collections: Arc<Mutex<HashMap<OwnedObjectPath, (String, String)>>>,
    // pending unlock: object_path -> prompt path (for deduplication)
    pending_unlocks: Arc<Mutex<HashMap<OwnedObjectPath, OwnedObjectPath>>>,
    // pending keyring migrations: name -> migration
    pub(crate) pending_migrations: Arc<Mutex<HashMap<String, PendingMigration>>>,
    // Data directory for keyrings (e.g., ~/.local/share or test temp dir)
    data_dir: std::path::PathBuf,
    // PAM socket path (None for tests that don't need PAM listener)
    pub(crate) pam_socket: Option<std::path::PathBuf>,
    // Override for prompter type (mainly for tests)
    pub(crate) prompter_type_override: Arc<Mutex<Option<PrompterType>>>,
    // Whether encrypted sessions are supported
    encrypted_supported: bool,
}

#[zbus::interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    #[zbus(out_args("output", "result"))]
    pub async fn open_session(
        &self,
        algorithm: Algorithm,
        input: Variant<'_>,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<(OwnedVariant, OwnedObjectPath), ServiceError> {
        let (public_key, aes_key) = match algorithm {
            Algorithm::Plain => (None, None),
            Algorithm::Encrypted if !self.encrypted_supported => {
                return Err(ServiceError::ZBus(zbus::Error::FDO(Box::new(
                    zbus::fdo::Error::NotSupported(
                        "Algorithm dh-ietf1024-sha256-aes128-cbc-pkcs7 is not supported"
                            .to_string(),
                    ),
                ))));
            }
            Algorithm::Encrypted => {
                let client_public_key = Key::try_from(input).map_err(|err| {
                    custom_service_error(&format!(
                        "Input Variant could not be converted into a Key {err}."
                    ))
                })?;
                let private_key = Key::generate_private_key().map_err(|err| {
                    custom_service_error(&format!("Failed to generate private key {err}."))
                })?;
                (
                    Some(Key::generate_public_key(&private_key).map_err(|err| {
                        custom_service_error(&format!("Failed to generate public key {err}."))
                    })?),
                    Some(
                        Key::generate_aes_key(&private_key, &client_public_key).map_err(|err| {
                            custom_service_error(&format!("Failed to generate aes key {err}."))
                        })?,
                    ),
                )
            }
        };

        let sender = Self::sender(&header)
            .ok_or_else(|| custom_service_error("Failed to get sender from header."))?;
        let peer_info = PeerInfo::lookup(&self.connection(), &sender).await;
        let session = Session::new(
            aes_key.map(Arc::new),
            self.clone(),
            sender.clone(),
            peer_info,
        )
        .await;
        let path = OwnedObjectPath::from(session.path().clone());

        match session.peer_info() {
            Some(info) => {
                tracing::info!("Client {} ({}) connected, session: {}", sender, info, path)
            }
            None => tracing::info!("Client {} connected, session: {}", sender, path),
        }

        self.sessions
            .lock()
            .await
            .insert(path.clone(), session.clone());

        object_server.at(&path, session).await?;

        let service_key = public_key
            .map(OwnedVariant::from)
            .unwrap_or_else(|| Variant::new::<Vec<u8>>(vec![]).try_into_owned().unwrap());

        Ok((service_key, path))
    }

    #[zbus(out_args("collection", "prompt"))]
    pub async fn create_collection(
        &self,
        properties: Properties,
        alias: &str,
    ) -> Result<(OwnedObjectPath, ObjectPath<'_>), ServiceError> {
        let label = properties.label().to_owned();
        let alias = alias.to_owned();

        // Create a prompt to get the password for the new collection
        let prompt = Prompt::new(
            self.clone(),
            PromptRole::CreateCollection,
            label.clone(),
            None,
        )
        .await;
        let prompt_path = OwnedObjectPath::from(prompt.path().clone());

        // Store the collection metadata for later creation
        self.pending_collections
            .lock()
            .await
            .insert(prompt_path.clone(), (label, alias));

        // Create the collection creation action
        let service = self.clone();
        let creation_prompt_path = prompt_path.clone();
        let action = PromptAction::new(move |secret: Option<Secret>| async move {
            let collection_path = service
                .complete_collection_creation(&creation_prompt_path, secret)
                .await?;

            Ok(Variant::new(collection_path).try_into_owned().unwrap())
        });

        prompt.set_action(action).await;

        // Register the prompt
        self.prompts
            .lock()
            .await
            .insert(prompt_path.clone(), prompt.clone());

        self.object_server().at(&prompt_path, prompt).await?;

        tracing::debug!("CreateCollection prompt created at `{}`", prompt_path);

        // Return empty collection path and the prompt path
        Ok((OwnedObjectPath::default(), prompt_path.into()))
    }

    #[zbus(out_args("unlocked", "locked"))]
    pub async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), ServiceError> {
        let mut unlocked = Vec::new();
        let mut locked = Vec::new();
        let snapshot: Vec<Collection> = self.collections.lock().await.values().cloned().collect();

        for collection in &snapshot {
            let items = collection.search_inner_items(&attributes).await?;
            for item in items {
                if item.is_locked().await {
                    locked.push(item.path().clone().into());
                } else {
                    unlocked.push(item.path().clone().into());
                }
            }
        }

        if unlocked.is_empty() && locked.is_empty() {
            tracing::debug!(
                "Items with attributes {:?} does not exist in any collection.",
                attributes
            );
        } else {
            tracing::debug!("Items with attributes {:?} found.", attributes);
        }

        Ok((unlocked, locked))
    }

    #[zbus(out_args("unlocked", "prompt"))]
    pub async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath), ServiceError> {
        tracing::info!("Unlock requested for {} objects.", objects.len());
        let (unlocked, not_unlocked) = self.set_locked(false, &objects).await?;
        if !not_unlocked.is_empty() {
            // Hold the lock across both the lookup and the registration so
            // a concurrent Unlock cannot slip between the two.
            let mut pending = self.pending_unlocks.lock().await;

            // Another unlock for the same object(s) is already prompting;
            // return the same prompt path so both callers share one prompt.
            if let Some(prompt_path) = not_unlocked
                .iter()
                .find_map(|obj| pending.get(obj).cloned())
            {
                drop(pending);
                return Ok((unlocked, prompt_path));
            }

            // First caller: reserve the prompt path while holding the lock
            // so concurrent callers see it before the Prompt is fully created.
            let index = self.prompt_index();
            let prompt_path =
                OwnedObjectPath::try_from(format!("/org/freedesktop/secrets/prompt/p{index}"))
                    .unwrap();
            for obj in &not_unlocked {
                pending.insert(obj.clone(), prompt_path.clone());
            }
            drop(pending);

            let collection = self.collection_for_objects(&not_unlocked).await;
            let label = if let Some(c) = &collection {
                c.label().await
            } else {
                String::default()
            };

            let prompt = Prompt::with_path(
                self.clone(),
                PromptRole::Unlock,
                label,
                collection,
                prompt_path,
            );
            let path = OwnedObjectPath::from(prompt.path().clone());

            // Create the unlock action
            let service = self.clone();
            let not_unlocked_for_action = not_unlocked.clone();
            let action = PromptAction::new(move |secret: Option<Secret>| async move {
                // The prompter will handle secret validation
                // Here we just perform the unlock operation

                // First, check for pending migrations (without holding
                // collections lock)
                for object in &not_unlocked_for_action {
                    let collection = {
                        let collections = service.collections.lock().await;
                        collections.get(object).cloned()
                    };

                    if let Some(collection) = collection {
                        // Check if this collection has a pending migration by
                        // name
                        let migration_opt = {
                            let pending = service.pending_migrations.lock().await;
                            pending.get(collection.name()).cloned()
                        };

                        if let Some(migration) = migration_opt {
                            let migration_name = migration.name();
                            tracing::debug!(
                                "Attempting migration for '{}' during unlock",
                                migration_name
                            );

                            // Attempt migration with the provided secret (no
                            // locks held)
                            match migration.migrate(&service.data_dir, secret.as_ref()).await {
                                Ok(unlocked_keyring) => {
                                    tracing::info!(
                                        "Successfully migrated '{}' during unlock",
                                        migration_name
                                    );

                                    // Replace the keyring in the collection
                                    let mut keyring_guard = collection.keyring.write().await;
                                    *keyring_guard = Some(Keyring::Unlocked(unlocked_keyring));
                                    drop(keyring_guard);

                                    // Dispatch items from the migrated keyring
                                    if let Err(e) = collection.dispatch_items().await {
                                        tracing::error!(
                                            "Failed to dispatch items after migration: {}",
                                            e
                                        );
                                    }

                                    // Remove from pending migrations
                                    service
                                        .pending_migrations
                                        .lock()
                                        .await
                                        .remove(migration_name);
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "Failed to migrate '{}' during unlock: {}",
                                        migration_name,
                                        e
                                    );
                                    let _ = collection.set_locked(false, secret.clone()).await;
                                }
                            }
                        } else {
                            // Normal unlock
                            let _ = collection.set_locked(false, secret.clone()).await;
                        }
                    } else {
                        // Try to find as item within collections
                        let collections = service.collections.lock().await;
                        let mut found_collection = None;
                        for collection in collections.values() {
                            if let Some(item) = collection.item_from_path(object).await {
                                found_collection = Some((
                                    collection.clone(),
                                    item.clone(),
                                    collection.is_locked().await,
                                ));
                                break;
                            }
                        }
                        drop(collections);

                        if let Some((collection, item, is_locked)) = found_collection {
                            if is_locked {
                                let _ = collection.set_locked(false, secret.clone()).await;
                            } else {
                                let keyring = collection.keyring.read().await;
                                match keyring.as_ref() {
                                    Some(k) if !k.is_locked() => {
                                        let _ = item.set_locked(false, k.as_unlocked()).await;
                                    }
                                    _ => {
                                        drop(keyring);
                                        let _ = collection.set_locked(false, secret.clone()).await;
                                    }
                                }
                            }
                        }
                    }
                }
                {
                    let mut pending = service.pending_unlocks.lock().await;
                    for obj in &not_unlocked_for_action {
                        pending.remove(obj);
                    }
                }
                Ok(Variant::new(not_unlocked_for_action)
                    .try_into_owned()
                    .unwrap())
            });

            prompt.set_action(action).await;

            self.prompts
                .lock()
                .await
                .insert(path.clone(), prompt.clone());

            self.object_server().at(&path, prompt).await?;
            return Ok((unlocked, path));
        }

        Ok((unlocked, OwnedObjectPath::default()))
    }

    #[zbus(out_args("locked", "Prompt"))]
    pub async fn lock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath), ServiceError> {
        tracing::info!("Lock requested for {} objects.", objects.len());
        let (locked, not_locked) = self.set_locked(true, &objects).await?;
        // Locking never requires prompts, so not_locked should always be empty
        debug_assert!(
            not_locked.is_empty(),
            "Lock operation should never require prompts"
        );
        Ok((locked, OwnedObjectPath::default()))
    }

    #[zbus(out_args("secrets"))]
    pub async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
    ) -> Result<HashMap<OwnedObjectPath, DBusSecretInner>, ServiceError> {
        tracing::debug!(
            "GetSecrets called for {} items with session {}.",
            items.len(),
            session
        );
        let mut secrets = HashMap::new();
        let snapshot: Vec<Collection> = self.collections.lock().await.values().cloned().collect();

        'outer: for collection in &snapshot {
            for item in &items {
                if let Some(item) = collection.item_from_path(item).await {
                    match item.get_secret(session.clone()).await {
                        Ok((secret,)) => {
                            secrets.insert(item.path().clone().into(), secret);
                            // To avoid iterating through all the remaining
                            // collections, if the items secrets are already
                            // retrieved.
                            if secrets.len() == items.len() {
                                break 'outer;
                            }
                        }
                        // Avoid erroring out if an item is locked.
                        Err(ServiceError::IsLocked(_)) => {
                            continue;
                        }
                        Err(err) => {
                            return Err(err);
                        }
                    };
                }
            }
        }

        tracing::debug!(
            "GetSecrets returned {} of {} requested secrets.",
            secrets.len(),
            items.len()
        );
        Ok(secrets)
    }

    #[zbus(out_args("collection"))]
    pub async fn read_alias(&self, name: &str) -> Result<OwnedObjectPath, ServiceError> {
        // Map "login" alias to "default" for compatibility with gnome-keyring
        let alias_to_find = if name == Self::LOGIN_ALIAS {
            oo7::dbus::Service::DEFAULT_COLLECTION
        } else {
            name
        };

        let collections = self.collections.lock().await;

        for (path, collection) in collections.iter() {
            if collection.alias().await == alias_to_find {
                tracing::debug!("Collection: {} found for alias: {}.", path, name);
                return Ok(path.to_owned());
            }
        }

        tracing::info!("Collection with alias {} does not exist.", name);

        Ok(OwnedObjectPath::default())
    }

    pub async fn set_alias(
        &self,
        name: &str,
        collection: OwnedObjectPath,
    ) -> Result<(), ServiceError> {
        let collections = self.collections.lock().await;

        for (path, other_collection) in collections.iter() {
            if *path == collection {
                other_collection.set_alias(name).await;

                tracing::info!("Collection: {} alias updated to {}.", collection, name);
                return Ok(());
            }
        }

        tracing::info!("Collection: {} does not exist.", collection);

        Err(ServiceError::NoSuchObject(format!(
            "The collection: {collection} does not exist.",
        )))
    }

    #[zbus(property, name = "Collections")]
    pub async fn collections(&self) -> Vec<OwnedObjectPath> {
        self.collections.lock().await.keys().cloned().collect()
    }

    #[zbus(signal, name = "CollectionCreated")]
    pub async fn collection_created(
        signal_emitter: &SignalEmitter<'_>,
        collection: &ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal, name = "CollectionDeleted")]
    pub async fn collection_deleted(
        signal_emitter: &SignalEmitter<'_>,
        collection: &ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal, name = "CollectionChanged")]
    pub async fn collection_changed(
        signal_emitter: &SignalEmitter<'_>,
        collection: &ObjectPath<'_>,
    ) -> zbus::Result<()>;
}

impl Service {
    const LOGIN_ALIAS: &str = "login";

    /// Set the prompter type override
    #[allow(unused)]
    pub(crate) async fn set_prompter_type(&self, prompter_type: PrompterType) {
        *self.prompter_type_override.lock().await = Some(prompter_type);
    }

    /// Get the prompter type to use based on the caller's session type
    pub(crate) async fn prompter_type(&self, peer_info: Option<&PeerInfo>) -> PrompterType {
        let is_graphical = peer_info
            .map(|p| p.session_type().is_graphical())
            .unwrap_or_default();

        if is_graphical {
            if let Some(override_type) = self.prompter_type_override.lock().await.as_ref() {
                return *override_type;
            }

            #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
            {
                if in_plasma_environment(&self.connection()).await {
                    return PrompterType::Plasma;
                }
            }

            return PrompterType::GNOME;
        }

        PrompterType::Cli
    }

    pub(crate) fn new(
        data_dir: std::path::PathBuf,
        pam_socket: Option<std::path::PathBuf>,
        encrypted_supported: bool,
    ) -> Self {
        Self {
            collections: Arc::new(Mutex::new(HashMap::new())),
            connection: Default::default(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session_index: Arc::new(AtomicU32::new(0)),
            prompts: Arc::new(Mutex::new(HashMap::new())),
            prompt_index: Arc::new(AtomicU32::new(0)),
            pending_collections: Arc::new(Mutex::new(HashMap::new())),
            pending_unlocks: Arc::new(Mutex::new(HashMap::new())),
            pending_migrations: Arc::new(Mutex::new(HashMap::new())),
            data_dir,
            pam_socket,
            prompter_type_override: Arc::new(Mutex::new(None)),
            encrypted_supported,
        }
    }

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

    /// Generate a unique label and alias by checking registered
    /// collections and appending a counter if needed. Returns a tuple of
    /// (label, alias).
    async fn make_unique_label_and_alias(
        collections: &HashMap<OwnedObjectPath, Collection>,
        label: &str,
        alias: &str,
    ) -> (String, String) {
        // Sanitize the label to create the path (for checking uniqueness)
        let base_path = crate::collection::collection_path(label)
            .expect("Sanitized label should always produce valid object path");
        if !collections.contains_key(&base_path) && !Self::has_alias(collections, alias).await {
            return (label.to_owned(), alias.to_owned());
        }

        // Append counter until we find a unique one
        let mut counter = 2;
        loop {
            let new_label = format!("{label}{counter}");
            let path = crate::collection::collection_path(&new_label)
                .expect("Sanitized label should always produce valid object path");
            let new_alias = format!("{alias}{counter}");

            if !collections.contains_key(&path) && !Self::has_alias(collections, &new_alias).await {
                return (new_label, new_alias);
            }
            counter += 1;
        }
    }

    async fn has_alias(collections: &HashMap<OwnedObjectPath, Collection>, alias: &str) -> bool {
        if alias.is_empty() {
            return false;
        }
        for collection in collections.values() {
            if collection.alias().await == alias {
                return true;
            }
        }
        false
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

    /// Initialize the service with collections and start client disconnect
    /// handler
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
                Self::make_unique_label_and_alias(&collections, &dk.label, &dk.alias).await;
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

    async fn on_client_disconnect(&self) -> zbus::Result<()> {
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
            let Ok((_name, old_owner, new_owner)) =
                body.deserialize::<(String, Optional<UniqueName<'_>>, Optional<UniqueName<'_>>)>()
            else {
                continue;
            };
            debug_assert!(new_owner.is_none()); // We enforce that in the matching rule
            let old_owner = old_owner
                .as_ref()
                .expect("A disconnected client requires an old_owner");
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

    async fn cleanup_stale_sessions(&self) {
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

    pub async fn set_locked(
        &self,
        locked: bool,
        objects: &[OwnedObjectPath],
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), ServiceError> {
        let mut without_prompt = Vec::new();
        let mut with_prompt = Vec::new();
        let snapshot: HashMap<OwnedObjectPath, Collection> = self.collections.lock().await.clone();

        for object in objects {
            let resolved = Self::resolve_alias(&snapshot, object)
                .await
                .unwrap_or_else(|| object.clone());
            let mut found = false;
            for (path, collection) in snapshot.iter() {
                let collection_locked = collection.is_locked().await;
                if resolved == *path {
                    found = true;
                    if collection_locked == locked {
                        tracing::debug!(
                            "Collection: {} is already {}.",
                            resolved,
                            if locked { "locked" } else { "unlocked" }
                        );
                        without_prompt.push(resolved.clone());
                    } else if locked {
                        // Locking never requires a prompt
                        collection.set_locked(true, None).await?;
                        without_prompt.push(resolved.clone());
                    } else {
                        // Unlocking may require a prompt
                        with_prompt.push(resolved.clone());
                    }
                    break;
                } else if let Some(item) = collection.item_from_path(&resolved).await {
                    found = true;
                    // If collection is locked, can't perform any item
                    // lock/unlock operations
                    if collection_locked {
                        // Unlocking an item when collection is locked requires
                        // unlocking collection
                        if !locked {
                            with_prompt.push(resolved.clone());
                        } else {
                            // Can't lock an item when collection is locked
                            return Err(ServiceError::IsLocked(format!(
                                "Cannot lock item {} when collection is locked",
                                resolved
                            )));
                        }
                    } else if locked == item.is_locked().await {
                        tracing::debug!(
                            "Item: {} is already {}.",
                            resolved,
                            if locked { "locked" } else { "unlocked" }
                        );
                        without_prompt.push(resolved.clone());
                    } else {
                        let keyring = collection.keyring.read().await;
                        match keyring.as_ref() {
                            Some(k) if !k.is_locked() => {
                                item.set_locked(locked, k.as_unlocked()).await?;
                                without_prompt.push(resolved.clone());
                            }
                            _ => {
                                if locked {
                                    return Err(ServiceError::IsLocked(format!(
                                        "Cannot lock item {} when collection is locked",
                                        resolved
                                    )));
                                } else {
                                    with_prompt.push(resolved.clone());
                                }
                            }
                        }
                    }
                    break;
                }
            }
            if !found {
                tracing::warn!("Object: {} does not exist.", object);
            }
        }

        Ok((without_prompt, with_prompt))
    }

    pub fn connection(&self) -> zbus::Connection {
        self.connection
            .read()
            .unwrap()
            .clone()
            .expect("service is not initialized")
    }

    pub fn object_server(&self) -> zbus::ObjectServer {
        self.connection().object_server().clone()
    }

    /// Drop the service's reference to its connection.
    ///
    /// The connection's object server holds the service, which in turn holds
    /// the connection, so neither is ever freed otherwise.
    #[cfg(any(test, feature = "test-util"))]
    #[allow(dead_code)]
    pub(crate) fn release_connection(&self) {
        self.connection.write().unwrap().take();
    }

    async fn resolve_alias(
        collections: &HashMap<OwnedObjectPath, Collection>,
        path: &ObjectPath<'_>,
    ) -> Option<OwnedObjectPath> {
        let alias = path.strip_prefix("/org/freedesktop/secrets/aliases/")?;
        let alias_to_find = if alias == Self::LOGIN_ALIAS {
            oo7::dbus::Service::DEFAULT_COLLECTION
        } else {
            alias
        };
        for (real_path, collection) in collections.iter() {
            if collection.alias().await == alias_to_find {
                return Some(real_path.clone());
            }
        }
        None
    }

    pub async fn collection_from_path(&self, path: &ObjectPath<'_>) -> Option<Collection> {
        let collections = self.collections.lock().await;
        if let Some(collection) = collections.get(path).cloned() {
            return Some(collection);
        }
        let resolved = Self::resolve_alias(&collections, path).await?;
        collections.get(&resolved).cloned()
    }

    pub fn session_index(&self) -> u32 {
        self.session_index.fetch_add(1, Ordering::Relaxed)
    }

    /// The sender of a method call
    pub(crate) fn sender(header: &zbus::message::Header<'_>) -> Option<UniqueName<'static>> {
        match header.sender() {
            Some(sender) => Some(sender.to_owned()),
            // p2p test connections don't have a bus to assign unique names
            #[cfg(any(test, feature = "test-util"))]
            None => Some(UniqueName::from_static_str_unchecked(P2P_TEST_SENDER)),
            #[cfg(not(any(test, feature = "test-util")))]
            None => None,
        }
    }

    /// The caller's process, even when it never opened a session
    pub(crate) async fn peer_info(&self, sender: &UniqueName<'_>) -> Option<PeerInfo> {
        match self.session_from_sender(sender).await {
            Some(session) => session.peer_info().cloned(),
            None => PeerInfo::lookup(&self.connection(), sender).await,
        }
    }

    pub(crate) async fn session_from_sender(&self, sender: &UniqueName<'_>) -> Option<Session> {
        let sessions = self.sessions.lock().await;

        sessions.values().find(|s| s.sender() == sender).cloned()
    }

    pub async fn peer_display_name(&self, sender: &UniqueName<'_>) -> String {
        match self.session_from_sender(sender).await {
            Some(session) => match session.peer_info() {
                Some(info) => format!("{sender} ({info})"),
                None => sender.to_string(),
            },
            None => sender.to_string(),
        }
    }

    pub async fn session(&self, path: &ObjectPath<'_>) -> Option<Session> {
        let session = self.sessions.lock().await.get(path).cloned()?;
        session.unmark_stale().await;
        Some(session)
    }

    pub async fn remove_session(&self, path: &ObjectPath<'_>) {
        self.sessions.lock().await.remove(path);
    }

    pub async fn remove_collection(&self, path: &ObjectPath<'_>) {
        self.collections.lock().await.remove(path);

        if let Ok(signal_emitter) =
            self.signal_emitter(oo7::dbus::api::Service::PATH.as_deref().unwrap())
        {
            let _ = self.collections_changed(&signal_emitter).await;
        }
    }

    pub fn prompt_index(&self) -> u32 {
        self.prompt_index.fetch_add(1, Ordering::Relaxed)
    }

    pub async fn prompt(&self, path: &ObjectPath<'_>) -> Option<Prompt> {
        self.prompts.lock().await.get(path).cloned()
    }

    pub async fn remove_prompt(&self, path: &ObjectPath<'_>) {
        self.prompts.lock().await.remove(path);
        // Also clean up pending collection if it exists
        self.pending_collections.lock().await.remove(path);
    }

    pub async fn register_prompt(&self, path: OwnedObjectPath, prompt: Prompt) {
        self.prompts.lock().await.insert(path, prompt);
    }

    pub async fn pending_collection(
        &self,
        prompt_path: &ObjectPath<'_>,
    ) -> Option<(String, String)> {
        self.pending_collections
            .lock()
            .await
            .get(prompt_path)
            .cloned()
    }

    /// Build a new collection with a unique label/alias, register it on the
    /// object server, insert it into the collections map, and emit D-Bus
    /// signals.
    async fn register_collection(
        &self,
        name: &str,
        label: &str,
        alias: &str,
        keyring: Keyring,
    ) -> Result<(OwnedObjectPath, Collection), ServiceError> {
        let (unique_label, unique_alias) = {
            let collections = self.collections.lock().await;
            Self::make_unique_label_and_alias(&collections, label, alias).await
        };
        let collection =
            Collection::new(name, &unique_label, &unique_alias, self.clone(), keyring).await;
        let collection_path: OwnedObjectPath = collection.path().to_owned().into();

        self.object_server()
            .at(collection.path(), collection.clone())
            .await?;
        collection.serve_alias_path(&unique_alias).await;

        self.collections
            .lock()
            .await
            .insert(collection_path.clone(), collection.clone());

        let service_path = oo7::dbus::api::Service::PATH.as_ref().unwrap();
        let signal_emitter = self.signal_emitter(service_path)?;
        Service::collection_created(&signal_emitter, &collection_path).await?;
        self.collections_changed(&signal_emitter).await?;

        tracing::info!("Collection `{collection_path}` created with label '{label}'");

        Ok((collection_path, collection))
    }

    pub async fn create_collection_with_secret(
        &self,
        label: &str,
        alias: &str,
        secret: Option<Secret>,
    ) -> Result<OwnedObjectPath, ServiceError> {
        // Create a persistent keyring with the provided secret
        let keyring = UnlockedKeyring::open_at(&self.data_dir, &label.to_lowercase(), secret)
            .await
            .map_err(|err| custom_service_error(&format!("Failed to create keyring: {err}")))?;

        // Write the keyring file to disk immediately
        keyring
            .write()
            .await
            .map_err(|err| custom_service_error(&format!("Failed to write keyring file: {err}")))?;

        let name = label.to_lowercase();
        let (path, _) = self
            .register_collection(&name, label, alias, Keyring::Unlocked(keyring))
            .await?;
        Ok(path)
    }

    pub async fn complete_collection_creation(
        &self,
        prompt_path: &ObjectPath<'_>,
        secret: Option<Secret>,
    ) -> Result<OwnedObjectPath, ServiceError> {
        let Some((label, alias)) = self.pending_collection(prompt_path).await else {
            return Err(ServiceError::NoSuchObject(format!(
                "No pending collection for prompt `{prompt_path}`"
            )));
        };

        let collection_path = self
            .create_collection_with_secret(&label, &alias, secret)
            .await?;

        self.pending_collections.lock().await.remove(prompt_path);

        Ok(collection_path)
    }

    pub fn signal_emitter<'a, P>(
        &self,
        path: P,
    ) -> Result<zbus::object_server::SignalEmitter<'a>, oo7::dbus::ServiceError>
    where
        P: TryInto<ObjectPath<'a>>,
        P::Error: Into<zbus::Error>,
    {
        let signal_emitter = zbus::object_server::SignalEmitter::new(&self.connection(), path)?;

        Ok(signal_emitter)
    }

    async fn collection_for_objects(&self, objects: &[OwnedObjectPath]) -> Option<Collection> {
        for object in objects {
            if let Some(collection) = self.collection_from_path(object).await {
                return Some(collection);
            }
        }

        // Fall back to the parent path of the first item
        let parent = objects.first()?.as_str().rsplit_once('/')?.0;
        self.collection_from_path(&ObjectPath::try_from(parent).ok()?)
            .await
    }

    /// Attempt to migrate pending keyrings with the provided secret
    /// Returns a list of successfully migrated keyring names
    pub async fn migrate_pending_keyrings(&self, secret: &Secret) -> Vec<String> {
        let mut migrated = Vec::new();
        let mut pending = self.pending_migrations.lock().await;
        let mut to_remove = Vec::new();

        for (name, migration) in pending.iter() {
            tracing::debug!("Attempting to migrate pending keyring: {name}");

            match migration.migrate(&self.data_dir, Some(secret)).await {
                Ok(unlocked) => {
                    // Look for the placeholder collection that was registered
                    // at startup.
                    let placeholder = {
                        let collections = self.collections.lock().await;
                        collections.values().find(|c| c.name() == name).cloned()
                    };

                    if let Some(collection) = placeholder {
                        *collection.keyring.write().await = Some(Keyring::Unlocked(unlocked));

                        if let Err(e) = collection.dispatch_items().await {
                            tracing::error!(
                                "Failed to dispatch items for migrated keyring '{name}': {e}",
                            );
                            continue;
                        }

                        if let Ok(signal_emitter) =
                            self.signal_emitter(oo7::dbus::api::Service::PATH.as_ref().unwrap())
                        {
                            let _ = self.collections_changed(&signal_emitter).await;
                        }

                        tracing::info!(
                            "Replaced placeholder for keyring '{name}' with migrated data",
                        );
                    } else {
                        let label = migration.label();
                        let alias = migration.alias();

                        let collection = match self
                            .register_collection(name, label, alias, Keyring::Unlocked(unlocked))
                            .await
                        {
                            Ok((_, collection)) => collection,
                            Err(e) => {
                                tracing::error!(
                                    "Failed to register migrated collection '{name}': {e}",
                                );
                                continue;
                            }
                        };

                        if let Err(e) = collection.dispatch_items().await {
                            tracing::error!(
                                "Failed to dispatch items for migrated collection '{name}': {e}",
                            );
                        }
                    }

                    migrated.push(name.clone());
                    to_remove.push(name.clone());
                }
                Err(e) => {
                    tracing::debug!(
                        "Failed to migrate keyring '{name}' found at {} with provided secret: {e}",
                        migration.path().display()
                    );
                }
            }
        }

        for name in &to_remove {
            pending.remove(name);
        }

        migrated
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unencrypted_tests;
