// org.freedesktop.Secret.Service

use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};

use oo7::{
    Key, Secret,
    dbus::{
        Algorithm, ServiceError,
        api::{DBusSecretInner, Properties},
    },
    file::{Keyring, LockedKeyring, UnlockedKeyring},
};
use tokio::sync::{Mutex, RwLock};
use tokio_stream::StreamExt;
use zbus::{
    names::UniqueName,
    object_server::SignalEmitter,
    proxy::Defaults,
    zvariant::{ObjectPath, Optional, OwnedObjectPath, OwnedValue, Value},
};

use crate::{
    collection::Collection,
    error::{Error, custom_service_error},
    prompt::{Prompt, PromptAction, PromptRole},
    session::Session,
};

const DEFAULT_COLLECTION_ALIAS_PATH: ObjectPath<'static> =
    ObjectPath::from_static_str_unchecked("/org/freedesktop/secrets/aliases/default");

#[derive(Debug, Default, Clone)]
pub struct Service {
    // Properties
    pub(crate) collections: Arc<Mutex<HashMap<OwnedObjectPath, Collection>>>,
    // Other attributes
    connection: Arc<OnceLock<zbus::Connection>>,
    // sessions mapped to their corresponding object path on the bus
    sessions: Arc<Mutex<HashMap<OwnedObjectPath, Session>>>,
    session_index: Arc<RwLock<u32>>,
    // prompts mapped to their corresponding object path on the bus
    prompts: Arc<Mutex<HashMap<OwnedObjectPath, Prompt>>>,
    prompt_index: Arc<RwLock<u32>>,
    // pending collection creations: prompt_path -> (label, alias)
    pending_collections: Arc<Mutex<HashMap<OwnedObjectPath, (String, String)>>>,
    // pending v0 keyring migrations: name -> (path, label, alias)
    #[allow(clippy::type_complexity)]
    pub(crate) pending_migrations:
        Arc<Mutex<HashMap<String, (std::path::PathBuf, String, String)>>>,
}

#[zbus::interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    #[zbus(out_args("output", "result"))]
    pub async fn open_session(
        &self,
        algorithm: Algorithm,
        input: Value<'_>,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<(OwnedValue, OwnedObjectPath), ServiceError> {
        let (public_key, aes_key) = match algorithm {
            Algorithm::Plain => (None, None),
            Algorithm::Encrypted => {
                let client_public_key = Key::try_from(input).map_err(|err| {
                    custom_service_error(&format!(
                        "Input Value could not be converted into a Key {err}."
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

        let sender = if let Some(s) = header.sender() {
            s.to_owned()
        } else {
            #[cfg(test)]
            {
                // For p2p test connections, use a dummy sender since p2p connections
                // don't have a bus to assign unique names
                UniqueName::try_from(":p2p.test").unwrap().into()
            }
            #[cfg(not(test))]
            {
                return Err(custom_service_error("Failed to get sender from header."));
            }
        };

        tracing::info!("Client {} connected", sender);

        let session = Session::new(aes_key.map(Arc::new), self.clone(), sender).await;
        let path = OwnedObjectPath::from(session.path().clone());

        self.sessions
            .lock()
            .await
            .insert(path.clone(), session.clone());

        object_server.at(&path, session).await?;

        let service_key = public_key
            .map(OwnedValue::from)
            .unwrap_or_else(|| Value::new::<Vec<u8>>(vec![]).try_into_owned().unwrap());

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
        let action = PromptAction::new(move |secret: Secret| async move {
            let collection_path = service
                .complete_collection_creation(&creation_prompt_path, secret)
                .await?;

            Ok(Value::new(collection_path).try_into_owned().unwrap())
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
        let collections = self.collections.lock().await;

        for (_path, collection) in collections.iter() {
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
        let (unlocked, not_unlocked) = self.set_locked(false, &objects).await?;
        if !not_unlocked.is_empty() {
            // Extract the label and collection before creating the prompt
            let label = self.extract_label_from_objects(&not_unlocked).await;
            let collection = self.extract_collection_from_objects(&not_unlocked).await;

            let prompt = Prompt::new(self.clone(), PromptRole::Unlock, label, collection).await;
            let path = OwnedObjectPath::from(prompt.path().clone());

            // Create the unlock action
            let service = self.clone();
            let action = PromptAction::new(move |secret: Secret| async move {
                // The prompter will handle secret validation
                // Here we just perform the unlock operation
                let collections = service.collections.lock().await;
                for object in &not_unlocked {
                    // Try to find as collection first
                    if let Some(collection) = collections.get(object) {
                        let _ = collection.set_locked(false, Some(secret.clone())).await;
                    } else {
                        // Try to find as item within collections
                        for (_path, collection) in collections.iter() {
                            if let Some(item) = collection.item_from_path(object).await {
                                // If the collection is locked, unlock it
                                if collection.is_locked().await {
                                    let _ =
                                        collection.set_locked(false, Some(secret.clone())).await;
                                } else {
                                    // Collection is already unlocked, just unlock the item
                                    let keyring = collection.keyring.read().await;
                                    let _ = item
                                        .set_locked(false, keyring.as_ref().unwrap().as_unlocked())
                                        .await;
                                }
                                break;
                            }
                        }
                    }
                }
                Ok(Value::new(not_unlocked).try_into_owned().unwrap())
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
        // set_locked now handles locking directly (without prompts)
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
        let mut secrets = HashMap::new();
        let collections = self.collections.lock().await;

        'outer: for (_path, collection) in collections.iter() {
            for item in &items {
                if let Some(item) = collection.item_from_path(item).await {
                    match item.get_secret(session.clone()).await {
                        Ok((secret,)) => {
                            secrets.insert(item.path().clone().into(), secret);
                            // To avoid iterating through all the remaining collections, if the
                            // items secrets are already retrieved.
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

    pub async fn run(secret: Option<Secret>, request_replacement: bool) -> Result<(), Error> {
        let service = Self::default();

        let connection = zbus::connection::Builder::session()?
            .allow_name_replacements(true)
            .replace_existing_names(request_replacement)
            .name(oo7::dbus::api::Service::DESTINATION.as_deref().unwrap())?
            .serve_at(
                oo7::dbus::api::Service::PATH.as_deref().unwrap(),
                service.clone(),
            )?
            .build()
            .await?;

        // Discover existing keyrings
        let discovered_keyrings = service.discover_keyrings(secret).await?;

        service
            .initialize(connection, discovered_keyrings, true)
            .await?;

        // Start PAM listener
        tracing::info!("Starting PAM listener");
        let pam_listener = crate::pam_listener::PamListener::new(service.clone());
        tokio::spawn(async move {
            if let Err(e) = pam_listener.start().await {
                tracing::error!("PAM listener error: {}", e);
            }
        });

        Ok(())
    }

    #[cfg(test)]
    pub async fn run_with_connection(
        connection: zbus::Connection,
        secret: Option<Secret>,
    ) -> Result<Self, Error> {
        let service = Self::default();

        // Serve the service at the standard path
        connection
            .object_server()
            .at(
                oo7::dbus::api::Service::PATH.as_deref().unwrap(),
                service.clone(),
            )
            .await?;

        let default_keyring = if let Some(secret) = secret {
            vec![(
                "Login".to_owned(),
                oo7::dbus::Service::DEFAULT_COLLECTION.to_owned(),
                Keyring::Unlocked(UnlockedKeyring::temporary(secret).await?),
            )]
        } else {
            vec![]
        };

        service
            .initialize(connection, default_keyring, false)
            .await?;
        Ok(service)
    }

    /// Discover existing keyrings in the data directory
    /// Returns a vector of (label, alias, keyring) tuples
    pub(crate) async fn discover_keyrings(
        &self,
        secret: Option<Secret>,
    ) -> Result<Vec<(String, String, Keyring)>, Error> {
        let mut discovered = Vec::new();

        // Get data directory using the same logic as oo7::file::api::data_dir()
        let data_dir = std::env::var_os("XDG_DATA_HOME")
            .and_then(|h| if h.is_empty() { None } else { Some(h) })
            .map(std::path::PathBuf::from)
            .and_then(|p| if p.is_absolute() { Some(p) } else { None })
            .or_else(|| {
                std::env::var_os("HOME")
                    .and_then(|h| if h.is_empty() { None } else { Some(h) })
                    .map(std::path::PathBuf::from)
                    .map(|p| p.join(".local/share"))
            });

        let Some(data_dir) = data_dir else {
            tracing::warn!("No data directory found, skipping keyring discovery");
            return Ok(discovered);
        };

        let keyrings_dir = data_dir.join("keyrings");

        // Scan for v1 keyrings first
        let v1_dir = keyrings_dir.join("v1");
        if v1_dir.exists() {
            tracing::debug!("Scanning for v1 keyrings in {}", v1_dir.display());
            if let Ok(mut entries) = tokio::fs::read_dir(&v1_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();

                    // Skip directories and non-.keyring files
                    if path.is_dir() || path.extension() != Some(std::ffi::OsStr::new("keyring")) {
                        continue;
                    }

                    if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                        tracing::debug!("Found v1 keyring: {name}");

                        // Try to load the keyring
                        match self.load_keyring(&path, name, secret.as_ref()).await {
                            Ok((label, alias, keyring)) => discovered.push((label, alias, keyring)),
                            Err(e) => tracing::warn!("Failed to load keyring {:?}: {}", path, e),
                        }
                    }
                }
            }
        }

        // Scan for v0 keyrings
        if keyrings_dir.exists() {
            tracing::debug!("Scanning for v0 keyrings in {}", keyrings_dir.display());
            if let Ok(mut entries) = tokio::fs::read_dir(&keyrings_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();

                    // Skip directories and non-.keyring files
                    if path.is_dir() || path.extension() != Some(std::ffi::OsStr::new("keyring")) {
                        continue;
                    }

                    if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                        tracing::debug!("Found v0 keyring: {name}");

                        // Try to load the keyring
                        match self.load_keyring(&path, name, secret.as_ref()).await {
                            Ok((label, alias, keyring)) => discovered.push((label, alias, keyring)),
                            Err(e) => tracing::warn!("Failed to load keyring {:?}: {}", path, e),
                        }
                    }
                }
            }
        }

        let pending_count = self.pending_migrations.lock().await.len();

        if discovered.is_empty() && pending_count == 0 {
            tracing::info!("No keyrings discovered in data directory");
        } else {
            tracing::info!(
                "Discovered {} keyring(s), {} pending v0 migration(s)",
                discovered.len(),
                pending_count
            );
        }

        Ok(discovered)
    }

    /// Load a single keyring from a file path
    /// Returns (label, alias, keyring)
    async fn load_keyring(
        &self,
        path: &std::path::Path,
        name: &str,
        secret: Option<&Secret>,
    ) -> Result<(String, String, Keyring), Error> {
        let alias = if name.eq_ignore_ascii_case(Self::LOGIN_ALIAS) {
            oo7::dbus::Service::DEFAULT_COLLECTION.to_owned()
        } else {
            name.to_owned().to_lowercase()
        };

        // Use name as label (capitalized for consistency with Login)
        let label = {
            let mut chars = name.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        };

        // Try to load the keyring
        let keyring = match LockedKeyring::load(path).await {
            Ok(locked_keyring) => {
                // Successfully loaded as v1 keyring
                if let Some(secret) = secret {
                    match locked_keyring.unlock(secret.clone()).await {
                        Ok(unlocked) => {
                            tracing::info!("Unlocked keyring '{}' from {:?}", name, path);
                            Keyring::Unlocked(unlocked)
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to unlock keyring '{}' with provided secret: {}. Keeping it locked.",
                                name,
                                e
                            );
                            // Reload as locked since unlock consumed it
                            Keyring::Locked(LockedKeyring::load(path).await?)
                        }
                    }
                } else {
                    tracing::debug!("No secret provided, keeping keyring '{}' locked", name);
                    Keyring::Locked(locked_keyring)
                }
            }
            Err(oo7::file::Error::VersionMismatch(Some(version)))
                if version.first() == Some(&0) =>
            // v0 is the legacy version
            {
                // This is a v0 keyring that needs migration
                tracing::info!(
                    "Found legacy v0 keyring '{name}' at {}, registering for migration",
                    path.display()
                );

                if let Some(secret) = secret {
                    tracing::debug!("Attempting immediate migration of v0 keyring '{name}'",);
                    match UnlockedKeyring::open(name, secret.clone()).await {
                        Ok(unlocked) => {
                            tracing::info!("Successfully migrated v0 keyring '{name}' to v1",);

                            // Write the migrated keyring to disk
                            unlocked.write().await?;
                            tracing::info!("Wrote migrated keyring '{name}' to disk");

                            // Remove the v0 keyring file after successful migration
                            if let Err(e) = tokio::fs::remove_file(path).await {
                                tracing::warn!(
                                    "Failed to remove v0 keyring at {}: {e}",
                                    path.display()
                                );
                            } else {
                                tracing::info!("Removed v0 keyring file at {}", path.display());
                            }

                            Keyring::Unlocked(unlocked)
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to migrate v0 keyring '{name}': {e}. Will retry when secret is available.",
                            );
                            self.pending_migrations.lock().await.insert(
                                name.to_owned(),
                                (path.to_path_buf(), label.clone(), alias.clone()),
                            );
                            return Err(e.into());
                        }
                    }
                } else {
                    tracing::debug!(
                        "No secret available for v0 keyring '{}', registering for pending migration",
                        name
                    );
                    self.pending_migrations.lock().await.insert(
                        name.to_owned(),
                        (path.to_path_buf(), label.clone(), alias.clone()),
                    );
                    return Err(Error::IO(std::io::Error::other(
                        "v0 keyring requires migration, no secret available",
                    )));
                }
            }
            Err(e) => {
                return Err(e.into());
            }
        };

        Ok((label, alias, keyring))
    }

    /// Initialize the service with collections and start client disconnect
    /// handler
    pub(crate) async fn initialize(
        &self,
        connection: zbus::Connection,
        mut discovered_keyrings: Vec<(String, String, Keyring)>, // (name, alias, keyring)
        auto_create_default: bool,
    ) -> Result<(), Error> {
        self.connection.set(connection.clone()).unwrap();

        let object_server = connection.object_server();
        let mut collections = self.collections.lock().await;

        // Check if we have a default collection
        let has_default = discovered_keyrings.iter().any(|(_, alias, _)| {
            alias == oo7::dbus::Service::DEFAULT_COLLECTION || alias == Self::LOGIN_ALIAS
        });

        if !has_default && auto_create_default {
            tracing::info!("No default collection found, creating 'Login' keyring");

            let locked_keyring = LockedKeyring::open(Self::LOGIN_ALIAS)
                .await
                .inspect_err(|e| {
                    tracing::error!("Failed to create default Login keyring: {}", e);
                })?;

            discovered_keyrings.push((
                "Login".to_owned(),
                oo7::dbus::Service::DEFAULT_COLLECTION.to_owned(),
                Keyring::Locked(locked_keyring),
            ));

            tracing::info!("Created default 'Login' collection (locked)");
        }

        // Set up discovered collections
        for (label, alias, keyring) in discovered_keyrings {
            let collection = Collection::new(&label, &alias, self.clone(), keyring).await;
            collections.insert(collection.path().to_owned().into(), collection.clone());
            collection.dispatch_items().await?;
            object_server
                .at(collection.path(), collection.clone())
                .await?;

            // If this is the default collection, also register it at the alias path
            if alias == oo7::dbus::Service::DEFAULT_COLLECTION {
                object_server
                    .at(DEFAULT_COLLECTION_ALIAS_PATH, collection)
                    .await?;
            }
        }

        // Always create session collection (always temporary)
        let collection = Collection::new(
            "session",
            oo7::dbus::Service::SESSION_COLLECTION,
            self.clone(),
            Keyring::Unlocked(UnlockedKeyring::temporary(Secret::random().unwrap()).await?),
        )
        .await;
        object_server
            .at(collection.path(), collection.clone())
            .await?;
        collections.insert(collection.path().to_owned().into(), collection);

        drop(collections); // Release the lock

        // Spawn client disconnect handler
        let service = self.clone();
        tokio::spawn(async move { service.on_client_disconnect().await });

        Ok(())
    }

    async fn on_client_disconnect(&self) -> zbus::Result<()> {
        let rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender("org.freedesktop.DBus")?
            .interface("org.freedesktop.DBus")?
            .member("NameOwnerChanged")?
            .arg(2, "")?
            .build();
        let mut stream = zbus::MessageStream::for_match_rule(rule, self.connection(), None).await?;
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
                match session.close().await {
                    Ok(_) => tracing::info!(
                        "Client {} disconnected. Session: {} closed.",
                        old_owner,
                        session.path()
                    ),
                    Err(err) => tracing::error!("Failed to close session: {}", err),
                }
            }
        }
        Ok(())
    }

    pub async fn set_locked(
        &self,
        locked: bool,
        objects: &[OwnedObjectPath],
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), ServiceError> {
        let mut without_prompt = Vec::new();
        let mut with_prompt = Vec::new();
        let collections = self.collections.lock().await;

        for object in objects {
            for (path, collection) in collections.iter() {
                let collection_locked = collection.is_locked().await;
                if *object == *path {
                    if collection_locked == locked {
                        tracing::debug!(
                            "Collection: {} is already {}.",
                            object,
                            if locked { "locked" } else { "unlocked" }
                        );
                        without_prompt.push(object.clone());
                    } else if locked {
                        // Locking never requires a prompt
                        collection.set_locked(true, None).await?;
                        without_prompt.push(object.clone());
                    } else {
                        // Unlocking may require a prompt
                        with_prompt.push(object.clone());
                    }
                    break;
                } else if let Some(item) = collection.item_from_path(object).await {
                    if locked == item.is_locked().await {
                        tracing::debug!(
                            "Item: {} is already {}.",
                            object,
                            if locked { "locked" } else { "unlocked" }
                        );
                        without_prompt.push(object.clone());
                    // If the collection is unlocked, we can lock/unlock the
                    // item directly
                    } else if !collection_locked {
                        let keyring = collection.keyring.read().await;
                        item.set_locked(locked, keyring.as_ref().unwrap().as_unlocked())
                            .await?;
                        without_prompt.push(object.clone());
                    } else {
                        // Collection is locked, unlocking the item requires unlocking the
                        // collection
                        with_prompt.push(object.clone());
                    }
                    break;
                }
                tracing::warn!("Object: {} does not exist.", object);
            }
        }

        Ok((without_prompt, with_prompt))
    }

    pub fn connection(&self) -> &zbus::Connection {
        self.connection.get().unwrap()
    }

    pub fn object_server(&self) -> &zbus::ObjectServer {
        self.connection().object_server()
    }

    pub async fn collection_from_path(&self, path: &ObjectPath<'_>) -> Option<Collection> {
        let collections = self.collections.lock().await;
        collections.get(path).cloned()
    }

    pub async fn session_index(&self) -> u32 {
        let n_sessions = *self.session_index.read().await + 1;
        *self.session_index.write().await = n_sessions;

        n_sessions
    }

    async fn session_from_sender(&self, sender: &UniqueName<'_>) -> Option<Session> {
        let sessions = self.sessions.lock().await;

        sessions.values().find(|s| s.sender() == sender).cloned()
    }

    pub async fn session(&self, path: &ObjectPath<'_>) -> Option<Session> {
        self.sessions.lock().await.get(path).cloned()
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

    pub async fn prompt_index(&self) -> u32 {
        let n_prompts = *self.prompt_index.read().await + 1;
        *self.prompt_index.write().await = n_prompts;

        n_prompts
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

    pub async fn complete_collection_creation(
        &self,
        prompt_path: &ObjectPath<'_>,
        secret: Secret,
    ) -> Result<OwnedObjectPath, ServiceError> {
        // Retrieve the pending collection metadata
        let Some((label, alias)) = self.pending_collection(prompt_path).await else {
            return Err(ServiceError::NoSuchObject(format!(
                "No pending collection for prompt `{prompt_path}`"
            )));
        };

        // Create a persistent keyring with the provided secret
        let keyring = UnlockedKeyring::open(&label.to_lowercase(), secret)
            .await
            .map_err(|err| custom_service_error(&format!("Failed to create keyring: {err}")))?;

        // Write the keyring file to disk immediately
        keyring
            .write()
            .await
            .map_err(|err| custom_service_error(&format!("Failed to write keyring file: {err}")))?;

        let keyring = Keyring::Unlocked(keyring);

        // Create the collection
        let collection = Collection::new(&label, &alias, self.clone(), keyring).await;
        let collection_path: OwnedObjectPath = collection.path().to_owned().into();

        // Register with object server
        self.object_server()
            .at(collection.path(), collection.clone())
            .await?;

        // Add to collections
        self.collections
            .lock()
            .await
            .insert(collection_path.clone(), collection);

        // Clean up pending collection
        self.pending_collections.lock().await.remove(prompt_path);

        // Emit CollectionCreated signal
        let service_path = oo7::dbus::api::Service::PATH.as_ref().unwrap();
        let signal_emitter = self.signal_emitter(service_path)?;
        Service::collection_created(&signal_emitter, &collection_path).await?;

        // Emit PropertiesChanged for Collections property to invalidate client cache
        self.collections_changed(&signal_emitter).await?;

        tracing::info!(
            "Collection `{}` created with label '{}'",
            collection_path,
            label
        );

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
        let signal_emitter = zbus::object_server::SignalEmitter::new(self.connection(), path)?;

        Ok(signal_emitter)
    }

    /// Extract the collection label from a list of object paths
    /// The objects can be either collections or items
    async fn extract_label_from_objects(&self, objects: &[OwnedObjectPath]) -> String {
        if objects.is_empty() {
            return String::new();
        }

        // Check if at least one of the objects is a Collection
        for object in objects {
            if let Some(collection) = self.collection_from_path(object).await {
                return collection.label().await;
            }
        }

        // Get the collection path from the first item
        // assumes all items are from the same collection
        if let Some(path_str) = objects.first().and_then(|p| p.as_str().rsplit_once('/')) {
            let collection_path = path_str.0;
            if let Ok(obj_path) = ObjectPath::try_from(collection_path)
                && let Some(collection) = self.collection_from_path(&obj_path).await
            {
                return collection.label().await;
            }
        }

        String::new()
    }

    /// Extract the collection from a list of object paths
    /// The objects can be either collections or items
    async fn extract_collection_from_objects(
        &self,
        objects: &[OwnedObjectPath],
    ) -> Option<Collection> {
        if objects.is_empty() {
            return None;
        }

        // Check if at least one of the objects is a Collection
        for object in objects {
            if let Some(collection) = self.collection_from_path(object).await {
                return Some(collection);
            }
        }

        // Get the collection path from the first item
        // (assumes all items are from the same collection)
        let path = objects
            .first()
            .unwrap()
            .as_str()
            .rsplit_once('/')
            .map(|(parent, _)| parent)?;
        self.collection_from_path(&ObjectPath::try_from(path).unwrap())
            .await
    }

    /// Attempt to migrate pending v0 keyrings with the provided secret
    /// Returns a list of successfully migrated keyring names
    pub async fn migrate_pending_keyrings(&self, secret: &Secret) -> Vec<String> {
        let mut migrated = Vec::new();
        let mut pending = self.pending_migrations.lock().await;
        let mut to_remove = Vec::new();

        for (name, (path, label, alias)) in pending.iter() {
            tracing::debug!("Attempting to migrate pending v0 keyring: {}", name);

            match UnlockedKeyring::open(name, secret.clone()).await {
                Ok(unlocked) => {
                    tracing::info!("Successfully migrated v0 keyring '{}' to v1", name);

                    // Write the migrated keyring to disk
                    match unlocked.write().await {
                        Ok(_) => {
                            tracing::info!("Wrote migrated keyring '{}' to disk", name);

                            // Remove the v0 keyring file after successful migration
                            if let Err(e) = tokio::fs::remove_file(path).await {
                                tracing::warn!("Failed to remove v0 keyring at {:?}: {}", path, e);
                            } else {
                                tracing::info!("Removed v0 keyring file at {:?}", path);
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                "Failed to write migrated keyring '{}' to disk: {}",
                                name,
                                e
                            );
                            continue;
                        }
                    }

                    // Create a collection for this migrated keyring
                    let keyring = Keyring::Unlocked(unlocked);
                    let collection = Collection::new(label, alias, self.clone(), keyring).await;
                    let collection_path: OwnedObjectPath = collection.path().to_owned().into();

                    // Dispatch items
                    if let Err(e) = collection.dispatch_items().await {
                        tracing::error!(
                            "Failed to dispatch items for migrated keyring '{}': {}",
                            name,
                            e
                        );
                        continue;
                    }

                    if let Err(e) = self
                        .object_server()
                        .at(collection.path(), collection.clone())
                        .await
                    {
                        tracing::error!(
                            "Failed to register migrated collection '{}' with object server: {}",
                            name,
                            e
                        );
                        continue;
                    }

                    self.collections
                        .lock()
                        .await
                        .insert(collection_path.clone(), collection.clone());

                    if alias == oo7::dbus::Service::DEFAULT_COLLECTION
                        && let Err(e) = self
                            .object_server()
                            .at(DEFAULT_COLLECTION_ALIAS_PATH, collection)
                            .await
                    {
                        tracing::error!(
                            "Failed to register default alias for migrated collection '{}': {}",
                            name,
                            e
                        );
                    }

                    if let Ok(signal_emitter) =
                        self.signal_emitter(oo7::dbus::api::Service::PATH.as_ref().unwrap())
                    {
                        let _ =
                            Service::collection_created(&signal_emitter, &collection_path).await;
                        let _ = self.collections_changed(&signal_emitter).await;
                    }

                    tracing::info!("Migrated keyring '{}' added as collection", name);
                    migrated.push(name.clone());
                    to_remove.push(name.clone());
                }
                Err(e) => {
                    tracing::debug!(
                        "Failed to migrate v0 keyring '{}' with provided secret: {}",
                        name,
                        e
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
