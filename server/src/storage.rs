//! File-backed storage used by daemon collections.

use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, OnceLock},
    time::Duration,
};

use oo7::{AsAttributes, Key, Secret, file};

pub(crate) enum Keyring {
    V1(file::Keyring),
}

impl Keyring {
    pub async fn open(
        data_dir: &Path,
        name: &str,
        secret: Option<Secret>,
    ) -> Result<Self, file::Error> {
        let keyring = file::UnlockedKeyring::open_at(data_dir, name, secret).await?;
        Ok(Self::V1(keyring.into()))
    }

    pub async fn open_locked(data_dir: &Path, name: &str) -> Result<Self, file::Error> {
        let keyring = file::LockedKeyring::open_at(data_dir, name).await?;
        Ok(Self::V1(keyring.into()))
    }

    pub async fn load_locked(path: &Path) -> Result<Self, file::Error> {
        let keyring = file::LockedKeyring::load(path).await?;
        Ok(Self::V1(keyring.into()))
    }

    pub async fn temporary(secret: Secret) -> Result<Self, file::Error> {
        let keyring = file::UnlockedKeyring::temporary(secret).await?;
        Ok(Self::V1(keyring.into()))
    }

    pub async fn write(&self) -> Result<(), file::Error> {
        self.unlocked_v1()?.write().await
    }

    #[cfg(feature = "kwallet_migration")]
    pub async fn create_items(&self, items: Vec<file::ItemDefinition>) -> Result<(), file::Error> {
        self.unlocked_v1()?.create_items(items).await
    }

    pub fn is_locked(&self) -> bool {
        match self {
            Self::V1(keyring) => keyring.is_locked(),
        }
    }

    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::V1(keyring) => keyring.path(),
        }
    }

    pub async fn timestamps(&self) -> (Duration, Duration) {
        match self {
            Self::V1(keyring) => {
                let modified = keyring.modified_time().await;
                (keyring.created_time().await.unwrap_or(modified), modified)
            }
        }
    }

    pub async fn validate_secret(&self, secret: &Secret) -> Result<bool, file::Error> {
        match self {
            Self::V1(keyring) => keyring.validate_secret(secret).await,
        }
    }

    pub async fn validate_unencrypted(&self) -> Result<bool, file::Error> {
        match self {
            Self::V1(keyring) => keyring.validate_unencrypted().await,
        }
    }

    pub async fn items(&self) -> Result<Vec<Record>, file::Error> {
        match self {
            Self::V1(keyring) => Ok(keyring
                .items()
                .await?
                .into_iter()
                .map(Record::from)
                .collect()),
        }
    }

    pub async fn query<'a>(
        &self,
        attributes: &'a HashMap<String, String>,
        exact: bool,
    ) -> Result<ItemQuery<'a>, oo7::crypto::Error> {
        match self {
            Self::V1(keyring) => ItemQuery::new(keyring, attributes, exact).await,
        }
    }

    pub fn lock(self) -> Self {
        match self {
            Self::V1(file::Keyring::Unlocked(keyring)) => Self::V1(keyring.lock().into()),
            locked => locked,
        }
    }

    /// Try the supplied credential while keeping the locked keyring available
    /// for retry.
    pub async fn try_unlock(&self, secret: Option<Secret>) -> Result<Self, file::Error> {
        match self {
            Self::V1(keyring) => {
                let locked = keyring.as_locked();
                let unlocked = match secret {
                    Some(secret) => locked.try_unlock(secret).await?,
                    None => locked.try_unlock_unencrypted().await?,
                };
                Ok(Self::V1(unlocked.into()))
            }
        }
    }

    fn unlocked_v1(&self) -> Result<&file::UnlockedKeyring, file::Error> {
        match self {
            Self::V1(file::Keyring::Unlocked(keyring)) => Ok(keyring),
            Self::V1(file::Keyring::Locked(_)) => Err(file::Error::Locked),
        }
    }

    pub async fn change_secret(&self, secret: Secret) -> Result<(), file::Error> {
        self.unlocked_v1()?.change_secret(secret).await
    }

    pub async fn create_item(
        &self,
        label: &str,
        attributes: &impl AsAttributes,
        secret: impl Into<Secret>,
        replace: bool,
    ) -> Result<Record, file::Error> {
        self.unlocked_v1()?
            .create_item(label, attributes, secret, replace)
            .await
            .map(Record::from)
    }

    pub async fn delete(&self, attributes: &impl AsAttributes) -> Result<(), file::Error> {
        self.unlocked_v1()?.delete(attributes).await
    }
}

/// A search or replacement can check every cached record with the same file
/// key.
pub(crate) struct ItemQuery<'a> {
    attributes: &'a HashMap<String, String>,
    v0_attributes: OnceLock<HashMap<String, String>>,
    key: Option<Arc<Key>>,
    exact: bool,
}

impl<'a> ItemQuery<'a> {
    async fn new(
        keyring: &file::Keyring,
        attributes: &'a HashMap<String, String>,
        exact: bool,
    ) -> Result<Self, oo7::crypto::Error> {
        let key = match keyring {
            file::Keyring::Unlocked(keyring) => keyring.key().await?,
            file::Keyring::Locked(_) => None,
        };
        Ok(Self {
            attributes,
            v0_attributes: OnceLock::new(),
            key,
            exact,
        })
    }
}

/// The cached storage record for a registered D-Bus item.
pub(crate) struct Record {
    item: file::Item,
    v0_placeholder: bool,
}

impl From<file::Item> for Record {
    fn from(item: file::Item) -> Self {
        Self {
            item,
            v0_placeholder: false,
        }
    }
}

impl From<file::UnlockedItem> for Record {
    fn from(item: file::UnlockedItem) -> Self {
        Self::from(file::Item::from(item))
    }
}

impl Record {
    pub fn from_v0(item: file::Item) -> Self {
        Self {
            v0_placeholder: item.is_locked(),
            item,
        }
    }

    pub fn matches(&self, query: &ItemQuery<'_>) -> bool {
        let (attributes, key) = if self.v0_placeholder {
            // Encrypted V0 placeholders expose MD5 digests. An absent schema
            // is matched by the file reader using the generic schema name.
            let attributes = query.v0_attributes.get_or_init(|| {
                query
                    .attributes
                    .iter()
                    .map(|(name, value)| {
                        let value =
                            if name == oo7::XDG_SCHEMA_ATTRIBUTE && value == oo7::GENERIC_SCHEMA {
                                value.clone()
                            } else {
                                oo7::crypto::md5_hex(value)
                            };
                        (name.clone(), value)
                    })
                    .collect()
            });
            (attributes, None)
        } else {
            (query.attributes, query.key.as_deref())
        };
        if query.exact {
            self.item.matches_attributes_exact(attributes, key)
        } else {
            self.item.matches_attributes(attributes, key)
        }
    }

    pub fn is_locked(&self) -> bool {
        self.item.is_locked()
    }

    pub fn unlocked(&self) -> &file::UnlockedItem {
        self.item.as_unlocked()
    }

    pub async fn with_lock_state(
        &self,
        locked: bool,
        keyring: &Keyring,
    ) -> Result<Option<Self>, file::Error> {
        let keyring = keyring.unlocked_v1()?;
        let item = match (&self.item, locked) {
            (file::Item::Unlocked(item), true) => {
                file::Item::Locked(keyring.lock_item(item.clone()).await?)
            }
            (file::Item::Locked(item), false) => {
                file::Item::Unlocked(keyring.unlock_item(item.clone()).await?)
            }
            _ => return Ok(None),
        };
        Ok(Some(Self::from(item)))
    }

    /// The caller holds the collection's write lock so the index stays valid.
    /// Match the whole record since other items can share its attributes.
    pub async fn replace(&mut self, keyring: &Keyring, new: Record) -> Result<bool, file::Error> {
        let keyring = keyring.unlocked_v1()?;
        let index = keyring
            .all_items()
            .await?
            .iter()
            .position(|entry| entry.as_ref().is_ok_and(|item| item == self.unlocked()));
        let Some(index) = index else { return Ok(false) };
        keyring.replace_item_index(index, new.unlocked()).await?;
        *self = new;
        Ok(true)
    }
}
