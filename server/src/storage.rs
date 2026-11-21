//! File-backed storage used by daemon collections.

use std::{borrow::Cow, collections::HashMap, path::Path, sync::Arc, time::Duration};

use oo7::{AsAttributes, Key, Secret, file};

use crate::migration;

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

/// Match cached records without deriving the file key for each item.
pub(crate) struct ItemQuery<'a> {
    attributes: Cow<'a, HashMap<String, String>>,
    key: Option<Arc<Key>>,
    exact: bool,
}

impl<'a> ItemQuery<'a> {
    async fn new(
        keyring: &file::Keyring,
        attributes: &'a HashMap<String, String>,
        exact: bool,
    ) -> Result<Self, oo7::crypto::Error> {
        let (attributes, key) = match keyring {
            file::Keyring::Unlocked(keyring) => (Cow::Borrowed(attributes), keyring.key().await?),
            file::Keyring::Locked(_) => (
                Cow::Owned(migration::placeholder_attributes(attributes)),
                None,
            ),
        };
        Ok(Self {
            attributes,
            key,
            exact,
        })
    }

    pub fn matches(&self, record: &Record) -> bool {
        if self.exact {
            record
                .0
                .matches_attributes_exact(self.attributes.as_ref(), self.key.as_deref())
        } else {
            record
                .0
                .matches_attributes(self.attributes.as_ref(), self.key.as_deref())
        }
    }
}

/// The cached storage record for a registered D-Bus item.
pub(crate) struct Record(file::Item);

impl From<file::Item> for Record {
    fn from(item: file::Item) -> Self {
        Self(item)
    }
}

impl From<file::UnlockedItem> for Record {
    fn from(item: file::UnlockedItem) -> Self {
        Self(item.into())
    }
}

impl Record {
    pub fn is_locked(&self) -> bool {
        self.0.is_locked()
    }

    pub fn unlocked(&self) -> &file::UnlockedItem {
        self.0.as_unlocked()
    }

    pub async fn with_lock_state(
        &self,
        locked: bool,
        keyring: &Keyring,
    ) -> Result<Option<Self>, file::Error> {
        let keyring = keyring.unlocked_v1()?;
        let item = match (&self.0, locked) {
            (file::Item::Unlocked(item), true) => {
                file::Item::Locked(keyring.lock_item(item.clone()).await?)
            }
            (file::Item::Locked(item), false) => {
                file::Item::Unlocked(keyring.unlock_item(item.clone()).await?)
            }
            _ => return Ok(None),
        };
        Ok(Some(Self(item)))
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
