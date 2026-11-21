//! File-backed storage used by daemon collections.

use std::{borrow::Cow, collections::HashMap, sync::Arc};

use oo7::{Key, file};

use crate::migration;

/// Match cached records without deriving the file key for each item.
pub(crate) struct ItemQuery<'a> {
    attributes: Cow<'a, HashMap<String, String>>,
    key: Option<Arc<Key>>,
    exact: bool,
}

impl<'a> ItemQuery<'a> {
    pub async fn new(
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

    pub async fn set_locked(
        &mut self,
        locked: bool,
        keyring: &file::UnlockedKeyring,
    ) -> Result<(), file::Error> {
        self.0 = match (&self.0, locked) {
            (file::Item::Unlocked(item), true) => keyring.lock_item(item.clone()).await?.into(),
            (file::Item::Locked(item), false) => keyring.unlock_item(item.clone()).await?.into(),
            _ => return Ok(()),
        };
        Ok(())
    }

    /// The caller holds the collection's write lock so the index stays valid.
    /// Match the whole record since other items can share its attributes.
    pub async fn replace(
        &mut self,
        keyring: &file::UnlockedKeyring,
        new: file::UnlockedItem,
    ) -> Result<bool, file::Error> {
        let index = keyring
            .all_items()
            .await?
            .iter()
            .position(|entry| entry.as_ref().is_ok_and(|item| item == self.unlocked()));
        let Some(index) = index else { return Ok(false) };
        keyring.replace_item_index(index, &new).await?;
        self.0 = new.into();
        Ok(true)
    }
}
