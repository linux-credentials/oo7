//! File-backed storage used by daemon collections.

use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};

use oo7::{Key, file};

/// A search or replacement can check every cached record with the same file
/// key.
pub(crate) struct ItemQuery<'a> {
    attributes: &'a HashMap<String, String>,
    v0_attributes: OnceLock<HashMap<String, String>>,
    key: Option<Arc<Key>>,
    exact: bool,
}

impl<'a> ItemQuery<'a> {
    pub async fn new(
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
        keyring: &file::UnlockedKeyring,
    ) -> Result<Option<Self>, file::Error> {
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
        self.item = new.into();
        Ok(true)
    }
}
