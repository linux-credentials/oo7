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

    pub fn matches(&self, item: &file::Item) -> bool {
        if self.exact {
            item.matches_attributes_exact(self.attributes.as_ref(), self.key.as_deref())
        } else {
            item.matches_attributes(self.attributes.as_ref(), self.key.as_deref())
        }
    }
}
