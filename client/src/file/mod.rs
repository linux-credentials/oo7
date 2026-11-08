//! File backend implementation that can be backed by the [Secret portal](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Secret.html).
//!
//! ```no_run
//! use oo7::{Secret, file::UnlockedKeyring};
//!
//! # async fn run() -> oo7::Result<()> {
//! let keyring = UnlockedKeyring::load("default.keyring", Some(Secret::text("some_text"))).await?;
//! keyring
//!     .create_item("My Label", &[("account", "alice")], "My Password", true)
//!     .await?;
//!
//! let items = keyring.search_items(&[("account", "alice")]).await?;
//! assert_eq!(items[0].secret(), oo7::Secret::blob("My Password"));
//!
//! keyring.delete(&[("account", "alice")]).await?;
//! #   Ok(())
//! # }
//! ```
//!
//! # File format
//!
//! Keyrings use the format of libsecret's file backend. A file starts with
//! the `GnomeKeyring\n\r\0\n` header, the major and minor versions as two
//! bytes (`1`, `0`), and a little-endian
//! [GVariant](https://docs.gtk.org/glib/struct.Variant.html) of type
//! `(uayutua(a{say}ay))`:
//!
//! | Type          | Field                                         |
//! | ------------- | --------------------------------------------- |
//! | `u`           | salt size                                     |
//! | `ay`          | salt                                          |
//! | `u`           | PBKDF2 iteration count                        |
//! | `t`           | modification time, in seconds since the epoch |
//! | `u`           | usage count                                   |
//! | `a(a{say}ay)` | items                                         |
//!
//! Each item is a pair of:
//!
//! - `a{say}`: its attributes, mapping each name to the HMAC of its value, so
//!   items can be searched without decrypting them.
//! - `ay`: the encrypted item, `ciphertext ‖ IV ‖ HMAC(ciphertext ‖ IV)`.
//!
//! Decrypted, an item is a `(a{ss}sttay)` GVariant holding its attributes,
//! label, creation and modification times, and secret.
//!
//! The key is derived from the password with PBKDF2-HMAC-SHA256, using at
//! least 100000 iterations and a 32 bytes salt. Items are encrypted with
//! AES-128-CBC, with PKCS#7 padding and a random IV, and the same key is used
//! for HMAC-SHA256. These algorithms were chosen for being FIPS 140-3
//! approved.
//!
//! oo7 also supports keyrings without a password, which store attribute
//! values and items in plain text.
//!
//! gnome-keyring keyrings, in either its encrypted binary format or the plain
//! text one used for keyrings without a password, are migrated to this
//! format.

#[cfg(feature = "unstable")]
#[cfg_attr(docsrs, doc(cfg(feature = "unstable")))]
pub mod api;
#[cfg(not(feature = "unstable"))]
pub(crate) mod api;

mod error;
mod locked_item;
mod locked_keyring;
mod unlocked_item;
mod unlocked_keyring;

pub use error::{Error, InvalidItemError, WeakKeyError};
pub use locked_item::LockedItem;
pub use locked_keyring::LockedKeyring;
pub use unlocked_item::UnlockedItem;
pub use unlocked_keyring::{ItemDefinition, UnlockedKeyring};

use crate::{AsAttributes, Key, Secret};

#[derive(Debug)]
pub enum Item {
    Locked(LockedItem),
    Unlocked(UnlockedItem),
}

impl From<UnlockedItem> for Item {
    fn from(item: UnlockedItem) -> Self {
        Self::Unlocked(item)
    }
}

impl From<LockedItem> for Item {
    fn from(item: LockedItem) -> Self {
        Self::Locked(item)
    }
}

impl Item {
    pub const fn is_locked(&self) -> bool {
        matches!(self, Self::Locked(_))
    }

    pub fn as_unlocked(&self) -> &UnlockedItem {
        match self {
            Self::Unlocked(item) => item,
            _ => panic!("The item is locked"),
        }
    }

    pub fn as_mut_unlocked(&mut self) -> &mut UnlockedItem {
        match self {
            Self::Unlocked(item) => item,
            _ => panic!("The item is locked"),
        }
    }

    pub fn as_locked(&self) -> &LockedItem {
        match self {
            Self::Locked(item) => item,
            _ => panic!("The item is unlocked"),
        }
    }

    /// Check if this item matches the given attributes
    pub fn matches_attributes(&self, attributes: &impl AsAttributes, key: Option<&Key>) -> bool {
        match self {
            Self::Unlocked(unlocked) => {
                let item_attrs = unlocked.attributes();
                attributes.search_attributes().iter().all(|(k, value)| {
                    item_attrs.get(k.as_str()).map(|v| v.as_ref()) == Some(value.as_str())
                })
            }
            Self::Locked(locked) => locked.inner.matches(attributes, key),
        }
    }

    /// Check if this item has exactly the given attributes.
    pub fn matches_attributes_exact(
        &self,
        attributes: &impl AsAttributes,
        key: Option<&Key>,
    ) -> bool {
        match self {
            Self::Unlocked(unlocked) => unlocked.matches_exact(attributes),
            Self::Locked(locked) => locked.inner.matches_exact(attributes, key),
        }
    }
}

#[derive(Debug)]
pub enum Keyring {
    Locked(LockedKeyring),
    Unlocked(UnlockedKeyring),
}

impl From<LockedKeyring> for Keyring {
    fn from(keyring: LockedKeyring) -> Self {
        Self::Locked(keyring)
    }
}

impl From<UnlockedKeyring> for Keyring {
    fn from(keyring: UnlockedKeyring) -> Self {
        Self::Unlocked(keyring)
    }
}

impl Keyring {
    /// Validate that a secret can decrypt the items in this keyring.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, secret)))]
    pub async fn validate_secret(&self, secret: &Secret) -> Result<bool, Error> {
        match self {
            Self::Locked(keyring) => keyring.validate_secret(secret).await,
            Self::Unlocked(keyring) => keyring.validate_secret(secret).await,
        }
    }

    pub async fn validate_unencrypted(&self) -> Result<bool, Error> {
        match self {
            Self::Locked(keyring) => keyring.validate_unencrypted().await,
            Self::Unlocked(keyring) => keyring.validate_unencrypted().await,
        }
    }

    /// Get the modification timestamp
    pub async fn modified_time(&self) -> std::time::Duration {
        match self {
            Self::Locked(keyring) => keyring.modified_time().await,
            Self::Unlocked(keyring) => keyring.modified_time().await,
        }
    }

    /// Get the creation timestamp from the filesystem if the keyring has an
    /// associated file.
    pub async fn created_time(&self) -> Option<std::time::Duration> {
        let path = self.path()?;

        #[cfg(feature = "tokio")]
        let metadata = tokio::fs::metadata(path).await.ok()?;
        #[cfg(feature = "async-std")]
        let metadata = async_fs::metadata(path).await.ok()?;

        metadata
            .created()
            .ok()
            .and_then(|time| time.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
    }

    pub async fn items(&self) -> Result<Vec<Item>, Error> {
        match self {
            Self::Locked(keyring) => Ok(keyring
                .items()
                .await?
                .into_iter()
                .map(Item::Locked)
                .collect()),
            Self::Unlocked(keyring) => Ok(keyring
                .items()
                .await?
                .into_iter()
                .map(Item::Unlocked)
                .collect()),
        }
    }

    /// Return the associated file if any.
    pub fn path(&self) -> Option<&std::path::Path> {
        match self {
            Self::Locked(keyring) => keyring.path(),
            Self::Unlocked(keyring) => keyring.path(),
        }
    }

    pub const fn is_locked(&self) -> bool {
        matches!(self, Self::Locked(_))
    }

    pub fn as_unlocked(&self) -> &UnlockedKeyring {
        match self {
            Self::Unlocked(unlocked_keyring) => unlocked_keyring,
            _ => panic!("The keyring is locked"),
        }
    }

    pub fn as_locked(&self) -> &LockedKeyring {
        match self {
            Self::Locked(locked_keyring) => locked_keyring,
            _ => panic!("The keyring is unlocked"),
        }
    }
}
