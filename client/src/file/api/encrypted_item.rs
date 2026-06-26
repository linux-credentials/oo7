use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zbus::zvariant::Type;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{Error, UnlockedItem};
use crate::{AsAttributes, Key, Mac, crypto};

#[derive(Deserialize, Serialize, Type, Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct EncryptedItem {
    #[zeroize(skip)]
    pub(crate) hashed_attributes: HashMap<String, Mac>,
    #[serde(with = "serde_bytes")]
    pub(crate) blob: Vec<u8>,
}

impl EncryptedItem {
    pub fn has_attribute(&self, key: &str, value_mac: &Mac) -> bool {
        self.hashed_attributes.get(key) == Some(value_mac)
    }

    fn has_plaintext_attribute(&self, key: &str, value: &str) -> bool {
        self.hashed_attributes
            .get(key)
            .is_some_and(|mac| mac.as_slice() == value.as_bytes())
    }

    pub fn matches(&self, attributes: &impl AsAttributes, key: Option<&Key>) -> bool {
        match key {
            Some(key) => {
                let hashed = attributes.hash(key);
                hashed
                    .iter()
                    .all(|(k, v)| v.as_ref().is_ok_and(|v| self.has_attribute(k.as_str(), v)))
            }
            None => attributes
                .as_attributes()
                .iter()
                .all(|(k, v)| self.has_plaintext_attribute(k.as_str(), v.as_str())),
        }
    }

    fn try_decrypt_inner(&self, key: Option<&Key>) -> Result<UnlockedItem, Error> {
        match key {
            Some(key) => self.try_decrypt_encrypted(key),
            None => UnlockedItem::try_from(self.blob.as_slice()),
        }
    }

    fn try_decrypt_encrypted(&self, key: &Key) -> Result<UnlockedItem, Error> {
        let n = self.blob.len();
        let n_mac = crypto::mac_len();
        let n_iv = crypto::iv_len();

        // The encrypted data, the iv, and the mac are concatenated into blob.
        let (encrypted_data_with_iv, mac_tag) = &self.blob.split_at(n - n_mac);

        // verify item
        if !crypto::verify_mac(encrypted_data_with_iv, key, mac_tag)? {
            return Err(Error::MacError);
        }

        let (encrypted_data, iv) = encrypted_data_with_iv.split_at(n - n_mac - n_iv);

        // decrypt item
        let decrypted = crypto::decrypt(encrypted_data, key, iv)?;

        let item = UnlockedItem::try_from(decrypted.as_slice())?;

        Self::validate(&self.hashed_attributes, &item, key)?;

        Ok(item)
    }

    pub fn is_valid(&self, key: Option<&Key>) -> bool {
        self.try_decrypt_inner(key).is_ok()
    }

    pub fn decrypt(self, key: Option<&Key>) -> Result<UnlockedItem, Error> {
        self.try_decrypt_inner(key)
    }

    fn validate(
        hashed_attributes: &HashMap<String, Mac>,
        item: &UnlockedItem,
        key: &Key,
    ) -> Result<(), Error> {
        for (attribute_key, hashed_attribute) in hashed_attributes.iter() {
            if let Some(attribute_plaintext) = item.attributes().get(attribute_key) {
                if !crypto::verify_mac(
                    attribute_plaintext.as_bytes(),
                    key,
                    hashed_attribute.as_slice(),
                )? {
                    return Err(Error::HashedAttributeMac(attribute_key.to_owned()));
                }
            } else {
                return Err(Error::HashedAttributeMac(attribute_key.to_owned()));
            }
        }

        Ok(())
    }
}
