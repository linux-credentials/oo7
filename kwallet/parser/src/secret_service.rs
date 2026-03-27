//! Helper functions for migrating KWallet entries to Secret Service format
//! matching the behavior of KWallet's own migration code.

use std::collections::HashMap;

use base64::Engine;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Entry, EntryType};

/// Result of converting a KWallet entry to Secret Service format
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretServiceEntry {
    #[zeroize(skip)]
    label: String,
    #[zeroize(skip)]
    attributes: HashMap<String, String>,
    secret: Vec<u8>,
}

impl SecretServiceEntry {
    /// The Secret Service label (format: "folder/key")
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Attributes that should be set on the Secret Service item
    pub fn attributes(&self) -> &HashMap<String, String> {
        &self.attributes
    }

    /// The secret value (as bytes)
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }
}

/// Convert a KWallet entry to Secret Service format
///
/// This follows KWallet's migration behavior:
/// - Attributes: `user` (key), `server` (folder), `type` (password/map/base64)
/// - Label: "folder/key"
/// - Secret:
///   - Password: UTF-8 text
///   - Map: JSON object
///   - Stream: Base64-encoded binary data
pub fn convert_entry(
    folder: &str,
    key: &str,
    entry: &Entry,
) -> Result<SecretServiceEntry, Box<dyn std::error::Error>> {
    let label = format!("{}/{}", folder, key);
    let mut attributes = HashMap::new();

    // Standard Secret Service attributes used by KWallet
    attributes.insert("user".to_string(), key.to_string());
    attributes.insert("server".to_string(), folder.to_string());

    let (type_str, secret) = match entry.entry_type() {
        EntryType::Password => {
            let password = entry.as_password()?;
            ("password".to_string(), password.into_bytes())
        }
        EntryType::Map => {
            let map = entry.as_map()?;
            // Convert map to JSON like KWallet does
            let json_value = serde_json::to_value(map)?;
            let json_bytes = serde_json::to_vec(&json_value)?;
            ("map".to_string(), json_bytes)
        }
        EntryType::Stream => {
            // KWallet stores streams as base64
            let stream_data = entry.as_stream();
            let base64_data = base64::engine::general_purpose::STANDARD.encode(stream_data);
            ("base64".to_string(), base64_data.into_bytes())
        }
        EntryType::Unknown => {
            return Err("Cannot convert unknown entry type".into());
        }
    };

    attributes.insert("type".to_string(), type_str);

    Ok(SecretServiceEntry {
        label,
        attributes,
        secret,
    })
}
