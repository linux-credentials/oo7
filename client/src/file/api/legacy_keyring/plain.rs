//! Plain-text keyring format.
//!
//! gnome-keyring writes this format instead of the encrypted one when the
//! keyring password is empty. It is a GLib key file:
//!
//! ```ini
//! [keyring]
//! display-name=Login
//!
//! [1]
//! display-name=Item label
//! secret=the secret
//!
//! [1:attribute0]
//! name=user
//! type=string
//! value=alice
//! ```
//!
//! Items are the groups whose name contains no `:`, their attributes are the
//! `<id>:attribute<N>` groups. Non UTF-8 secrets are stored hex encoded in
//! `binary-secret` instead of `secret`.

use std::{collections::HashMap, io};

use zeroize::Zeroizing;

use super::FILE_HEADER_LEN;
use crate::{
    Secret,
    file::{Error, UnlockedItem},
};

const KEYRING_GROUP: &str = "keyring";

#[derive(Debug)]
pub struct Keyring {
    items: Vec<UnlockedItem>,
}

impl Keyring {
    pub fn into_items(self) -> Vec<UnlockedItem> {
        self.items
    }

    fn read_item(id: &str, group: &Group, attribute_groups: &[&Group]) -> UnlockedItem {
        let label = group.string("display-name").unwrap_or_else(|| {
            #[cfg(feature = "tracing")]
            tracing::warn!("Item '{id}' has no label, defaulting to empty");
            String::new()
        });

        let secret = if let Some(secret) = group.string("secret").map(Zeroizing::new) {
            Secret::text(&*secret)
        } else if let Some(encoded) = group.string("binary-secret").map(Zeroizing::new) {
            let decoded = Zeroizing::new(hex::decode(&*encoded).unwrap_or_else(|_err| {
                #[cfg(feature = "tracing")]
                tracing::warn!("Item '{id}' has an invalid binary secret, defaulting to empty");
                Vec::new()
            }));
            Secret::blob(&*decoded)
        } else {
            #[cfg(feature = "tracing")]
            tracing::warn!("Item '{id}' has no secret, defaulting to empty");
            Secret::blob([])
        };
        #[cfg(not(feature = "tracing"))]
        let _ = id;

        let mut attributes = HashMap::new();
        for group in attribute_groups {
            let Some(name) = group.string("name") else {
                continue;
            };
            let value = if group.string("type").as_deref() == Some("uint32") {
                // gnome-keyring reads the number as a u64 and truncates it.
                group
                    .value("value")
                    .and_then(|v| v.parse::<u64>().ok())
                    .map(|v| (v as u32).to_string())
            } else {
                group.string("value")
            };
            if let Some(value) = value {
                attributes.insert(name, value);
            }
        }

        UnlockedItem::new(label, &attributes, secret)
    }
}

impl TryFrom<&[u8]> for Keyring {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Error> {
        let header_mismatch = || {
            Error::FileHeaderMismatch(
                value
                    .get(..FILE_HEADER_LEN)
                    .map(|x| String::from_utf8_lossy(x).to_string()),
            )
        };

        let content = std::str::from_utf8(value).map_err(|_| header_mismatch())?;
        let groups = parse_key_file(content)?.ok_or_else(header_mismatch)?;

        let mut attribute_groups = HashMap::<&str, Vec<&Group>>::new();
        for (name, group) in &groups {
            if let Some((id, rest)) = name.split_once(':')
                && rest.starts_with("attribute")
            {
                attribute_groups.entry(id).or_default().push(group);
            }
        }

        let items = groups
            .iter()
            .filter(|(name, _)| *name != KEYRING_GROUP && !name.contains(':'))
            .map(|(id, group)| {
                let attributes = attribute_groups.get(id).map_or(&[][..], Vec::as_slice);
                Self::read_item(id, group, attributes)
            })
            .collect();

        Ok(Self { items })
    }
}

#[derive(Debug, Default)]
struct Group<'a>(HashMap<&'a str, &'a str>);

impl Group<'_> {
    /// The raw value, like `g_key_file_get_value`.
    fn value(&self, key: &str) -> Option<&str> {
        self.0.get(key).copied()
    }

    /// The unescaped value, like `g_key_file_get_string`.
    fn string(&self, key: &str) -> Option<String> {
        unescape(self.value(key)?)
    }
}

/// Parse a GLib key file, keeping the groups in file order.
///
/// Returns `None` if the first group is not `[keyring]`, i.e. it is not a
/// plain keyring.
fn parse_key_file(content: &str) -> Result<Option<Vec<(&str, Group<'_>)>>, Error> {
    let mut groups: Vec<(&str, Group)> = Vec::new();
    let mut current = None;

    for (index, line) in content.split('\n').enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let line = line.trim_start_matches(|c: char| c.is_ascii_whitespace());
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|l| l.split_once(']'))
            .filter(|(_, rest)| rest.trim_matches([' ', '\t']).is_empty())
            .map(|(name, _)| name)
        {
            if groups.is_empty() && name != KEYRING_GROUP {
                return Ok(None);
            }
            // Duplicated groups are merged
            current = Some(match groups.iter().position(|(n, _)| *n == name) {
                Some(position) => position,
                None => {
                    groups.push((name, Group::default()));
                    groups.len() - 1
                }
            });
            continue;
        }

        let Some(current) = current else {
            return Ok(None);
        };
        let Some((key, value)) = line.split_once('=') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid key file line {}", index + 1),
            )
            .into());
        };
        let key = key.trim_end_matches(|c: char| c.is_ascii_whitespace());
        let value = value.trim_start_matches(|c: char| c.is_ascii_whitespace());
        groups[current].1.0.insert(key, value);
    }

    Ok(current.map(|_| groups))
}

fn unescape(value: &str) -> Option<String> {
    let mut result = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            result.push(c);
            continue;
        }
        result.push(match chars.next()? {
            's' => ' ',
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            '\\' => '\\',
            _ => return None,
        });
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{CONTENT_TYPE_ATTRIBUTE, XDG_SCHEMA_ATTRIBUTE};

    fn load(name: &str) -> Result<Vec<UnlockedItem>, Error> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join(name);
        let blob = std::fs::read(path)?;
        Ok(Keyring::try_from(blob.as_slice())?.into_items())
    }

    #[test]
    fn plain() -> Result<(), Error> {
        let items = load("plain.keyring")?;
        assert_eq!(items.len(), 3);

        assert_eq!(items[0].label(), "Remmina: Shore - password");
        assert_eq!(items[0].secret(), Secret::text("some password"));
        let attributes = items[0].attributes();
        assert_eq!(attributes.len(), 4); // also content-type
        assert_eq!(
            attributes.get(XDG_SCHEMA_ATTRIBUTE).map(|v| v.as_ref()),
            Some("org.remmina.Password")
        );
        assert_eq!(attributes.get("key").map(|v| v.as_ref()), Some("password"));
        assert_eq!(
            attributes.get(CONTENT_TYPE_ATTRIBUTE).map(|v| v.as_ref()),
            Some("text/plain")
        );

        assert_eq!(items[1].label(), "Binary");
        assert_eq!(items[1].secret(), Secret::blob([0xff, 0x00, 0xab]));
        let attributes = items[1].attributes();
        assert_eq!(attributes.get("num").map(|v| v.as_ref()), Some("3"));
        assert_eq!(attributes.get("empty").map(|v| v.as_ref()), Some(""));
        assert_eq!(
            attributes.get("escaped").map(|v| v.as_ref()),
            Some(" a\tb\\c\n")
        );
        assert!(!attributes.contains_key("bad-number"));
        assert!(!attributes.contains_key("missing-number"));
        assert!(!attributes.contains_key("bad-escape"));

        assert_eq!(items[2].label(), "");
        assert_eq!(items[2].secret(), Secret::blob([]));

        Ok(())
    }

    #[test]
    fn not_plain() {
        assert!(matches!(
            Keyring::try_from(&b"[other]\nfoo=bar\n"[..]),
            Err(Error::FileHeaderMismatch(_))
        ));
        assert!(matches!(
            Keyring::try_from(&b"random data"[..]),
            Err(Error::FileHeaderMismatch(_))
        ));
        assert!(matches!(
            Keyring::try_from(&b"\xff\xfe"[..]),
            Err(Error::FileHeaderMismatch(_))
        ));
        assert!(matches!(
            Keyring::try_from(&b""[..]),
            Err(Error::FileHeaderMismatch(_))
        ));
        assert!(matches!(
            Keyring::try_from(&b"[keyring]\nnot a key value\n"[..]),
            Err(Error::Io(_))
        ));
    }

    #[test]
    fn legacy_keyring_dispatch() -> Result<(), Error> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("plain.keyring");
        let blob = std::fs::read(path)?;
        let keyring = super::super::Keyring::try_from(blob.as_slice())?;
        assert!(matches!(keyring, super::super::Keyring::Plain(_)));
        // The secret is ignored
        let items = keyring.decrypt_items(&Secret::blob("whatever"))?;
        assert_eq!(items.len(), 3);
        Ok(())
    }
}
