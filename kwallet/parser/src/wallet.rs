use std::{collections::HashMap, io::Cursor, ops::Index};

use zeroize::Zeroizing;

use crate::{
    error::{Error, Result},
    qdata::QDataStreamReader,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
#[repr(i32)]
pub enum EntryType {
    Unknown = 0,
    Password = 1,
    Stream = 2,
    Map = 3,
}

impl TryFrom<i32> for EntryType {
    type Error = Error;

    fn try_from(value: i32) -> Result<Self> {
        match value {
            0 => Ok(EntryType::Unknown),
            1 => Ok(EntryType::Password),
            2 => Ok(EntryType::Stream),
            3 => Ok(EntryType::Map),
            _ => Err(Error::InvalidDataStructure),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Entry {
    key: String,
    entry_type: EntryType,
    value: Zeroizing<Vec<u8>>,
}

impl Entry {
    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn entry_type(&self) -> EntryType {
        self.entry_type
    }

    /// Parse as password
    pub fn as_password(&self) -> Result<String> {
        if self.entry_type != EntryType::Password {
            return Err(Error::InvalidDataStructure);
        }

        let mut reader = QDataStreamReader::new(Cursor::new(&**self.value));
        reader.read_string()
    }

    /// Parse as map of strings
    pub fn as_map(&self) -> Result<HashMap<String, String>> {
        if self.entry_type != EntryType::Map {
            return Err(Error::InvalidDataStructure);
        }

        let mut reader = QDataStreamReader::new(Cursor::new(&**self.value));
        let count = reader.read_u32()?;

        let mut map = HashMap::new();
        for _ in 0..count {
            let key = reader.read_string()?;
            let value = reader.read_string()?;
            map.insert(key, value);
        }

        Ok(map)
    }

    /// Get raw bytes
    pub fn as_stream(&self) -> &[u8] {
        &self.value
    }
}

impl AsRef<[u8]> for Entry {
    fn as_ref(&self) -> &[u8] {
        &self.value
    }
}

#[derive(Debug, Clone)]
pub struct Folder {
    name: String,
    entries: HashMap<String, Entry>,
}

impl Folder {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn entries(&self) -> &HashMap<String, Entry> {
        &self.entries
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &Entry)> {
        self.entries.iter()
    }
}

impl<'a> IntoIterator for &'a Folder {
    type Item = (&'a String, &'a Entry);
    type IntoIter = std::collections::hash_map::Iter<'a, String, Entry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

impl Index<&str> for Folder {
    type Output = Entry;

    fn index(&self, key: &str) -> &Self::Output {
        &self.entries[key]
    }
}

#[derive(Debug, Clone)]
pub struct Wallet {
    folders: HashMap<String, Folder>,
}

impl Wallet {
    pub fn folders(&self) -> &HashMap<String, Folder> {
        &self.folders
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &Folder)> {
        self.folders.iter()
    }

    /// Parse wallet from decrypted data
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut reader = QDataStreamReader::new(Cursor::new(data));
        let mut folders = HashMap::new();

        loop {
            let folder_name = match reader.read_string() {
                Ok(name) if !name.is_empty() => name,
                Ok(_) => break,
                Err(_) => break,
            };
            let entry_count = reader.read_u32()?;
            let mut entries = HashMap::new();

            for _ in 0..entry_count {
                let key = reader.read_string()?;
                let entry_type_raw = reader.read_i32()?;
                let entry_type = EntryType::try_from(entry_type_raw)?;
                let value = reader.read_byte_array()?;

                if entry_type == EntryType::Unknown {
                    continue;
                }

                let entry = Entry {
                    key: key.clone(),
                    entry_type,
                    value: Zeroizing::new(value),
                };

                entries.insert(key, entry);
            }

            let folder = Folder {
                name: folder_name.clone(),
                entries,
            };

            folders.insert(folder_name, folder);
        }

        Ok(Self { folders })
    }

    pub fn get_folder(&self, name: &str) -> Option<&Folder> {
        self.folders.get(name)
    }

    pub fn get_entry(&self, folder: &str, key: &str) -> Option<&Entry> {
        self.folders.get(folder)?.entries.get(key)
    }

    pub fn folder_names(&self) -> Vec<&str> {
        self.folders.keys().map(|s| s.as_str()).collect()
    }
}

impl<'a> IntoIterator for &'a Wallet {
    type Item = (&'a String, &'a Folder);
    type IntoIter = std::collections::hash_map::Iter<'a, String, Folder>;

    fn into_iter(self) -> Self::IntoIter {
        self.folders.iter()
    }
}

impl Index<&str> for Wallet {
    type Output = Folder;

    fn index(&self, name: &str) -> &Self::Output {
        &self.folders[name]
    }
}
