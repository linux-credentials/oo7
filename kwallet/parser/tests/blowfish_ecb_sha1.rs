use std::path::Path;

use kwallet_parser::{CipherType, EntryType, HashType, KWalletFile};

#[test]
fn test_blowfish_ecb_sha1_empty_password() {
    let password = "";
    let wallet_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/blowfish_ecb_sha1_empty_password.kwl");

    let wallet_file =
        KWalletFile::open(&wallet_path, password.as_bytes()).expect("Failed to open wallet");

    // Validate header
    assert_eq!(wallet_file.version(), (0, 0));
    assert_eq!(wallet_file.cipher_type(), CipherType::BlowfishECB);
    assert_eq!(wallet_file.hash_type(), HashType::SHA1);

    let passwords_folder = &wallet_file.wallet()["Passwords"];
    assert_eq!(passwords_folder.entries().len(), 3);

    // Validate Password entry: 'abcdef' -> 'qwerty'
    let abcdef_entry = &passwords_folder.entries()["abcdef"];
    assert_eq!(abcdef_entry.entry_type(), EntryType::Password);
    let password_value = abcdef_entry
        .as_password()
        .expect("abcdef should be a valid password");
    assert_eq!(password_value, "qwerty");

    // Validate Stream/Binary entry: 'bindata' -> ''
    let bindata_entry = &passwords_folder.entries()["bindata"];
    assert_eq!(bindata_entry.entry_type(), EntryType::Stream);
    assert_eq!(bindata_entry.as_stream().len(), 0);

    // Validate Map entry: 'kde.org' -> {key1: value1, key2: value2}
    let kde_entry = &passwords_folder.entries()["kde.org"];
    assert_eq!(kde_entry.entry_type(), EntryType::Map);
    let map_value = kde_entry.as_map().expect("kde.org should be a valid map");
    assert_eq!(map_value.len(), 2);
    assert_eq!(map_value.get("key1"), Some(&"value1".to_string()));
    assert_eq!(map_value.get("key2"), Some(&"value2".to_string()));
}

#[test]
fn test_blowfish_ecb_sha1_long_password() {
    let password = "pythonpythonpythonpythonpython";
    let wallet_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/blowfish_ecb_sha1_long_password.kwl");

    let wallet_file =
        KWalletFile::open(&wallet_path, password.as_bytes()).expect("Failed to open wallet");

    // Validate header
    assert_eq!(wallet_file.version(), (0, 0));
    assert_eq!(wallet_file.cipher_type(), CipherType::BlowfishECB);
    assert_eq!(wallet_file.hash_type(), HashType::SHA1);
    let passwords_folder = &wallet_file.wallet()["Passwords"];
    assert_eq!(passwords_folder.entries().len(), 3);

    // Validate Password entry: 'abcdef' -> 'qwerty'
    let abcdef_entry = &passwords_folder.entries()["abcdef"];
    assert_eq!(abcdef_entry.entry_type(), EntryType::Password);
    let password_value = abcdef_entry
        .as_password()
        .expect("abcdef should be a valid password");
    assert_eq!(password_value, "qwerty");

    // Validate Stream/Binary entry: 'bindata' -> ''
    let bindata_entry = &passwords_folder.entries()["bindata"];
    assert_eq!(bindata_entry.entry_type(), EntryType::Stream);
    assert_eq!(bindata_entry.as_stream().len(), 0);

    // Validate Map entry: 'kde.org' -> {key1: value1, key2: value2}
    let kde_entry = &passwords_folder.entries()["kde.org"];
    assert_eq!(kde_entry.entry_type(), EntryType::Map);
    let map_value = kde_entry.as_map().expect("kde.org should be a valid map");
    assert_eq!(map_value.len(), 2);
    assert_eq!(map_value.get("key1"), Some(&"value1".to_string()));
    assert_eq!(map_value.get("key2"), Some(&"value2".to_string()));
}

#[test]
fn test_legacy_decryption_fails_with_invalid_password() {
    let wallet_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/blowfish_ecb_sha1_empty_password.kwl");
    let wrong_password = b"wrongpassword";

    let result = KWalletFile::open(&wallet_path, wrong_password);
    assert!(result.is_err(), "Should fail with wrong password");
}
