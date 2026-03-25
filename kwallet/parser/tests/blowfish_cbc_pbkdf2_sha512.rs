use std::path::Path;

use kwallet_parser::{CipherType, EntryType, HashType, KWalletFile};

#[test]
fn test_blowfish_cbc_pbkdf2_wallet_with_password_entry() {
    let password = "password";
    let wallet_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/blowfish_cbc_pbkdf2_sha512_manual.kwl");

    let wallet_file =
        KWalletFile::open(&wallet_path, password.as_bytes()).expect("Failed to open wallet");

    assert_eq!(wallet_file.version(), (0, 1));
    assert_eq!(wallet_file.cipher_type(), CipherType::BlowfishCBC);
    assert_eq!(wallet_file.hash_type(), HashType::PBKDF2SHA512);

    let folder_names = wallet_file.wallet().folder_names();
    assert_eq!(folder_names.len(), 3);
    assert!(folder_names.contains(&"Form Data"));
    assert!(folder_names.contains(&"Passwords"));
    assert!(folder_names.contains(&"test2"));

    let test2_folder = &wallet_file.wallet()["test2"];
    assert_eq!(test2_folder.entries().len(), 1);

    let help_entry = &test2_folder.entries()["help"];
    assert_eq!(help_entry.entry_type(), EntryType::Password);

    let password_value = help_entry
        .as_password()
        .expect("help entry should be a valid password");
    assert_eq!(password_value, "ttttt");

    assert_eq!(wallet_file.wallet()["Form Data"].entries().len(), 0);
    assert_eq!(wallet_file.wallet()["Passwords"].entries().len(), 0);
}

#[test]
fn test_decryption_fails_with_invalid_password() {
    let wallet_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/blowfish_cbc_pbkdf2_sha512_manual.kwl");
    let wrong_password = b"wrongpassword";

    let result = KWalletFile::open(&wallet_path, wrong_password);
    assert!(result.is_err(), "Should fail with wrong password");
}
