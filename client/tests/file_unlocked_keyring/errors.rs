use std::path::PathBuf;

#[cfg(feature = "async-std")]
use async_std::fs;
use oo7::{Key, Secret, file::*};
use tempfile::tempdir;
#[cfg(feature = "tokio")]
use tokio::fs;

#[tokio::test]
async fn delete_broken_items() -> Result<(), Error> {
    const VALID_TO_ADD: usize = 5;
    const BROKEN_TO_ADD: usize = 3;

    let data_dir = tempdir()?;
    let v0_dir = data_dir.path().join("keyrings");
    let v1_dir = v0_dir.join("v1");
    fs::create_dir_all(&v1_dir).await?;

    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("default.keyring");
    let keyring_path = v1_dir.join("default.keyring");
    fs::copy(&fixture_path, &keyring_path).await?;

    // 1) Load with the correct password and add several valid items.
    // This ensures valid_items > broken_items that we'll add later.
    let keyring = UnlockedKeyring::load(&keyring_path, Some(Secret::blob("test"))).await?;
    for i in 0..VALID_TO_ADD {
        keyring
            .create_item(
                &format!("valid {}", i),
                &[("attr_valid", "value")],
                format!("password_valid_{}", i),
                false,
            )
            .await?;
    }
    drop(keyring);

    // 2) Load_unchecked with the wrong password and add a few "broken" items.
    let keyring = unsafe {
        UnlockedKeyring::load_unchecked(&keyring_path, Secret::blob("wrong_password")).await?
    };
    for i in 0..BROKEN_TO_ADD {
        keyring
            .create_item(
                &format!("bad{}", i),
                &[("attr_bad", "value_bad")],
                format!("pw_bad{}", i),
                false,
            )
            .await?;
    }
    drop(keyring);

    // 3) Load with the correct password and run the deletion.
    let keyring = UnlockedKeyring::load(&keyring_path, Some(Secret::blob("test"))).await?;
    let removed = keyring.delete_broken_items().await?;
    assert!(
        removed >= BROKEN_TO_ADD,
        "expected at least {} broken items removed, got {}",
        BROKEN_TO_ADD,
        removed
    );

    // Second call should find nothing left to clean up.
    assert_eq!(keyring.delete_broken_items().await?, 0);

    fs::remove_file(keyring_path).await?;
    Ok(())
}

#[tokio::test]
async fn partially_corrupted_keyring_error() -> Result<(), Error> {
    let temp_dir = tempdir().unwrap();
    let keyring_path = temp_dir.path().join("partially_corrupted.keyring");

    // Create keyring with correct password and add 2 valid items
    let correct_secret = Secret::from("correct-password-long-enough".as_bytes());
    let keyring = UnlockedKeyring::load(&keyring_path, Some(correct_secret.clone())).await?;
    keyring
        .create_item("valid1", &[("attr", "value1")], "password1", false)
        .await?;
    keyring
        .create_item("valid2", &[("attr", "value2")], "password2", false)
        .await?;
    let key = keyring.key().await?.unwrap();
    let key = key.as_ref().as_ref().to_vec();
    drop(keyring);

    // Load_unchecked with wrong password and add 3 broken items (more than
    // valid)
    let wrong_secret = Secret::from("wrong-password-long-enough".as_bytes());
    let keyring = unsafe { UnlockedKeyring::load_unchecked(&keyring_path, wrong_secret).await? };
    keyring
        .create_item("broken1", &[("bad", "value1")], "bad_password1", false)
        .await?;
    keyring
        .create_item("broken2", &[("bad", "value2")], "bad_password2", false)
        .await?;
    keyring
        .create_item("broken3", &[("bad", "value3")], "bad_password3", false)
        .await?;
    drop(keyring);

    let locked = LockedKeyring::load(&keyring_path).await?;
    assert!(locked.validate_key(&Key::new(key.clone())).await?);
    assert!(matches!(
        locked.unlock_with_key(Key::new(key)).await,
        Err(Error::PartiallyCorruptedKeyring {
            valid_items: 2,
            broken_items: 3,
        })
    ));

    let result = UnlockedKeyring::load(&keyring_path, Some(correct_secret)).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        Error::PartiallyCorruptedKeyring {
            valid_items,
            broken_items,
        } => {
            assert_eq!(valid_items, 2);
            assert_eq!(broken_items, 3);
            assert!(broken_items > valid_items);
        }
        other => panic!("Expected PartiallyCorruptedKeyring, got: {:?}", other),
    }

    Ok(())
}

#[tokio::test]
async fn invalid_item_error_on_decrypt_failure() -> Result<(), Error> {
    let temp_dir = tempdir().unwrap();
    let keyring_path = temp_dir.path().join("invalid_item_test.keyring");

    // 1) Create keyring with correct password and add 2 items
    let correct_secret = Secret::from("correct-password-long-enough".as_bytes());
    let keyring = UnlockedKeyring::load(&keyring_path, Some(correct_secret)).await?;
    keyring
        .create_item("item1", &[("app", "test1")], "password1", false)
        .await?;
    keyring
        .create_item("item2", &[("app", "test2")], "password2", false)
        .await?;
    drop(keyring);

    // 2) Load_unchecked with wrong password - items won't decrypt
    let wrong_secret = Secret::from("wrong-password-long-enough".as_bytes());
    let keyring = unsafe { UnlockedKeyring::load_unchecked(&keyring_path, wrong_secret).await? };

    let items_result = keyring.all_items().await?;
    assert_eq!(items_result.len(), 2);

    assert!(matches!(
        items_result[0].as_ref().unwrap_err(),
        InvalidItemError { .. }
    ));
    assert!(matches!(
        items_result[1].as_ref().unwrap_err(),
        InvalidItemError { .. }
    ));

    Ok(())
}
