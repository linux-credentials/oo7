use std::path::PathBuf;

#[cfg(feature = "async-std")]
use async_std::fs;
use oo7::{Key, Secret, file::*};
use tempfile::tempdir;
#[cfg(feature = "tokio")]
use tokio::fs;

use super::strong_key;

#[tokio::test]
async fn validate_and_unlock_with_key() -> Result<(), Error> {
    let temp_dir = tempdir()?;
    let path = temp_dir.path().join("key-unlock.keyring");
    let keyring = UnlockedKeyring::load(&path, Some(strong_key())).await?;
    keyring
        .create_item("Item", &[("account", "alice")], "secret", false)
        .await?;
    let key = keyring.key().await?.unwrap();
    let key = key.as_ref().as_ref().to_vec();
    drop(keyring);

    let locked = LockedKeyring::load(&path).await?;
    assert!(!locked.validate_key(&Key::new(vec![9; 16])).await?);
    assert!(locked.validate_key(&Key::new(key.clone())).await?);

    let locked_with_wrong_key = LockedKeyring::load(&path).await?;
    assert!(matches!(
        locked_with_wrong_key
            .unlock_with_key(Key::new(vec![9; 16]))
            .await,
        Err(Error::IncorrectSecret)
    ));

    let keyring = locked.unlock_with_key(Key::new(key.clone())).await?;
    let cached_key = keyring.key().await?.unwrap();
    assert_eq!(cached_key.as_ref().as_ref(), key);
    let item = keyring.lookup_item(&[("account", "alice")]).await?.unwrap();
    assert_eq!(item.secret(), Secret::text("secret"));

    Ok(())
}

#[tokio::test]
async fn malformed_file_keys_are_rejected() -> Result<(), Error> {
    let temp_dir = tempdir()?;
    let path = temp_dir.path().join("invalid-key-length.keyring");
    let keyring = UnlockedKeyring::load(&path, Some(strong_key())).await?;
    keyring
        .create_item("Item", &[("account", "alice")], "secret", false)
        .await?;
    drop(keyring);

    for actual in [0, 15, 17, 32] {
        let locked = LockedKeyring::load(&path).await?;
        assert!(matches!(
            locked.validate_key(&Key::new(vec![0; actual])).await,
            Err(Error::InvalidKeyLength {
                expected: 16,
                actual: error_actual,
            }) if error_actual == actual
        ));

        let locked = LockedKeyring::load(&path).await?;
        assert!(matches!(
            locked.unlock_with_key(Key::new(vec![0; actual])).await,
            Err(Error::InvalidKeyLength {
                expected: 16,
                actual: error_actual,
            }) if error_actual == actual
        ));
    }

    Ok(())
}

#[tokio::test]
async fn key_only_lifecycle_and_password_change() -> Result<(), Error> {
    let temp_dir = tempdir()?;
    let path = temp_dir.path().join("key-lifecycle.keyring");
    let original_secret = strong_key();
    let keyring = UnlockedKeyring::load(&path, Some(original_secret.clone())).await?;
    keyring
        .create_item("Original", &[("id", "original")], "before", false)
        .await?;
    let key = keyring.key().await?.unwrap();
    let key = key.as_ref().as_ref().to_vec();
    drop(keyring);

    let keyring = UnlockedKeyring::load_with_key(&path, Key::new(key.clone())).await?;
    let cached_key = keyring.key().await?.unwrap();
    assert_eq!(cached_key.as_ref().as_ref(), key);
    let mut original = keyring.lookup_item(&[("id", "original")]).await?.unwrap();
    original.set_secret("after");
    keyring.replace_item_index(0, &original).await?;
    keyring
        .create_item("Added", &[("id", "added")], "created", false)
        .await?;
    drop(keyring);

    let locked = LockedKeyring::load(&path).await?;
    assert!(locked.validate_key(&Key::new(key.clone())).await?);
    let keyring = UnlockedKeyring::load_with_key(&path, Key::new(key)).await?;
    assert_eq!(
        keyring
            .lookup_item(&[("id", "original")])
            .await?
            .unwrap()
            .secret(),
        Secret::text("after")
    );
    assert_eq!(
        keyring
            .lookup_item(&[("id", "added")])
            .await?
            .unwrap()
            .secret(),
        Secret::text("created")
    );

    let replacement_secret = Secret::blob(vec![3; 64]);
    keyring.change_secret(replacement_secret.clone()).await?;
    drop(keyring);

    assert!(
        UnlockedKeyring::load(&path, Some(original_secret))
            .await
            .is_err()
    );
    let keyring = UnlockedKeyring::load(&path, Some(replacement_secret)).await?;
    assert_eq!(keyring.n_items().await, 2);

    Ok(())
}

#[tokio::test]
async fn empty_keyring_cannot_authenticate_key() -> Result<(), Error> {
    let temp_dir = tempdir()?;
    let path = temp_dir.path().join("empty-key.keyring");
    let keyring = UnlockedKeyring::load(&path, Some(strong_key())).await?;
    assert!(keyring.key().await?.is_some());
    keyring.write().await?;
    drop(keyring);

    let locked = LockedKeyring::load(&path).await?;
    assert!(locked.validate_key(&Key::new(vec![9; 16])).await?);
    let keyring = locked.unlock_with_key(Key::new(vec![9; 16])).await?;
    keyring
        .create_item("Rebound", &[("id", "rebound")], "secret", false)
        .await?;
    drop(keyring);

    assert!(
        UnlockedKeyring::load(&path, Some(strong_key()))
            .await
            .is_err()
    );
    let keyring = UnlockedKeyring::load_with_key(&path, Key::new(vec![9; 16])).await?;
    assert_eq!(keyring.n_items().await, 1);

    Ok(())
}

#[tokio::test]
async fn unencrypted_keyring_requires_no_key() -> Result<(), Error> {
    let temp_dir = tempdir()?;
    let path = temp_dir.path().join("unencrypted-key.keyring");
    let keyring = UnlockedKeyring::load(&path, None).await?;
    keyring
        .create_item("Plain", &[("id", "plain")], "secret", false)
        .await?;
    drop(keyring);

    let locked = LockedKeyring::load(&path).await?;
    assert!(!locked.validate_key(&Key::new(vec![1; 16])).await?);
    assert!(matches!(
        locked.unlock_with_key(Key::new(vec![1; 16])).await,
        Err(Error::IncorrectSecret)
    ));

    let keyring = LockedKeyring::load(&path)
        .await?
        .unlock_unencrypted()
        .await?;
    assert!(keyring.key().await?.is_none());
    assert_eq!(keyring.n_items().await, 1);

    Ok(())
}

#[tokio::test]
async fn open_at_with_key_uses_named_current_keyring() -> Result<(), Error> {
    let data_dir = tempdir()?;
    let keyring = UnlockedKeyring::open_at(data_dir.path(), "named", Some(strong_key())).await?;
    keyring
        .create_item("Named", &[("id", "named")], "secret", false)
        .await?;
    let key = keyring.key().await?.unwrap();
    let key = key.as_ref().as_ref().to_vec();
    drop(keyring);

    let keyring =
        UnlockedKeyring::open_at_with_key(data_dir.path(), "named", Key::new(key)).await?;
    assert_eq!(
        keyring
            .lookup_item(&[("id", "named")])
            .await?
            .unwrap()
            .secret(),
        Secret::text("secret")
    );

    let direct_key = vec![4; 16];
    let direct = UnlockedKeyring::open_at_with_key(
        data_dir.path(),
        "new-with-key",
        Key::new(direct_key.clone()),
    )
    .await?;
    direct
        .create_item("Direct", &[("id", "direct")], "secret", false)
        .await?;
    drop(direct);
    let direct =
        UnlockedKeyring::open_at_with_key(data_dir.path(), "new-with-key", Key::new(direct_key))
            .await?;
    assert_eq!(direct.n_items().await, 1);

    Ok(())
}

#[tokio::test]
async fn open_at_with_key_ignores_legacy_keyring() -> Result<(), Error> {
    let data_dir = tempdir()?;
    let keyrings_dir = data_dir.path().join("keyrings");
    fs::create_dir_all(&keyrings_dir).await?;
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("default.keyring");
    let v0_path = keyrings_dir.join("named.keyring");
    let v1_path = keyrings_dir.join("v1").join("named.keyring");
    fs::copy(fixture, &v0_path).await?;
    let v0_bytes = fs::read(&v0_path).await?;
    let v0_metadata = fs::metadata(&v0_path).await?;
    assert!(!v1_path.exists());

    let key = vec![1; 16];
    let keyring =
        UnlockedKeyring::open_at_with_key(data_dir.path(), "named", Key::new(key.clone())).await?;
    assert_eq!(keyring.n_items().await, 0);
    assert!(!v1_path.exists());
    assert_eq!(fs::read(&v0_path).await?, v0_bytes);
    assert_eq!(fs::metadata(&v0_path).await?.len(), v0_metadata.len());
    assert_eq!(
        fs::metadata(&v0_path).await?.modified()?,
        v0_metadata.modified()?
    );

    keyring
        .create_item("Direct", &[("id", "direct")], "secret", false)
        .await?;
    drop(keyring);
    assert!(v1_path.exists());
    assert_eq!(fs::read(&v0_path).await?, v0_bytes);

    let keyring =
        UnlockedKeyring::open_at_with_key(data_dir.path(), "named", Key::new(key)).await?;
    assert_eq!(
        keyring
            .lookup_item(&[("id", "direct")])
            .await?
            .unwrap()
            .secret(),
        Secret::text("secret")
    );
    drop(keyring);
    assert!(matches!(
        UnlockedKeyring::open_at_with_key(data_dir.path(), "named", Key::new(vec![2; 16])).await,
        Err(Error::IncorrectSecret)
    ));

    Ok(())
}

#[tokio::test]
async fn open_wrong_password() -> Result<(), Error> {
    let data_dir = tempdir()?;
    let v0_dir = data_dir.path().join("keyrings");
    let v1_dir = v0_dir.join("v1");
    fs::create_dir_all(&v1_dir).await?;

    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("default.keyring");
    fs::copy(&fixture_path, &v1_dir.join("default.keyring")).await?;

    let secret = Secret::blob("wrong");
    let keyring = UnlockedKeyring::open_at(data_dir.path(), "default", Some(secret)).await;

    assert!(keyring.is_err());
    assert!(matches!(keyring.unwrap_err(), Error::IncorrectSecret));

    let secret = Secret::blob("test");
    let keyring = UnlockedKeyring::open_at(data_dir.path(), "default", Some(secret)).await;

    assert!(keyring.is_ok());

    Ok(())
}

#[tokio::test]
async fn open() -> Result<(), Error> {
    let data_dir = tempdir()?;
    let v0_dir = data_dir.path().join("keyrings");
    let v1_dir = v0_dir.join("v1");
    fs::create_dir_all(&v1_dir).await?;

    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("default.keyring");
    fs::copy(&fixture_path, &v1_dir.join("default.keyring")).await?;

    let secret = Secret::blob("test");
    let keyring = UnlockedKeyring::open_at(data_dir.path(), "default", Some(secret)).await?;

    assert!(v1_dir.join("default.keyring").exists());

    super::check_items(&keyring).await?;

    keyring.write().await?;
    assert!(v1_dir.join("default.keyring").exists());

    Ok(())
}

#[tokio::test]
async fn open_nonexistent() -> Result<(), Error> {
    let data_dir = tempdir()?;
    let v0_dir = data_dir.path().join("keyrings");
    let v1_dir = v0_dir.join("v1");
    fs::create_dir_all(&v1_dir).await?;

    let secret = Secret::blob("test");
    let keyring = UnlockedKeyring::open_at(data_dir.path(), "default", Some(secret)).await?;

    assert!(!v1_dir.join("default.keyring").exists());

    keyring
        .create_item(
            "foo",
            &[(oo7::XDG_SCHEMA_ATTRIBUTE, "org.gnome.keyring.Note")],
            "foo",
            false,
        )
        .await?;
    keyring.write().await?;

    assert!(v1_dir.join("default.keyring").exists());

    Ok(())
}

#[tokio::test]
async fn change_secret() -> Result<(), Error> {
    let data_dir = tempdir()?;
    let v0_dir = data_dir.path().join("keyrings");
    let v1_dir = v0_dir.join("v1");
    fs::create_dir_all(&v1_dir).await?;

    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("default.keyring");
    let keyring_path = v1_dir.join("default.keyring");
    fs::copy(&fixture_path, &keyring_path).await?;

    let keyring = UnlockedKeyring::load(&keyring_path, Some(Secret::blob("test"))).await?;
    let attributes = &[("attr", "value")];
    let item_before = keyring
        .create_item("test", attributes, "password", false)
        .await?;

    let secret = Secret::blob("new_secret");
    keyring.change_secret(secret).await?;

    let secret = Secret::blob("new_secret");
    let keyring = UnlockedKeyring::load(&keyring_path, Some(secret)).await?;
    let item_now = keyring.lookup_item(attributes).await?.unwrap();

    assert_eq!(item_before.label(), item_now.label());
    assert_eq!(item_before.secret(), item_now.secret());
    assert_eq!(item_before.attributes(), item_now.attributes());

    // No items were broken during the secret change
    assert_eq!(keyring.delete_broken_items().await?, 0);

    fs::remove_file(keyring_path).await?;

    Ok(())
}

#[tokio::test]
async fn wrong_password_error_type() -> Result<(), Error> {
    let temp_dir = tempdir().unwrap();
    let keyring_path = temp_dir.path().join("wrong_password_test.keyring");
    let correct_secret = Secret::from("correct-password-that-is-long-enough".as_bytes());
    let wrong_secret = Secret::from("wrong-password-that-is-long-enough".as_bytes());

    // Create a keyring with the correct password
    let keyring = UnlockedKeyring::load(&keyring_path, Some(correct_secret)).await?;
    keyring
        .create_item("Test Item", &[("app", "test")], "my-secret", false)
        .await?;

    // Try to load with wrong password
    let result = UnlockedKeyring::load(&keyring_path, Some(wrong_secret)).await;

    // Verify this returns IncorrectSecret, not ChecksumMismatch
    assert!(matches!(result, Err(Error::IncorrectSecret)));

    Ok(())
}

#[tokio::test]
async fn empty_keyring_operations() -> Result<(), Error> {
    let temp_dir = tempdir().unwrap();
    let keyring_path = temp_dir.path().join("empty_test.keyring");
    let keyring = UnlockedKeyring::load(&keyring_path, Some(strong_key())).await?;

    // Test operations on empty keyring
    let items = keyring.items().await?;
    assert_eq!(items.len(), 0);

    let search_results = keyring.search_items(&[("any", "thing")]).await?;
    assert_eq!(search_results.len(), 0);

    // Delete on empty keyring should succeed
    keyring.delete(&[("nonexistent", "key")]).await?;

    // Verify still empty after delete
    assert_eq!(keyring.n_items().await, 0);

    // Test lookup on empty keyring
    let lookup_result = keyring.lookup_item(&[("test", "value")]).await?;
    assert!(lookup_result.is_none());

    Ok(())
}
