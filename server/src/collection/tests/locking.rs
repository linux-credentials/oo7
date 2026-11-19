use crate::{service::PrompterType, tests::TestServiceSetup};

async fn unlock_retry_impl(prompter_type: PrompterType) -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    setup.server.set_prompter_type(prompter_type).await;
    let default_collection = &setup.collections[0];

    let dbus_secret = setup.create_dbus_secret("test-secret-data")?;
    default_collection
        .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
        .await?;

    setup.lock_collection(default_collection).await?;

    assert!(
        default_collection.is_locked().await?,
        "Collection should be locked"
    );

    setup
        .set_password_queue(vec![
            oo7::Secret::from("wrong-password"),
            oo7::Secret::from("wrong-password2"),
            oo7::Secret::from("test-password-long-enough"),
        ])
        .await;

    let unlocked = setup
        .service_api
        .unlock(&[default_collection.inner().path()], None)
        .await?;

    assert_eq!(unlocked.len(), 1, "Should have unlocked 1 collection");
    assert_eq!(
        unlocked[0].as_str(),
        default_collection.inner().path().as_str(),
        "Should return the collection path"
    );
    assert!(
        !default_collection.is_locked().await?,
        "Collection should be unlocked after retry with correct password"
    );

    Ok(())
}

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[tokio::test]
async fn unlock_retry_gnome() -> Result<(), Box<dyn std::error::Error>> {
    unlock_retry_impl(PrompterType::GNOME).await
}

#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
#[tokio::test]
async fn unlock_retry_plasma() -> Result<(), Box<dyn std::error::Error>> {
    unlock_retry_impl(PrompterType::Plasma).await
}

#[tokio::test]
async fn locked_collection_operations() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Verify collection is unlocked initially
    assert!(
        !setup.collections[0].is_locked().await?,
        "Collection should start unlocked"
    );

    // Lock the collection
    setup.lock_collection(&setup.collections[0]).await?;

    // Verify collection is now locked
    assert!(
        setup.collections[0].is_locked().await?,
        "Collection should be locked"
    );

    // Test 1: set_label should fail with IsLocked
    let result = setup.collections[0].set_label("New Label").await;
    assert!(
        matches!(result, Err(oo7::dbus::Error::ZBus(zbus::Error::FDO(_)))),
        "set_label should fail with IsLocked error, got: {:?}",
        result
    );

    // Verify read-only operations still work on locked collections
    assert!(
        setup.collections[0].label().await.is_ok(),
        "Should be able to read label of locked collection"
    );

    let items = setup.collections[0].items().await?;
    assert!(
        items.is_empty(),
        "Should be able to read items (empty) from locked collection"
    );

    Ok(())
}

// A failed unlock must not brick the collection when the keyring file
// can no longer be read from disk
enum KeyringDamage {
    Corrupted,
    Deleted,
}

async fn unlock_after_keyring_file_is_damaged(
    damage: KeyringDamage,
) -> Result<(), Box<dyn std::error::Error>> {
    use oo7::{Secret, file::UnlockedKeyring};

    let temp_dir = tempfile::tempdir()?;
    let secret = Secret::from("test-password-long-enough");
    let keyring = UnlockedKeyring::open_at(temp_dir.path(), "login", Some(secret.clone())).await?;
    keyring
        .create_item(
            "Test Item",
            &[("app", "test")],
            Secret::text("item-secret"),
            false,
        )
        .await?;
    keyring.write().await?;

    let setup = TestServiceSetup::with_disk_keyrings(
        temp_dir.path().to_path_buf(),
        None,
        Some(secret.clone()),
    )
    .await?;

    let collection = setup
        .server
        .collection_from_path(
            setup
                .service_api
                .read_alias("default")
                .await?
                .expect("default collection should exist")
                .inner()
                .path(),
        )
        .await
        .expect("collection should exist");

    // Damage the keyring file behind the daemon's back
    let keyring_path = temp_dir.path().join("keyrings/v1/login.keyring");
    match damage {
        KeyringDamage::Corrupted => tokio::fs::write(&keyring_path, b"corrupted").await?,
        KeyringDamage::Deleted => tokio::fs::remove_file(&keyring_path).await?,
    }

    collection.set_locked(true, None).await?;
    assert!(collection.is_locked().await);

    // A wrong secret fails and leaves the collection locked
    assert!(
        collection
            .set_locked(false, Some(Secret::from("wrong-password")))
            .await
            .is_err()
    );
    assert!(collection.is_locked().await);

    // The correct secret still unlocks the in-memory keyring, with its
    // items
    collection.set_locked(false, Some(secret)).await?;
    assert!(!collection.is_locked().await);
    let found = collection
        .search_inner_items(&std::collections::HashMap::from([(
            "app".to_string(),
            "test".to_string(),
        )]))
        .await?;
    assert_eq!(found.len(), 1, "The in-memory items should have survived");

    Ok(())
}

#[tokio::test]
async fn unlock_after_keyring_file_is_corrupted() -> Result<(), Box<dyn std::error::Error>> {
    unlock_after_keyring_file_is_damaged(KeyringDamage::Corrupted).await
}

#[tokio::test]
async fn unlock_after_keyring_file_is_deleted() -> Result<(), Box<dyn std::error::Error>> {
    unlock_after_keyring_file_is_damaged(KeyringDamage::Deleted).await
}
