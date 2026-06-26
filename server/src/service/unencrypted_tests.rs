use oo7::{Secret, file::UnlockedKeyring};
use zbus::zvariant::ObjectPath;

use crate::tests::TestServiceSetup;

#[tokio::test]
async fn discover_unencrypted_keyrings() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;

    let v1_dir = temp_dir.path().join("keyrings/v1");
    tokio::fs::create_dir_all(&v1_dir).await?;

    // Create an unencrypted keyring with items on disk
    let keyring = UnlockedKeyring::open_at(temp_dir.path(), "nopass", None).await?;
    keyring
        .create_item(
            "Unencrypted Item",
            &[("app", "test-unenc")],
            Secret::text("plain-secret"),
            false,
        )
        .await?;
    keyring.write().await?;

    // Discover keyrings without any secret — should find it locked
    let setup =
        TestServiceSetup::with_disk_keyrings(temp_dir.path().to_path_buf(), None, None).await?;

    let collections = setup.server.collections.lock().await;
    let mut nopass_collection = None;
    for collection in collections.values() {
        if collection.label().await == "Nopass" {
            nopass_collection = Some(collection.clone());
            break;
        }
    }
    let nopass_collection = nopass_collection.expect("nopass collection should be discovered");
    assert!(
        nopass_collection.is_locked().await,
        "Should be locked initially"
    );
    drop(collections);

    // Unlock with None (unencrypted)
    nopass_collection.set_locked(false, None).await?;
    assert!(
        !nopass_collection.is_locked().await,
        "Should be unlocked after set_locked(false, None)"
    );

    // Verify items are accessible
    let keyring_guard = nopass_collection.keyring.read().await;
    let unlocked = keyring_guard.as_ref().unwrap().as_unlocked();
    let items = unlocked.search_items(&[("app", "test-unenc")]).await?;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].label(), "Unencrypted Item");
    assert_eq!(items[0].secret(), Secret::text("plain-secret"));

    Ok(())
}

#[tokio::test]
async fn complete_collection_creation_unencrypted() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;

    let v1_dir = temp_dir.path().join("keyrings/v1");
    tokio::fs::create_dir_all(&v1_dir).await?;

    let setup =
        TestServiceSetup::with_disk_keyrings(temp_dir.path().to_path_buf(), None, None).await?;

    // Register a pending collection creation
    let prompt_path = ObjectPath::try_from("/org/freedesktop/secrets/prompt/p_unenc_test").unwrap();
    setup.server.pending_collections.lock().await.insert(
        prompt_path.to_owned().into(),
        ("Unenc".into(), "unenc".into()),
    );

    // Complete with None secret
    let collection_path = setup
        .server
        .complete_collection_creation(&prompt_path, None)
        .await?;

    // Verify the collection exists and is unlocked
    let collection = setup
        .server
        .collection_from_path(&ObjectPath::try_from(collection_path.as_str()).unwrap())
        .await
        .expect("collection should exist");

    assert!(
        !collection.is_locked().await,
        "Newly created unencrypted collection should be unlocked"
    );

    // Add an item and verify it works
    let keyring_guard = collection.keyring.read().await;
    let unlocked = keyring_guard.as_ref().unwrap().as_unlocked();
    unlocked
        .create_item(
            "Test Item",
            &[("created", "unenc-test")],
            Secret::text("test-value"),
            false,
        )
        .await?;

    let items = unlocked.search_items(&[("created", "unenc-test")]).await?;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].secret(), Secret::text("test-value"));

    Ok(())
}
