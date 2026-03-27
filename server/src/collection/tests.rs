use std::sync::Arc;

use oo7::dbus;
use tokio_stream::StreamExt;

use crate::tests::{TestServiceSetup, gnome_prompter_test, plasma_prompter_test};

#[tokio::test]
async fn create_item_plain() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Get initial modified timestamp
    let initial_modified = setup.collections[0].modified().await?;

    // Wait to ensure timestamp will be different
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Create an item
    let item = setup
        .create_item(
            "Test Item",
            &[("application", "test-app"), ("type", "password")],
            "my-secret-password",
            false,
        )
        .await?;

    // Verify item exists in collection
    let items = setup.collections[0].items().await?;
    assert_eq!(items.len(), 1, "Collection should have one item");
    assert_eq!(items[0].inner().path(), item.inner().path());

    // Verify item label
    let label = item.label().await?;
    assert_eq!(label, "Test Item");

    // Verify modified timestamp was updated
    let new_modified = setup.collections[0].modified().await?;
    assert!(
        new_modified > initial_modified,
        "Modified timestamp should be updated after creating item"
    );

    Ok(())
}

#[tokio::test]
async fn create_item_encrypted() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::encrypted_session(true).await?;

    // Create an encrypted item using the helper (automatically handles encryption)
    let item = setup
        .create_item(
            "Test Encrypted Item",
            &[("application", "test-app"), ("type", "encrypted-password")],
            "my-encrypted-secret",
            false,
        )
        .await?;

    // Verify item exists
    let items = setup.collections[0].items().await?;
    assert_eq!(items.len(), 1, "Collection should have one item");
    assert_eq!(items[0].inner().path(), item.inner().path());

    Ok(())
}

#[tokio::test]
async fn search_items_after_creation() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Create two items with different attributes
    setup
        .create_item(
            "Firefox Password",
            &[("application", "firefox"), ("username", "user1")],
            "password1",
            false,
        )
        .await?;

    setup
        .create_item(
            "Chrome Password",
            &[("application", "chrome"), ("username", "user2")],
            "password2",
            false,
        )
        .await?;

    // Search for firefox item
    let firefox_attrs = &[("application", "firefox")];
    let firefox_items = setup.collections[0].search_items(firefox_attrs).await?;

    assert_eq!(firefox_items.len(), 1, "Should find one firefox item");

    // Search for chrome item
    let chrome_items = setup.collections[0]
        .search_items(&[("application", "chrome")])
        .await?;

    assert_eq!(chrome_items.len(), 1, "Should find one chrome item");

    // Search for non-existent item
    let nonexistent_items = setup.collections[0]
        .search_items(&[("application", "nonexistent")])
        .await?;

    assert_eq!(
        nonexistent_items.len(),
        0,
        "Should find no nonexistent items"
    );

    Ok(())
}

#[tokio::test]
async fn search_items_subset_matching() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Create an item with multiple attributes (url and username)
    setup
        .create_item(
            "Zed Login",
            &[("url", "https://zed.dev"), ("username", "alice")],
            "my-password",
            false,
        )
        .await?;

    // Search with only the url attribute (subset of stored attributes)
    let results = setup.collections[0]
        .search_items(&[("url", "https://zed.dev")])
        .await?;

    assert_eq!(
        results.len(),
        1,
        "Should find item when searching with subset of its attributes"
    );

    // Search with only the username attribute (another subset)
    let results = setup.collections[0]
        .search_items(&[("username", "alice")])
        .await?;

    assert_eq!(
        results.len(),
        1,
        "Should find item when searching with different subset of its attributes"
    );

    // Search with both attributes (exact match)
    let results = setup.collections[0]
        .search_items(&[("url", "https://zed.dev"), ("username", "alice")])
        .await?;

    assert_eq!(
        results.len(),
        1,
        "Should find item when searching with all its attributes"
    );

    // Search with superset of attributes (should not match)
    let results = setup.collections[0]
        .search_items(&[
            ("url", "https://zed.dev"),
            ("username", "alice"),
            ("extra", "attribute"),
        ])
        .await?;

    assert_eq!(
        results.len(),
        0,
        "Should not find item when searching with superset of its attributes"
    );

    Ok(())
}

#[tokio::test]
async fn create_item_with_replace() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Create first item
    let secret1 = oo7::Secret::text("original-password");
    let item1 = setup
        .create_item(
            "Test Item",
            &[("application", "myapp"), ("username", "user")],
            secret1.clone(),
            false,
        )
        .await?;

    // Verify one item exists
    let items = setup.collections[0].items().await?;
    assert_eq!(items.len(), 1, "Should have one item");

    // Get the secret from first item
    let retrieved1 = item1.secret(&setup.session).await?;
    assert_eq!(retrieved1.value(), secret1.as_bytes());

    // Create second item with same attributes and replace=true
    let secret2 = oo7::Secret::text("replaced-password");
    let item2 = setup
        .create_item(
            "Test Item",
            &[("application", "myapp"), ("username", "user")],
            secret2.clone(),
            true, // replace=true
        )
        .await?;

    // Should still have only one item (replaced)
    let items = setup.collections[0].items().await?;
    assert_eq!(items.len(), 1, "Should still have one item after replace");

    // Verify the new item has the updated secret
    let retrieved2 = item2.secret(&setup.session).await?;
    assert_eq!(retrieved2.value(), secret2.as_bytes());

    Ok(())
}

#[tokio::test]
async fn label_property() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Get the Login collection via alias (don't rely on collection ordering)
    let login_collection = setup
        .service_api
        .read_alias("default")
        .await?
        .expect("Default collection should exist");

    // Get initial label (should be "Login" for default collection)
    let label = login_collection.label().await?;
    assert_eq!(label, "Login");

    // Get initial modified timestamp
    let initial_modified = login_collection.modified().await?;

    // Wait to ensure timestamp will be different
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Set new label
    login_collection.set_label("My Custom Collection").await?;

    // Verify new label
    let label = login_collection.label().await?;
    assert_eq!(label, "My Custom Collection");

    // Verify modified timestamp was updated
    let new_modified = login_collection.modified().await?;
    assert!(
        new_modified > initial_modified,
        "Modified timestamp should be updated after label change"
    );

    Ok(())
}

#[tokio::test]
async fn timestamps() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Get created timestamp
    let created = setup.collections[0].created().await?;
    assert!(created.as_secs() > 0, "Created timestamp should be set");

    // Get modified timestamp
    let modified = setup.collections[0].modified().await?;
    assert!(modified.as_secs() > 0, "Modified timestamp should be set");

    // Created and modified should be close (within a second for new collection)
    let diff = if created > modified {
        created.as_secs() - modified.as_secs()
    } else {
        modified.as_secs() - created.as_secs()
    };
    assert!(diff <= 1, "Created and modified should be within 1 second");

    Ok(())
}

#[tokio::test]
async fn create_item_invalid_session() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Create an item using the proper API
    let secret = oo7::Secret::text("my-secret-password");
    let invalid_session =
        dbus::api::Session::new(&setup.client_conn, "/invalid/session/path").await?;
    let dbus_secret = dbus::api::DBusSecret::new(Arc::new(invalid_session), secret.clone());

    let result = setup.collections[0]
        .create_item(
            "Test Item",
            &[("application", "test-app"), ("type", "password")],
            &dbus_secret,
            false,
            None,
        )
        .await;

    assert!(
        matches!(
            result,
            Err(oo7::dbus::Error::Service(
                oo7::dbus::ServiceError::NoSession(_)
            ))
        ),
        "Should be NoSession error"
    );

    Ok(())
}

#[tokio::test]
async fn item_created_signal() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Subscribe to ItemCreated signal
    let signal_stream = setup.collections[0].receive_item_created().await?;
    tokio::pin!(signal_stream);

    // Create an item
    let item = setup
        .create_item("Test Item", &[("app", "test")], "test-secret", false)
        .await?;

    // Wait for signal with timeout
    let signal_result =
        tokio::time::timeout(tokio::time::Duration::from_secs(1), signal_stream.next()).await;

    assert!(signal_result.is_ok(), "Should receive ItemCreated signal");
    let signal = signal_result.unwrap();
    assert!(signal.is_some(), "Signal should not be None");

    let signal_item = signal.unwrap();
    assert_eq!(
        signal_item.inner().path().as_str(),
        item.inner().path().as_str(),
        "Signal should contain the created item path"
    );

    Ok(())
}

#[tokio::test]
async fn item_deleted_signal() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Create an item
    let item = setup
        .create_item("Test Item", &[("app", "test")], "test-secret", false)
        .await?;

    let item_path = item.inner().path().to_owned();

    // Subscribe to ItemDeleted signal
    let signal_stream = setup.collections[0].receive_item_deleted().await?;
    tokio::pin!(signal_stream);

    // Delete the item
    item.delete(None).await?;

    // Wait for signal with timeout
    let signal_result =
        tokio::time::timeout(tokio::time::Duration::from_secs(1), signal_stream.next()).await;

    assert!(signal_result.is_ok(), "Should receive ItemDeleted signal");
    let signal = signal_result.unwrap();
    assert!(signal.is_some(), "Signal should not be None");

    let signal_item = signal.unwrap();
    assert_eq!(
        signal_item.as_str(),
        item_path.as_str(),
        "Signal should contain the deleted item path"
    );

    Ok(())
}

#[tokio::test]
async fn collection_changed_signal() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Subscribe to CollectionChanged signal
    let signal_stream = setup.service_api.receive_collection_changed().await?;
    tokio::pin!(signal_stream);

    // Change the collection label
    setup.collections[0]
        .set_label("Updated Collection Label")
        .await?;

    // Wait for signal with timeout
    let signal_result =
        tokio::time::timeout(tokio::time::Duration::from_secs(1), signal_stream.next()).await;

    assert!(
        signal_result.is_ok(),
        "Should receive CollectionChanged signal after label change"
    );
    let signal = signal_result.unwrap();
    assert!(signal.is_some(), "Signal should not be None");

    let signal_collection = signal.unwrap();
    assert_eq!(
        signal_collection.inner().path().as_str(),
        setup.collections[0].inner().path().as_str(),
        "Signal should contain the changed collection path"
    );

    Ok(())
}

#[tokio::test]
async fn delete_collection() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Create some items in the collection
    setup
        .create_item("Item 1", &[("app", "test")], "password1", false)
        .await?;

    setup
        .create_item("Item 2", &[("app", "test")], "password2", false)
        .await?;

    // Verify items were created
    let items = setup.collections[0].items().await?;
    assert_eq!(items.len(), 2, "Should have 2 items before deletion");

    // Get collection path for later verification
    let collection_path = setup.collections[0].inner().path().to_owned();

    // Verify collection exists in service
    let collections_before = setup.service_api.collections().await?;
    let initial_count = collections_before.len();

    // Delete the collection
    setup.collections[0].delete(None).await?;

    // Give the system a moment to process the deletion
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Verify collection is no longer in service's collection list
    let collections_after = setup.service_api.collections().await?;
    assert_eq!(
        collections_after.len(),
        initial_count - 1,
        "Service should have one less collection after deletion"
    );

    // Verify the specific collection is not in the list
    let collection_paths: Vec<_> = collections_after
        .iter()
        .map(|c| c.inner().path().as_str())
        .collect();
    assert!(
        !collection_paths.contains(&collection_path.as_str()),
        "Deleted collection should not be in service collections list"
    );

    Ok(())
}

#[tokio::test]
async fn collection_deleted_signal() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Subscribe to CollectionDeleted signal
    let signal_stream = setup.service_api.receive_collection_deleted().await?;
    tokio::pin!(signal_stream);

    let collection_path = setup.collections[0].inner().path().to_owned();

    // Delete the collection
    setup.collections[0].delete(None).await?;

    // Wait for signal with timeout
    let signal_result =
        tokio::time::timeout(tokio::time::Duration::from_secs(1), signal_stream.next()).await;

    assert!(
        signal_result.is_ok(),
        "Should receive CollectionDeleted signal"
    );
    let signal = signal_result.unwrap();
    assert!(signal.is_some(), "Signal should not be None");

    let signal_collection = signal.unwrap();
    assert_eq!(
        signal_collection.as_str(),
        collection_path.as_str(),
        "Signal should contain the deleted collection path"
    );

    Ok(())
}

gnome_prompter_test!(
    create_item_in_locked_collection_gnome,
    create_item_in_locked_collection
);
plasma_prompter_test!(
    create_item_in_locked_collection_plasma,
    create_item_in_locked_collection
);

async fn create_item_in_locked_collection() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    let collection = setup
        .server
        .collection_from_path(setup.collections[0].inner().path())
        .await
        .expect("Collection should exist");
    collection
        .set_locked(true, setup.keyring_secret.clone())
        .await?;

    assert!(
        setup.collections[0].is_locked().await?,
        "Collection should be locked"
    );

    let secret = oo7::Secret::text("test-password");
    let item = setup
        .create_item(
            "Test Item",
            &[("app", "test"), ("type", "password")],
            secret.clone(),
            false,
        )
        .await?;

    assert!(
        !setup.collections[0].is_locked().await?,
        "Collection should be unlocked after prompt"
    );

    let items = setup.collections[0].items().await?;
    assert_eq!(items.len(), 1, "Collection should have one item");
    assert_eq!(
        items[0].inner().path(),
        item.inner().path(),
        "Created item should be in the collection"
    );

    let label = item.label().await?;
    assert_eq!(label, "Test Item", "Item should have correct label");

    let attributes = item.attributes().await?;
    assert_eq!(attributes.get("app"), Some(&"test".to_string()));
    assert_eq!(attributes.get("type"), Some(&"password".to_string()));

    let retrieved_secret = item.secret(&setup.session).await?;
    assert_eq!(retrieved_secret.value(), secret.as_bytes());

    Ok(())
}

gnome_prompter_test!(
    delete_locked_collection_with_prompt_gnome,
    delete_locked_collection_with_prompt
);
plasma_prompter_test!(
    delete_locked_collection_with_prompt_plasma,
    delete_locked_collection_with_prompt
);

async fn delete_locked_collection_with_prompt() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    let default_collection = setup.default_collection().await?;

    let collection = setup
        .server
        .collection_from_path(default_collection.inner().path())
        .await
        .expect("Collection should exist");
    collection
        .set_locked(true, setup.keyring_secret.clone())
        .await?;

    assert!(
        default_collection.is_locked().await?,
        "Collection should be locked"
    );

    let collection_path = default_collection.inner().path().to_owned();

    // Get initial collection count
    let collections_before = setup.service_api.collections().await?;
    let initial_count = collections_before.len();

    // Delete the locked collection
    default_collection.delete(None).await?;

    // Give the system a moment to process the deletion
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Verify collection was deleted
    let collections_after = setup.service_api.collections().await?;
    assert_eq!(
        collections_after.len(),
        initial_count - 1,
        "Collection should be deleted after prompt"
    );

    // Verify the specific collection is not in the list
    let collection_paths: Vec<_> = collections_after
        .iter()
        .map(|c| c.inner().path().as_str())
        .collect();
    assert!(
        !collection_paths.contains(&collection_path.as_str()),
        "Deleted collection should not be in service collections list"
    );

    Ok(())
}

gnome_prompter_test!(unlock_retry_gnome, unlock_retry);
plasma_prompter_test!(unlock_retry_plasma, unlock_retry);

async fn unlock_retry() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    let default_collection = setup.default_collection().await?;

    let secret = oo7::Secret::text("test-secret-data");
    let dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret);
    default_collection
        .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
        .await?;

    let collection = setup
        .server
        .collection_from_path(default_collection.inner().path())
        .await
        .expect("Collection should exist");
    collection
        .set_locked(true, setup.keyring_secret.clone())
        .await?;

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

#[tokio::test]
async fn locked_collection_operations() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Verify collection is unlocked initially
    assert!(
        !setup.collections[0].is_locked().await?,
        "Collection should start unlocked"
    );

    // Lock the collection
    let collection = setup
        .server
        .collection_from_path(setup.collections[0].inner().path())
        .await
        .expect("Collection should exist");
    collection
        .set_locked(true, setup.keyring_secret.clone())
        .await?;

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
