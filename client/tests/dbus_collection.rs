use futures_util::StreamExt;
use oo7::dbus::Service;

async fn create_item(service: Service, encrypted: bool) {
    let attributes = if encrypted {
        &[("type", "encrypted-type-test")]
    } else {
        &[("type", "plain-type-test")]
    };
    let secret = oo7::Secret::text("a password");

    let collection = service.default_collection().await.unwrap();
    let n_search_items = collection.search_items(&attributes).await.unwrap().len();

    let item = collection
        .create_item("A secret", &attributes, secret.clone(), true, None)
        .await
        .unwrap();

    assert_eq!(item.secret().await.unwrap(), secret);
    assert_eq!(
        item.attributes().await.unwrap().get("type").unwrap(),
        attributes[0].1,
    );

    assert_eq!(
        collection.search_items(&attributes).await.unwrap().len(),
        n_search_items + 1
    );

    item.delete(None).await.unwrap();

    assert_eq!(
        collection.search_items(&attributes).await.unwrap().len(),
        n_search_items
    );
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn create_plain_item() {
    let setup = oo7_server::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();
    create_item(service, false).await;
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn create_encrypted_item() {
    let setup = oo7_server::tests::TestServiceSetup::encrypted_session(true)
        .await
        .unwrap();
    let service = Service::encrypted_with_connection(&setup.client_conn)
        .await
        .unwrap();
    create_item(service, true).await;
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn attribute_search_patterns() {
    let setup = oo7_server::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();
    let collection = service.default_collection().await.unwrap();

    let secret = oo7::Secret::text("search test");

    // Create items with unique test attributes
    let item1 = collection
        .create_item(
            "Pattern Test 1",
            &[("test-pattern", "pattern-test-a"), ("category", "group1")],
            secret.clone(),
            true,
            None,
        )
        .await
        .unwrap();

    let item2 = collection
        .create_item(
            "Pattern Test 2",
            &[("test-pattern", "pattern-test-a"), ("category", "group2")],
            secret.clone(),
            true,
            None,
        )
        .await
        .unwrap();

    let item3 = collection
        .create_item(
            "Pattern Test 3",
            &[("test-pattern", "pattern-test-b"), ("category", "group1")],
            secret.clone(),
            true,
            None,
        )
        .await
        .unwrap();

    // Search by test-pattern - should find items with pattern-test-a
    let pattern_a_items = collection
        .search_items(&[("test-pattern", "pattern-test-a")])
        .await
        .unwrap();
    let found_paths: std::collections::HashSet<_> =
        pattern_a_items.iter().map(|item| item.path()).collect();
    assert!(found_paths.contains(item1.path()));
    assert!(found_paths.contains(item2.path()));

    // Search by category - should find items in group1
    let group1_items = collection
        .search_items(&[("category", "group1")])
        .await
        .unwrap();
    let found_group1_paths: std::collections::HashSet<_> =
        group1_items.iter().map(|item| item.path()).collect();
    assert!(found_group1_paths.contains(item1.path()));
    assert!(found_group1_paths.contains(item3.path()));

    // Search by both attributes - should find only item1
    let specific_items = collection
        .search_items(&[("test-pattern", "pattern-test-a"), ("category", "group1")])
        .await
        .unwrap();
    let found_specific_paths: std::collections::HashSet<_> =
        specific_items.iter().map(|item| item.path()).collect();
    assert!(found_specific_paths.contains(item1.path()));

    item1.delete(None).await.unwrap();
    item2.delete(None).await.unwrap();
    item3.delete(None).await.unwrap();
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn items() {
    let setup = oo7_server::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();
    let collection = service.default_collection().await.unwrap();

    let secret = oo7::Secret::text("items test");

    // Create some test items with unique attributes
    let item1 = collection
        .create_item(
            "Test Item 1",
            &[("test", "items-test-1"), ("unique", "test-1")],
            secret.clone(),
            true,
            None,
        )
        .await
        .unwrap();

    let item2 = collection
        .create_item(
            "Test Item 2",
            &[("test", "items-test-2"), ("unique", "test-2")],
            secret.clone(),
            true,
            None,
        )
        .await
        .unwrap();

    // Get all items and verify our items are included by path
    let all_items = collection.items().await.unwrap();
    let item_paths: std::collections::HashSet<_> =
        all_items.iter().map(|item| item.path()).collect();

    assert!(item_paths.contains(item1.path()));
    assert!(item_paths.contains(item2.path()));

    // Clean up
    item1.delete(None).await.unwrap();
    item2.delete(None).await.unwrap();
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn label_mutation() {
    let setup = oo7_server::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();
    let collection = service.session_collection().await.unwrap();

    let initial_label = collection.label().await.unwrap();

    collection.set_label("Updated Label").await.unwrap();
    assert_eq!(collection.label().await.unwrap(), "Updated Label");
    assert_ne!(collection.label().await.unwrap(), initial_label);

    // Restore original label
    collection.set_label(&initial_label).await.unwrap();
    assert_eq!(collection.label().await.unwrap(), initial_label);
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn collections_list() {
    let setup = oo7_server::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();

    let collection1 = service
        .create_collection("Collection One", None, None)
        .await
        .unwrap();
    let collection2 = service
        .create_collection("Collection Two", None, None)
        .await
        .unwrap();

    let collections = service.collections().await.unwrap();
    // Should have at least our 2 collections plus the default collection
    assert!(collections.len() >= 3);

    // Verify our collections are in the list
    let labels: Vec<String> = futures_util::future::join_all(collections.iter().map(|c| c.label()))
        .await
        .into_iter()
        .filter_map(Result::ok)
        .collect();

    assert!(labels.contains(&"Collection One".to_string()));
    assert!(labels.contains(&"Collection Two".to_string()));

    collection1.delete(None).await.unwrap();
    collection2.delete(None).await.unwrap();
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn with_alias() {
    let setup = oo7_server::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();

    // Default alias should exist
    let default_collection = service
        .with_alias(Service::DEFAULT_COLLECTION)
        .await
        .unwrap();
    assert!(default_collection.is_some());

    // Create a collection with a custom alias
    let collection = service
        .create_collection("Aliased Collection", Some("custom-alias"), None)
        .await
        .unwrap();

    // Should be able to find it by alias
    let found = service.with_alias("custom-alias").await.unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().label().await.unwrap(), "Aliased Collection");

    // Non-existent alias should return None
    let not_found = service.with_alias("nonexistent-alias").await.unwrap();
    assert!(not_found.is_none());

    collection.delete(None).await.unwrap();
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn timestamps() {
    let setup = oo7_server::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();

    let collection = service
        .create_collection("Timestamp Test", None, None)
        .await
        .unwrap();

    let created = collection.created().await.unwrap();
    let modified = collection.modified().await.unwrap();

    // Created timestamp should be a valid UNIX timestamp
    assert!(created.as_secs() > 0);
    // Modified should be >= created
    assert!(modified >= created);

    // Modify the collection
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    collection.set_label("Modified Label").await.unwrap();

    let new_modified = collection.modified().await.unwrap();
    // Modified timestamp should have increased
    assert!(new_modified >= modified);

    collection.delete(None).await.unwrap();
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn deleted_error() {
    let setup = oo7_server::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();

    let collection = service
        .create_collection("Delete Error Test", None, None)
        .await
        .unwrap();

    // Verify collection works before deletion
    assert!(collection.label().await.is_ok());

    // Delete the collection
    collection.delete(None).await.unwrap();

    // All operations should now return Error::Deleted
    assert!(matches!(
        collection.label().await,
        Err(oo7::dbus::Error::Deleted)
    ));
    assert!(matches!(
        collection.set_label("New").await,
        Err(oo7::dbus::Error::Deleted)
    ));
    assert!(matches!(
        collection.items().await,
        Err(oo7::dbus::Error::Deleted)
    ));
    assert!(matches!(
        collection.search_items(&[("test", "test")]).await,
        Err(oo7::dbus::Error::Deleted)
    ));
    assert!(matches!(
        collection
            .create_item("test", &[("test", "test")], "secret", true, None)
            .await,
        Err(oo7::dbus::Error::Deleted)
    ));
    assert!(matches!(
        collection.created().await,
        Err(oo7::dbus::Error::Deleted)
    ));
    assert!(matches!(
        collection.modified().await,
        Err(oo7::dbus::Error::Deleted)
    ));
    assert!(matches!(
        collection.is_locked().await,
        Err(oo7::dbus::Error::Deleted)
    ));
    assert!(matches!(
        collection.lock(None).await,
        Err(oo7::dbus::Error::Deleted)
    ));
    assert!(matches!(
        collection.unlock(None).await,
        Err(oo7::dbus::Error::Deleted)
    ));
    assert!(matches!(
        collection.delete(None).await,
        Err(oo7::dbus::Error::Deleted)
    ));
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn lock_unlock() {
    let setup = oo7_server::tests::TestServiceSetup::plain_session(false)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();

    let collection = service
        .create_collection("Lock Collection", None, None)
        .await
        .unwrap();

    // Collection should start unlocked
    assert!(!collection.is_locked().await.unwrap());

    // Lock the collection
    collection.lock(None).await.unwrap();
    assert!(collection.is_locked().await.unwrap());

    // Unlock the collection
    collection.unlock(None).await.unwrap();
    assert!(!collection.is_locked().await.unwrap());

    collection.delete(None).await.unwrap();
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn item_created_signal() {
    let setup = oo7_server::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();
    let collection = service.default_collection().await.unwrap();

    // Setup signal stream before creating item
    let created_stream = collection.receive_item_created().await.unwrap();
    tokio::pin!(created_stream);

    // Create an item in a separate task
    let collection_clone = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap()
        .default_collection()
        .await
        .unwrap();
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        let _ = collection_clone
            .create_item(
                "Signal Test",
                &[("test", "signals")],
                oo7::Secret::text("test"),
                true,
                None,
            )
            .await;
    });

    // Wait for the signal
    tokio::select! {
        Some(item) = created_stream.next() => {
            assert_eq!(item.label().await.unwrap(), "Signal Test");
            item.delete(None).await.unwrap();
        }
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {
            panic!("Timeout waiting for item created signal");
        }
    }
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn item_changed_signal() {
    let setup = oo7_server::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();
    let collection = service.default_collection().await.unwrap();

    let item = collection
        .create_item(
            "Change Test",
            &[("test", "change-signal")],
            oo7::Secret::text("test"),
            true,
            None,
        )
        .await
        .unwrap();

    // Setup signal stream
    let changed_stream = collection.receive_item_changed().await.unwrap();
    tokio::pin!(changed_stream);

    // Get a path reference before moving
    let item_path = item.path().to_owned();

    // Modify the item in a separate task
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        let _ = item.set_label("Modified Label").await;
    });

    // Wait for the signal
    tokio::select! {
        Some(changed_item) = changed_stream.next() => {
            assert_eq!(changed_item.label().await.unwrap(), "Modified Label");
            assert_eq!(changed_item.path(), &item_path);
            changed_item.delete(None).await.unwrap();
        }
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {
            panic!("Timeout waiting for item changed signal");
        }
    }
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn item_deleted_signal() {
    let setup = oo7_server::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();
    let collection = service.default_collection().await.unwrap();

    let item = collection
        .create_item(
            "Delete Test",
            &[("test", "delete-signal")],
            oo7::Secret::text("test"),
            true,
            None,
        )
        .await
        .unwrap();

    // Setup signal stream
    let deleted_stream = collection.receive_item_deleted().await.unwrap();
    tokio::pin!(deleted_stream);

    // Delete the item in a separate task
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        let _ = item.delete(None).await;
    });

    // Wait for the signal
    tokio::select! {
        Some(_deleted_path) = deleted_stream.next() => {
            // Signal received successfully
        }
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {
            panic!("Timeout waiting for item deleted signal");
        }
    }
}
