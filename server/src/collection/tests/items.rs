use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

use oo7::dbus;

use crate::{
    service::PrompterType,
    tests::{TestServiceSetup, assert_next_signal},
};

#[tokio::test]
async fn create_item_plain() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Get initial modified timestamp
    let initial_modified = setup.collections[0].modified().await?;

    // Wait to ensure timestamp will be different
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Subscribe to ItemCreated signal before creating
    let signal_stream = setup.collections[0].receive_item_created().await?;
    tokio::pin!(signal_stream);

    // Create an item
    let item = setup
        .create_item(
            "Test Item",
            &[("application", "test-app"), ("type", "password")],
            "my-secret-password",
            false,
        )
        .await?;

    // Verify ItemCreated signal was emitted
    let signal_item = assert_next_signal(&mut signal_stream).await;
    assert_eq!(
        signal_item.inner().path().as_str(),
        item.inner().path().as_str(),
        "Signal should contain the created item path"
    );

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

    // Create an encrypted item using the helper (automatically handles
    // encryption)
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
async fn create_item_with_replace_after_content_type_change()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    let attributes = &[("application", "browser"), ("account", "alice")];

    // A migrated GNOME Keyring item can be a blob, even when a subsequent
    // secret-tool store sends the same attributes with a text/plain secret.
    setup
        .create_item("Imported", attributes, oo7::Secret::blob(b"old"), false)
        .await?;
    let replacement = setup
        .create_item("Updated", attributes, oo7::Secret::text("new"), true)
        .await?;

    assert_eq!(setup.collections[0].items().await?.len(), 1);
    assert_eq!(replacement.secret(&setup.session).await?.value(), b"new");
    Ok(())
}

#[tokio::test]
async fn create_item_with_replace_matches_attributes() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    setup
        .create_item(
            "Alice",
            &[("application", "myapp"), ("username", "alice")],
            "alice-password",
            false,
        )
        .await?;
    setup
        .create_item(
            "Bob",
            &[("application", "myapp"), ("username", "bob")],
            "bob-password",
            false,
        )
        .await?;

    // A coarser attribute set must not replace either item.
    setup
        .create_item(
            "Coarse",
            &[("application", "myapp")],
            "coarse-password",
            true,
        )
        .await?;

    let items = setup.collections[0].items().await?;
    assert_eq!(items.len(), 3);
    assert_eq!(
        setup.collections[0]
            .search_items(&[("application", "myapp"), ("username", "alice")])
            .await?
            .len(),
        1
    );
    assert_eq!(
        setup.collections[0]
            .search_items(&[("application", "myapp"), ("username", "bob")])
            .await?
            .len(),
        1
    );

    // Replacing the coarse item must not add a duplicate.
    setup
        .create_item(
            "Updated Coarse",
            &[("application", "myapp")],
            "updated-coarse-password",
            true,
        )
        .await?;

    let items = setup.collections[0].items().await?;
    assert_eq!(items.len(), 3);

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

    let signal_item = assert_next_signal(&mut signal_stream).await;
    assert_eq!(
        signal_item.as_str(),
        item_path.as_str(),
        "Signal should contain the deleted item path"
    );

    Ok(())
}

async fn create_item_in_locked_collection_impl(
    prompter_type: PrompterType,
) -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    setup.server.set_prompter_type(prompter_type).await;

    setup.lock_collection(&setup.collections[0]).await?;

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

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[tokio::test]
async fn create_item_in_locked_collection_gnome() -> Result<(), Box<dyn std::error::Error>> {
    create_item_in_locked_collection_impl(PrompterType::GNOME).await
}

#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
#[tokio::test]
async fn create_item_in_locked_collection_plasma() -> Result<(), Box<dyn std::error::Error>> {
    create_item_in_locked_collection_impl(PrompterType::Plasma).await
}

// https://github.com/linux-credentials/oo7/issues/652
#[tokio::test]
async fn concurrent_replace_and_lookup() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    let conn = &setup.client_conn;
    let default_collection = &setup.collections[0];
    let collection_path = default_collection.inner().path().to_owned();

    // Seed both items.
    let dbus_secret = setup.create_dbus_secret("initial")?;
    default_collection
        .create_item(
            "race item",
            &[("test", "oo7-race-repro")],
            &dbus_secret,
            false,
            None,
        )
        .await?;
    let dbus_secret = setup.create_dbus_secret("other-value")?;
    default_collection
        .create_item(
            "other item",
            &[("test", "oo7-race-other")],
            &dbus_secret,
            false,
            None,
        )
        .await?;

    let failures = Arc::new(AtomicU32::new(0));
    const ROUNDS: u32 = 100;

    for _ in 0..ROUNDS {
        // Each task gets its own proxy to avoid lifetime issues.
        let conn_a = conn.clone();
        let conn_b = conn.clone();
        let conn_c = conn.clone();
        let conn_d = conn.clone();
        let path = collection_path.clone();
        let session = Arc::clone(&setup.session);
        let session_b = Arc::clone(&setup.session);
        let failures_a = Arc::clone(&failures);
        let failures_b = Arc::clone(&failures);

        // Case A: replace the same item while looking it up.
        let lookup_a = tokio::spawn({
            let path = path.clone();
            async move {
                let coll = dbus::api::Collection::new(&conn_a, path).await.unwrap();
                let found = coll
                    .search_items(&[("test", "oo7-race-repro")])
                    .await
                    .unwrap();
                if found.is_empty() {
                    failures_a.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                if found[0].secret(&session).await.is_err() {
                    failures_a.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        let dbus_secret = setup.create_dbus_secret("dummy")?;
        let store_a = tokio::spawn({
            let path = path.clone();
            async move {
                let coll = dbus::api::Collection::new(&conn_b, path).await.unwrap();
                let _ = coll
                    .create_item(
                        "race item",
                        &[("test", "oo7-race-repro")],
                        &dbus_secret,
                        true,
                        None,
                    )
                    .await;
            }
        });

        // Case B: replace an unrelated item while looking up the race item.
        let lookup_b = tokio::spawn({
            let path = path.clone();
            async move {
                let coll = dbus::api::Collection::new(&conn_c, path).await.unwrap();
                let found = coll
                    .search_items(&[("test", "oo7-race-repro")])
                    .await
                    .unwrap();
                if found.is_empty() {
                    failures_b.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                if found[0].secret(&session_b).await.is_err() {
                    failures_b.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        let dbus_secret_other = setup.create_dbus_secret("other")?;
        let store_b = tokio::spawn({
            let path = path.clone();
            async move {
                let coll = dbus::api::Collection::new(&conn_d, path).await.unwrap();
                let _ = coll
                    .create_item(
                        "other item",
                        &[("test", "oo7-race-other")],
                        &dbus_secret_other,
                        true,
                        None,
                    )
                    .await;
            }
        });

        let _ = tokio::join!(lookup_a, store_a, lookup_b, store_b);
    }

    let total_failures = failures.load(Ordering::Relaxed);
    assert_eq!(
        total_failures,
        0,
        "Concurrent lookups should never miss an item ({total_failures}/{} failed)",
        ROUNDS * 2
    );

    Ok(())
}
