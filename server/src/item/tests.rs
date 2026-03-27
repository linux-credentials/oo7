use std::sync::Arc;

use oo7::dbus;
use tokio_stream::StreamExt;

use crate::tests::{TestServiceSetup, gnome_prompter_test, plasma_prompter_test};

#[tokio::test]
async fn label_property() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    let item = setup
        .create_item("Original Label", &[("app", "test")], "test-secret", false)
        .await?;

    // Get label
    let label = item.label().await?;
    assert_eq!(label, "Original Label");

    // Get initial modified timestamp
    let initial_modified = item.modified().await?;

    // Wait to ensure timestamp will be different
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Set label
    item.set_label("New Label").await?;

    // Verify new label
    let label = item.label().await?;
    assert_eq!(label, "New Label");

    // Verify modified timestamp was updated
    let new_modified = item.modified().await?;
    println!("New modified: {:?}", new_modified);
    assert!(
        new_modified > initial_modified,
        "Modified timestamp should be updated after label change (initial: {:?}, new: {:?})",
        initial_modified,
        new_modified
    );

    Ok(())
}

#[tokio::test]
async fn attributes_property() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    let item = setup
        .create_item(
            "Test Item",
            &[("app", "firefox"), ("username", "user@example.com")],
            "test-secret",
            false,
        )
        .await?;

    // Get attributes
    let attrs = item.attributes().await?;
    assert_eq!(attrs.get("app").unwrap(), "firefox");
    assert_eq!(attrs.get("username").unwrap(), "user@example.com");

    // Get initial modified timestamp
    let initial_modified = item.modified().await?;

    // Wait to ensure timestamp will be different
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Set new attributes
    item.set_attributes(&[("app", "chrome"), ("username", "newuser@example.com")])
        .await?;

    // Verify new attributes
    let attrs = item.attributes().await?;
    assert_eq!(attrs.get("app").unwrap(), "chrome");
    assert_eq!(attrs.get("username").unwrap(), "newuser@example.com");

    // Verify modified timestamp was updated
    let new_modified = item.modified().await?;
    assert!(
        new_modified > initial_modified,
        "Modified timestamp should be updated after attributes change"
    );

    Ok(())
}

#[tokio::test]
async fn timestamps() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    let item = setup
        .create_item("Test Item", &[("app", "test")], "test-secret", false)
        .await?;

    // Get created timestamp
    let created = item.created().await?;
    assert!(created.as_secs() > 0, "Created timestamp should be set");

    // Get modified timestamp
    let modified = item.modified().await?;
    assert!(modified.as_secs() > 0, "Modified timestamp should be set");

    // Created and modified should be close (within a second for new item)
    let diff = if created > modified {
        created.as_secs() - modified.as_secs()
    } else {
        modified.as_secs() - created.as_secs()
    };
    assert!(diff <= 1, "Created and modified should be within 1 second");
    Ok(())
}

#[tokio::test]
async fn secret_retrieval_plain() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    let secret = oo7::Secret::blob(b"my-secret-password");
    let item = setup
        .create_item("Test Item", &[("app", "test")], secret.clone(), false)
        .await?;

    // Retrieve secret
    let retrieved_secret = item.secret(&setup.session).await?;
    assert_eq!(retrieved_secret.value(), secret.as_bytes());

    // Verify content-type is preserved
    assert_eq!(
        retrieved_secret.content_type(),
        secret.content_type(),
        "Content-type should be preserved"
    );
    Ok(())
}

#[tokio::test]
async fn secret_retrieval_encrypted() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::encrypted_session(true).await?;

    let aes_key = setup.aes_key.as_ref().unwrap();
    let secret = oo7::Secret::text("my-encrypted-secret");
    let item = setup
        .create_item("Test Item", &[("app", "test")], secret.clone(), false)
        .await?;

    // Retrieve secret
    let retrieved_secret = item.secret(&setup.session).await?;
    assert_eq!(
        retrieved_secret.decrypt(Some(&aes_key.clone()))?.as_bytes(),
        secret.as_bytes()
    );
    // Verify content-type is preserved
    assert_eq!(
        retrieved_secret
            .decrypt(Some(&aes_key.clone()))?
            .content_type(),
        secret.content_type(),
        "Content-type should be preserved"
    );

    Ok(())
}

#[tokio::test]
async fn delete_item() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    let item = setup
        .create_item("Test Item", &[("app", "test")], "test-secret", false)
        .await?;

    // Verify item exists
    let items = setup.collections[0].items().await?;
    assert_eq!(items.len(), 1);

    // Delete item
    item.delete(None).await?;

    // Verify item is deleted
    let items = setup.collections[0].items().await?;
    assert_eq!(items.len(), 0, "Item should be deleted from collection");
    Ok(())
}

#[tokio::test]
async fn set_secret_plain() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    let original_secret = oo7::Secret::text("original-password");
    let item = setup
        .create_item(
            "Test Item",
            &[("app", "test")],
            original_secret.clone(),
            false,
        )
        .await?;

    // Verify original secret
    let retrieved = item.secret(&setup.session).await?;
    assert_eq!(retrieved.value(), original_secret.as_bytes());
    assert_eq!(
        retrieved.content_type(),
        original_secret.content_type(),
        "Content-type should be preserved"
    );

    // Get initial modified timestamp
    let initial_modified = item.modified().await?;

    // Wait to ensure timestamp will be different
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Update the secret
    let new_secret = oo7::Secret::blob(b"new-password");
    let new_dbus_secret =
        dbus::api::DBusSecret::new(Arc::clone(&setup.session), new_secret.clone());
    item.set_secret(&new_dbus_secret).await?;

    // Verify updated secret
    let retrieved = item.secret(&setup.session).await?;
    assert_eq!(retrieved.value(), new_secret.as_bytes());
    assert_eq!(
        retrieved.content_type(),
        new_secret.content_type(),
        "Content-type should be preserved"
    );

    // Verify modified timestamp was updated
    let new_modified = item.modified().await?;
    assert!(
        new_modified > initial_modified,
        "Modified timestamp should be updated after secret change"
    );

    Ok(())
}

#[tokio::test]
async fn set_secret_encrypted() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::encrypted_session(true).await?;
    let aes_key = setup.aes_key.as_ref().unwrap().clone();

    let original_secret = oo7::Secret::text("original-encrypted-password");
    let item = setup
        .create_item(
            "Test Item",
            &[("app", "test")],
            original_secret.clone(),
            false,
        )
        .await?;

    // Verify original secret
    let retrieved = item.secret(&setup.session).await?;
    assert_eq!(
        retrieved.decrypt(Some(&aes_key.clone()))?.as_bytes(),
        original_secret.as_bytes()
    );

    // Get initial modified timestamp
    let initial_modified = item.modified().await?;

    // Wait to ensure timestamp will be different
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Update the secret
    let new_secret = oo7::Secret::text("new-encrypted-password");
    let new_dbus_secret = dbus::api::DBusSecret::new_encrypted(
        Arc::clone(&setup.session),
        new_secret.clone(),
        &aes_key,
    )?;
    item.set_secret(&new_dbus_secret).await?;

    // Verify updated secret
    let retrieved = item.secret(&setup.session).await?;
    assert_eq!(
        retrieved.decrypt(Some(&aes_key.clone()))?.as_bytes(),
        new_secret.as_bytes()
    );

    // Verify modified timestamp was updated
    let new_modified = item.modified().await?;
    assert!(
        new_modified > initial_modified,
        "Modified timestamp should be updated after secret change"
    );

    Ok(())
}

#[tokio::test]
async fn get_secret_invalid_session() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    let item = setup
        .create_item("Test Item", &[("app", "test")], "test-secret", false)
        .await?;

    // Try to get secret with invalid session path
    let invalid_session =
        oo7::dbus::api::Session::new(&setup.client_conn, "/invalid/session").await?;
    let result = item.secret(&invalid_session).await;

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
async fn set_secret_invalid_session() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    let item = setup
        .create_item("Test Item", &[("app", "test")], "test-secret", false)
        .await?;

    let new_secret = oo7::Secret::text("new-secret");
    let invalid_dbus_secret = dbus::api::DBusSecret::new(
        Arc::new(dbus::api::Session::new(&setup.client_conn, "/invalid/session").await?),
        new_secret,
    );

    let result = item.set_secret(&invalid_dbus_secret).await;

    // Should return NoSession error
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
async fn item_changed_signal() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    let item = setup
        .create_item("Test Item", &[("app", "test")], "test-secret", false)
        .await?;

    // Subscribe to ItemChanged signal
    let signal_stream = setup.collections[0].receive_item_changed().await?;
    tokio::pin!(signal_stream);

    // Change the label
    item.set_label("Updated Label").await?;

    // Wait for signal
    let signal_result =
        tokio::time::timeout(tokio::time::Duration::from_secs(1), signal_stream.next()).await;

    assert!(
        signal_result.is_ok(),
        "Should receive ItemChanged signal after label change"
    );
    let signal = signal_result.unwrap();
    assert!(signal.is_some(), "Signal should not be None");

    let signal_item = signal.unwrap();
    assert_eq!(
        signal_item.inner().path().as_str(),
        item.inner().path().as_str(),
        "Signal should contain the changed item path"
    );

    // Change attributes and verify signal again
    item.set_attributes(&[("app", "updated-app")]).await?;

    let signal_result =
        tokio::time::timeout(tokio::time::Duration::from_secs(1), signal_stream.next()).await;

    assert!(
        signal_result.is_ok(),
        "Should receive ItemChanged signal after attributes change"
    );

    // Change secret and verify signal again
    let new_secret = oo7::Secret::text("new-secret");
    let new_dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), new_secret);
    item.set_secret(&new_dbus_secret).await?;

    let signal_result =
        tokio::time::timeout(tokio::time::Duration::from_secs(1), signal_stream.next()).await;

    assert!(
        signal_result.is_ok(),
        "Should receive ItemChanged signal after secret change"
    );

    Ok(())
}

gnome_prompter_test!(
    delete_locked_item_with_prompt_gnome,
    delete_locked_item_with_prompt
);
plasma_prompter_test!(
    delete_locked_item_with_prompt_plasma,
    delete_locked_item_with_prompt
);

async fn delete_locked_item_with_prompt() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    let default_collection = setup.default_collection().await?;

    let secret = oo7::Secret::text("test-password");
    let dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret.clone());

    let item = default_collection
        .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
        .await?;

    let items = default_collection.items().await?;
    assert_eq!(items.len(), 1, "Should have one item");

    let collection = setup
        .server
        .collection_from_path(default_collection.inner().path())
        .await
        .expect("Collection should exist");
    collection
        .set_locked(true, setup.keyring_secret.clone())
        .await?;

    assert!(item.is_locked().await?, "Item should be locked");

    item.delete(None).await?;

    let items = default_collection.items().await?;
    assert_eq!(items.len(), 0, "Item should be deleted after prompt");

    Ok(())
}

#[tokio::test]
async fn locked_item_operations() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Create an item
    let item = setup
        .create_item("Test Item", &[("app", "test")], "test-password", false)
        .await?;

    // Verify item is unlocked initially
    assert!(!item.is_locked().await?, "Item should start unlocked");

    // Lock the collection (which locks the item)
    let collection = setup
        .server
        .collection_from_path(setup.collections[0].inner().path())
        .await
        .expect("Collection should exist");
    collection
        .set_locked(true, setup.keyring_secret.clone())
        .await?;

    // Verify item is now locked
    assert!(
        item.is_locked().await?,
        "Item should be locked after locking collection"
    );

    // Test 1: get_secret should fail with IsLocked
    let result = item.secret(&setup.session).await;
    assert!(
        matches!(
            result,
            Err(oo7::dbus::Error::Service(
                oo7::dbus::ServiceError::IsLocked(_)
            ))
        ),
        "get_secret should fail with IsLocked error, got: {:?}",
        result
    );

    // Test 2: set_secret should fail with IsLocked
    let new_secret = oo7::Secret::text("new-password");
    let new_dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), new_secret);
    let result = item.set_secret(&new_dbus_secret).await;
    assert!(
        matches!(
            result,
            Err(oo7::dbus::Error::Service(
                oo7::dbus::ServiceError::IsLocked(_)
            ))
        ),
        "set_secret should fail with IsLocked error, got: {:?}",
        result
    );

    // Test 3: set_attributes should fail with IsLocked
    let result = item.set_attributes(&[("app", "new-app")]).await;
    assert!(
        matches!(result, Err(oo7::dbus::Error::ZBus(zbus::Error::FDO(_)))),
        "set_attributes should fail with IsLocked error, got: {:?}",
        result
    );

    // Test 4: set_label should fail with IsLocked
    let result = item.set_label("New Label").await;
    assert!(
        matches!(result, Err(oo7::dbus::Error::ZBus(zbus::Error::FDO(_)))),
        "set_label should fail with IsLocked error, got: {:?}",
        result
    );

    // Test 5: Reading properties should also fail on locked items
    let result = item.label().await;
    assert!(
        matches!(result, Err(oo7::dbus::Error::ZBus(zbus::Error::FDO(_)))),
        "label should fail on locked item, got: {:?}",
        result
    );

    let result = item.attributes().await;
    assert!(
        matches!(result, Err(oo7::dbus::Error::ZBus(zbus::Error::FDO(_)))),
        "attributes should fail on locked item, got: {:?}",
        result
    );

    let result = item.created().await;
    assert!(
        matches!(result, Err(oo7::dbus::Error::ZBus(zbus::Error::FDO(_)))),
        "created should fail on locked item, got: {:?}",
        result
    );

    let result = item.modified().await;
    assert!(
        matches!(result, Err(oo7::dbus::Error::ZBus(zbus::Error::FDO(_)))),
        "modified should fail on locked item, got: {:?}",
        result
    );

    Ok(())
}
