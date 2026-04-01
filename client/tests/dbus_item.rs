use futures_util::StreamExt;
use oo7::dbus::Service;

#[tokio::test]
#[cfg(feature = "tokio")]
async fn label_mutation() {
    let setup = oo7_daemon::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();
    let collection = service.default_collection().await.unwrap();

    let secret = oo7::Secret::text("test secret");

    let item = collection
        .create_item(
            "Original Label",
            &[("test", "label-mutation")],
            secret,
            true,
            None,
        )
        .await
        .unwrap();

    let initial_label = item.label().await.unwrap();
    assert_eq!(initial_label, "Original Label");

    item.set_label("Updated Label").await.unwrap();

    let updated_label = item.label().await.unwrap();
    assert_eq!(updated_label, "Updated Label");

    item.delete(None).await.unwrap();
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn secret_mutation() {
    let setup = oo7_daemon::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();
    let collection = service.default_collection().await.unwrap();

    let original_secret = oo7::Secret::text("original secret");

    let item = collection
        .create_item(
            "Secret Test",
            &[("test", "secret-mutation")],
            original_secret.clone(),
            true,
            None,
        )
        .await
        .unwrap();

    assert_eq!(item.secret().await.unwrap(), original_secret);

    let new_secret = oo7::Secret::text("updated secret");
    item.set_secret(new_secret.clone()).await.unwrap();

    assert_eq!(item.secret().await.unwrap(), new_secret);

    item.delete(None).await.unwrap();
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn secret_mutation_encrypted() {
    let setup = oo7_daemon::tests::TestServiceSetup::encrypted_session(true)
        .await
        .unwrap();
    let service = Service::encrypted_with_connection(&setup.client_conn)
        .await
        .unwrap();
    let collection = service.default_collection().await.unwrap();

    let original_secret = oo7::Secret::text("original encrypted secret");

    let item = collection
        .create_item(
            "Encrypted Secret Test",
            &[("test", "secret-mutation-encrypted")],
            original_secret.clone(),
            true,
            None,
        )
        .await
        .unwrap();

    assert_eq!(item.secret().await.unwrap(), original_secret);

    let new_secret = oo7::Secret::text("updated encrypted secret");
    item.set_secret(new_secret.clone()).await.unwrap();

    assert_eq!(item.secret().await.unwrap(), new_secret);

    item.delete(None).await.unwrap();
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn attributes_mutation() {
    let setup = oo7_daemon::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();
    let collection = service.default_collection().await.unwrap();

    let secret = oo7::Secret::text("test secret");

    let item = collection
        .create_item(
            "Attributes Test",
            &[("service", "email"), ("username", "user1")],
            secret,
            true,
            None,
        )
        .await
        .unwrap();

    let retrieved_attrs = item.attributes().await.unwrap();
    assert_eq!(retrieved_attrs.get("service"), Some(&"email".to_string()));
    assert_eq!(retrieved_attrs.get("username"), Some(&"user1".to_string()));

    item.set_attributes(&[
        ("service", "web"),
        ("username", "user2"),
        ("domain", "example.com"),
    ])
    .await
    .unwrap();

    let updated_attrs = item.attributes().await.unwrap();
    assert_eq!(updated_attrs.get("service"), Some(&"web".to_string()));
    assert_eq!(updated_attrs.get("username"), Some(&"user2".to_string()));
    assert_eq!(
        updated_attrs.get("domain"),
        Some(&"example.com".to_string())
    );
    assert!(!updated_attrs.contains_key("email")); // old attribute should be gone

    item.delete(None).await.unwrap();
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn text_secret_type() {
    let setup = oo7_daemon::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();
    let collection = service.default_collection().await.unwrap();

    let text_secret = oo7::Secret::text("text password");
    let text_item = collection
        .create_item(
            "Text Secret",
            &[("type", "text-secret")],
            text_secret.clone(),
            true,
            None,
        )
        .await
        .unwrap();

    assert_eq!(text_item.secret().await.unwrap(), text_secret);
    text_item.delete(None).await.unwrap();
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn blob_secret_type() {
    let setup = oo7_daemon::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();
    let collection = service.default_collection().await.unwrap();

    let blob_secret = oo7::Secret::blob(b"binary data");
    let blob_item = collection
        .create_item(
            "Blob Secret",
            &[("type", "blob-secret")],
            blob_secret.clone(),
            true,
            None,
        )
        .await
        .unwrap();

    let retrieved_secret = blob_item.secret().await.unwrap();

    // TODO: gnome-keyring doesn't preserve content types - everything becomes
    // text/plain But the actual secret data should be preserved
    assert_eq!(retrieved_secret.as_bytes(), blob_secret.as_bytes());
    blob_item.delete(None).await.unwrap();
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn timestamps() {
    let setup = oo7_daemon::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();
    let collection = service.default_collection().await.unwrap();

    let secret = oo7::Secret::text("timestamp test");

    let item = collection
        .create_item(
            "Timestamp Test",
            &[("test", "timestamps")],
            secret,
            true,
            None,
        )
        .await
        .unwrap();

    let created = item.created().await.unwrap();
    let modified = item.modified().await.unwrap();

    eprintln!("Created: {:?}, Modified: {:?}", created, modified);
    assert_eq!(created, modified);

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    item.set_label("Updated Label").await.unwrap();

    // Allow time for D-Bus changes to propagate
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let new_modified = item.modified().await.unwrap();
    assert!(new_modified > modified);
    assert_eq!(item.created().await.unwrap(), created);

    item.delete(None).await.unwrap();
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn deleted_error() {
    let setup = oo7_daemon::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();
    let collection = service.default_collection().await.unwrap();

    let attributes = &[("test", "deleted-error")];
    let secret = oo7::Secret::text("delete test");

    let item = collection
        .create_item("Delete Test", attributes, secret, true, None)
        .await
        .unwrap();

    // Verify item works before deletion
    assert!(item.label().await.is_ok());

    // Delete the item
    item.delete(None).await.unwrap();

    // All operations should now return Error::Deleted
    assert!(matches!(item.label().await, Err(oo7::dbus::Error::Deleted)));
    assert!(matches!(
        item.set_label("New").await,
        Err(oo7::dbus::Error::Deleted)
    ));
    assert!(matches!(
        item.secret().await,
        Err(oo7::dbus::Error::Deleted)
    ));
    assert!(matches!(
        item.set_secret("new secret").await,
        Err(oo7::dbus::Error::Deleted)
    ));
    assert!(matches!(
        item.attributes().await,
        Err(oo7::dbus::Error::Deleted)
    ));
    assert!(matches!(
        item.set_attributes(attributes).await,
        Err(oo7::dbus::Error::Deleted)
    ));
    assert!(matches!(
        item.created().await,
        Err(oo7::dbus::Error::Deleted)
    ));
    assert!(matches!(
        item.modified().await,
        Err(oo7::dbus::Error::Deleted)
    ));
    assert!(matches!(
        item.is_locked().await,
        Err(oo7::dbus::Error::Deleted)
    ));
    assert!(matches!(
        item.lock(None).await,
        Err(oo7::dbus::Error::Deleted)
    ));
    assert!(matches!(
        item.unlock(None).await,
        Err(oo7::dbus::Error::Deleted)
    ));
    assert!(matches!(
        item.delete(None).await,
        Err(oo7::dbus::Error::Deleted)
    ));
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn lock_unlock() {
    let setup = oo7_daemon::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();
    let collection = service.default_collection().await.unwrap();

    let secret = oo7::Secret::text("test secret");
    let item = collection
        .create_item("Lock Test", &[("test", "lock-unlock")], secret, true, None)
        .await
        .unwrap();

    // Item should start unlocked
    assert!(!item.is_locked().await.unwrap());

    // Lock the item
    item.lock(None).await.unwrap();
    assert!(item.is_locked().await.unwrap());

    // Unlock the item
    item.unlock(None).await.unwrap();
    assert!(!item.is_locked().await.unwrap());

    item.delete(None).await.unwrap();
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn item_created_signal() {
    let setup = oo7_daemon::tests::TestServiceSetup::plain_session(true)
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
    let setup = oo7_daemon::tests::TestServiceSetup::plain_session(true)
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
    let setup = oo7_daemon::tests::TestServiceSetup::plain_session(true)
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
