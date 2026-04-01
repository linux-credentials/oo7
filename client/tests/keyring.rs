#[cfg(feature = "schema")]
use oo7::{ContentType, SecretSchema};
use oo7::{Keyring, Secret, file};
use tempfile::tempdir;

async fn all_backends(
    temp_dir: &tempfile::TempDir,
) -> (oo7_daemon::tests::TestServiceSetup, Vec<Keyring>) {
    let mut backends = Vec::new();

    let keyring_path = temp_dir.path().join("test.keyring");
    let secret = Secret::from([1, 2].into_iter().cycle().take(64).collect::<Vec<_>>());
    let unlocked = Keyring::sandboxed_with_path(keyring_path, secret)
        .await
        .unwrap();
    backends.push(unlocked);

    let setup = oo7_daemon::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();

    let service = Keyring::host_with_connection(setup.client_conn.clone())
        .await
        .unwrap();
    backends.push(service);

    (setup, backends)
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn create_and_retrieve_items() {
    let temp_dir = tempdir().unwrap();
    let (_setup, backends) = all_backends(&temp_dir).await;

    for (idx, keyring) in backends.iter().enumerate() {
        println!("Running test on backend {}", idx);

        keyring
            .create_item(
                "Item 1",
                &[
                    ("test-name", "create_and_retrieve_items"),
                    ("user", "alice"),
                ],
                "secret1",
                false,
            )
            .await
            .unwrap();
        keyring
            .create_item(
                "Item 2",
                &[("test-name", "create_and_retrieve_items"), ("user", "bob")],
                "secret2",
                false,
            )
            .await
            .unwrap();

        let items = keyring
            .search_items(&[("test-name", "create_and_retrieve_items")])
            .await
            .unwrap();
        assert_eq!(items.len(), 2);

        let alice_items = keyring
            .search_items(&[
                ("test-name", "create_and_retrieve_items"),
                ("user", "alice"),
            ])
            .await
            .unwrap();
        assert_eq!(alice_items.len(), 1);
        assert_eq!(alice_items[0].label().await.unwrap(), "Item 1");

        keyring
            .delete(&[("test-name", "create_and_retrieve_items")])
            .await
            .unwrap();
    }
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn delete_items() {
    let temp_dir = tempdir().unwrap();
    let (_setup, backends) = all_backends(&temp_dir).await;

    for (idx, keyring) in backends.iter().enumerate() {
        println!("Running test on backend {}", idx);

        keyring
            .create_item(
                "Item 1",
                &[("test-name", "delete_items"), ("app", "test")],
                "secret1",
                false,
            )
            .await
            .unwrap();
        keyring
            .create_item(
                "Item 2",
                &[("test-name", "delete_items"), ("app", "other")],
                "secret2",
                false,
            )
            .await
            .unwrap();

        keyring
            .delete(&[("test-name", "delete_items"), ("app", "test")])
            .await
            .unwrap();

        let items = keyring
            .search_items(&[("test-name", "delete_items")])
            .await
            .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label().await.unwrap(), "Item 2");

        keyring
            .delete(&[("test-name", "delete_items")])
            .await
            .unwrap();
    }
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn item_update_label() {
    let temp_dir = tempdir().unwrap();
    let (_setup, backends) = all_backends(&temp_dir).await;

    for (idx, keyring) in backends.iter().enumerate() {
        println!("Running test on backend {}", idx);

        keyring
            .create_item(
                "Original Label",
                &[("test-name", "item_update_label")],
                "secret",
                false,
            )
            .await
            .unwrap();

        let items = keyring
            .search_items(&[("test-name", "item_update_label")])
            .await
            .unwrap();
        let item = &items[0];

        assert_eq!(item.label().await.unwrap(), "Original Label");

        item.set_label("New Label").await.unwrap();
        assert_eq!(item.label().await.unwrap(), "New Label");

        let items = keyring
            .search_items(&[("test-name", "item_update_label")])
            .await
            .unwrap();
        assert_eq!(items[0].label().await.unwrap(), "New Label");

        keyring
            .delete(&[("test-name", "item_update_label")])
            .await
            .unwrap();
    }
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn item_update_attributes() {
    let temp_dir = tempdir().unwrap();
    let (_setup, backends) = all_backends(&temp_dir).await;

    for (idx, keyring) in backends.iter().enumerate() {
        println!("Running test on backend {}", idx);

        keyring
            .create_item(
                "Test",
                &[("test-name", "item_update_attributes"), ("version", "1.0")],
                "secret",
                false,
            )
            .await
            .unwrap();

        let items = keyring
            .search_items(&[("test-name", "item_update_attributes")])
            .await
            .unwrap();
        let item = &items[0];

        item.set_attributes(&[("test-name", "item_update_attributes"), ("version", "2.0")])
            .await
            .unwrap();

        let attrs = item.attributes().await.unwrap();
        assert_eq!(attrs.get("version").unwrap(), "2.0");

        // Test edge case: set_attributes when item doesn't exist in keyring
        if idx == 0 {
            keyring
                .delete(&[("test-name", "item_update_attributes")])
                .await
                .unwrap();

            item.set_attributes(&[("test-name", "item_update_attributes"), ("version", "3.0")])
                .await
                .unwrap();

            let new_items = keyring
                .search_items(&[("test-name", "item_update_attributes")])
                .await
                .unwrap();
            assert_eq!(new_items.len(), 1);
        }

        keyring
            .delete(&[("test-name", "item_update_attributes")])
            .await
            .unwrap();
    }
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn item_update_secret() {
    let temp_dir = tempdir().unwrap();
    let (_setup, backends) = all_backends(&temp_dir).await;

    for (idx, keyring) in backends.iter().enumerate() {
        println!("Running test on backend {}", idx);

        keyring
            .create_item(
                "Test",
                &[("test-name", "item_update_secret")],
                "old_secret",
                false,
            )
            .await
            .unwrap();

        let items = keyring
            .search_items(&[("test-name", "item_update_secret")])
            .await
            .unwrap();
        let item = &items[0];

        assert_eq!(item.secret().await.unwrap(), Secret::text("old_secret"));

        item.set_secret("new_secret").await.unwrap();
        assert_eq!(item.secret().await.unwrap(), Secret::text("new_secret"));

        keyring
            .delete(&[("test-name", "item_update_secret")])
            .await
            .unwrap();
    }
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn item_delete() {
    let temp_dir = tempdir().unwrap();
    let (_setup, backends) = all_backends(&temp_dir).await;

    for (idx, keyring) in backends.iter().enumerate() {
        println!("Running test on backend {}", idx);

        keyring
            .create_item(
                "Item 1",
                &[("test-name", "item_delete"), ("id", "1")],
                "secret1",
                false,
            )
            .await
            .unwrap();
        keyring
            .create_item(
                "Item 2",
                &[("test-name", "item_delete"), ("id", "2")],
                "secret2",
                false,
            )
            .await
            .unwrap();

        let items = keyring
            .search_items(&[("test-name", "item_delete")])
            .await
            .unwrap();
        assert_eq!(items.len(), 2);

        items[0].delete().await.unwrap();

        let items = keyring
            .search_items(&[("test-name", "item_delete")])
            .await
            .unwrap();
        assert_eq!(items.len(), 1);

        keyring
            .delete(&[("test-name", "item_delete")])
            .await
            .unwrap();
    }
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn item_replace() {
    let temp_dir = tempdir().unwrap();
    let (_setup, backends) = all_backends(&temp_dir).await;

    for (idx, keyring) in backends.iter().enumerate() {
        println!("Running test on backend {}", idx);

        keyring
            .create_item("Item 1", &[("test-name", "item_replace")], "secret1", false)
            .await
            .unwrap();

        keyring
            .create_item("Item 2", &[("test-name", "item_replace")], "secret2", true)
            .await
            .unwrap();

        let items = keyring
            .search_items(&[("test-name", "item_replace")])
            .await
            .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label().await.unwrap(), "Item 2");
        assert_eq!(items[0].secret().await.unwrap(), Secret::text("secret2"));

        // Cleanup
        keyring
            .delete(&[("test-name", "item_replace")])
            .await
            .unwrap();
    }
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn item_timestamps() {
    let temp_dir = tempdir().unwrap();
    let (_setup, backends) = all_backends(&temp_dir).await;

    for (idx, keyring) in backends.iter().enumerate() {
        println!("Running test on backend {}", idx);

        keyring
            .create_item("Test", &[("test-name", "item_timestamps")], "secret", false)
            .await
            .unwrap();

        let items = keyring
            .search_items(&[("test-name", "item_timestamps")])
            .await
            .unwrap();
        let item = &items[0];

        let created = item.created().await.unwrap();
        let modified = item.modified().await.unwrap();

        assert!(created.as_secs() > 0);
        assert!(modified.as_secs() > 0);

        assert!(modified >= created);

        // Cleanup
        keyring
            .delete(&[("test-name", "item_timestamps")])
            .await
            .unwrap();
    }
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn item_is_locked() {
    let temp_dir = tempdir().unwrap();
    let (_setup, backends) = all_backends(&temp_dir).await;

    for (idx, keyring) in backends.iter().enumerate() {
        println!("Running test on backend {}", idx);

        keyring
            .create_item("Test", &[("test-name", "item_is_locked")], "secret", false)
            .await
            .unwrap();

        let items = keyring
            .search_items(&[("test-name", "item_is_locked")])
            .await
            .unwrap();
        let item = &items[0];

        assert!(!item.is_locked().await.unwrap());

        let all_items = keyring.items().await.unwrap();
        assert!(!all_items.is_empty());

        keyring
            .delete(&[("test-name", "item_is_locked")])
            .await
            .unwrap();
    }
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn keyring_lock_unlock() {
    let temp_dir = tempdir().unwrap();
    let (_setup, backends) = all_backends(&temp_dir).await;

    for keyring in backends.iter() {
        assert!(!keyring.is_locked().await.unwrap());

        keyring.lock().await.unwrap();
        assert!(keyring.is_locked().await.unwrap());

        // Test edge case: locking an already locked keyring
        keyring.lock().await.unwrap();
        assert!(keyring.is_locked().await.unwrap());

        keyring.unlock().await.unwrap();
        assert!(!keyring.is_locked().await.unwrap());

        // Test edge case: unlocking an already unlocked keyring
        keyring.unlock().await.unwrap();
        assert!(!keyring.is_locked().await.unwrap());
    }
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn item_lock_unlock() {
    let temp_dir = tempdir().unwrap();
    let (_setup, backends) = all_backends(&temp_dir).await;

    for (idx, keyring) in backends.iter().enumerate() {
        println!("Testing item lock/unlock on backend {}", idx);

        keyring
            .create_item(
                "Test Item",
                &[("test-name", "item_lock_unlock")],
                "secret",
                false,
            )
            .await
            .unwrap();

        let items = keyring
            .search_items(&[("test-name", "item_lock_unlock")])
            .await
            .unwrap();
        let item = &items[0];

        assert!(!item.is_locked().await.unwrap());
        assert_eq!(item.secret().await.unwrap(), Secret::text("secret"));

        // Test edge case: unlocking an already unlocked item
        item.unlock().await.unwrap();
        assert!(!item.is_locked().await.unwrap());

        item.lock().await.unwrap();
        assert!(item.is_locked().await.unwrap());

        // Test edge case: locking an already locked item
        item.lock().await.unwrap();
        assert!(item.is_locked().await.unwrap());

        // Unlock the item
        item.unlock().await.unwrap();
        assert!(!item.is_locked().await.unwrap());
        assert_eq!(item.secret().await.unwrap(), Secret::text("secret"));

        // Cleanup
        keyring
            .delete(&[("test-name", "item_lock_unlock")])
            .await
            .unwrap();
    }
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn locked_item_operations_fail() {
    let temp_dir = tempdir().unwrap();
    let (_setup, backends) = all_backends(&temp_dir).await;

    for (idx, keyring) in backends.iter().enumerate() {
        println!("Testing locked item operations on backend {}", idx);

        keyring
            .create_item("Test", &[("test-name", "locked_item_ops")], "secret", false)
            .await
            .unwrap();

        let items = keyring
            .search_items(&[("test-name", "locked_item_ops")])
            .await
            .unwrap();
        let item = &items[0];

        item.lock().await.unwrap();

        // All operations should fail on locked items
        assert!(item.label().await.is_err());
        assert!(item.attributes().await.is_err());
        assert!(item.secret().await.is_err());
        assert!(item.set_label("new").await.is_err());
        assert!(item.set_attributes(&[("app", "test")]).await.is_err());
        assert!(item.set_secret("new").await.is_err());
        // Note: delete() prompts for unlock on D-Bus backend, skip testing
        assert!(item.created().await.is_err());
        assert!(item.modified().await.is_err());

        // Cleanup: unlock and delete
        item.unlock().await.unwrap();
        keyring
            .delete(&[("test-name", "locked_item_ops")])
            .await
            .unwrap();
    }
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn file_locked_keyring_operations_fail() {
    let temp_dir = tempdir().unwrap();
    let (_setup, backends) = all_backends(&temp_dir).await;
    let keyring = &backends[0];

    keyring
        .create_item("Test", &[("app", "test")], "secret", false)
        .await
        .unwrap();

    let items = keyring.items().await.unwrap();
    let item = &items[0];

    keyring.lock().await.unwrap();

    assert!(matches!(
        keyring
            .create_item("test", &[("app", "test")], "secret", false)
            .await,
        Err(oo7::Error::File(file::Error::Locked))
    ));
    assert!(matches!(
        keyring.items().await,
        Err(oo7::Error::File(file::Error::Locked))
    ));
    assert!(matches!(
        keyring.search_items(&[("app", "test")]).await,
        Err(oo7::Error::File(file::Error::Locked))
    ));
    assert!(matches!(
        keyring.delete(&[("app", "test")]).await,
        Err(oo7::Error::File(file::Error::Locked))
    ));

    assert!(matches!(
        item.set_label("new label").await,
        Err(oo7::Error::File(file::Error::Locked))
    ));
    assert!(matches!(
        item.set_attributes(&[("app", "new")]).await,
        Err(oo7::Error::File(file::Error::Locked))
    ));
    assert!(matches!(
        item.set_secret("new secret").await,
        Err(oo7::Error::File(file::Error::Locked))
    ));
    assert!(matches!(
        item.delete().await,
        Err(oo7::Error::File(file::Error::Locked))
    ));
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn item_lock_with_locked_keyring_fails() {
    let temp_dir = tempdir().unwrap();
    let (_setup, backends) = all_backends(&temp_dir).await;

    for keyring in backends.iter() {
        keyring
            .create_item("Test", &[("app", "test")], "secret", false)
            .await
            .unwrap();

        let items = keyring.items().await.unwrap();
        let item = &items[0];

        keyring.lock().await.unwrap();

        let result = item.lock().await;
        assert!(result.is_err());

        keyring.unlock().await.unwrap();
        keyring.delete(&[("app", "test")]).await.unwrap();
    }
}

#[tokio::test]
#[cfg(all(feature = "tokio", feature = "schema"))]
async fn attributes_as() {
    #[derive(SecretSchema, Debug, Default, PartialEq)]
    #[schema(name = "org.example.Test")]
    struct TestSchema {
        username: String,
        port: Option<u16>,
    }

    let temp_dir = tempdir().unwrap();
    let (_setup, backends) = all_backends(&temp_dir).await;

    for (idx, keyring) in backends.iter().enumerate() {
        println!("Testing attributes_as on backend {}", idx);

        // Create an item with text content
        keyring
            .create_item(
                "Text Item",
                &TestSchema {
                    username: "alice".to_string(),
                    port: Some(8080),
                },
                Secret::text("my-password"),
                true,
            )
            .await
            .unwrap();

        // Create an item with blob content
        keyring
            .create_item(
                "Blob Item",
                &TestSchema {
                    username: "bob".to_string(),
                    port: None,
                },
                Secret::blob(b"binary data"),
                true,
            )
            .await
            .unwrap();

        // Search for the text item
        let text_items = keyring
            .search_items(&TestSchema {
                username: "alice".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(text_items.len(), 1);
        let text_item = &text_items[0];

        // Verify content type
        let attrs = text_item.attributes().await.unwrap();
        assert_eq!(attrs.get("xdg:content-type").unwrap(), "text/plain");
        assert_eq!(
            text_item.secret().await.unwrap().content_type(),
            ContentType::Text
        );

        // Test attributes_as
        let schema = text_item.attributes_as::<TestSchema>().await.unwrap();
        assert_eq!(
            schema,
            TestSchema {
                username: "alice".to_string(),
                port: Some(8080)
            }
        );
        assert_eq!(schema.username, "alice");
        assert_eq!(schema.port, Some(8080));

        // Search for the blob item
        let blob_items = keyring
            .search_items(&TestSchema {
                username: "bob".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(blob_items.len(), 1);
        let blob_item = &blob_items[0];

        // Verify content type
        let attrs = blob_item.attributes().await.unwrap();
        assert_eq!(
            attrs.get("xdg:content-type").unwrap(),
            "application/octet-stream"
        );
        assert_eq!(
            blob_item.secret().await.unwrap().content_type(),
            ContentType::Blob
        );

        // Test attributes_as
        let schema = blob_item.attributes_as::<TestSchema>().await.unwrap();
        assert_eq!(
            schema,
            TestSchema {
                username: "bob".to_string(),
                port: None
            }
        );
        assert_eq!(schema.username, "bob");
        assert_eq!(schema.port, None);

        // Cleanup
        keyring
            .delete(&TestSchema {
                username: "alice".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
        keyring
            .delete(&TestSchema {
                username: "bob".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
    }
}
