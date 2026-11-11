use std::collections::HashMap;

use oo7::{Secret, XDG_SCHEMA_ATTRIBUTE, file::*};
use tempfile::tempdir;

use super::strong_key;

#[tokio::test]
async fn delete() -> Result<(), Error> {
    let temp_dir = tempdir()?;
    let path = temp_dir.path().join("test-delete.keyring");

    let keyring = UnlockedKeyring::load(&path, Some(strong_key())).await?;
    let attributes: HashMap<&str, &str> = HashMap::default();
    keyring
        .create_item("Label", &attributes, "secret", false)
        .await?;

    keyring.delete_item_index(0).await?;

    let result = keyring.delete_item_index(100).await;

    assert!(matches!(result, Err(Error::InvalidItemIndex(100))));

    Ok(())
}

#[tokio::test]
async fn comprehensive_search_patterns() -> Result<(), Error> {
    let temp_dir = tempdir().unwrap();
    let keyring_path = temp_dir.path().join("search_test.keyring");
    let keyring = UnlockedKeyring::load(&keyring_path, Some(strong_key())).await?;

    // Create diverse test data
    let test_items = [
        (
            "Email Password",
            vec![
                ("app", "email"),
                ("user", "alice@example.com"),
                ("type", "password"),
            ],
        ),
        (
            "Email Token",
            vec![
                ("app", "email"),
                ("user", "alice@example.com"),
                ("type", "token"),
            ],
        ),
        (
            "SSH Key",
            vec![("app", "ssh"), ("user", "alice"), ("type", "key")],
        ),
        (
            "Database Password",
            vec![
                ("app", "database"),
                ("env", "production"),
                ("type", "password"),
            ],
        ),
        (
            "API Key",
            vec![("app", "api"), ("service", "github"), ("type", "key")],
        ),
    ];

    for (i, (label, attrs)) in test_items.iter().enumerate() {
        let attrs_map: HashMap<&str, &str> = attrs.iter().cloned().collect();
        keyring
            .create_item(label, &attrs_map, format!("secret{}", i), false)
            .await?;
    }

    // Test exact match
    let exact = keyring
        .search_items(&[
            ("app", "email"),
            ("user", "alice@example.com"),
            ("type", "password"),
        ])
        .await?;
    assert_eq!(exact.len(), 1);
    assert_eq!(exact[0].label(), "Email Password");

    // Test partial match - by app
    let email_items = keyring.search_items(&[("app", "email")]).await?;
    assert_eq!(email_items.len(), 2);

    // Test partial match - by type
    let passwords = keyring.search_items(&[("type", "password")]).await?;
    assert_eq!(passwords.len(), 2);

    let keys = keyring.search_items(&[("type", "key")]).await?;
    assert_eq!(keys.len(), 2);

    // Test no match
    let nonexistent = keyring.search_items(&[("app", "nonexistent")]).await?;
    assert_eq!(nonexistent.len(), 0);

    Ok(())
}

#[tokio::test]
async fn item_replacement_behavior() -> Result<(), Error> {
    let temp_dir = tempdir().unwrap();
    let keyring_path = temp_dir.path().join("replace_test.keyring");
    let keyring = UnlockedKeyring::load(&keyring_path, Some(strong_key())).await?;

    let attrs = &[("app", "test"), ("user", "alice")];

    // Create initial item
    keyring
        .create_item("Original", attrs, "secret1", false)
        .await?;

    // Verify initial state
    let items = keyring.search_items(attrs).await?;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].label(), "Original");
    assert_eq!(items[0].secret(), Secret::text("secret1"));

    // With replace=false, allows duplicates (discovered behavior)
    keyring
        .create_item("Duplicate", attrs, "secret2", false)
        .await?;

    // Verify we now have 2 items with same attributes
    let items = keyring.search_items(attrs).await?;
    assert_eq!(items.len(), 2);

    // Verify both items exist with different content
    let labels: Vec<_> = items.iter().map(|i| i.label()).collect();
    assert!(labels.contains(&"Original"));
    assert!(labels.contains(&"Duplicate"));

    // Now test replace=true behavior - should remove existing items with same
    // attributes
    keyring
        .create_item("Replacement", attrs, "secret3", true)
        .await?;

    // After replace=true, should only have the new item
    let items = keyring.search_items(attrs).await?;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].label(), "Replacement");
    assert_eq!(items[0].secret(), Secret::text("secret3"));

    // Test replace=true on empty attributes (should just add)
    let unique_attrs = &[("app", "unique"), ("user", "bob")];
    keyring
        .create_item("Unique Item", unique_attrs, "unique_secret", true)
        .await?;

    let unique_items = keyring.search_items(unique_attrs).await?;
    assert_eq!(unique_items.len(), 1);
    assert_eq!(unique_items[0].label(), "Unique Item");

    // Test replace=true again on the unique item - should replace it
    keyring
        .create_item("Updated Unique", unique_attrs, "updated_secret", true)
        .await?;

    let unique_items = keyring.search_items(unique_attrs).await?;
    assert_eq!(unique_items.len(), 1);
    assert_eq!(unique_items[0].label(), "Updated Unique");
    assert_eq!(unique_items[0].secret(), Secret::text("updated_secret"));

    Ok(())
}

#[tokio::test]
async fn item_replacement_ignores_secret_content_type() -> Result<(), Error> {
    let temp_dir = tempdir().unwrap();
    let keyring_path = temp_dir.path().join("replace_content_type.keyring");
    let keyring = UnlockedKeyring::load(&keyring_path, Some(strong_key())).await?;
    let attrs = &[("app", "browser"), ("account", "alice")];

    keyring
        .create_item("Imported", attrs, Secret::blob(b"old"), false)
        .await?;
    keyring
        .create_item("Updated", attrs, Secret::text("new"), true)
        .await?;

    let items = keyring.search_items(attrs).await?;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].secret(), Secret::text("new"));
    Ok(())
}

#[tokio::test]
async fn item_replacement_matches_attributes() -> Result<(), Error> {
    let temp_dir = tempdir().unwrap();
    let keyring_path = temp_dir.path().join("replace_attributes_test.keyring");
    let keyring = UnlockedKeyring::load(&keyring_path, Some(strong_key())).await?;

    keyring
        .create_item(
            "Alice",
            &[("app", "test"), ("user", "alice")],
            "alice-secret",
            false,
        )
        .await?;
    keyring
        .create_item(
            "Bob",
            &[("app", "test"), ("user", "bob")],
            "bob-secret",
            false,
        )
        .await?;

    // A coarser attribute set must not replace either item.
    keyring
        .create_item("Coarse", &[("app", "test")], "coarse-secret", true)
        .await?;

    let items = keyring.search_items(&[("app", "test")]).await?;
    assert_eq!(items.len(), 3);
    assert_eq!(
        keyring
            .search_items(&[("app", "test"), ("user", "alice")])
            .await?
            .len(),
        1
    );
    assert_eq!(
        keyring
            .search_items(&[("app", "test"), ("user", "bob")])
            .await?
            .len(),
        1
    );

    // Replacing the coarse item must not add a duplicate.
    keyring
        .create_item(
            "Updated Coarse",
            &[("app", "test")],
            "updated-coarse-secret",
            true,
        )
        .await?;

    let items = keyring.search_items(&[("app", "test")]).await?;
    assert_eq!(items.len(), 3);
    assert_eq!(
        items
            .iter()
            .filter(|item| item.attributes().get("user").is_none())
            .map(|item| item.label())
            .collect::<Vec<_>>(),
        vec!["Updated Coarse"]
    );

    Ok(())
}

#[tokio::test]
async fn secret_types_handling() -> Result<(), Error> {
    let temp_dir = tempdir().unwrap();
    let keyring_path = temp_dir.path().join("secret_types_test.keyring");
    let keyring = UnlockedKeyring::load(&keyring_path, Some(strong_key())).await?;

    // Test text secret
    keyring
        .create_item(
            "Text Secret",
            &[("type", "text")],
            Secret::text("Hello, World!"),
            false,
        )
        .await?;

    // Test binary secret
    keyring
        .create_item(
            "Binary Secret",
            &[("type", "binary")],
            Secret::blob([0x00, 0x01, 0x02, 0xFF]),
            false,
        )
        .await?;

    // Test large secret
    let large_data = vec![42u8; 10000];
    keyring
        .create_item(
            "Large Secret",
            &[("type", "large")],
            Secret::blob(&large_data),
            false,
        )
        .await?;

    // Test empty secret
    keyring
        .create_item(
            "Empty Secret",
            &[("type", "empty")],
            Secret::text(""),
            false,
        )
        .await?;

    // Verify all secrets can be retrieved correctly
    let text_items = keyring.search_items(&[("type", "text")]).await?;
    assert_eq!(text_items.len(), 1);
    assert_eq!(text_items[0].secret(), Secret::text("Hello, World!"));
    assert_eq!(
        text_items[0].secret().content_type(),
        oo7::ContentType::Text
    );

    let binary_items = keyring.search_items(&[("type", "binary")]).await?;
    assert_eq!(binary_items.len(), 1);
    assert_eq!(&*binary_items[0].secret(), &[0x00, 0x01, 0x02, 0xFF]);
    assert_eq!(
        binary_items[0].secret().content_type(),
        oo7::ContentType::Blob
    );

    let large_items = keyring.search_items(&[("type", "large")]).await?;
    assert_eq!(large_items.len(), 1);
    assert_eq!(&*large_items[0].secret(), &large_data);

    let empty_items = keyring.search_items(&[("type", "empty")]).await?;
    assert_eq!(empty_items.len(), 1);
    assert_eq!(empty_items[0].secret(), Secret::text(""));

    Ok(())
}

#[tokio::test]
async fn item_lifecycle_operations() -> Result<(), Error> {
    let temp_dir = tempdir().unwrap();
    let keyring_path = temp_dir.path().join("lifecycle_test.keyring");
    let keyring = UnlockedKeyring::load(&keyring_path, Some(strong_key())).await?;

    // Test creating multiple items
    keyring
        .create_item(
            "Test Item 1",
            &[("app", "myapp"), ("user", "alice")],
            "secret1",
            false,
        )
        .await?;

    keyring
        .create_item(
            "Test Item 2",
            &[("app", "myapp"), ("user", "bob")],
            "secret2",
            false,
        )
        .await?;

    // Test retrieving all items
    let items = keyring.items().await?;
    assert_eq!(items.len(), 2);

    // Test searching by user
    let alice_items = keyring.search_items(&[("user", "alice")]).await?;
    assert_eq!(alice_items.len(), 1);
    assert_eq!(alice_items[0].label(), "Test Item 1");
    assert_eq!(alice_items[0].secret(), Secret::text("secret1"));

    // Test searching by app (should find both)
    let app_items = keyring.search_items(&[("app", "myapp")]).await?;
    assert_eq!(app_items.len(), 2);

    // Test deleting items
    keyring.delete(&[("user", "alice")]).await?;
    let remaining_items = keyring.items().await?;
    assert_eq!(remaining_items.len(), 1);
    assert_eq!(remaining_items[0].label(), "Test Item 2");

    Ok(())
}

#[tokio::test]
async fn item_attribute_operations() -> Result<(), Error> {
    let temp_dir = tempdir().unwrap();
    let keyring_path = temp_dir.path().join("attr_test.keyring");
    let keyring = UnlockedKeyring::load(&keyring_path, Some(strong_key())).await?;

    // Create item with initial attributes
    keyring
        .create_item(
            "Attribute Test",
            &[("app", "testapp"), ("version", "1.0"), ("env", "test")],
            "test-secret",
            false,
        )
        .await?;

    let items = keyring.search_items(&[("app", "testapp")]).await?;
    assert_eq!(items.len(), 1);
    let item = &items[0];

    // Test reading attributes
    let attrs = item.attributes();
    assert_eq!(attrs.len(), 4); // 3 + xdg:schema
    assert_eq!(attrs.get("app").unwrap().to_string(), "testapp");
    assert_eq!(attrs.get("version").unwrap().to_string(), "1.0");
    assert_eq!(attrs.get("env").unwrap().to_string(), "test");

    // Test updating attributes
    let index = keyring
        .lookup_item_index(&[("app", "testapp")])
        .await?
        .unwrap();

    let items = keyring.items().await?;
    let mut item_to_replace = items.into_iter().next().unwrap();

    item_to_replace.set_attributes(&[
        ("app", "testapp"),
        ("version", "2.0"),        // updated
        ("env", "production"),     // updated
        ("new_attr", "new_value"), // added
    ]);

    keyring.replace_item_index(index, &item_to_replace).await?;

    let updated_items = keyring.search_items(&[("app", "testapp")]).await?;
    assert_eq!(updated_items.len(), 1);
    let updated_attrs = updated_items[0].attributes();
    assert_eq!(updated_attrs.get("version").unwrap().to_string(), "2.0");
    assert_eq!(updated_attrs.get("env").unwrap().to_string(), "production");
    assert_eq!(
        updated_attrs.get("new_attr").unwrap().to_string(),
        "new_value"
    );
    assert_eq!(updated_items[0].secret(), Secret::text("test-secret"));

    Ok(())
}

#[tokio::test]
async fn bulk_create_items() -> Result<(), Error> {
    let temp_dir = tempdir().unwrap();
    let keyring_path = temp_dir.path().join("bulk_create_test.keyring");
    let keyring = UnlockedKeyring::load(&keyring_path, Some(strong_key())).await?;

    // Prepare multiple items to create at once
    let items_to_create = vec![
        (
            "Bulk Item 1".to_string(),
            HashMap::from([
                ("app".to_string(), "bulk-app".to_string()),
                ("user".to_string(), "user1".to_string()),
            ]),
            Secret::text("secret1"),
            false,
        ),
        (
            "Bulk Item 2".to_string(),
            HashMap::from([
                ("app".to_string(), "bulk-app".to_string()),
                ("user".to_string(), "user2".to_string()),
            ]),
            Secret::text("secret2"),
            false,
        ),
        (
            "Bulk Item 3".to_string(),
            HashMap::from([
                ("app".to_string(), "bulk-app".to_string()),
                ("user".to_string(), "user3".to_string()),
            ]),
            Secret::text("secret3"),
            false,
        ),
    ];

    // Create all items in bulk
    keyring.create_items(items_to_create).await?;
    // Verify all items were created
    let all_items = keyring.search_items(&[("app", "bulk-app")]).await?;
    assert_eq!(all_items.len(), 3);

    // Test replace=true in bulk create
    let replace_items = vec![(
        "Replaced Item".to_string(),
        HashMap::from([
            ("app".to_string(), "bulk-app".to_string()),
            ("user".to_string(), "user1".to_string()),
        ]),
        Secret::text("new_secret1"),
        true, // replace=true should remove existing item with same attributes
    )];

    keyring.create_items(replace_items).await?;

    // Verify the item was replaced - should still have 3 items total
    let all_items_after = keyring.search_items(&[("app", "bulk-app")]).await?;
    assert_eq!(all_items_after.len(), 3);

    // A coarse replacement must preserve the three specific items.
    keyring
        .create_items(vec![(
            "Coarse Item".to_string(),
            HashMap::from([("app".to_string(), "bulk-app".to_string())]),
            Secret::text("coarse-secret"),
            true,
        )])
        .await?;
    assert_eq!(keyring.search_items(&[("app", "bulk-app")]).await?.len(), 4);

    // Replacing the coarse item removes only its predecessor.
    keyring
        .create_items(vec![(
            "Updated Coarse Item".to_string(),
            HashMap::from([("app".to_string(), "bulk-app".to_string())]),
            Secret::text("updated-coarse-secret"),
            true,
        )])
        .await?;
    assert_eq!(keyring.search_items(&[("app", "bulk-app")]).await?.len(), 4);
    Ok(())
}

#[tokio::test]
async fn replace_item_index_invalid() -> Result<(), Error> {
    let temp_dir = tempdir().unwrap();
    let keyring_path = temp_dir.path().join("replace_invalid_index.keyring");
    let keyring = UnlockedKeyring::load(&keyring_path, Some(strong_key())).await?;

    // Create one item
    keyring
        .create_item("Test Item", &[("app", "test")], "secret", false)
        .await?;

    // Try to replace at invalid index
    let items = keyring.items().await?;
    let existing_item = items.into_iter().next().unwrap();
    let result = keyring.replace_item_index(100, &existing_item).await;

    assert!(matches!(result, Err(Error::InvalidItemIndex(100))));

    Ok(())
}

#[tokio::test]
async fn replace_item_without_schema() -> Result<(), Error> {
    let keyring = UnlockedKeyring::temporary(Secret::blob("test_password")).await?;
    let unique = ("unique", "ssh-store:/home/user/.ssh/id_rsa");
    keyring
        .create_item("Migrated", &[unique], "old", false)
        .await?;

    // Another schema doesn't replace it
    keyring
        .create_item(
            "Other",
            &[unique, (XDG_SCHEMA_ATTRIBUTE, "org.example.Other")],
            "other",
            true,
        )
        .await?;
    assert_eq!(keyring.n_items().await, 2);

    // Items without a schema are implicitly generic
    keyring
        .create_item(
            "New",
            &[unique, (XDG_SCHEMA_ATTRIBUTE, oo7::GENERIC_SCHEMA)],
            "new",
            true,
        )
        .await?;
    let labels = keyring
        .items()
        .await?
        .iter()
        .map(|item| item.label().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(labels.len(), 2);
    assert!(labels.contains(&"New".to_owned()) && labels.contains(&"Other".to_owned()));

    Ok(())
}
