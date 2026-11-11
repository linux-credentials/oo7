use std::collections::HashMap;

use crate::tests::TestServiceSetup;

#[tokio::test]
async fn search_items() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Search for items (should return empty initially)
    let (unlocked, locked) = setup
        .service_api
        .search_items(&[("application", "test-app")])
        .await?;

    assert!(
        unlocked.is_empty(),
        "Should have no unlocked items initially"
    );
    assert!(locked.is_empty(), "Should have no locked items initially");

    // Search with empty attributes - edge case
    let attributes: HashMap<&str, &str> = HashMap::default();
    let (unlocked, locked) = setup.service_api.search_items(&attributes).await?;

    assert!(
        locked.is_empty(),
        "Should have no locked items with empty search"
    );
    assert!(
        unlocked.is_empty(),
        "Should have no unlocked items with empty search"
    );

    // Test with both locked and unlocked items
    // Create items in default collection (unlocked)
    setup
        .create_item("Unlocked Item", &[("app", "testapp")], "password1", false)
        .await?;

    // Create item in default collection and lock it
    let locked_item = setup
        .create_item("Locked Item", &[("app", "testapp")], "password2", false)
        .await?;

    // Lock just this item (not the whole collection)
    setup.lock_item(&locked_item).await?;

    // Search for items with the shared attribute
    let (unlocked, locked) = setup
        .service_api
        .search_items(&[("app", "testapp")])
        .await?;

    assert_eq!(unlocked.len(), 1, "Should find 1 unlocked item");
    assert_eq!(locked.len(), 1, "Should find 1 locked item");

    Ok(())
}

#[tokio::test]
async fn search_items_with_results() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Create items in default collection
    setup
        .create_item(
            "Firefox Login",
            &[("application", "firefox"), ("type", "login")],
            "password1",
            false,
        )
        .await?;

    setup
        .create_item(
            "Chrome Login",
            &[("application", "chrome"), ("type", "login")],
            "password2",
            false,
        )
        .await?;

    // Create item in session collection
    let dbus_secret3 = setup.create_dbus_secret("password3")?;

    setup.collections[1]
        .create_item(
            "Session Item",
            &[("application", "firefox"), ("type", "session")],
            &dbus_secret3,
            false,
            None,
        )
        .await?;

    // Search for all firefox items
    let (unlocked, locked) = setup
        .service_api
        .search_items(&[("application", "firefox")])
        .await?;

    assert_eq!(unlocked.len(), 2, "Should find 2 firefox items");
    assert!(locked.is_empty(), "Should have no locked items");

    // Search for login type items
    let (unlocked, locked) = setup.service_api.search_items(&[("type", "login")]).await?;

    assert_eq!(unlocked.len(), 2, "Should find 2 login items");
    assert!(locked.is_empty(), "Should have no locked items");

    // Search for chrome items
    let (unlocked, locked) = setup
        .service_api
        .search_items(&[("application", "chrome")])
        .await?;

    assert_eq!(unlocked.len(), 1, "Should find 1 chrome item");
    assert!(locked.is_empty(), "Should have no locked items");

    // Search for non-existent
    let (unlocked, locked) = setup
        .service_api
        .search_items(&[("application", "nonexistent")])
        .await?;

    assert!(unlocked.is_empty(), "Should find no items");
    assert!(locked.is_empty(), "Should have no locked items");

    Ok(())
}

// Reproducer for https://github.com/linux-credentials/oo7/issues/586
#[tokio::test]
async fn search_items_missing_xdg_schema() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Item without xdg:schema, as found in old gnome-keyring migrations.
    setup
        .create_item(
            "Unlock password for: user@example.com",
            &[("unique", "ssh-store:/home/user/.ssh/id_rsa")],
            "my-ssh-passphrase",
            false,
        )
        .await?;

    // gcr searches with xdg:schema via libsecret's SECRET_SCHEMA_NONE.
    let (unlocked, locked) = setup
        .service_api
        .search_items(&[
            ("unique", "ssh-store:/home/user/.ssh/id_rsa"),
            (oo7::XDG_SCHEMA_ATTRIBUTE, oo7::GENERIC_SCHEMA),
        ])
        .await?;

    assert_eq!(unlocked.len(), 1);
    assert!(locked.is_empty());

    Ok(())
}

// gcr stores the passphrase again with its schema, which must replace the
// item migrated without one instead of duplicating it.
#[tokio::test]
async fn replace_item_missing_xdg_schema() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    let unique = ("unique", "ssh-store:/home/user/.ssh/id_rsa");

    setup
        .create_item("Unlock password", &[unique], "old-passphrase", false)
        .await?;
    setup
        .create_item(
            "Unlock password",
            &[unique, (oo7::XDG_SCHEMA_ATTRIBUTE, oo7::GENERIC_SCHEMA)],
            "new-passphrase",
            true,
        )
        .await?;

    let items = setup.collections[0].items().await?;
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].attributes().await?.get(oo7::XDG_SCHEMA_ATTRIBUTE),
        Some(&oo7::GENERIC_SCHEMA.to_owned())
    );

    let server_collection = setup
        .server
        .collection_from_path(setup.collections[0].inner().path())
        .await
        .unwrap();
    let keyring = server_collection.keyring.read().await;
    assert_eq!(keyring.as_ref().unwrap().items().await?.len(), 1);

    Ok(())
}
