use crate::tests::{TestServiceSetup, assert_next_signal};

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

    let signal_item = assert_next_signal(&mut signal_stream).await;
    assert_eq!(
        signal_item.inner().path().as_str(),
        item.inner().path().as_str(),
        "Signal should contain the changed item path"
    );

    // Change attributes and verify signal again
    item.set_attributes(&[("app", "updated-app")]).await?;
    assert_next_signal(&mut signal_stream).await;

    // Change secret and verify signal again
    let new_dbus_secret = setup.create_dbus_secret("new-secret")?;
    item.set_secret(&new_dbus_secret).await?;
    assert_next_signal(&mut signal_stream).await;

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
async fn set_label_persists() -> Result<(), Box<dyn std::error::Error>> {
    let setup =
        TestServiceSetup::with_login_keyring(oo7::Secret::from("test-password-long-enough"))
            .await?;
    let collection = &setup.collections[0];

    // Stored first, with a superset of the changed item's attributes
    let other_secret = setup.create_dbus_secret("other-secret")?;
    collection
        .create_item(
            "Other Item",
            &[("app", "test"), ("user", "other")],
            &other_secret,
            false,
            None,
        )
        .await?;
    let secret = setup.create_dbus_secret("test-secret")?;
    let item = collection
        .create_item("Test Item", &[("app", "test")], &secret, false, None)
        .await?;

    item.set_label("New Label").await?;

    let items = setup.login_keyring().await?.items().await?;
    let labels = items.iter().map(|i| i.label()).collect::<Vec<_>>();
    assert_eq!(labels, ["Other Item", "New Label"]);

    Ok(())
}

#[tokio::test]
async fn set_attributes_persists() -> Result<(), Box<dyn std::error::Error>> {
    let setup =
        TestServiceSetup::with_login_keyring(oo7::Secret::from("test-password-long-enough"))
            .await?;
    let collection = &setup.collections[0];

    // Stored first, with a superset of the changed item's attributes
    let other_secret = setup.create_dbus_secret("other-secret")?;
    collection
        .create_item(
            "Other Item",
            &[("app", "test"), ("user", "other")],
            &other_secret,
            false,
            None,
        )
        .await?;
    let secret = setup.create_dbus_secret("test-secret")?;
    let item = collection
        .create_item("Test Item", &[("app", "test")], &secret, false, None)
        .await?;

    item.set_attributes(&[("app", "updated")]).await?;

    let items = setup.login_keyring().await?.items().await?;
    assert_eq!(items[0].attributes().get("user").unwrap(), "other");
    assert_eq!(items[1].label(), "Test Item");
    assert_eq!(items[1].attributes().get("app").unwrap(), "updated");

    Ok(())
}
