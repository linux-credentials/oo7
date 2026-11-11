use crate::{service::PrompterType, tests::TestServiceSetup};

async fn delete_locked_item_with_prompt_impl(
    prompter_type: PrompterType,
) -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    setup.server.set_prompter_type(prompter_type).await;
    let default_collection = &setup.collections[0];

    let dbus_secret = setup.create_dbus_secret("test-password")?;

    let item = default_collection
        .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
        .await?;

    let items = default_collection.items().await?;
    assert_eq!(items.len(), 1, "Should have one item");

    setup.lock_collection(default_collection).await?;

    assert!(item.is_locked().await?, "Item should be locked");

    item.delete(None).await?;

    let items = default_collection.items().await?;
    assert_eq!(items.len(), 0, "Item should be deleted after prompt");

    Ok(())
}

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[tokio::test]
async fn delete_locked_item_with_prompt_gnome() -> Result<(), Box<dyn std::error::Error>> {
    delete_locked_item_with_prompt_impl(PrompterType::GNOME).await
}

#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
#[tokio::test]
async fn delete_locked_item_with_prompt_plasma() -> Result<(), Box<dyn std::error::Error>> {
    delete_locked_item_with_prompt_impl(PrompterType::Plasma).await
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
    setup.lock_collection(&setup.collections[0]).await?;

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
    let new_dbus_secret = setup.create_dbus_secret("new-password")?;
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

    // Property setters go through org.freedesktop.DBus.Properties.Set,
    // so the error is wrapped in FDO rather than deserialized as ServiceError.
    let result = item.set_attributes(&[("app", "new-app")]).await;
    assert!(
        matches!(result, Err(oo7::dbus::Error::ZBus(zbus::Error::FDO(_)))),
        "set_attributes should fail with IsLocked error, got: {:?}",
        result
    );

    let result = item.set_label("New Label").await;
    assert!(
        matches!(result, Err(oo7::dbus::Error::ZBus(zbus::Error::FDO(_)))),
        "set_label should fail with IsLocked error, got: {:?}",
        result
    );

    // Property getters go through org.freedesktop.DBus.Properties.Get,
    // arriving as a MethodError with the IsLocked error name.
    let result = item.label().await;
    assert!(
        matches!(
            result,
            Err(oo7::dbus::Error::ZBus(zbus::Error::MethodError(..)))
        ),
        "label should fail on locked item, got: {:?}",
        result
    );

    let result = item.attributes().await;
    assert!(
        matches!(
            result,
            Err(oo7::dbus::Error::ZBus(zbus::Error::MethodError(..)))
        ),
        "attributes should fail on locked item, got: {:?}",
        result
    );

    let result = item.created().await;
    assert!(
        matches!(
            result,
            Err(oo7::dbus::Error::ZBus(zbus::Error::MethodError(..)))
        ),
        "created should fail on locked item, got: {:?}",
        result
    );

    let result = item.modified().await;
    assert!(
        matches!(
            result,
            Err(oo7::dbus::Error::ZBus(zbus::Error::MethodError(..)))
        ),
        "modified should fail on locked item, got: {:?}",
        result
    );

    Ok(())
}
