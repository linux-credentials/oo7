use crate::{service::PrompterType, tests::TestServiceSetup};

async fn unlock_retry_impl(prompter_type: PrompterType) -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    setup.server.set_prompter_type(prompter_type).await;
    let default_collection = &setup.collections[0];

    let dbus_secret = setup.create_dbus_secret("test-secret-data")?;
    default_collection
        .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
        .await?;

    setup.lock_collection(default_collection).await?;

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

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[tokio::test]
async fn unlock_retry_gnome() -> Result<(), Box<dyn std::error::Error>> {
    unlock_retry_impl(PrompterType::GNOME).await
}

#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
#[tokio::test]
async fn unlock_retry_plasma() -> Result<(), Box<dyn std::error::Error>> {
    unlock_retry_impl(PrompterType::Plasma).await
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
    setup.lock_collection(&setup.collections[0]).await?;

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
