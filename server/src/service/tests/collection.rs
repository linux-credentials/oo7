use zbus::wire::ObjectPath;

use super::super::*;
use crate::tests::TestServiceSetup;

async fn create_collection_basic_impl(
    prompter_type: PrompterType,
) -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    setup.server.set_prompter_type(prompter_type).await;

    // Get initial collection count
    let initial_collections = setup.service_api.collections().await?;
    let initial_count = initial_collections.len();

    // Subscribe to CollectionCreated signal before creating
    let signal_stream = setup.service_api.receive_collection_created().await?;
    tokio::pin!(signal_stream);

    // Create a new collection
    let collection = setup
        .service_api
        .create_collection("MyNewKeyring", Some("my-custom-alias"), None)
        .await?;

    // Verify CollectionCreated signal was emitted
    let signal_collection = crate::tests::assert_next_signal(&mut signal_stream).await;
    assert_eq!(
        signal_collection.inner().path().as_str(),
        collection.inner().path().as_str(),
        "Signal should contain the created collection path"
    );

    // Verify collection appears in collections list
    let collections = setup.service_api.collections().await?;
    assert_eq!(
        collections.len(),
        initial_count + 1,
        "Should have one more collection"
    );

    // Verify the collection label
    let label = collection.label().await?;
    assert_eq!(
        label, "MyNewKeyring",
        "Collection should have correct label"
    );

    // Verify the keyring file exists on disk
    let server_collection = setup
        .server
        .collection_from_path(collection.inner().path())
        .await
        .expect("Collection should exist on server");
    let keyring_guard = server_collection.keyring.read().await;
    let keyring_path = keyring_guard.as_ref().unwrap().path().unwrap();

    assert!(
        keyring_path.exists(),
        "Keyring file should exist on disk at {:?}",
        keyring_path
    );

    // Verify the alias was set
    let alias_collection = setup.service_api.read_alias("my-custom-alias").await?;
    assert!(
        alias_collection.is_some(),
        "Should be able to read collection by alias"
    );
    assert_eq!(
        alias_collection.unwrap().inner().path(),
        collection.inner().path(),
        "Alias should point to the new collection"
    );

    tokio::fs::remove_file(keyring_path).await?;
    Ok(())
}

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[tokio::test]
async fn create_collection_basic_gnome() -> Result<(), Box<dyn std::error::Error>> {
    create_collection_basic_impl(PrompterType::GNOME).await
}

#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
#[tokio::test]
async fn create_collection_basic_plasma() -> Result<(), Box<dyn std::error::Error>> {
    create_collection_basic_impl(PrompterType::Plasma).await
}

async fn create_collection_and_add_items_impl(
    prompter_type: PrompterType,
) -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    setup.server.set_prompter_type(prompter_type).await;

    // Create a new collection
    let collection = setup
        .service_api
        .create_collection("ItemTestKeyring", None, None)
        .await?;

    // Verify collection is unlocked and ready for items
    assert!(
        !collection.is_locked().await?,
        "New collection should be unlocked"
    );

    // Create an item in the new collection
    let secret = oo7::Secret::text("hello-world-test");
    let dbus_secret = setup.create_dbus_secret(secret.clone())?;

    let item = collection
        .create_item(
            "Test Item",
            &[("app", "test-app")],
            &dbus_secret,
            false,
            None,
        )
        .await?;

    // Verify item was created
    let items = collection.items().await?;
    assert_eq!(items.len(), 1, "Should have one item in new collection");
    assert_eq!(
        items[0].inner().path(),
        item.inner().path(),
        "Item path should match"
    );

    // Verify we can retrieve the secret
    let retrieved_secret = item.secret(&setup.session).await?;
    assert_eq!(
        retrieved_secret.value(),
        secret.as_bytes(),
        "Should be able to retrieve secret from item in new collection"
    );

    let server_collection = setup
        .server
        .collection_from_path(collection.inner().path())
        .await
        .expect("Collection should exist on server");
    let keyring_guard = server_collection.keyring.read().await;
    let keyring_path = keyring_guard.as_ref().unwrap().path().unwrap();
    tokio::fs::remove_file(&keyring_path).await?;
    Ok(())
}

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[tokio::test]
async fn create_collection_and_add_items_gnome() -> Result<(), Box<dyn std::error::Error>> {
    create_collection_and_add_items_impl(PrompterType::GNOME).await
}

#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
#[tokio::test]
async fn create_collection_and_add_items_plasma() -> Result<(), Box<dyn std::error::Error>> {
    create_collection_and_add_items_impl(PrompterType::Plasma).await
}

async fn create_collection_dismissed_impl(
    prompter_type: PrompterType,
) -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    setup.server.set_prompter_type(prompter_type).await;

    // Get initial collection count
    let initial_collections = setup.service_api.collections().await?;
    let initial_count = initial_collections.len();

    // Set mock prompter to dismiss
    setup.set_password_accept(false).await;

    // Try to create a collection
    let result = setup
        .service_api
        .create_collection("DismissedKeyring", None, None)
        .await;

    // Should get Dismissed error
    assert!(
        matches!(result, Err(oo7::dbus::Error::Dismissed)),
        "Should return Dismissed error when prompt dismissed"
    );

    // Verify collection was NOT created
    let collections = setup.service_api.collections().await?;
    assert_eq!(
        collections.len(),
        initial_count,
        "Should not have created a new collection after dismissal"
    );

    Ok(())
}

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[tokio::test]
async fn create_collection_dismissed_gnome() -> Result<(), Box<dyn std::error::Error>> {
    create_collection_dismissed_impl(PrompterType::GNOME).await
}

#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
#[tokio::test]
async fn create_collection_dismissed_plasma() -> Result<(), Box<dyn std::error::Error>> {
    create_collection_dismissed_impl(PrompterType::Plasma).await
}

#[tokio::test]
async fn complete_collection_creation_no_pending() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Try to complete collection creation with a prompt path that has no
    // pending collection
    let fake_prompt_path = ObjectPath::try_from("/org/freedesktop/secrets/prompt/p999").unwrap();
    let secret = oo7::Secret::from("test-password-long-enough");

    let result = setup
        .server
        .complete_collection_creation(&fake_prompt_path, Some(secret))
        .await;

    // Should get NoSuchObject error
    assert!(
        matches!(result, Err(ServiceError::NoSuchObject(_))),
        "Should return NoSuchObject error when no pending collection exists"
    );
    Ok(())
}
