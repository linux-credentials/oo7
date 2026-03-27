use oo7::dbus;

use super::*;
use crate::tests::TestServiceSetup;

#[tokio::test]
async fn open_session_plain() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    assert!(
        setup.aes_key.is_none(),
        "Plain session should not have AES key"
    );

    // Should have 2 collections: default + session
    assert_eq!(
        setup.collections.len(),
        2,
        "Expected default and session collections"
    );
    Ok(())
}

#[tokio::test]
async fn open_session_encrypted() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::encrypted_session(false).await?;
    assert!(
        setup.server_public_key.is_some(),
        "Encrypted session should have server public key"
    );
    let key = setup.aes_key.unwrap().clone();
    assert_eq!((*key).as_ref().len(), 16, "AES key should be 16 bytes");
    Ok(())
}

#[tokio::test]
async fn session_collection_only() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(false).await?;

    // Should have only session collection (no default)
    assert_eq!(
        setup.collections.len(),
        1,
        "Should have exactly one collection"
    );
    Ok(())
}

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
async fn get_secrets() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Test with empty items list - edge case
    #[allow(clippy::mutable_key_type)]
    let secrets = setup.service_api.secrets(&[], &setup.session).await?;
    assert!(
        secrets.is_empty(),
        "Should return empty secrets for empty items list"
    );

    // Create two items with different secrets
    let secret1 = Secret::text("password1");
    let item1 = setup
        .create_item("Item 1", &[("app", "test1")], secret1.clone(), false)
        .await?;

    let secret2 = Secret::text("password2");
    let item2 = setup
        .create_item("Item 2", &[("app", "test2")], secret2.clone(), false)
        .await?;

    // Get secrets for both items
    let item_paths = vec![item1.clone(), item2.clone()];
    #[allow(clippy::mutable_key_type)]
    let secrets = setup
        .service_api
        .secrets(&item_paths, &setup.session)
        .await?;

    // Should have both secrets
    assert_eq!(secrets.len(), 2, "Should retrieve both secrets");

    // Verify first secret
    let retrieved_secret1 = secrets.get(&item1).unwrap();
    assert_eq!(retrieved_secret1.value(), secret1.as_bytes());

    // Verify second secret
    let retrieved_secret2 = secrets.get(&item2).unwrap();
    assert_eq!(retrieved_secret2.value(), secret2.as_bytes());

    Ok(())
}

#[tokio::test]
async fn get_secrets_multiple_collections() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Should have 2 collections: default (Login) and session
    assert_eq!(setup.collections.len(), 2);

    // Create item in default collection (index 0)
    let secret1 = Secret::text("default-password");
    let item1 = setup
        .create_item(
            "Default Item",
            &[("app", "default-app")],
            secret1.clone(),
            false,
        )
        .await?;

    // Create item in session collection (index 1)
    let secret2 = Secret::text("session-password");
    let dbus_secret2 = setup.create_dbus_secret(secret2.clone())?;

    let item2 = setup.collections[1]
        .create_item(
            "Session Item",
            &[("app", "session-app")],
            &dbus_secret2,
            false,
            None,
        )
        .await?;

    // Get secrets for both items from different collections
    let item_paths = vec![item1.clone(), item2.clone()];
    #[allow(clippy::mutable_key_type)]
    let secrets = setup
        .service_api
        .secrets(&item_paths, &setup.session)
        .await?;

    // Should have both secrets
    assert_eq!(
        secrets.len(),
        2,
        "Should retrieve secrets from both collections"
    );

    // Verify default collection secret
    let retrieved_secret1 = secrets.get(&item1).unwrap();
    assert_eq!(retrieved_secret1.value(), secret1.as_bytes());

    // Verify session collection secret
    let retrieved_secret2 = secrets.get(&item2).unwrap();
    assert_eq!(retrieved_secret2.value(), secret2.as_bytes());

    Ok(())
}

#[tokio::test]
async fn read_alias() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Default collection should have "default" alias
    let default_collection = setup.service_api.read_alias("default").await?;
    assert!(
        default_collection.is_some(),
        "Default alias should return a collection"
    );

    // Verify it's the Login collection by checking its label
    let label = default_collection.as_ref().unwrap().label().await?;
    assert_eq!(
        label, "Login",
        "Default alias should point to Login collection"
    );

    // Non-existent alias should return None
    let nonexistent = setup.service_api.read_alias("nonexistent").await?;
    assert!(
        nonexistent.is_none(),
        "Non-existent alias should return None"
    );

    Ok(())
}

#[tokio::test]
async fn set_alias() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Set alias for session collection
    setup
        .service_api
        .set_alias("my-alias", &setup.collections[1])
        .await?;

    // Read the alias back
    let alias_collection = setup.service_api.read_alias("my-alias").await?;
    assert!(
        alias_collection.is_some(),
        "Alias should return a collection"
    );
    assert_eq!(
        alias_collection.unwrap().inner().path(),
        setup.collections[1].inner().path(),
        "Alias should point to session collection"
    );

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

#[tokio::test]
async fn get_secrets_invalid_session() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Create an item
    let item = setup
        .create_item("Test Item", &[("app", "test")], "test-password", false)
        .await?;

    // Try to get secrets with invalid session path
    let invalid_session =
        dbus::api::Session::new(&setup.client_conn, "/invalid/session/path").await?;
    let result = setup.service_api.secrets(&[item], &invalid_session).await;

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
async fn set_alias_invalid_collection() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Try to set alias for non-existent collection
    let invalid_collection = dbus::api::Collection::new(
        &setup.client_conn,
        "/org/freedesktop/secrets/collection/nonexistent",
    )
    .await?;
    let result = setup
        .service_api
        .set_alias("test-alias", &invalid_collection)
        .await;

    assert!(
        matches!(
            result,
            Err(oo7::dbus::Error::Service(
                oo7::dbus::ServiceError::NoSuchObject(_)
            ))
        ),
        "Should be NoSuchObject error"
    );

    Ok(())
}

#[tokio::test]
async fn get_secrets_with_non_existent_items() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Create one real item
    let item1 = setup
        .create_item("Item 1", &[("app", "test")], "password1", false)
        .await?;

    // Create a fake item path that doesn't exist
    let fake_item = dbus::api::Item::new(
        &setup.client_conn,
        "/org/freedesktop/secrets/collection/Login/999",
    )
    .await?;

    // Request secrets for both real and fake items
    let item_paths = vec![item1.clone(), fake_item];
    #[allow(clippy::mutable_key_type)]
    let secrets = setup
        .service_api
        .secrets(&item_paths, &setup.session)
        .await?;

    // Should only get the secret for the real item
    assert_eq!(
        secrets.len(),
        1,
        "Should only retrieve secret for existing item"
    );
    assert!(secrets.contains_key(&item1), "Should have item1 secret");

    Ok(())
}

#[tokio::test]
async fn search_items_across_collections() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    let collections = setup.service_api.collections().await?;
    assert_eq!(collections.len(), 2, "Should have 2 collections");

    // Create item in first collection
    let dbus_secret1 = setup.create_dbus_secret("password1")?;

    collections[0]
        .create_item(
            "Default Item",
            &[("shared", "attr")],
            &dbus_secret1,
            false,
            None,
        )
        .await?;

    // Create item in second collection with same attributes
    let dbus_secret2 = setup.create_dbus_secret("password2")?;

    collections[1]
        .create_item(
            "Session Item",
            &[("shared", "attr")],
            &dbus_secret2,
            false,
            None,
        )
        .await?;

    // Search should find items from both collections
    let (unlocked, locked) = setup
        .service_api
        .search_items(&[("shared", "attr")])
        .await?;

    assert_eq!(unlocked.len(), 2, "Should find items from both collections");
    assert!(locked.is_empty(), "Should have no locked items");

    Ok(())
}

#[tokio::test]
async fn unlock_edge_cases() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Test 1: Empty object list
    let items: Vec<ObjectPath<'_>> = vec![];
    let unlocked = setup.service_api.unlock(&items, None).await?;
    assert!(unlocked.is_empty(), "Should return empty for empty input");

    // Test 2: Non-existent objects
    let fake_collection = dbus::api::Collection::new(
        &setup.client_conn,
        "/org/freedesktop/secrets/collection/NonExistent",
    )
    .await?;

    let fake_item = dbus::api::Item::new(
        &setup.client_conn,
        "/org/freedesktop/secrets/collection/Login/999",
    )
    .await?;

    let unlocked = setup
        .service_api
        .unlock(
            &[fake_collection.inner().path(), fake_item.inner().path()],
            None,
        )
        .await?;

    assert!(
        unlocked.is_empty(),
        "Should have no unlocked objects for non-existent paths"
    );

    // Test 3: Already unlocked objects
    let item = setup
        .create_item("Test Item", &[("app", "test")], "test-password", false)
        .await?;

    // Verify item is unlocked
    assert!(!item.is_locked().await?, "Item should be unlocked");

    // Try to unlock already unlocked item
    let unlocked = setup
        .service_api
        .unlock(&[item.inner().path()], None)
        .await?;

    assert_eq!(unlocked.len(), 1, "Should return the already-unlocked item");
    assert_eq!(
        unlocked[0].as_str(),
        item.inner().path().as_str(),
        "Should return the same item path"
    );

    // Also test with collection (starts unlocked by default)
    assert!(
        !setup.collections[0].is_locked().await?,
        "Collection should be unlocked"
    );

    let unlocked = setup
        .service_api
        .unlock(&[setup.collections[0].inner().path()], None)
        .await?;

    assert_eq!(
        unlocked.len(),
        1,
        "Should return the already-unlocked collection"
    );

    Ok(())
}

#[tokio::test]
async fn lock_non_existent_objects() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::encrypted_session(true).await?;

    // Test with empty object list
    let items: Vec<ObjectPath<'_>> = vec![];
    let locked = setup.service_api.lock(&items, None).await?;
    assert!(locked.is_empty(), "Should return empty for empty input");

    // Test locking non-existent objects
    let fake_collection = dbus::api::Collection::new(
        &setup.client_conn,
        "/org/freedesktop/secrets/collection/NonExistent",
    )
    .await?;

    let fake_item = dbus::api::Item::new(
        &setup.client_conn,
        "/org/freedesktop/secrets/collection/Login/999",
    )
    .await?;

    let locked = setup
        .service_api
        .lock(
            &[fake_collection.inner().path(), fake_item.inner().path()],
            None,
        )
        .await?;

    assert!(
        locked.is_empty(),
        "Should have no locked objects for non-existent paths"
    );

    Ok(())
}

async fn unlock_collection_prompt_impl(
    prompter_type: PrompterType,
) -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    setup.server.set_prompter_type(prompter_type).await;

    // Lock the collection using server-side API
    setup.lock_collection(&setup.collections[0]).await?;

    assert!(
        setup.collections[0].is_locked().await?,
        "Collection should be locked"
    );

    // Test 1: Unlock with accept
    let unlocked = setup
        .service_api
        .unlock(&[setup.collections[0].inner().path()], None)
        .await?;

    assert_eq!(unlocked.len(), 1, "Should have unlocked 1 collection");
    assert_eq!(
        unlocked[0].as_str(),
        setup.collections[0].inner().path().as_str(),
        "Should return the collection path"
    );
    assert!(
        !setup.collections[0].is_locked().await?,
        "Collection should be unlocked after accepting prompt"
    );

    // Lock the collection again for dismiss test
    setup.lock_collection(&setup.collections[0]).await?;
    assert!(
        setup.collections[0].is_locked().await?,
        "Collection should be locked again"
    );

    // Test 2: Unlock with dismiss
    setup.set_password_accept(false).await;
    let result = setup
        .service_api
        .unlock(&[setup.collections[0].inner().path()], None)
        .await;

    assert!(
        matches!(result, Err(oo7::dbus::Error::Dismissed)),
        "Should return Dismissed error when prompt dismissed"
    );
    assert!(
        setup.collections[0].is_locked().await?,
        "Collection should still be locked after dismissing prompt"
    );

    Ok(())
}

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[tokio::test]
async fn unlock_collection_prompt_gnome() -> Result<(), Box<dyn std::error::Error>> {
    unlock_collection_prompt_impl(PrompterType::GNOME).await
}

#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
#[tokio::test]
async fn unlock_collection_prompt_plasma() -> Result<(), Box<dyn std::error::Error>> {
    unlock_collection_prompt_impl(PrompterType::Plasma).await
}

async fn unlock_item_prompt_impl(
    prompter_type: PrompterType,
) -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    setup.server.set_prompter_type(prompter_type).await;

    // Create an item
    let dbus_secret = setup.create_dbus_secret("test-password")?;
    let default_collection = setup.service_api.read_alias("default").await?.unwrap();
    let item = default_collection
        .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
        .await?;

    // Lock the collection (which locks the item)
    setup.lock_collection(&default_collection).await?;

    assert!(
        item.is_locked().await?,
        "Item should be locked when collection is locked"
    );

    // Test 1: Unlock with accept
    let unlocked = setup
        .service_api
        .unlock(&[item.inner().path()], None)
        .await?;

    assert_eq!(unlocked.len(), 1, "Should have unlocked 1 item");
    assert_eq!(
        unlocked[0].as_str(),
        item.inner().path().as_str(),
        "Should return the item path"
    );
    assert!(
        !item.is_locked().await?,
        "Item should be unlocked after accepting prompt"
    );

    // Lock the item again for dismiss test
    setup.lock_collection(&default_collection).await?;
    assert!(item.is_locked().await?, "Item should be locked again");

    // Test 2: Unlock with dismiss
    setup.set_password_accept(false).await;
    let result = setup.service_api.unlock(&[item.inner().path()], None).await;

    assert!(
        matches!(result, Err(oo7::dbus::Error::Dismissed)),
        "Should return Dismissed error when prompt dismissed"
    );
    assert!(
        item.is_locked().await?,
        "Item should still be locked after dismissing prompt"
    );

    Ok(())
}

#[tokio::test]
async fn lock_item_in_unlocked_collection() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Create an item (starts unlocked)
    let item = setup
        .create_item("Test Item", &[("app", "test")], "test-password", false)
        .await?;

    assert!(!item.is_locked().await?, "Item should start unlocked");
    assert!(
        !setup.collections[0].is_locked().await?,
        "Collection should be unlocked"
    );

    // When collection is unlocked, locking an item should happen directly without a
    // prompt
    let locked = setup.service_api.lock(&[item.inner().path()], None).await?;

    assert_eq!(locked.len(), 1, "Should have locked 1 item");
    assert_eq!(
        locked[0].as_str(),
        item.inner().path().as_str(),
        "Should return the item path"
    );
    assert!(item.is_locked().await?, "Item should be locked directly");

    // Unlock the item again (using service API to unlock just the item)
    let unlocked = setup
        .service_api
        .unlock(&[item.inner().path()], None)
        .await?;
    assert_eq!(unlocked.len(), 1, "Should have unlocked 1 item");
    assert!(!item.is_locked().await?, "Item should be unlocked again");

    // Locking again should work the same way (no prompt)
    let locked = setup.service_api.lock(&[item.inner().path()], None).await?;
    assert_eq!(locked.len(), 1, "Should have locked 1 item again");
    assert!(item.is_locked().await?, "Item should be locked again");

    Ok(())
}

#[tokio::test]
async fn lock_collection_no_prompt() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Collection starts unlocked
    assert!(
        !setup.collections[0].is_locked().await?,
        "Collection should start unlocked"
    );

    // Lock the collection
    let locked = setup
        .service_api
        .lock(&[setup.collections[0].inner().path()], None)
        .await?;

    assert_eq!(locked.len(), 1, "Should have locked 1 collection");
    assert_eq!(
        locked[0].as_str(),
        setup.collections[0].inner().path().as_str(),
        "Should return the collection path"
    );
    assert!(
        setup.collections[0].is_locked().await?,
        "Collection should be locked instantly"
    );

    // Unlock the collection
    setup.unlock_collection(&setup.collections[0]).await?;
    assert!(
        !setup.collections[0].is_locked().await?,
        "Collection should be unlocked"
    );

    // Lock again to verify it works multiple times
    let locked = setup
        .service_api
        .lock(&[setup.collections[0].inner().path()], None)
        .await?;

    assert_eq!(locked.len(), 1, "Should have locked 1 collection again");
    assert!(
        setup.collections[0].is_locked().await?,
        "Collection should be locked again"
    );

    Ok(())
}

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[tokio::test]
async fn unlock_item_prompt_gnome() -> Result<(), Box<dyn std::error::Error>> {
    unlock_item_prompt_impl(PrompterType::GNOME).await
}

#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
#[tokio::test]
async fn unlock_item_prompt_plasma() -> Result<(), Box<dyn std::error::Error>> {
    unlock_item_prompt_impl(PrompterType::Plasma).await
}

async fn create_collection_basic_impl(
    prompter_type: PrompterType,
) -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    setup.server.set_prompter_type(prompter_type).await;

    // Get initial collection count
    let initial_collections = setup.service_api.collections().await?;
    let initial_count = initial_collections.len();

    // Create a new collection
    let collection = setup
        .service_api
        .create_collection("MyNewKeyring", Some("my-custom-alias"), None)
        .await?;

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

async fn create_collection_signal_impl(
    prompter_type: PrompterType,
) -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    setup.server.set_prompter_type(prompter_type).await;

    // Subscribe to CollectionCreated signal
    let signal_stream = setup.service_api.receive_collection_created().await?;
    tokio::pin!(signal_stream);

    // Create a new collection
    let collection = setup
        .service_api
        .create_collection("TestKeyring", None, None)
        .await?;

    // Wait for signal with timeout
    let signal_result =
        tokio::time::timeout(tokio::time::Duration::from_secs(1), signal_stream.next()).await;

    assert!(
        signal_result.is_ok(),
        "Should receive CollectionCreated signal"
    );
    let signal = signal_result.unwrap();
    assert!(signal.is_some(), "Signal should not be None");

    let signal_collection = signal.unwrap();
    assert_eq!(
        signal_collection.inner().path().as_str(),
        collection.inner().path().as_str(),
        "Signal should contain the created collection path"
    );

    let server_collection = setup
        .server
        .collection_from_path(collection.inner().path())
        .await
        .expect("Collection should exist on server");
    let keyring_guard = server_collection.keyring.read().await;
    let keyring_path = keyring_guard.as_ref().unwrap().path().unwrap();
    tokio::fs::remove_file(keyring_path).await?;
    Ok(())
}

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[tokio::test]
async fn create_collection_signal_gnome() -> Result<(), Box<dyn std::error::Error>> {
    create_collection_signal_impl(PrompterType::GNOME).await
}

#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
#[tokio::test]
async fn create_collection_signal_plasma() -> Result<(), Box<dyn std::error::Error>> {
    create_collection_signal_impl(PrompterType::Plasma).await
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

    // Try to complete collection creation with a prompt path that has no pending
    // collection
    let fake_prompt_path = ObjectPath::try_from("/org/freedesktop/secrets/prompt/p999").unwrap();
    let secret = Secret::from("test-password-long-enough");

    let result = setup
        .server
        .complete_collection_creation(&fake_prompt_path, secret)
        .await;

    // Should get NoSuchObject error
    assert!(
        matches!(result, Err(ServiceError::NoSuchObject(_))),
        "Should return NoSuchObject error when no pending collection exists"
    );
    Ok(())
}

#[tokio::test]
async fn discover_v1_keyrings() -> Result<(), Box<dyn std::error::Error>> {
    // Set up a temporary data directory
    let temp_dir = tempfile::tempdir()?;
    let service = Service::new(temp_dir.path().to_path_buf(), None);

    // Create v1 keyrings directory
    let v1_dir = temp_dir.path().join("keyrings/v1");
    tokio::fs::create_dir_all(&v1_dir).await?;

    // Test 1: Empty directory
    let discovered = service.discover_keyrings(None).await?;
    assert!(
        discovered.is_empty(),
        "Should discover no keyrings in empty directory"
    );

    // Create multiple keyrings with different passwords
    // Add items to each so password validation works
    let secret1 = Secret::from("password-for-work");
    let keyring1 = UnlockedKeyring::open_at(temp_dir.path(), "work", secret1.clone()).await?;
    keyring1
        .create_item(
            "Work Item",
            &[("type", "work")],
            Secret::text("work-secret"),
            false,
        )
        .await?;
    keyring1.write().await?;

    let secret2 = Secret::from("password-for-personal");
    let keyring2 = UnlockedKeyring::open_at(temp_dir.path(), "personal", secret2.clone()).await?;
    keyring2
        .create_item(
            "Personal Item",
            &[("type", "personal")],
            Secret::text("personal-secret"),
            false,
        )
        .await?;
    keyring2.write().await?;

    // Create a "login" keyring which should get the default alias
    let secret3 = Secret::from("password-for-login");
    let keyring3 = UnlockedKeyring::open_at(temp_dir.path(), "login", secret3.clone()).await?;
    keyring3
        .create_item(
            "Login Item",
            &[("type", "login")],
            Secret::text("login-secret"),
            false,
        )
        .await?;
    keyring3.write().await?;

    // Create some non-keyring files that should be skipped
    tokio::fs::write(v1_dir.join("README.txt"), b"This is a readme").await?;
    tokio::fs::write(v1_dir.join("config.json"), b"{}").await?;
    tokio::fs::create_dir(v1_dir.join("subdir")).await?;

    // Test 2: Discover without any password, all should be locked
    let discovered = service.discover_keyrings(None).await?;
    assert_eq!(discovered.len(), 3, "Should discover 3 keyrings");
    for (_, _, _, keyring) in &discovered {
        assert!(
            keyring.is_locked(),
            "All keyrings should be locked without secret"
        );
    }

    // Test 3: Discover with one password, only that keyring should be unlocked
    let discovered = service.discover_keyrings(Some(secret1.clone())).await?;
    assert_eq!(discovered.len(), 3, "Should discover 3 keyrings");

    let work_keyring = discovered
        .iter()
        .find(|(_, label, _, _)| label == "Work")
        .unwrap();
    assert!(
        !work_keyring.3.is_locked(),
        "Work keyring should be unlocked with correct password"
    );

    let personal_keyring = discovered
        .iter()
        .find(|(_, label, _, _)| label == "Personal")
        .unwrap();
    assert!(
        personal_keyring.3.is_locked(),
        "Personal keyring should be locked with wrong password"
    );

    // Test 4: Verify login keyring gets default alias
    let login_keyring = discovered
        .iter()
        .find(|(_, label, _, _)| label == "Login")
        .unwrap();
    assert_eq!(
        login_keyring.2,
        oo7::dbus::Service::DEFAULT_COLLECTION,
        "Login keyring should have default alias"
    );
    assert!(
        login_keyring.3.is_locked(),
        "Login keyring should be locked with wrong password"
    );

    // Test 5: Verify labels are properly capitalized
    let labels: Vec<_> = discovered
        .iter()
        .map(|(_, label, _, _)| label.as_str())
        .collect();
    assert!(labels.contains(&"Work"), "Should have Work with capital W");
    assert!(
        labels.contains(&"Personal"),
        "Should have Personal with capital P"
    );
    assert!(
        labels.contains(&"Login"),
        "Should have Login with capital L"
    );

    Ok(())
}

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[tokio::test]
async fn unlock_pending_v0_migration_gnome() -> Result<(), Box<dyn std::error::Error>> {
    unlock_pending_v0_migration_impl(PrompterType::GNOME).await
}

#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
#[tokio::test]
async fn unlock_pending_v0_migration_plasma() -> Result<(), Box<dyn std::error::Error>> {
    unlock_pending_v0_migration_impl(PrompterType::Plasma).await
}

async fn unlock_pending_v0_migration_impl(
    prompter_type: PrompterType,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;

    let keyrings_dir = temp_dir.path().join("keyrings");
    let v1_dir = keyrings_dir.join("v1");
    tokio::fs::create_dir_all(&v1_dir).await?;

    // Copy the v0 keyring fixture
    let v0_secret = Secret::from("test");
    let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("client/fixtures/legacy.keyring");
    let v0_path = keyrings_dir.join("legacy.keyring");
    tokio::fs::copy(&fixture_path, &v0_path).await?;

    // Create test service that discovers keyrings WITHOUT the password
    let setup = crate::tests::TestServiceSetup::with_disk_keyrings(
        temp_dir.path().to_path_buf(),
        None,
        None,
    )
    .await?;
    setup.server.set_prompter_type(prompter_type).await;

    // Verify v0 is pending migration
    assert_eq!(
        setup.server.pending_migrations.lock().await.len(),
        1,
        "V0 keyring should be pending migration"
    );

    // Find the placeholder collection
    let collections = setup.service_api.collections().await?;
    let mut legacy_collection = None;
    for collection in &collections {
        if collection.label().await? == "Legacy" {
            legacy_collection = Some(collection);
            break;
        }
    }
    let legacy_collection = legacy_collection.expect("Should have Legacy placeholder collection");

    // Verify it's locked
    assert!(
        legacy_collection.is_locked().await?,
        "Placeholder should be locked"
    );

    // Set up mock prompter to provide the correct password
    setup.set_password_queue(vec![v0_secret.clone()]).await;

    // Unlock via D-Bus API (should trigger migration)
    let unlocked = setup
        .service_api
        .unlock(&[legacy_collection.inner().path()], None)
        .await?;

    assert_eq!(unlocked.len(), 1, "Should have unlocked the collection");
    assert!(
        !legacy_collection.is_locked().await?,
        "Collection should be unlocked"
    );

    // Verify migration happened
    assert_eq!(
        setup.server.pending_migrations.lock().await.len(),
        0,
        "Should have no pending migrations after unlock"
    );

    // Verify v1 file was created
    let v1_migrated = v1_dir.join("legacy.keyring");
    assert!(v1_migrated.exists(), "V1 file should exist after migration");

    // Verify v0 file was removed
    assert!(
        !v0_path.exists(),
        "V0 file should be removed after migration"
    );
    Ok(())
}

#[tokio::test]
async fn discover_v0_keyrings() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;
    let service = Service::new(temp_dir.path().to_path_buf(), None);

    let keyrings_dir = temp_dir.path().join("keyrings");
    let v1_dir = keyrings_dir.join("v1");
    tokio::fs::create_dir_all(&keyrings_dir).await?;
    tokio::fs::create_dir_all(&v1_dir).await?;

    // Copy the existing v0 keyring fixture
    let v0_secret = Secret::from("test");
    let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("client/fixtures/legacy.keyring");
    let v0_path = keyrings_dir.join("legacy.keyring");
    tokio::fs::copy(&fixture_path, &v0_path).await?;

    // Create a v1 keyring for mixed scenario
    let v1_secret = Secret::from("v1-password");
    let v1_keyring = UnlockedKeyring::open_at(temp_dir.path(), "modern", v1_secret.clone()).await?;
    v1_keyring
        .create_item(
            "V1 Item",
            &[("type", "v1")],
            Secret::text("v1-secret"),
            false,
        )
        .await?;
    v1_keyring.write().await?;

    // Test 1: Discover without secret, v0 marked for migration, v1 locked
    let discovered = service.discover_keyrings(None).await?;
    assert_eq!(
        discovered.len(),
        2,
        "Should discover v1 keyring + v0 placeholder"
    );

    let pending = service.pending_migrations.lock().await;
    assert_eq!(pending.len(), 1, "V0 should be pending migration");
    assert!(pending.contains_key("legacy"));
    drop(pending);

    // Test 2: Discover with v0 secret, v0 migrated, v1 locked
    service.pending_migrations.lock().await.clear();
    let discovered = service.discover_keyrings(Some(v0_secret.clone())).await?;
    assert_eq!(discovered.len(), 2, "Should discover both keyrings");

    let legacy = discovered
        .iter()
        .find(|(_, l, _, _)| l == "Legacy")
        .unwrap();
    assert!(!legacy.3.is_locked(), "V0 should be migrated and unlocked");
    assert_eq!(
        service.pending_migrations.lock().await.len(),
        0,
        "No pending after successful migration"
    );

    // Verify v1 file was created
    let v1_migrated = temp_dir.path().join("keyrings/v1/legacy.keyring");
    assert!(v1_migrated.exists(), "V1 file should exist after migration");

    // Test 3: Discover with wrong v0 secret,  marked for pending migration
    tokio::fs::remove_file(&v1_migrated).await?;
    service.pending_migrations.lock().await.clear();

    // Restore the v0 file for this test
    tokio::fs::copy(&fixture_path, &v0_path).await?;

    let wrong_secret = Secret::from("wrong-password");
    let discovered = service.discover_keyrings(Some(wrong_secret)).await?;
    assert_eq!(
        discovered.len(),
        2,
        "V1 + v0 placeholder should be discovered with wrong v0 password"
    );
    assert_eq!(
        service.pending_migrations.lock().await.len(),
        1,
        "V0 should be pending with wrong password"
    );

    Ok(())
}

#[cfg(feature = "kwallet_migration")]
#[tokio::test]
async fn discover_kwallet_keyrings() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;
    let service = Service::new(temp_dir.path().to_path_buf(), None);

    let kwallet_dir = temp_dir.path().join("kwalletd");
    let v1_dir = temp_dir.path().join("keyrings/v1");
    tokio::fs::create_dir_all(&kwallet_dir).await?;
    tokio::fs::create_dir_all(&v1_dir).await?;

    // Copy KWallet test fixture
    let kwallet_secret = Secret::from("password");
    let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("kwallet/parser/tests/blowfish_cbc_pbkdf2_sha512_manual.kwl");
    let kwallet_path = kwallet_dir.join("kdewallet.kwl");
    tokio::fs::copy(&fixture_path, &kwallet_path).await?;

    // Copy the salt file too (required for PBKDF2-SHA512)
    let salt_fixture = fixture_path.with_extension("salt");
    let salt_path = kwallet_path.with_extension("salt");
    tokio::fs::copy(&salt_fixture, &salt_path).await?;

    // Create a v1 keyring for mixed scenario
    let v1_secret = Secret::from("v1-password");
    let v1_keyring = UnlockedKeyring::open_at(temp_dir.path(), "modern", v1_secret.clone()).await?;
    v1_keyring
        .create_item(
            "V1 Item",
            &[("type", "v1")],
            Secret::text("v1-secret"),
            false,
        )
        .await?;
    v1_keyring.write().await?;

    // Test 1: Discover without secret, KWallet marked for migration, v1 locked
    let discovered = service.discover_keyrings(None).await?;
    assert_eq!(
        discovered.len(),
        2,
        "Should discover v1 keyring + kwallet placeholder"
    );

    let pending = service.pending_migrations.lock().await;
    assert_eq!(pending.len(), 1, "KWallet should be pending migration");
    assert!(pending.contains_key("kdewallet"));
    drop(pending);

    // Test 2: Discover with KWallet secret, KWallet migrated, v1 locked
    service.pending_migrations.lock().await.clear();
    let discovered = service
        .discover_keyrings(Some(kwallet_secret.clone()))
        .await?;
    assert_eq!(discovered.len(), 2, "Should discover both keyrings");

    let kdewallet = discovered
        .iter()
        .find(|(_, l, _, _)| l == "Kdewallet")
        .unwrap();
    assert!(
        !kdewallet.3.is_locked(),
        "KWallet should be migrated and unlocked"
    );
    assert_eq!(
        kdewallet.2, "kdewallet",
        "kdewallet should have kdewallet alias (not default)"
    );
    assert_eq!(
        service.pending_migrations.lock().await.len(),
        0,
        "No pending after successful migration"
    );

    // Verify v1 file was created
    let v1_migrated = temp_dir.path().join("keyrings/v1/kdewallet.keyring");
    assert!(v1_migrated.exists(), "V1 file should exist after migration");

    // Verify old KWallet files were removed
    assert!(
        !kwallet_path.exists(),
        "Original .kwl file should be removed"
    );
    assert!(!salt_path.exists(), "Original .salt file should be removed");

    // Test 3: Discover with wrong KWallet secret, marked for pending migration
    tokio::fs::remove_file(&v1_migrated).await?;
    service.pending_migrations.lock().await.clear();

    // Restore the KWallet files for this test
    tokio::fs::copy(&fixture_path, &kwallet_path).await?;
    tokio::fs::copy(&salt_fixture, &salt_path).await?;

    let wrong_secret = Secret::from("wrong-password");
    let discovered = service.discover_keyrings(Some(wrong_secret)).await?;
    assert_eq!(
        discovered.len(),
        2,
        "V1 + kwallet placeholder should be discovered with wrong KWallet password"
    );
    assert_eq!(
        service.pending_migrations.lock().await.len(),
        1,
        "KWallet should be pending with wrong password"
    );

    // Verify the pending migration has the correct type
    let pending = service.pending_migrations.lock().await;
    let migration = pending.get("kdewallet").unwrap();
    assert_eq!(migration.label(), "Kdewallet");
    assert_eq!(migration.alias(), "kdewallet");
    Ok(())
}
