use std::collections::HashMap;

use oo7::dbus;
use zbus::wire::ObjectPath;

use super::super::*;
use crate::{prompt::MAX_UNLOCK_ATTEMPTS, tests::TestServiceSetup};

#[tokio::test]
async fn lock_unlock_edge_cases() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Unlock: empty object list
    let items: Vec<ObjectPath<'_>> = vec![];
    let unlocked = setup.service_api.unlock(&items, None).await?;
    assert!(unlocked.is_empty(), "Should return empty for empty input");

    // Lock: empty object list
    let locked = setup.service_api.lock(&items, None).await?;
    assert!(locked.is_empty(), "Should return empty for empty input");

    // Shared fake objects for non-existent tests
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

    let fake_paths = [fake_collection.inner().path(), fake_item.inner().path()];

    // Unlock: non-existent objects
    let unlocked = setup.service_api.unlock(&fake_paths, None).await?;
    assert!(
        unlocked.is_empty(),
        "Should have no unlocked objects for non-existent paths"
    );

    // Lock: non-existent objects
    let locked = setup.service_api.lock(&fake_paths, None).await?;
    assert!(
        locked.is_empty(),
        "Should have no locked objects for non-existent paths"
    );

    // Unlock: already unlocked item
    let item = setup
        .create_item("Test Item", &[("app", "test")], "test-password", false)
        .await?;

    assert!(!item.is_locked().await?, "Item should be unlocked");

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

    // Unlock: already unlocked collection
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

/// Clients like Chromium call Unlock and Prompt without opening a session.
async fn unlock_collection_prompt_without_session_impl(
    prompter_type: PrompterType,
) -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    setup.server.set_prompter_type(prompter_type).await;
    setup.lock_collection(&setup.collections[0]).await?;
    setup.session.close().await?;

    let unlocked = setup
        .service_api
        .unlock(&[setup.collections[0].inner().path()], None)
        .await?;

    assert_eq!(unlocked.len(), 1, "Should have unlocked 1 collection");
    assert!(
        !setup.collections[0].is_locked().await?,
        "Collection should be unlocked after accepting prompt"
    );

    Ok(())
}

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[tokio::test]
async fn unlock_collection_prompt_without_session_gnome() -> Result<(), Box<dyn std::error::Error>>
{
    unlock_collection_prompt_without_session_impl(PrompterType::GNOME).await
}

#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
#[tokio::test]
async fn unlock_collection_prompt_without_session_plasma() -> Result<(), Box<dyn std::error::Error>>
{
    unlock_collection_prompt_without_session_impl(PrompterType::Plasma).await
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

    // When collection is unlocked, locking an item should happen directly
    // without a prompt
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

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[tokio::test]
async fn concurrent_unlock_creates_single_prompt_gnome() -> Result<(), Box<dyn std::error::Error>> {
    concurrent_unlock_creates_single_prompt_impl(PrompterType::GNOME).await
}

#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
#[tokio::test]
async fn concurrent_unlock_creates_single_prompt_plasma() -> Result<(), Box<dyn std::error::Error>>
{
    concurrent_unlock_creates_single_prompt_impl(PrompterType::Plasma).await
}

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[tokio::test]
async fn concurrent_item_unlock_creates_single_prompt_gnome()
-> Result<(), Box<dyn std::error::Error>> {
    concurrent_item_unlock_creates_single_prompt_impl(PrompterType::GNOME).await
}

#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
#[tokio::test]
async fn concurrent_item_unlock_creates_single_prompt_plasma()
-> Result<(), Box<dyn std::error::Error>> {
    concurrent_item_unlock_creates_single_prompt_impl(PrompterType::Plasma).await
}

async fn concurrent_item_unlock_creates_single_prompt_impl(
    prompter_type: PrompterType,
) -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    setup.server.set_prompter_type(prompter_type).await;

    let collection = &setup.collections[0];
    let dbus_secret = setup.create_dbus_secret("item-secret")?;
    let item = collection
        .create_item(
            "test-item",
            &HashMap::from([("app", "test")]),
            &dbus_secret,
            false,
            None,
        )
        .await?;

    setup.lock_collection(collection).await?;
    assert!(collection.is_locked().await?);

    let secret = setup.keyring_secret.clone().unwrap();
    setup
        .set_password_queue(vec![secret.clone(), secret.clone(), secret])
        .await;

    let item_path = item.inner().path().to_owned();
    let paths1 = [item_path.clone()];
    let paths2 = [item_path];
    let (r1, r2) = tokio::join!(
        setup.service_api.unlock(&paths1, None),
        setup.service_api.unlock(&paths2, None),
    );

    let _unlocked1 = r1?;
    let _unlocked2 = r2?;

    assert!(
        !collection.is_locked().await?,
        "Collection should be unlocked after concurrent item unlock requests"
    );

    Ok(())
}

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[tokio::test]
async fn unlock_wrong_password_dismissed_gnome() -> Result<(), Box<dyn std::error::Error>> {
    unlock_wrong_password_dismissed_impl(PrompterType::GNOME).await
}

#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
#[tokio::test]
async fn unlock_wrong_password_dismissed_plasma() -> Result<(), Box<dyn std::error::Error>> {
    unlock_wrong_password_dismissed_impl(PrompterType::Plasma).await
}

async fn unlock_wrong_password_dismissed_impl(
    prompter_type: PrompterType,
) -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    setup.server.set_prompter_type(prompter_type).await;

    let collection = &setup.collections[0];
    let dbus_secret = setup.create_dbus_secret("item-secret")?;
    collection
        .create_item(
            "test-item",
            &HashMap::from([("app", "test")]),
            &dbus_secret,
            false,
            None,
        )
        .await?;

    setup.lock_collection(collection).await?;
    assert!(collection.is_locked().await?);

    let wrong = oo7::Secret::from("wrong-password-intentionally");
    setup
        .set_password_queue(vec![wrong; MAX_UNLOCK_ATTEMPTS as usize + 1])
        .await;

    let collection_path = collection.inner().path().to_owned();
    let result = setup.service_api.unlock(&[collection_path], None).await;

    assert!(
        matches!(result, Err(dbus::Error::Dismissed)),
        "Expected Dismissed error after max failed attempts, got: {result:?}"
    );

    assert!(
        collection.is_locked().await?,
        "Collection should remain locked after failed unlock attempts"
    );

    Ok(())
}

async fn concurrent_unlock_creates_single_prompt_impl(
    prompter_type: PrompterType,
) -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    setup.server.set_prompter_type(prompter_type).await;

    let collection = &setup.collections[0];

    // Lock the collection
    setup.lock_collection(collection).await?;
    assert!(collection.is_locked().await?);

    // Queue enough passwords for however many prompts get created
    let secret = setup.keyring_secret.clone().unwrap();
    setup
        .set_password_queue(vec![secret.clone(), secret.clone(), secret])
        .await;

    // Fire two Unlock calls concurrently for the same collection.
    let collection_path = collection.inner().path().to_owned();
    let paths1 = [collection_path.clone()];
    let paths2 = [collection_path];
    let (r1, r2) = tokio::join!(
        setup.service_api.unlock(&paths1, None),
        setup.service_api.unlock(&paths2, None),
    );

    // Both should succeed (not panic the daemon).
    let _unlocked1 = r1?;
    let _unlocked2 = r2?;

    // The collection should be unlocked.
    assert!(
        !collection.is_locked().await?,
        "Collection should be unlocked after concurrent requests"
    );

    Ok(())
}
