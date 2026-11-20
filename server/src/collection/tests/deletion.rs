use crate::{
    service::PrompterType,
    tests::{TestServiceSetup, assert_next_signal},
};

#[tokio::test]
async fn delete_collection() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Create some items in the collection
    setup
        .create_item("Item 1", &[("app", "test")], "password1", false)
        .await?;

    setup
        .create_item("Item 2", &[("app", "test")], "password2", false)
        .await?;

    // Verify items were created
    let items = setup.collections[0].items().await?;
    assert_eq!(items.len(), 2, "Should have 2 items before deletion");

    // Get collection path for later verification
    let collection_path = setup.collections[0].inner().path().to_owned();

    // Verify collection exists in service
    let collections_before = setup.service_api.collections().await?;
    let initial_count = collections_before.len();

    // Subscribe to CollectionDeleted signal before deleting
    let signal_stream = setup.service_api.receive_collection_deleted().await?;
    tokio::pin!(signal_stream);

    // Delete the collection
    setup.collections[0].delete(None).await?;

    // Verify CollectionDeleted signal was emitted
    let signal_collection = assert_next_signal(&mut signal_stream).await;
    assert_eq!(
        signal_collection.as_str(),
        collection_path.as_str(),
        "Signal should contain the deleted collection path"
    );

    // Give the system a moment to process the deletion
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Verify collection is no longer in service's collection list
    let collections_after = setup.service_api.collections().await?;
    assert_eq!(
        collections_after.len(),
        initial_count - 1,
        "Service should have one less collection after deletion"
    );

    // Verify the specific collection is not in the list
    let collection_paths: Vec<_> = collections_after
        .iter()
        .map(|c| c.inner().path().as_str())
        .collect();
    assert!(
        !collection_paths.contains(&collection_path.as_str()),
        "Deleted collection should not be in service collections list"
    );

    Ok(())
}

async fn delete_locked_collection_with_prompt_impl(
    prompter_type: PrompterType,
) -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    setup.server.set_prompter_type(prompter_type).await;
    let default_collection = &setup.collections[0];

    setup.lock_collection(default_collection).await?;

    assert!(
        default_collection.is_locked().await?,
        "Collection should be locked"
    );

    let collection_path = default_collection.inner().path().to_owned();

    // Get initial collection count
    let collections_before = setup.service_api.collections().await?;
    let initial_count = collections_before.len();

    // Delete the locked collection
    default_collection.delete(None).await?;

    // Give the system a moment to process the deletion
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Verify collection was deleted
    let collections_after = setup.service_api.collections().await?;
    assert_eq!(
        collections_after.len(),
        initial_count - 1,
        "Collection should be deleted after prompt"
    );

    // Verify the specific collection is not in the list
    let collection_paths: Vec<_> = collections_after
        .iter()
        .map(|c| c.inner().path().as_str())
        .collect();
    assert!(
        !collection_paths.contains(&collection_path.as_str()),
        "Deleted collection should not be in service collections list"
    );

    Ok(())
}

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[tokio::test]
async fn delete_locked_collection_with_prompt_gnome() -> Result<(), Box<dyn std::error::Error>> {
    delete_locked_collection_with_prompt_impl(PrompterType::GNOME).await
}

#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
#[tokio::test]
async fn delete_locked_collection_with_prompt_plasma() -> Result<(), Box<dyn std::error::Error>> {
    delete_locked_collection_with_prompt_impl(PrompterType::Plasma).await
}

// https://github.com/linux-credentials/oo7/issues/696
#[tokio::test]
async fn delete_locked_pending_migration() -> Result<(), Box<dyn std::error::Error>> {
    let (setup, _temp_dir, collection_path) = crate::tests::pending_migration_setup(None).await?;

    let collection =
        oo7::dbus::api::Collection::new(&setup.client_conn, collection_path.clone()).await?;
    assert!(collection.is_locked().await?);

    // Deleting the placeholder is refused even with the correct secret, it
    // stands in for the legacy keyring and deleting it would throw the
    // migrated data away
    setup
        .set_password_queue(vec![oo7::Secret::from("test")])
        .await;
    let result = collection.delete(None).await;
    assert!(
        result.is_err(),
        "Deleting a collection with a pending migration should fail"
    );
    assert_eq!(
        setup.server.pending_migrations.lock().await.len(),
        1,
        "The migration should still be pending"
    );

    // Once unlocked, the migrated collection can be deleted
    let unlocked = setup
        .service_api
        .unlock(std::slice::from_ref(&collection_path), None)
        .await?;
    assert_eq!(unlocked.len(), 1);

    collection.delete(None).await?;
    assert_eq!(setup.server.pending_migrations.lock().await.len(), 0);
    let collections = setup.service_api.collections().await?;
    assert!(
        collections
            .iter()
            .all(|c| c.inner().path() != collection.inner().path())
    );

    Ok(())
}
