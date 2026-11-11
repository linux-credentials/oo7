use crate::tests::{TestServiceSetup, assert_next_signal};

#[tokio::test]
async fn label_property() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Get the Login collection via alias (don't rely on collection ordering)
    let login_collection = setup
        .service_api
        .read_alias("default")
        .await?
        .expect("Default collection should exist");

    // Get initial label (should be "Login" for default collection)
    let label = login_collection.label().await?;
    assert_eq!(label, "Login");

    // Get initial modified timestamp
    let initial_modified = login_collection.modified().await?;

    // Wait to ensure timestamp will be different
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Subscribe to CollectionChanged signal before changing label
    let signal_stream = setup.service_api.receive_collection_changed().await?;
    tokio::pin!(signal_stream);

    // Set new label
    login_collection.set_label("My Custom Collection").await?;

    // Verify CollectionChanged signal was emitted
    let signal_collection = assert_next_signal(&mut signal_stream).await;
    assert_eq!(
        signal_collection.inner().path().as_str(),
        login_collection.inner().path().as_str(),
        "Signal should contain the changed collection path"
    );

    // Verify new label
    let label = login_collection.label().await?;
    assert_eq!(label, "My Custom Collection");

    // Verify modified timestamp was updated
    let new_modified = login_collection.modified().await?;
    assert!(
        new_modified > initial_modified,
        "Modified timestamp should be updated after label change"
    );

    Ok(())
}

#[tokio::test]
async fn timestamps() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Get created timestamp
    let created = setup.collections[0].created().await?;
    assert!(created.as_secs() > 0, "Created timestamp should be set");

    // Get modified timestamp
    let modified = setup.collections[0].modified().await?;
    assert!(modified.as_secs() > 0, "Modified timestamp should be set");

    // Created and modified should be close (within a second for new collection)
    let diff = if created > modified {
        created.as_secs() - modified.as_secs()
    } else {
        modified.as_secs() - created.as_secs()
    };
    assert!(diff <= 1, "Created and modified should be within 1 second");

    Ok(())
}

#[test]
fn test_collection_path() {
    use crate::collection::collection_path;

    assert!(collection_path("").is_err());
    assert_eq!(
        collection_path("bär").unwrap().as_str(),
        "/org/freedesktop/secrets/collection/b_r"
    );
}
