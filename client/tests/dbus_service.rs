use futures_util::StreamExt;
use oo7::dbus::Service;

#[tokio::test]
#[cfg(feature = "tokio")]
async fn create_collection() {
    let setup = oo7_daemon::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();
    let collection = service
        .create_collection("somelabel", None, None)
        .await
        .unwrap();

    let found_collection = service.with_label("somelabel").await.unwrap();
    assert!(found_collection.is_some());

    assert_eq!(
        found_collection.unwrap().label().await.unwrap(),
        collection.label().await.unwrap()
    );

    collection.delete(None).await.unwrap();

    let found_collection = service.with_label("somelabel").await.unwrap();
    assert!(found_collection.is_none());
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn default_collections() {
    let setup = oo7_daemon::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();

    assert!(service.default_collection().await.is_ok());
    assert!(service.session_collection().await.is_ok());
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn encrypted_session() {
    let setup = oo7_daemon::tests::TestServiceSetup::encrypted_session(true)
        .await
        .unwrap();
    let service = Service::encrypted_with_connection(&setup.client_conn)
        .await
        .unwrap();
    assert!(service.default_collection().await.is_ok());
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn plain_session() {
    let setup = oo7_daemon::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();
    assert!(service.default_collection().await.is_ok());
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn collection_created_signal() {
    let setup = oo7_daemon::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();

    // Setup signal stream before creating collection
    let created_stream = service.receive_collection_created().await.unwrap();
    tokio::pin!(created_stream);

    // Create a collection in a separate task
    let service_clone = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        let _ = service_clone
            .create_collection("Test Collection", None, None)
            .await;
    });

    // Wait for the signal
    tokio::select! {
        Some(collection) = created_stream.next() => {
            assert_eq!(collection.label().await.unwrap(), "Test Collection");
            collection.delete(None).await.unwrap();
        }
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {
            panic!("Timeout waiting for collection created signal");
        }
    }
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn collection_changed_signal() {
    let setup = oo7_daemon::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();

    let collection = service
        .create_collection("Change Signal Test", None, None)
        .await
        .unwrap();

    // Setup signal stream
    let changed_stream = service.receive_collection_changed().await.unwrap();
    tokio::pin!(changed_stream);

    // Get the collection path for comparison
    let collection_path = collection.path().to_owned();

    // Modify the collection in a separate task
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        let _ = collection.set_label("Modified Collection Label").await;
    });

    // Wait for the signal
    tokio::select! {
        Some(changed_collection) = changed_stream.next() => {
            assert_eq!(changed_collection.label().await.unwrap(), "Modified Collection Label");
            assert_eq!(changed_collection.path(), &collection_path);
            changed_collection.delete(None).await.unwrap();
        }
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {
            panic!("Timeout waiting for collection changed signal");
        }
    }
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn collection_deleted_signal() {
    let setup = oo7_daemon::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();

    let collection = service
        .create_collection("Delete Signal Test", None, None)
        .await
        .unwrap();

    // Setup signal stream
    let deleted_stream = service.receive_collection_deleted().await.unwrap();
    tokio::pin!(deleted_stream);

    // Get the collection path for comparison
    let collection_path = collection.path().to_owned();

    // Delete the collection in a separate task
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        let _ = collection.delete(None).await;
    });

    // Wait for the signal
    tokio::select! {
        Some(deleted_path) = deleted_stream.next() => {
            assert_eq!(deleted_path.as_str(), collection_path.as_str());
        }
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {
            panic!("Timeout waiting for collection deleted signal");
        }
    }
}
