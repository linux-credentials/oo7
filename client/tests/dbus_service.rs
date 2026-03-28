use oo7::dbus::Service;

#[tokio::test]
#[cfg(feature = "tokio")]
async fn create_collection() {
    let setup = oo7_server::tests::TestServiceSetup::plain_session(true)
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
    let setup = oo7_server::tests::TestServiceSetup::plain_session(true)
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
    let setup = oo7_server::tests::TestServiceSetup::encrypted_session(true)
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
    let setup = oo7_server::tests::TestServiceSetup::plain_session(true)
        .await
        .unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();
    assert!(service.default_collection().await.is_ok());
}
