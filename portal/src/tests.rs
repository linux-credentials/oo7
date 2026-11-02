use std::os::unix::net::UnixStream;

use oo7::dbus::Service;
use oo7_daemon::tests::TestServiceSetup;
use tokio::io::AsyncReadExt;

use super::send_secret_to_app;

async fn retrieve(service: &Service, app_id: &str) -> Vec<u8> {
    let (writer, reader) = UnixStream::pair().unwrap();
    reader.set_nonblocking(true).unwrap();
    let mut reader = tokio::net::UnixStream::from_std(reader).unwrap();
    send_secret_to_app(service, &app_id.into(), writer.into())
        .await
        .unwrap();
    let mut secret = Vec::new();
    reader.read_to_end(&mut secret).await.unwrap();
    secret
}

#[tokio::test]
async fn retrieve_existing_secrets_for_native_and_empty_app_ids() {
    let setup = TestServiceSetup::plain_session(true).await.unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();
    let collection = service.default_collection().await.unwrap();
    let cases = [
        ("io.m51.Gelly", "existing valid app secret"),
        ("cider", "existing native app secret"),
        ("", "existing empty app ID secret"),
    ];
    for (app_id, secret) in cases {
        collection
            .create_item(
                "Existing portal secret",
                &[("app_id", app_id)],
                oo7::Secret::text(secret),
                false,
                None,
            )
            .await
            .unwrap();
    }

    for (app_id, secret) in cases {
        assert_eq!(retrieve(&service, app_id).await, secret.as_bytes());
    }
    assert_eq!(collection.items().await.unwrap().len(), cases.len());
}

#[tokio::test]
async fn create_and_reuse_separate_secrets_for_native_and_empty_app_ids() {
    let setup = TestServiceSetup::plain_session(true).await.unwrap();
    let service = Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap();
    let collection = service.default_collection().await.unwrap();
    let mut secrets = Vec::new();

    for app_id in ["io.m51.Gelly", "cider", ""] {
        let secret = retrieve(&service, app_id).await;
        assert!(!secret.is_empty());
        assert!(!secrets.contains(&secret));
        assert_eq!(retrieve(&service, app_id).await, secret);

        let items = collection
            .search_items(&[("app_id", app_id)])
            .await
            .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].attributes().await.unwrap()["app_id"], app_id);
        secrets.push(secret);
    }
    assert_eq!(collection.items().await.unwrap().len(), 3);
}
