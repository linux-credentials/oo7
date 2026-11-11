use oo7::{Secret, dbus};

use crate::tests::TestServiceSetup;

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
