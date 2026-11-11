use std::sync::Arc;

use oo7::dbus;

use crate::tests::TestServiceSetup;

#[tokio::test]
async fn secret_retrieval_plain() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    let secret = oo7::Secret::blob(b"my-secret-password");
    let item = setup
        .create_item("Test Item", &[("app", "test")], secret.clone(), false)
        .await?;

    // Retrieve secret
    let retrieved_secret = item.secret(&setup.session).await?;
    assert_eq!(retrieved_secret.value(), secret.as_bytes());

    // Verify content-type is preserved
    assert_eq!(
        retrieved_secret.content_type(),
        secret.content_type(),
        "Content-type should be preserved"
    );
    Ok(())
}

#[tokio::test]
async fn secret_retrieval_encrypted() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::encrypted_session(true).await?;

    let aes_key = setup.aes_key.as_ref().unwrap();
    let secret = oo7::Secret::text("my-encrypted-secret");
    let item = setup
        .create_item("Test Item", &[("app", "test")], secret.clone(), false)
        .await?;

    // Retrieve secret
    let retrieved_secret = item.secret(&setup.session).await?;
    assert_eq!(
        retrieved_secret.decrypt(Some(&aes_key.clone()))?.as_bytes(),
        secret.as_bytes()
    );
    // Verify content-type is preserved
    assert_eq!(
        retrieved_secret
            .decrypt(Some(&aes_key.clone()))?
            .content_type(),
        secret.content_type(),
        "Content-type should be preserved"
    );

    Ok(())
}

#[tokio::test]
async fn set_secret_plain() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    let original_secret = oo7::Secret::text("original-password");
    let item = setup
        .create_item(
            "Test Item",
            &[("app", "test")],
            original_secret.clone(),
            false,
        )
        .await?;

    // Verify original secret
    let retrieved = item.secret(&setup.session).await?;
    assert_eq!(retrieved.value(), original_secret.as_bytes());
    assert_eq!(
        retrieved.content_type(),
        original_secret.content_type(),
        "Content-type should be preserved"
    );

    // Get initial modified timestamp
    let initial_modified = item.modified().await?;

    // Wait to ensure timestamp will be different
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Update the secret
    let new_secret = oo7::Secret::blob(b"new-password");
    let new_dbus_secret = setup.create_dbus_secret(new_secret.clone())?;
    item.set_secret(&new_dbus_secret).await?;

    // Verify updated secret
    let retrieved = item.secret(&setup.session).await?;
    assert_eq!(retrieved.value(), new_secret.as_bytes());
    assert_eq!(
        retrieved.content_type(),
        new_secret.content_type(),
        "Content-type should be preserved"
    );

    // Verify modified timestamp was updated
    let new_modified = item.modified().await?;
    assert!(
        new_modified > initial_modified,
        "Modified timestamp should be updated after secret change"
    );

    Ok(())
}

#[tokio::test]
async fn set_secret_encrypted() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::encrypted_session(true).await?;
    let aes_key = setup.aes_key.as_ref().unwrap().clone();

    let original_secret = oo7::Secret::text("original-encrypted-password");
    let item = setup
        .create_item(
            "Test Item",
            &[("app", "test")],
            original_secret.clone(),
            false,
        )
        .await?;

    // Verify original secret
    let retrieved = item.secret(&setup.session).await?;
    assert_eq!(
        retrieved.decrypt(Some(&aes_key.clone()))?.as_bytes(),
        original_secret.as_bytes()
    );

    // Get initial modified timestamp
    let initial_modified = item.modified().await?;

    // Wait to ensure timestamp will be different
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Update the secret
    let new_secret = oo7::Secret::text("new-encrypted-password");
    let new_dbus_secret = setup.create_dbus_secret(new_secret.clone())?;
    item.set_secret(&new_dbus_secret).await?;

    // Verify updated secret
    let retrieved = item.secret(&setup.session).await?;
    assert_eq!(
        retrieved.decrypt(Some(&aes_key.clone()))?.as_bytes(),
        new_secret.as_bytes()
    );

    // Verify modified timestamp was updated
    let new_modified = item.modified().await?;
    assert!(
        new_modified > initial_modified,
        "Modified timestamp should be updated after secret change"
    );

    Ok(())
}

#[tokio::test]
async fn get_secret_invalid_session() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    let item = setup
        .create_item("Test Item", &[("app", "test")], "test-secret", false)
        .await?;

    // Try to get secret with invalid session path
    let invalid_session =
        oo7::dbus::api::Session::new(&setup.client_conn, "/invalid/session").await?;
    let result = item.secret(&invalid_session).await;

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
async fn set_secret_invalid_session() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    let item = setup
        .create_item("Test Item", &[("app", "test")], "test-secret", false)
        .await?;

    let new_secret = oo7::Secret::text("new-secret");
    let invalid_dbus_secret = dbus::api::DBusSecret::new(
        Arc::new(dbus::api::Session::new(&setup.client_conn, "/invalid/session").await?),
        new_secret,
    );

    let result = item.set_secret(&invalid_dbus_secret).await;

    // Should return NoSession error
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
async fn set_secret_persists() -> Result<(), Box<dyn std::error::Error>> {
    let setup =
        TestServiceSetup::with_login_keyring(oo7::Secret::from("test-password-long-enough"))
            .await?;
    let collection = &setup.collections[0];

    // Stored first, with a superset of the changed item's attributes
    let other_secret = setup.create_dbus_secret("other-secret")?;
    collection
        .create_item(
            "Other Item",
            &[("app", "test"), ("user", "other")],
            &other_secret,
            false,
            None,
        )
        .await?;
    let secret = setup.create_dbus_secret("test-secret")?;
    let item = collection
        .create_item("Test Item", &[("app", "test")], &secret, false, None)
        .await?;

    let new_secret = oo7::Secret::text("new-secret");
    item.set_secret(&setup.create_dbus_secret(new_secret.clone())?)
        .await?;

    let items = setup.login_keyring().await?.items().await?;
    assert_eq!(items[0].secret(), oo7::Secret::text("other-secret"));
    assert_eq!(items[1].secret(), new_secret);

    Ok(())
}
