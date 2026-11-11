use oo7::{Secret, dbus, file::UnlockedKeyring};

use crate::tests::TestServiceSetup;

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
async fn set_alias_updates_alias_path() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    let login = setup.service_api.read_alias("default").await?.unwrap();
    let other = setup
        .collections
        .iter()
        .find(|c| c.inner().path() != login.inner().path())
        .unwrap();
    let alias = |name: &str| {
        dbus::api::Collection::new(
            &setup.client_conn,
            format!("/org/freedesktop/secrets/aliases/{name}"),
        )
    };

    setup.service_api.set_alias("work", other).await?;
    assert_eq!(alias("work").await?.label().await?, other.label().await?);

    setup.service_api.set_alias("default", other).await?;
    assert_eq!(alias("default").await?.label().await?, other.label().await?);
    assert!(alias("work").await?.label().await.is_err());

    Ok(())
}

#[tokio::test]
async fn delete_collection_removes_alias_path() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    let login = setup.service_api.read_alias("default").await?.unwrap();

    login.delete(None).await?;

    let alias = dbus::api::Collection::new(
        &setup.client_conn,
        "/org/freedesktop/secrets/aliases/default",
    )
    .await?;
    assert!(alias.label().await.is_err());

    Ok(())
}

#[tokio::test]
async fn delete_collection_through_alias_path() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    let login = setup.service_api.read_alias("default").await?.unwrap();
    let other = setup
        .collections
        .iter()
        .find(|c| c.inner().path() != login.inner().path())
        .unwrap();
    setup.service_api.set_alias("work", other).await?;

    for name in ["default", "work"] {
        let alias = dbus::api::Collection::new(
            &setup.client_conn,
            format!("/org/freedesktop/secrets/aliases/{name}"),
        )
        .await?;
        tokio::time::timeout(std::time::Duration::from_secs(5), alias.delete(None)).await??;
        assert!(alias.label().await.is_err());
    }
    assert!(setup.service_api.collections().await?.is_empty());

    Ok(())
}

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[tokio::test]
async fn create_collection_serves_alias_path() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    let collection = setup
        .service_api
        .create_collection("Extra", Some("spare"), None)
        .await?;

    let alias =
        dbus::api::Collection::new(&setup.client_conn, "/org/freedesktop/secrets/aliases/spare")
            .await?;
    assert_eq!(alias.label().await?, "Extra");
    let path = setup.service_api.read_alias("spare").await?.unwrap();
    assert_eq!(path.inner().path(), collection.inner().path());

    Ok(())
}

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[tokio::test]
async fn alias_paths_served_at_startup() -> Result<(), Box<dyn std::error::Error>> {
    let secret = Secret::from("test-password-long-enough");
    let data_dir = tempfile::tempdir()?;
    UnlockedKeyring::open_at(data_dir.path(), "login", Some(secret.clone()))
        .await?
        .write()
        .await?;
    let setup = TestServiceSetup::with_disk_keyrings(
        data_dir.path().to_path_buf(),
        None,
        Some(secret.clone()),
    )
    .await?;
    setup
        .service_api
        .create_collection("Work", Some("work"), None)
        .await?;

    // A new service on the same keyrings
    let setup =
        TestServiceSetup::with_disk_keyrings(data_dir.path().to_path_buf(), None, Some(secret))
            .await?;

    for (name, label) in [
        ("default", "Login"),
        ("work", "Work"),
        ("session", "session"),
    ] {
        let alias = dbus::api::Collection::new(
            &setup.client_conn,
            format!("/org/freedesktop/secrets/aliases/{name}"),
        )
        .await?;
        assert_eq!(alias.label().await?, label);
    }

    Ok(())
}

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[tokio::test]
async fn duplicate_default_alias_resolved() -> Result<(), Box<dyn std::error::Error>> {
    let secret = Secret::from("test-password-long-enough");
    let data_dir = tempfile::tempdir()?;

    // Create a "login" keyring
    let login_kr = UnlockedKeyring::open_at(data_dir.path(), "login", Some(secret.clone())).await?;
    login_kr
        .create_item("Login Item", &[("src", "login")], Secret::text("s"), false)
        .await?;
    login_kr.write().await?;

    // Create a "default" keyring
    let default_kr =
        UnlockedKeyring::open_at(data_dir.path(), "default", Some(secret.clone())).await?;
    default_kr
        .create_item(
            "Default Item",
            &[("src", "default")],
            Secret::text("s"),
            false,
        )
        .await?;
    default_kr.write().await?;

    let setup =
        TestServiceSetup::with_disk_keyrings(data_dir.path().to_path_buf(), None, Some(secret))
            .await?;

    // ReadAlias("default") must return the login collection
    let default_collection = setup.service_api.read_alias("default").await?.unwrap();
    assert_eq!(
        default_collection.label().await?,
        "Login",
        "ReadAlias(\"default\") should return the Login collection, not Default"
    );

    // Both keyrings plus the session collection should be present
    let collections = setup.service_api.collections().await?;
    assert_eq!(
        collections.len(),
        3,
        "Both keyrings + session should be registered"
    );

    Ok(())
}
