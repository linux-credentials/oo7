use std::path::PathBuf;

#[cfg(feature = "async-std")]
use async_std::fs;
use oo7::{Secret, XDG_SCHEMA_ATTRIBUTE, file::*};
use tempfile::tempdir;
#[cfg(feature = "tokio")]
use tokio::fs;

#[tokio::test]
async fn migrate_from_legacy() -> Result<(), Error> {
    let data_dir = tempdir()?;
    let v0_dir = data_dir.path().join("keyrings");
    let v1_dir = v0_dir.join("v1");
    fs::create_dir_all(&v1_dir).await?;

    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("legacy.keyring");
    fs::copy(&fixture_path, &v0_dir.join("default.keyring")).await?;

    assert!(!v1_dir.join("default.keyring").exists());

    let secret = Secret::blob("test");
    let keyring = UnlockedKeyring::open_at(data_dir.path(), "default", Some(secret)).await?;

    super::check_items(&keyring).await?;

    keyring.write().await?;
    assert!(v1_dir.join("default.keyring").exists());

    Ok(())
}

async fn migrate_from_plain_legacy(secret: Option<Secret>) -> Result<(), Error> {
    let data_dir = tempdir()?;
    let v0_dir = data_dir.path().join("keyrings");
    let v1_dir = v0_dir.join("v1");
    fs::create_dir_all(&v1_dir).await?;

    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("plain.keyring");
    fs::copy(&fixture_path, &v0_dir.join("login.keyring")).await?;

    let keyring = UnlockedKeyring::open_at(data_dir.path(), "login", secret.clone()).await?;
    keyring.write().await?;
    assert!(v1_dir.join("login.keyring").exists());

    let keyring = UnlockedKeyring::open_at(data_dir.path(), "login", secret).await?;
    let items = keyring
        .search_items(&[(XDG_SCHEMA_ATTRIBUTE, "org.remmina.Password")])
        .await?;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].label(), "Remmina: Shore - password");
    assert_eq!(items[0].secret(), Secret::text("some password"));
    assert_eq!(keyring.n_items().await, 3);

    Ok(())
}

#[tokio::test]
async fn migrate_from_plain_legacy_without_secret() -> Result<(), Error> {
    migrate_from_plain_legacy(None).await
}

#[tokio::test]
async fn migrate_from_plain_legacy_with_secret() -> Result<(), Error> {
    migrate_from_plain_legacy(Some(Secret::blob("test"))).await
}

#[tokio::test]
async fn migrate_from_plain_legacy_with_short_secret() -> Result<(), Error> {
    migrate_from_plain_legacy(Some(Secret::from(vec![1]))).await
}

#[tokio::test]
async fn migrate() -> Result<(), Error> {
    let data_dir = tempdir()?;
    let v0_dir = data_dir.path().join("keyrings");
    let v1_dir = v0_dir.join("v1");
    fs::create_dir_all(&v1_dir).await?;

    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("default.keyring");
    fs::copy(&fixture_path, &v0_dir.join("default.keyring")).await?;

    let secret = Secret::blob("test");
    let keyring = UnlockedKeyring::open_at(data_dir.path(), "default", Some(secret)).await?;

    assert!(!v1_dir.join("default.keyring").exists());

    super::check_items(&keyring).await?;

    keyring.write().await?;
    assert!(v1_dir.join("default.keyring").exists());

    Ok(())
}
