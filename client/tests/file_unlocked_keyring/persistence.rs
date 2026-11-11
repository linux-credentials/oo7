use std::{collections::HashMap, sync::Arc};

use oo7::{Secret, file::*};
use tempfile::tempdir;

use super::strong_key;

#[tokio::test]
async fn repeated_write() -> Result<(), Error> {
    let temp_dir = tempdir()?;
    let path = temp_dir.path().join("test.keyring");

    let secret = Secret::from(vec![1, 2]);
    let keyring = UnlockedKeyring::load(&path, Some(secret)).await?;

    keyring.write().await?;
    keyring.write().await?;

    Ok(())
}

#[tokio::test]
async fn write_with_short_password() -> Result<(), Error> {
    let temp_dir = tempdir()?;
    let path = temp_dir.path().join("write_with_short_password.keyring");

    // Password policy is up to the caller, e.g. keyrings migrated from
    // gnome-keyring can have any password.
    let secret = Secret::from(vec![1]);
    let keyring = UnlockedKeyring::load(&path, Some(secret.clone())).await?;
    let attributes: HashMap<&str, &str> = HashMap::default();

    keyring
        .create_item("label", &attributes, "my-password", false)
        .await?;
    keyring.write().await?;

    let keyring = UnlockedKeyring::load(&path, Some(secret)).await?;
    let items = keyring.items().await?;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].secret(), Secret::text("my-password"));

    Ok(())
}

#[tokio::test]
async fn concurrent_writes() -> Result<(), Error> {
    let temp_dir = tempdir()?;
    let path = temp_dir.path().join("concurrent_writes.keyring");

    let keyring = Arc::new(UnlockedKeyring::load(&path, Some(strong_key())).await?);

    let keyring_clone = keyring.clone();
    let handle_1 = tokio::task::spawn(async move { keyring_clone.write().await });
    let handle_2 = tokio::task::spawn(async move { keyring.write().await });

    let (res_1, res_2) = futures_util::future::join(handle_1, handle_2).await;
    res_1.unwrap()?;
    res_2.unwrap()?;

    Ok(())
}
