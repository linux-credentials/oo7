use oo7::{Secret, file::*};
use tempfile::tempdir;

#[tokio::test]
async fn unencrypted_roundtrip() -> Result<(), Error> {
    let data_dir = tempdir()?;
    let keyring = UnlockedKeyring::open_at(data_dir.path(), "plain", None).await?;

    keyring
        .create_item(
            "Item 1",
            &[("app", "test"), ("user", "alice")],
            "secret-1",
            false,
        )
        .await?;
    keyring
        .create_item(
            "Item 2",
            &[("app", "test"), ("user", "bob")],
            "secret-2",
            false,
        )
        .await?;

    keyring.write().await?;

    let v1_path = data_dir
        .path()
        .join("keyrings")
        .join("v1")
        .join("plain.keyring");
    assert!(v1_path.exists());

    let reloaded = UnlockedKeyring::load(&v1_path, None).await?;
    let items = reloaded.search_items(&[("app", "test")]).await?;
    assert_eq!(items.len(), 2);

    let alice = items
        .iter()
        .find(|i| {
            i.attributes()
                .get("user")
                .map(|v| v == "alice")
                .unwrap_or(false)
        })
        .expect("alice item");
    assert_eq!(alice.label(), "Item 1");
    assert_eq!(alice.secret(), Secret::text("secret-1"));

    let bob = items
        .iter()
        .find(|i| {
            i.attributes()
                .get("user")
                .map(|v| v == "bob")
                .unwrap_or(false)
        })
        .expect("bob item");
    assert_eq!(bob.label(), "Item 2");
    assert_eq!(bob.secret(), Secret::text("secret-2"));

    Ok(())
}

#[tokio::test]
async fn unencrypted_search() -> Result<(), Error> {
    let data_dir = tempdir()?;
    let keyring = UnlockedKeyring::open_at(data_dir.path(), "search", None).await?;

    keyring
        .create_item(
            "A",
            &[("kind", "password"), ("service", "github")],
            "pw1",
            false,
        )
        .await?;
    keyring
        .create_item(
            "B",
            &[("kind", "password"), ("service", "gitlab")],
            "pw2",
            false,
        )
        .await?;
    keyring
        .create_item(
            "C",
            &[("kind", "token"), ("service", "github")],
            "tok1",
            false,
        )
        .await?;

    let passwords = keyring.search_items(&[("kind", "password")]).await?;
    assert_eq!(passwords.len(), 2);

    let github = keyring.search_items(&[("service", "github")]).await?;
    assert_eq!(github.len(), 2);

    let exact = keyring
        .search_items(&[("kind", "password"), ("service", "github")])
        .await?;
    assert_eq!(exact.len(), 1);
    assert_eq!(exact[0].label(), "A");

    let none = keyring.search_items(&[("kind", "nonexistent")]).await?;
    assert!(none.is_empty());

    Ok(())
}

#[tokio::test]
async fn unencrypted_delete() -> Result<(), Error> {
    let data_dir = tempdir()?;
    let keyring = UnlockedKeyring::open_at(data_dir.path(), "del", None).await?;

    keyring
        .create_item("Keep", &[("id", "keep")], "s1", false)
        .await?;
    keyring
        .create_item("Remove", &[("id", "remove")], "s2", false)
        .await?;

    assert_eq!(keyring.n_items().await, 2);

    keyring.delete(&[("id", "remove")]).await?;
    assert_eq!(keyring.n_items().await, 1);

    keyring.write().await?;

    let v1_path = data_dir
        .path()
        .join("keyrings")
        .join("v1")
        .join("del.keyring");
    let reloaded = UnlockedKeyring::load(&v1_path, None).await?;
    assert_eq!(reloaded.n_items().await, 1);

    let items = reloaded.search_items(&[("id", "keep")]).await?;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].label(), "Keep");

    let removed = reloaded.search_items(&[("id", "remove")]).await?;
    assert!(removed.is_empty());

    Ok(())
}

#[tokio::test]
async fn unencrypted_unlock_encrypted_fails() -> Result<(), Error> {
    let data_dir = tempdir()?;
    let secret = Secret::from([1, 2].into_iter().cycle().take(64).collect::<Vec<_>>());
    let keyring = UnlockedKeyring::open_at(data_dir.path(), "enc", Some(secret)).await?;

    keyring
        .create_item("Encrypted", &[("a", "b")], "secret", false)
        .await?;
    keyring.write().await?;

    let v1_path = data_dir
        .path()
        .join("keyrings")
        .join("v1")
        .join("enc.keyring");
    let locked = LockedKeyring::load(&v1_path).await?;
    let result = locked.unlock_unencrypted().await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::IncorrectSecret));

    Ok(())
}

#[tokio::test]
async fn encrypted_unlock_unencrypted_fails() -> Result<(), Error> {
    let data_dir = tempdir()?;
    let keyring = UnlockedKeyring::open_at(data_dir.path(), "plain", None).await?;

    keyring
        .create_item("Plaintext", &[("a", "b")], "secret", false)
        .await?;
    keyring.write().await?;

    let v1_path = data_dir
        .path()
        .join("keyrings")
        .join("v1")
        .join("plain.keyring");
    let locked = LockedKeyring::load(&v1_path).await?;
    let wrong_secret = Secret::from([9, 8].into_iter().cycle().take(64).collect::<Vec<_>>());
    let result = locked.unlock(wrong_secret).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::IncorrectSecret));

    Ok(())
}

#[tokio::test]
async fn unencrypted_temporary() -> Result<(), Error> {
    let keyring = UnlockedKeyring::temporary_unencrypted().await?;

    keyring
        .create_item("Temp", &[("x", "y")], "temp-secret", false)
        .await?;

    let items = keyring.search_items(&[("x", "y")]).await?;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].label(), "Temp");
    assert_eq!(items[0].secret(), Secret::text("temp-secret"));

    Ok(())
}

#[tokio::test]
async fn validate_unencrypted() -> Result<(), Error> {
    // Empty keyring validates as unencrypted
    let data_dir = tempdir()?;
    let empty = UnlockedKeyring::open_at(data_dir.path(), "empty", None).await?;
    assert!(empty.validate_unencrypted().await?);

    // Unencrypted keyring with items validates
    let plain = UnlockedKeyring::open_at(data_dir.path(), "plain", None).await?;
    plain
        .create_item("Item", &[("a", "b")], "secret", false)
        .await?;
    assert!(plain.validate_unencrypted().await?);

    // Encrypted keyring does not validate as unencrypted
    let secret = Secret::from([1, 2].into_iter().cycle().take(64).collect::<Vec<_>>());
    let encrypted = UnlockedKeyring::open_at(data_dir.path(), "enc", Some(secret)).await?;
    encrypted
        .create_item("Item", &[("a", "b")], "secret", false)
        .await?;
    assert!(!encrypted.validate_unencrypted().await?);

    Ok(())
}
