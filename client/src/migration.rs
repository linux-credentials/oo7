use std::path::Path;

use crate::{AsAttributes, Result, Secret, dbus::Service, file::UnlockedKeyring};

/// Helper to migrate your secrets from the host Secret Service
/// to the sandboxed file backend.
///
/// If the migration is successful, the items are removed from the host
/// Secret Service.
pub async fn migrate(attributes: Vec<impl AsAttributes>, replace: bool) -> Result<()> {
    let service = Service::new().await?;
    let secret = match Secret::sandboxed().await {
        Ok(secret) => Ok(secret),
        Err(super::file::Error::Portal(ashpd::Error::PortalNotFound(_))) => {
            #[cfg(feature = "tracing")]
            tracing::debug!("Portal not available, no migration to do");
            return Ok(());
        }
        Err(err) => Err(err),
    }?;
    let keyring_path = crate::file::api::Keyring::default_path()?;

    migrate_inner(&service, secret, &keyring_path, attributes, replace).await
}

/// Inner migration function for testing.
async fn migrate_inner(
    service: &Service,
    secret: Secret,
    keyring_path: &Path,
    attributes: Vec<impl AsAttributes>,
    replace: bool,
) -> Result<()> {
    let file_backend = UnlockedKeyring::load(keyring_path, Some(secret)).await?;

    let collection = service.default_collection().await?;
    let mut all_items = Vec::default();

    for attrs in attributes {
        let items = collection.search_items(&attrs).await?;
        all_items.extend(items);
    }
    let mut new_items = Vec::with_capacity(all_items.capacity());

    for item in all_items.iter() {
        let attributes = item.attributes().await?;
        let label = item.label().await?;
        let secret = item.secret().await?;

        new_items.push((label, attributes, secret, replace));
    }

    file_backend.create_items(new_items).await?;

    // Delete items from source after successful creation in destination
    let mut deletion_errors = Vec::new();
    for item in all_items.iter() {
        if let Err(e) = item.delete(None).await {
            deletion_errors.push(e);
        }
    }

    // Report deletion failures - partial migration is still an error condition
    if !deletion_errors.is_empty() {
        #[cfg(feature = "tracing")]
        tracing::error!(
            "Migration partially failed: {} items could not be deleted from source",
            deletion_errors.len()
        );
        return Err(deletion_errors.into_iter().next().unwrap().into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Secret, dbus::Service, file::UnlockedKeyring};

    #[tokio::test]
    #[cfg(feature = "tokio")]
    async fn test_migrate_from_dbus_to_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let setup = oo7_daemon::tests::TestServiceSetup::plain_session(true)
            .await
            .unwrap();

        // Create a DBus service with test connection
        let service = Service::new_with_connection(&setup.client_conn)
            .await
            .unwrap();

        // Create some items on the DBus backend
        let collection = service.default_collection().await.unwrap();

        collection
            .create_item(
                "Migration Test 1",
                &[("app", "test-migration"), ("user", "alice")],
                "secret1",
                false,
                None,
            )
            .await
            .unwrap();

        collection
            .create_item(
                "Migration Test 2",
                &[("app", "test-migration"), ("user", "bob")],
                "secret2",
                false,
                None,
            )
            .await
            .unwrap();

        // Verify items exist in DBus backend
        let items_before = collection
            .search_items(&[("app", "test-migration")])
            .await
            .unwrap();
        assert_eq!(items_before.len(), 2);

        // Create file backend keyring
        let keyring_path = temp_dir.path().join("migrated.keyring");
        let secret = Secret::from([1, 2].into_iter().cycle().take(64).collect::<Vec<_>>());

        // Perform migration using internal function
        migrate_inner(
            &service,
            secret.clone(),
            &keyring_path,
            vec![&[("app", "test-migration")]],
            false,
        )
        .await
        .unwrap();

        // Verify items are deleted from DBus backend
        let items_after = collection
            .search_items(&[("app", "test-migration")])
            .await
            .unwrap();
        assert_eq!(items_after.len(), 0);

        // Verify items exist in file backend
        let file_backend = UnlockedKeyring::load(&keyring_path, Some(secret))
            .await
            .unwrap();
        let migrated_items = file_backend
            .search_items(&[("app", "test-migration")])
            .await
            .unwrap();

        assert_eq!(migrated_items.len(), 2);

        // Verify item details
        let alice_item = migrated_items
            .iter()
            .find(|item| {
                item.attributes()
                    .get("user")
                    .map(|u| u == "alice")
                    .unwrap_or(false)
            })
            .expect("Alice's item should exist");

        assert_eq!(alice_item.label(), "Migration Test 1");
        assert_eq!(alice_item.secret(), Secret::text("secret1"));
        assert_eq!(
            alice_item.attributes().get("app").unwrap(),
            "test-migration"
        );

        let bob_item = migrated_items
            .iter()
            .find(|item| {
                item.attributes()
                    .get("user")
                    .map(|u| u == "bob")
                    .unwrap_or(false)
            })
            .expect("Bob's item should exist");

        assert_eq!(bob_item.label(), "Migration Test 2");
        assert_eq!(bob_item.secret(), Secret::text("secret2"));
        assert_eq!(bob_item.attributes().get("app").unwrap(), "test-migration");
    }
}
