use oo7::{Secret, file::UnlockedKeyring};

use super::super::*;
use crate::tests::TestServiceSetup;

#[tokio::test]
async fn discover_v1_keyrings() -> Result<(), Box<dyn std::error::Error>> {
    // Set up a temporary data directory
    let temp_dir = tempfile::tempdir()?;
    let service = Service::new(temp_dir.path().to_path_buf(), None, true);

    // Create v1 keyrings directory
    let v1_dir = temp_dir.path().join("keyrings/v1");
    tokio::fs::create_dir_all(&v1_dir).await?;

    // Test 1: Empty directory
    let discovered = service.discover_keyrings(None).await?;
    assert!(
        discovered.is_empty(),
        "Should discover no keyrings in empty directory"
    );

    // Create multiple keyrings with different passwords
    // Add items to each so password validation works
    let secret1 = Secret::from("password-for-work");
    let keyring1 = UnlockedKeyring::open_at(temp_dir.path(), "work", Some(secret1.clone())).await?;
    keyring1
        .create_item(
            "Work Item",
            &[("type", "work")],
            Secret::text("work-secret"),
            false,
        )
        .await?;
    keyring1.write().await?;

    let secret2 = Secret::from("password-for-personal");
    let keyring2 =
        UnlockedKeyring::open_at(temp_dir.path(), "personal", Some(secret2.clone())).await?;
    keyring2
        .create_item(
            "Personal Item",
            &[("type", "personal")],
            Secret::text("personal-secret"),
            false,
        )
        .await?;
    keyring2.write().await?;

    // Create a "login" keyring which should get the default alias
    let secret3 = Secret::from("password-for-login");
    let keyring3 =
        UnlockedKeyring::open_at(temp_dir.path(), "login", Some(secret3.clone())).await?;
    keyring3
        .create_item(
            "Login Item",
            &[("type", "login")],
            Secret::text("login-secret"),
            false,
        )
        .await?;
    keyring3.write().await?;

    // Create some non-keyring files that should be skipped
    tokio::fs::write(v1_dir.join("README.txt"), b"This is a readme").await?;
    tokio::fs::write(v1_dir.join("config.json"), b"{}").await?;
    tokio::fs::create_dir(v1_dir.join("subdir")).await?;

    // Test 2: Discover without any password, all should be locked
    let discovered = service.discover_keyrings(None).await?;
    assert_eq!(discovered.len(), 3, "Should discover 3 keyrings");
    for dk in &discovered {
        assert!(
            dk.keyring.is_locked(),
            "All keyrings should be locked without secret"
        );
    }

    // Test 3: Discover with one password, only that keyring should be unlocked
    let discovered = service.discover_keyrings(Some(secret1.clone())).await?;
    assert_eq!(discovered.len(), 3, "Should discover 3 keyrings");

    let work_keyring = discovered.iter().find(|dk| dk.label == "Work").unwrap();
    assert!(
        !work_keyring.keyring.is_locked(),
        "Work keyring should be unlocked with correct password"
    );

    let personal_keyring = discovered.iter().find(|dk| dk.label == "Personal").unwrap();
    assert!(
        personal_keyring.keyring.is_locked(),
        "Personal keyring should be locked with wrong password"
    );

    // Test 4: Verify login keyring gets default alias
    let login_keyring = discovered.iter().find(|dk| dk.label == "Login").unwrap();
    assert_eq!(
        login_keyring.alias,
        oo7::dbus::Service::DEFAULT_COLLECTION,
        "Login keyring should have default alias"
    );
    assert!(
        login_keyring.keyring.is_locked(),
        "Login keyring should be locked with wrong password"
    );

    // Test 5: Verify labels are properly capitalized
    let labels: Vec<_> = discovered.iter().map(|dk| dk.label.as_str()).collect();
    assert!(labels.contains(&"Work"), "Should have Work with capital W");
    assert!(
        labels.contains(&"Personal"),
        "Should have Personal with capital P"
    );
    assert!(
        labels.contains(&"Login"),
        "Should have Login with capital L"
    );

    Ok(())
}

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[tokio::test]
async fn unlock_pending_v0_migration_gnome() -> Result<(), Box<dyn std::error::Error>> {
    unlock_pending_v0_migration_impl(PrompterType::GNOME).await
}

#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
#[tokio::test]
async fn unlock_pending_v0_migration_plasma() -> Result<(), Box<dyn std::error::Error>> {
    unlock_pending_v0_migration_impl(PrompterType::Plasma).await
}

async fn unlock_pending_v0_migration_impl(
    prompter_type: PrompterType,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;

    let keyrings_dir = temp_dir.path().join("keyrings");
    let v1_dir = keyrings_dir.join("v1");
    tokio::fs::create_dir_all(&v1_dir).await?;

    // Copy the v0 keyring fixture
    let v0_secret = Secret::from("test");
    let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("client/fixtures/legacy.keyring");
    let v0_path = keyrings_dir.join("legacy.keyring");
    tokio::fs::copy(&fixture_path, &v0_path).await?;

    // Create test service that discovers keyrings WITHOUT the password
    let setup =
        TestServiceSetup::with_disk_keyrings(temp_dir.path().to_path_buf(), None, None).await?;
    setup.server.set_prompter_type(prompter_type).await;

    // Verify v0 is pending migration
    assert_eq!(
        setup.server.pending_migrations.lock().await.len(),
        1,
        "V0 keyring should be pending migration"
    );

    // Find the placeholder collection
    let collections = setup.service_api.collections().await?;
    let mut legacy_collection = None;
    for collection in &collections {
        if collection.label().await? == "Legacy" {
            legacy_collection = Some(collection);
            break;
        }
    }
    let legacy_collection = legacy_collection.expect("Should have Legacy placeholder collection");

    // Verify it's locked
    assert!(
        legacy_collection.is_locked().await?,
        "Placeholder should be locked"
    );

    // Set up mock prompter to provide the correct password
    setup.set_password_queue(vec![v0_secret.clone()]).await;

    // Unlock via D-Bus API (should trigger migration)
    let unlocked = setup
        .service_api
        .unlock(&[legacy_collection.inner().path()], None)
        .await?;

    assert_eq!(unlocked.len(), 1, "Should have unlocked the collection");
    assert!(
        !legacy_collection.is_locked().await?,
        "Collection should be unlocked"
    );

    // Verify migration happened
    assert_eq!(
        setup.server.pending_migrations.lock().await.len(),
        0,
        "Should have no pending migrations after unlock"
    );

    // Verify v1 file was created
    let v1_migrated = v1_dir.join("legacy.keyring");
    assert!(v1_migrated.exists(), "V1 file should exist after migration");

    // Verify v0 file still exists but stamp was created
    assert!(
        v0_path.exists(),
        "V0 file should still exist after migration"
    );
    assert!(
        crate::migration::stamp_path(&v0_path).exists(),
        "Migration stamp file should exist"
    );
    Ok(())
}

#[tokio::test]
async fn discover_v0_keyrings() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;
    let service = Service::new(temp_dir.path().to_path_buf(), None, true);

    let keyrings_dir = temp_dir.path().join("keyrings");
    let v1_dir = keyrings_dir.join("v1");
    tokio::fs::create_dir_all(&keyrings_dir).await?;
    tokio::fs::create_dir_all(&v1_dir).await?;

    // Copy the existing v0 keyring fixture
    let v0_secret = Secret::from("test");
    let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("client/fixtures/legacy.keyring");
    let v0_path = keyrings_dir.join("legacy.keyring");
    tokio::fs::copy(&fixture_path, &v0_path).await?;

    // Create a v1 keyring for mixed scenario
    let v1_secret = Secret::from("v1-password");
    let v1_keyring =
        UnlockedKeyring::open_at(temp_dir.path(), "modern", Some(v1_secret.clone())).await?;
    v1_keyring
        .create_item(
            "V1 Item",
            &[("type", "v1")],
            Secret::text("v1-secret"),
            false,
        )
        .await?;
    v1_keyring.write().await?;

    // Test 1: Discover without secret, v0 marked for migration, v1 locked
    let discovered = service.discover_keyrings(None).await?;
    assert_eq!(
        discovered.len(),
        2,
        "Should discover v1 keyring + v0 placeholder"
    );

    let pending = service.pending_migrations.lock().await;
    assert_eq!(pending.len(), 1, "V0 should be pending migration");
    assert!(pending.contains_key("legacy"));
    drop(pending);

    // Test 2: Discover with v0 secret, v0 migrated, v1 locked
    service.pending_migrations.lock().await.clear();
    let discovered = service.discover_keyrings(Some(v0_secret.clone())).await?;
    assert_eq!(discovered.len(), 2, "Should discover both keyrings");

    let legacy = discovered.iter().find(|dk| dk.label == "Legacy").unwrap();
    assert!(
        !legacy.keyring.is_locked(),
        "V0 should be migrated and unlocked"
    );
    assert_eq!(
        service.pending_migrations.lock().await.len(),
        0,
        "No pending after successful migration"
    );

    // Verify v1 file was created
    let v1_migrated = temp_dir.path().join("keyrings/v1/legacy.keyring");
    assert!(v1_migrated.exists(), "V1 file should exist after migration");

    // Test 3: Discover with wrong v0 secret,  marked for pending migration
    tokio::fs::remove_file(&v1_migrated).await?;
    let _ = tokio::fs::remove_file(crate::migration::stamp_path(&v0_path)).await;
    service.pending_migrations.lock().await.clear();

    // Restore the v0 file for this test
    tokio::fs::copy(&fixture_path, &v0_path).await?;

    let wrong_secret = Secret::from("wrong-password");
    let discovered = service.discover_keyrings(Some(wrong_secret)).await?;
    assert_eq!(
        discovered.len(),
        2,
        "V1 + v0 placeholder should be discovered with wrong v0 password"
    );
    assert_eq!(
        service.pending_migrations.lock().await.len(),
        1,
        "V0 should be pending with wrong password"
    );

    Ok(())
}

#[tokio::test]
async fn discover_plain_v0_keyrings() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;
    let service = Service::new(temp_dir.path().to_path_buf(), None, true);

    let keyrings_dir = temp_dir.path().join("keyrings");
    tokio::fs::create_dir_all(keyrings_dir.join("v1")).await?;

    let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("client/fixtures/plain.keyring");
    let v0_path = keyrings_dir.join("plain.keyring");
    tokio::fs::copy(&fixture_path, &v0_path).await?;
    // Not a keyring, should be skipped
    tokio::fs::write(keyrings_dir.join("junk.keyring"), b"junk").await?;

    // Plain keyrings are migrated even without a secret
    let discovered = service.discover_keyrings(None).await?;
    assert_eq!(discovered.len(), 1, "Only the plain keyring is discovered");

    assert_eq!(discovered[0].label, "Plain");
    assert!(
        !discovered[0].keyring.is_locked(),
        "Plain keyring should be migrated"
    );
    assert!(service.pending_migrations.lock().await.is_empty());
    assert!(keyrings_dir.join("v1/plain.keyring").exists());
    assert!(crate::migration::stamp_path(&v0_path).exists());

    Ok(())
}

// https://github.com/linux-credentials/oo7/issues/586
#[tokio::test]
async fn migrate_v0_items_without_schema() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;
    let service = Service::new(temp_dir.path().to_path_buf(), None, true);

    let keyrings_dir = temp_dir.path().join("keyrings");
    tokio::fs::create_dir_all(keyrings_dir.join("v1")).await?;

    // Its item only has a `unique` attribute and the generic secret type
    let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("client/fixtures/legacy-no-schema.keyring");
    tokio::fs::copy(&fixture_path, keyrings_dir.join("login.keyring")).await?;

    let secret = Secret::from("test");
    service.discover_keyrings(Some(secret.clone())).await?;

    let keyring = UnlockedKeyring::open_at(temp_dir.path(), "login", Some(secret)).await?;
    let items = keyring.items().await?;
    assert_eq!(items.len(), 1);
    let attributes = items[0].attributes();
    assert_eq!(
        attributes
            .get(oo7::XDG_SCHEMA_ATTRIBUTE)
            .map(|v| v.as_ref()),
        Some(oo7::GENERIC_SCHEMA)
    );

    Ok(())
}

#[cfg(feature = "kwallet_migration")]
#[cfg(target_endian = "little")]
#[tokio::test]
async fn discover_kwallet_keyrings() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;
    let service = Service::new(temp_dir.path().to_path_buf(), None, true);

    let kwallet_dir = temp_dir.path().join("kwalletd");
    let v1_dir = temp_dir.path().join("keyrings/v1");
    tokio::fs::create_dir_all(&kwallet_dir).await?;
    tokio::fs::create_dir_all(&v1_dir).await?;

    // Copy KWallet test fixture
    let kwallet_secret = Secret::from("password");
    let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("kwallet/parser/tests/blowfish_cbc_pbkdf2_sha512_manual.kwl");
    let kwallet_path = kwallet_dir.join("kdewallet.kwl");
    tokio::fs::copy(&fixture_path, &kwallet_path).await?;

    // Copy the salt file too (required for PBKDF2-SHA512)
    let salt_fixture = fixture_path.with_extension("salt");
    let salt_path = kwallet_path.with_extension("salt");
    tokio::fs::copy(&salt_fixture, &salt_path).await?;

    // Create a v1 keyring for mixed scenario
    let v1_secret = Secret::from("v1-password");
    let v1_keyring =
        UnlockedKeyring::open_at(temp_dir.path(), "modern", Some(v1_secret.clone())).await?;
    v1_keyring
        .create_item(
            "V1 Item",
            &[("type", "v1")],
            Secret::text("v1-secret"),
            false,
        )
        .await?;
    v1_keyring.write().await?;

    // Test 1: Discover without secret, KWallet marked for migration, v1 locked
    let discovered = service.discover_keyrings(None).await?;
    assert_eq!(
        discovered.len(),
        2,
        "Should discover v1 keyring + kwallet placeholder"
    );

    let pending = service.pending_migrations.lock().await;
    assert_eq!(pending.len(), 1, "KWallet should be pending migration");
    assert!(pending.contains_key("kdewallet"));
    drop(pending);

    // Test 2: Discover with KWallet secret, KWallet migrated, v1 locked
    service.pending_migrations.lock().await.clear();
    let discovered = service
        .discover_keyrings(Some(kwallet_secret.clone()))
        .await?;
    assert_eq!(discovered.len(), 2, "Should discover both keyrings");

    let kdewallet = discovered
        .iter()
        .find(|dk| dk.label == "Kdewallet")
        .unwrap();
    assert!(
        !kdewallet.keyring.is_locked(),
        "KWallet should be migrated and unlocked"
    );
    assert_eq!(
        kdewallet.alias, "kdewallet",
        "kdewallet should have kdewallet alias (not default)"
    );
    assert_eq!(
        service.pending_migrations.lock().await.len(),
        0,
        "No pending after successful migration"
    );

    // Verify v1 file was created
    let v1_migrated = temp_dir.path().join("keyrings/v1/kdewallet.keyring");
    assert!(v1_migrated.exists(), "V1 file should exist after migration");

    // Verify old KWallet file still exists but stamp was created
    assert!(
        kwallet_path.exists(),
        "Original .kwl file should still exist"
    );
    assert!(
        crate::migration::stamp_path(&kwallet_path).exists(),
        "Migration stamp file should exist"
    );

    // Test 3: Discover with wrong KWallet secret, marked for pending migration
    tokio::fs::remove_file(&v1_migrated).await?;
    let _ = tokio::fs::remove_file(crate::migration::stamp_path(&kwallet_path)).await;
    service.pending_migrations.lock().await.clear();

    // Restore the KWallet files for this test
    tokio::fs::copy(&fixture_path, &kwallet_path).await?;
    tokio::fs::copy(&salt_fixture, &salt_path).await?;

    let wrong_secret = Secret::from("wrong-password");
    let discovered = service.discover_keyrings(Some(wrong_secret)).await?;
    assert_eq!(
        discovered.len(),
        2,
        "V1 + kwallet placeholder should be discovered with wrong KWallet password"
    );
    assert_eq!(
        service.pending_migrations.lock().await.len(),
        1,
        "KWallet should be pending with wrong password"
    );

    // Verify the pending migration has the correct type
    let pending = service.pending_migrations.lock().await;
    let migration = pending.get("kdewallet").unwrap();
    assert_eq!(migration.label(), "Kdewallet");
    assert_eq!(migration.alias(), "kdewallet");
    Ok(())
}
