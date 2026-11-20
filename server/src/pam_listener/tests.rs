use oo7::file::UnlockedKeyring;
use zgvariant::serialized::Context;

use super::*;

/// Spawn the listener, returning its socket path and a clone sharing the
/// buffered secrets, for [`PamListener::replay_buffered_secrets`].
async fn spawn_pam_listener(server: &crate::Service) -> (std::path::PathBuf, PamListener) {
    let pam_listener = PamListener::new(server.clone());
    let socket_path = pam_listener.socket_path.clone();
    let spawned = pam_listener.clone();
    tokio::spawn(async move {
        let _ = spawned.start().await;
    });
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    (socket_path, pam_listener)
}

fn create_pam_message(
    operation: PamOperation,
    username: &str,
    old_secret: &[u8],
    new_secret: &[u8],
) -> Vec<u8> {
    let message = PamMessage {
        operation,
        username: username.to_owned(),
        old_secret: old_secret.to_vec(),
        new_secret: new_secret.to_vec(),
    };

    let ctxt = Context::new(zgvariant::LE, 0);
    let encoded = zgvariant::to_bytes(ctxt, &message).unwrap();
    let message_bytes = encoded.to_vec();

    // Prepend length prefix (4 bytes, little-endian)
    let mut result = (message_bytes.len() as u32).to_le_bytes().to_vec();
    result.extend_from_slice(&message_bytes);
    result
}

async fn send_pam_message(
    socket_path: &std::path::Path,
    message_bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let response = send_pam_bytes(socket_path, message_bytes).await?;
    if !response.success {
        return Err(format!("PAM operation failed: {}", response.error_message).into());
    }
    Ok(())
}

/// Send raw bytes on the PAM socket and read back the response, if any.
async fn send_pam_bytes(
    socket_path: &std::path::Path,
    message_bytes: &[u8],
) -> Result<PamResponse, Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::UnixStream::connect(socket_path).await?;
    stream.write_all(message_bytes).await?;
    stream.flush().await?;

    // Read response
    let mut length_bytes = [0u8; 4];
    stream.read_exact(&mut length_bytes).await?;
    let response_length = u32::from_le_bytes(length_bytes) as usize;

    let mut response_bytes = vec![0u8; response_length];
    stream.read_exact(&mut response_bytes).await?;

    Ok(PamResponse::from_bytes(&response_bytes)?)
}

#[tokio::test]
async fn pam_migrates_v0_keyrings() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;

    let keyrings_dir = temp_dir.path().join("keyrings");
    let v1_dir = keyrings_dir.join("v1");
    tokio::fs::create_dir_all(&v1_dir).await?;

    let v0_secret = Secret::from("test");
    let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("client/fixtures/legacy.keyring");
    let v0_path = keyrings_dir.join("legacy.keyring");
    tokio::fs::copy(&fixture_path, &v0_path).await?;

    let pam_socket_path = temp_dir.path().join("pam.sock");
    let setup = crate::tests::TestServiceSetup::with_disk_keyrings(
        temp_dir.path().to_path_buf(),
        Some(pam_socket_path),
        None,
    )
    .await?;

    assert_eq!(
        setup.server.pending_migrations.lock().await.len(),
        1,
        "V0 keyring should be pending migration"
    );

    let (socket_path, _) = spawn_pam_listener(&setup.server).await;

    let message = create_pam_message(PamOperation::Unlock, "testuser", &[], v0_secret.as_bytes());
    send_pam_message(&socket_path, &message).await?;

    // Response received means operation completed
    let pending = setup.server.pending_migrations.lock().await;
    assert_eq!(
        pending.len(),
        0,
        "V0 keyring should be migrated. Remaining: {:?}",
        pending.keys().collect::<Vec<_>>()
    );
    drop(pending);

    let collections = setup.server.collections.lock().await;
    let non_session: Vec<_> = collections
        .values()
        .filter(|c| c.name() != "session")
        .collect();
    assert_eq!(
        non_session.len(),
        1,
        "Should have exactly one non-session collection (placeholder replaced in place, not duplicated)"
    );
    // The migrated collection is served at the path of its alias, like the
    // others
    for collection in collections.values() {
        let path = crate::collection::alias_path(&collection.alias().await).unwrap();
        let served = setup
            .server
            .object_server()
            .interface::<_, crate::collection::Collection>(&path)
            .await?;
        assert_eq!(served.get().await.path(), collection.path());
    }
    drop(collections);

    assert!(
        setup.server.collection_by_label("Legacy").await.is_some(),
        "Migrated Legacy collection should exist"
    );

    let v1_migrated = v1_dir.join("legacy.keyring");
    assert!(v1_migrated.exists(), "V1 file should exist after migration");

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

// https://github.com/linux-credentials/oo7/issues/651
#[tokio::test]
async fn pam_migration_then_write_to_default_alias() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;

    let keyrings_dir = temp_dir.path().join("keyrings");
    let v1_dir = keyrings_dir.join("v1");
    tokio::fs::create_dir_all(&v1_dir).await?;

    let v0_secret = Secret::from("test");
    let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("client/fixtures/legacy.keyring");
    // Named "login" so it maps to the "default" alias.
    tokio::fs::copy(&fixture_path, keyrings_dir.join("login.keyring")).await?;

    let pam_socket_path = temp_dir.path().join("pam.sock");
    let setup = crate::tests::TestServiceSetup::with_disk_keyrings(
        temp_dir.path().to_path_buf(),
        Some(pam_socket_path),
        None,
    )
    .await?;

    assert_eq!(setup.server.pending_migrations.lock().await.len(), 1);

    let (socket_path, _) = spawn_pam_listener(&setup.server).await;

    let message = create_pam_message(PamOperation::Unlock, "testuser", &[], v0_secret.as_bytes());
    send_pam_message(&socket_path, &message).await?;

    assert_eq!(
        setup.server.pending_migrations.lock().await.len(),
        0,
        "V0 keyring should be migrated"
    );

    // The default alias must point to the migrated collection, not an empty
    // placeholder.
    let default = setup
        .service_api
        .read_alias("default")
        .await?
        .expect("default alias should exist");

    let dbus_secret = setup.create_dbus_secret("token")?;
    default
        .create_item(
            "Test item",
            &[("service", "test")],
            &dbus_secret,
            true,
            None,
        )
        .await
        .expect("Writing to default alias should succeed after migration");

    // Only one collection should hold the "Login" label (no "Login2").
    let collections = setup.server.collections.lock().await;
    let mut login_count = 0;
    for collection in collections.values() {
        if collection.label().await == "Login" {
            login_count += 1;
        }
    }
    assert_eq!(login_count, 1, "Should have exactly one Login collection");

    Ok(())
}

#[tokio::test]
async fn pam_unlocks_locked_collections() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;

    // Create the v1 directory structure
    let v1_dir = temp_dir.path().join("keyrings/v1");
    tokio::fs::create_dir_all(&v1_dir).await?;

    // Create a v1 keyring with a known password
    let secret = Secret::from("my-secure-password");
    let keyring = UnlockedKeyring::open_at(temp_dir.path(), "work", Some(secret.clone())).await?;
    keyring
        .create_item(
            "Work Item",
            &[("type", "work")],
            Secret::text("work-secret"),
            false,
        )
        .await?;
    keyring.write().await?;

    let pam_socket_path = temp_dir.path().join("pam.sock");
    let setup = crate::tests::TestServiceSetup::with_disk_keyrings(
        temp_dir.path().to_path_buf(),
        Some(pam_socket_path),
        None,
    )
    .await?;

    let work_collection = setup
        .server
        .collection_by_label("Work")
        .await
        .expect("Work collection should exist");
    assert!(
        work_collection.is_locked().await,
        "Work collection should be locked"
    );

    let (socket_path, _) = spawn_pam_listener(&setup.server).await;

    let message = create_pam_message(PamOperation::Unlock, "testuser", &[], secret.as_bytes());
    send_pam_message(&socket_path, &message).await?;

    // Response received means unlock completed
    let work_collection = setup
        .server
        .collection_by_label("Work")
        .await
        .expect("Work collection should exist");
    assert!(
        !work_collection.is_locked().await,
        "Work collection should be unlocked"
    );

    Ok(())
}

#[tokio::test]
async fn pam_change_password() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;

    let old_secret = Secret::from("old-password");
    let keyring =
        UnlockedKeyring::open_at(temp_dir.path(), "work", Some(old_secret.clone())).await?;
    keyring
        .create_item(
            "Work Item",
            &[("type", "work")],
            Secret::text("work-secret"),
            false,
        )
        .await?;
    keyring.write().await?;

    let pam_socket_path = temp_dir.path().join("pam.sock");
    let setup = crate::tests::TestServiceSetup::with_disk_keyrings(
        temp_dir.path().to_path_buf(),
        Some(pam_socket_path),
        None,
    )
    .await?;

    let work_collection = setup
        .server
        .collection_by_label("Work")
        .await
        .expect("Work collection should exist");
    assert!(
        work_collection.is_locked().await,
        "Work collection should be locked"
    );

    let (socket_path, _) = spawn_pam_listener(&setup.server).await;

    let new_secret = Secret::from("new-password");
    let message = create_pam_message(
        PamOperation::ChangePassword,
        "testuser",
        old_secret.as_bytes(),
        new_secret.as_bytes(),
    );
    send_pam_message(&socket_path, &message).await?;

    let work_collection = setup
        .server
        .collection_by_label("Work")
        .await
        .expect("Work collection should exist");
    assert!(
        work_collection.is_locked().await,
        "Collection should be locked after password change"
    );

    let unlock_result = work_collection
        .set_locked(false, Some(old_secret.clone()))
        .await;
    assert!(
        unlock_result.is_err(),
        "Old password should not unlock collection"
    );

    work_collection
        .set_locked(false, Some(new_secret.clone()))
        .await?;
    assert!(
        !work_collection.is_locked().await,
        "New password should unlock collection"
    );

    Ok(())
}

#[tokio::test]
async fn message_serialization() -> Result<(), Box<dyn std::error::Error>> {
    // Test that PamMessage can be properly serialized and deserialized
    let message = PamMessage {
        operation: PamOperation::Unlock,
        username: "testuser".to_owned(),
        old_secret: vec![],
        new_secret: b"my-password".to_vec(),
    };

    let ctxt = Context::new(zgvariant::LE, 0);
    let encoded = zgvariant::to_bytes(ctxt, &message)?;
    let decoded = PamMessage::from_bytes(&encoded)?;

    assert_eq!(decoded.operation, PamOperation::Unlock);
    assert_eq!(decoded.username, "testuser");
    assert_eq!(decoded.new_secret, b"my-password");

    let message = PamMessage {
        operation: PamOperation::ChangePassword,
        username: "testuser".to_owned(),
        old_secret: b"old-pass".to_vec(),
        new_secret: b"new-pass".to_vec(),
    };

    let ctxt = Context::new(zgvariant::LE, 0);
    let encoded = zgvariant::to_bytes(ctxt, &message)?;
    let decoded = PamMessage::from_bytes(&encoded)?;

    assert_eq!(decoded.operation, PamOperation::ChangePassword);
    assert_eq!(decoded.old_secret, b"old-pass");
    assert_eq!(decoded.new_secret, b"new-pass");

    // Test PamResponse serialization
    let success_response = PamResponse::success();
    let encoded = success_response.to_bytes()?;
    let decoded = PamResponse::from_bytes(&encoded[4..])?; // Skip length prefix
    assert!(decoded.success);
    assert!(decoded.error_message.is_empty());

    let error_response = PamResponse::error("Something went wrong".to_string());
    let encoded = error_response.to_bytes()?;
    let decoded = PamResponse::from_bytes(&encoded[4..])?; // Skip length prefix
    assert!(!decoded.success);
    assert_eq!(decoded.error_message, "Something went wrong");

    Ok(())
}

// https://github.com/linux-credentials/oo7/issues/696
#[tokio::test]
async fn pam_wrong_secret_keeps_pending_migration_locked() -> Result<(), Box<dyn std::error::Error>>
{
    let temp_dir = tempfile::tempdir()?;
    let (setup, _temp_dir, _) =
        crate::tests::pending_migration_setup(Some(temp_dir.path().join("pam.sock"))).await?;

    let legacy = setup
        .server
        .collection_by_label("Legacy")
        .await
        .expect("Legacy placeholder collection should exist");
    assert!(legacy.is_locked().await);

    let (socket_path, _) = spawn_pam_listener(&setup.server).await;

    let message = create_pam_message(
        PamOperation::Unlock,
        "testuser",
        &[],
        Secret::from("wrong-password").as_bytes(),
    );
    send_pam_message(&socket_path, &message).await?;

    let legacy = setup
        .server
        .collection_by_label("Legacy")
        .await
        .expect("Legacy placeholder collection should exist");
    assert!(
        legacy.is_locked().await,
        "The placeholder should stay locked, so the migration can be retried"
    );
    assert_eq!(
        setup.server.pending_migrations.lock().await.len(),
        1,
        "The migration should still be pending"
    );

    Ok(())
}

// https://github.com/linux-credentials/oo7/issues/696
#[tokio::test]
async fn pam_change_password_pending_migration() -> Result<(), Box<dyn std::error::Error>> {
    let socket_dir = tempfile::tempdir()?;
    let (setup, data_dir, _) =
        crate::tests::pending_migration_setup(Some(socket_dir.path().join("pam.sock"))).await?;

    let (socket_path, _) = spawn_pam_listener(&setup.server).await;

    let new_secret = Secret::from("new-password");
    let message = create_pam_message(
        PamOperation::ChangePassword,
        "testuser",
        Secret::from("test").as_bytes(),
        new_secret.as_bytes(),
    );
    send_pam_message(&socket_path, &message).await?;

    assert_eq!(
        setup.server.pending_migrations.lock().await.len(),
        0,
        "The migration should have completed"
    );

    let keyring = UnlockedKeyring::open_at(data_dir.path(), "legacy", Some(new_secret)).await?;
    let items = keyring.items().await?;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].label(), "foo");

    Ok(())
}

// A secret arriving before the service is initialized is buffered and
// replayed once initialization is done, like Service::run does
#[tokio::test]
async fn pam_secret_before_initialization_is_replayed() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;
    let keyrings_dir = temp_dir.path().join("keyrings");
    tokio::fs::create_dir_all(keyrings_dir.join("v1")).await?;

    let secret = Secret::from("pam-password");
    let keyring = UnlockedKeyring::open_at(temp_dir.path(), "login", Some(secret.clone())).await?;
    keyring
        .create_item(
            "Login Item",
            &[("app", "pam-replay")],
            Secret::text("item-secret"),
            false,
        )
        .await?;
    keyring.write().await?;

    // The service is served on the bus but not initialized yet
    let (server, server_conn, _client_conn, _parts_temp) =
        crate::tests::TestServiceSetup::uninitialized_service(
            temp_dir.path().to_path_buf(),
            Some(temp_dir.path().join("pam.sock")),
        )
        .await?;

    // The PAM secret arrives before the keyrings are discovered
    let (socket_path, listener) = spawn_pam_listener(&server).await;
    let message = create_pam_message(PamOperation::Unlock, "testuser", &[], secret.as_bytes());
    send_pam_message(&socket_path, &message).await?;

    // Initialize like Service::run does, then replay the buffered secret
    let discovered = server.discover_keyrings(None).await?;
    server
        .initialize(server_conn, discovered, None, false)
        .await?;

    let login = server
        .collection_by_label("Login")
        .await
        .expect("Login collection should exist");
    assert!(login.is_locked().await, "No secret known at this point");

    listener.replay_buffered_secrets().await;

    let login = server
        .collection_by_label("Login")
        .await
        .expect("Login collection should exist");
    assert!(
        !login.is_locked().await,
        "The buffered secret should replay"
    );

    Ok(())
}

// Garbage on the PAM socket fails the connection cleanly
#[tokio::test]
async fn pam_malformed_message() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;

    let setup = crate::tests::TestServiceSetup::with_disk_keyrings(
        temp_dir.path().to_path_buf(),
        Some(temp_dir.path().join("pam.sock")),
        None,
    )
    .await?;

    let (socket_path, _) = spawn_pam_listener(&setup.server).await;

    // A valid length prefix around bytes that don't parse as a message
    let payload = b"definitely not a pam message";
    let mut message = (payload.len() as u32).to_le_bytes().to_vec();
    message.extend_from_slice(payload);

    let result = send_pam_bytes(&socket_path, &message).await;
    assert!(
        result.is_err(),
        "A malformed message should fail the connection"
    );

    // The listener keeps serving valid messages afterwards
    let secret = Secret::from("good-password");
    let message = create_pam_message(PamOperation::Unlock, "testuser", &[], secret.as_bytes());
    send_pam_message(&socket_path, &message).await?;

    Ok(())
}
