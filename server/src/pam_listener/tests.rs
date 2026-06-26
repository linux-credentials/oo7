use oo7::file::UnlockedKeyring;
use zbus::zvariant::serialized::Context;

use super::*;

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

    let ctxt = Context::new_dbus(zvariant::LE, 0);
    let encoded = zvariant::to_bytes(ctxt, &message).unwrap();
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

    let response = PamResponse::from_bytes(&response_bytes)?;

    // Check if response indicates success or error
    if !response.success {
        return Err(format!("PAM operation failed: {}", response.error_message).into());
    }

    Ok(())
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

    let pam_listener = PamListener::new(setup.server.clone());
    let socket_path = pam_listener.socket_path.clone();
    tokio::spawn(async move {
        let _ = pam_listener.start().await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

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
    let mut legacy_collection = None;
    for collection in collections.values() {
        if collection.label().await == "Legacy" {
            legacy_collection = Some(collection);
            break;
        }
    }
    assert!(
        legacy_collection.is_some(),
        "Migrated Legacy collection should exist"
    );

    let v1_migrated = v1_dir.join("legacy.keyring");
    assert!(v1_migrated.exists(), "V1 file should exist after migration");

    assert!(
        !v0_path.exists(),
        "V0 file should be removed after migration"
    );

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

    let collections = setup.server.collections.lock().await;
    let mut work_collection = None;
    for collection in collections.values() {
        if collection.label().await == "Work" {
            work_collection = Some(collection);
            break;
        }
    }
    assert!(work_collection.is_some(), "Work collection should exist");
    let work_collection = work_collection.unwrap();
    assert!(
        work_collection.is_locked().await,
        "Work collection should be locked"
    );
    drop(collections);

    let pam_listener = PamListener::new(setup.server.clone());
    let socket_path = pam_listener.socket_path.clone();
    tokio::spawn(async move {
        let _ = pam_listener.start().await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    let message = create_pam_message(PamOperation::Unlock, "testuser", &[], secret.as_bytes());
    send_pam_message(&socket_path, &message).await?;

    // Response received means unlock completed
    let collections = setup.server.collections.lock().await;
    let mut work_collection = None;
    for collection in collections.values() {
        if collection.label().await == "Work" {
            work_collection = Some(collection);
            break;
        }
    }
    let work_collection = work_collection.unwrap();
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

    let collections = setup.server.collections.lock().await;
    let mut work_collection = None;
    for collection in collections.values() {
        if collection.label().await == "Work" {
            work_collection = Some(collection);
            break;
        }
    }
    let work_collection = work_collection.unwrap();
    assert!(
        work_collection.is_locked().await,
        "Work collection should be locked"
    );
    drop(collections);

    let pam_listener = PamListener::new(setup.server.clone());
    let socket_path = pam_listener.socket_path.clone();
    tokio::spawn(async move {
        let _ = pam_listener.start().await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    let new_secret = Secret::from("new-password");
    let message = create_pam_message(
        PamOperation::ChangePassword,
        "testuser",
        old_secret.as_bytes(),
        new_secret.as_bytes(),
    );
    send_pam_message(&socket_path, &message).await?;

    let collections = setup.server.collections.lock().await;
    let mut work_collection = None;
    for collection in collections.values() {
        if collection.label().await == "Work" {
            work_collection = Some(collection);
            break;
        }
    }
    let work_collection = work_collection.unwrap();
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

    let ctxt = Context::new_dbus(zvariant::LE, 0);
    let encoded = zvariant::to_bytes(ctxt, &message)?;
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

    let ctxt = Context::new_dbus(zvariant::LE, 0);
    let encoded = zvariant::to_bytes(ctxt, &message)?;
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
