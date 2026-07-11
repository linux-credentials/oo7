//! PAM integration - Unix socket listener for receiving secrets from PAM module

use std::{os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc};

use oo7::Secret;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use tokio::{
    io::AsyncReadExt,
    net::{UnixListener, UnixStream},
    sync::RwLock,
};
use zbus::zvariant::{
    self, Type,
    serialized::{Context, Data},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Service, error::Error};

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, Type, PartialEq, Eq)]
#[repr(u8)]
enum PamOperation {
    Unlock = 0,
    ChangePassword = 1,
}

#[derive(Serialize, Deserialize, Type, Zeroize, ZeroizeOnDrop)]
struct PamMessage {
    #[zeroize(skip)]
    operation: PamOperation,
    username: String,
    old_secret: Vec<u8>,
    new_secret: Vec<u8>,
}

#[derive(Serialize, Deserialize, Type)]
struct PamResponse {
    success: bool,
    error_message: String,
}

impl PamMessage {
    fn from_bytes(bytes: &[u8]) -> Result<Self, zvariant::Error> {
        let ctxt = Context::new_dbus(zvariant::LE, 0);
        let data = Data::new(bytes, ctxt);
        data.deserialize().map(|(msg, _)| msg)
    }
}

impl PamResponse {
    fn success() -> Self {
        Self {
            success: true,
            error_message: String::new(),
        }
    }

    fn error(message: String) -> Self {
        Self {
            success: false,
            error_message: message,
        }
    }

    #[cfg(test)]
    fn from_bytes(bytes: &[u8]) -> Result<Self, zvariant::Error> {
        let ctxt = Context::new_dbus(zvariant::LE, 0);
        let data = Data::new(bytes, ctxt);
        data.deserialize().map(|(msg, _)| msg)
    }

    fn to_bytes(&self) -> Result<Vec<u8>, zvariant::Error> {
        let ctxt = Context::new_dbus(zvariant::LE, 0);
        let encoded = zvariant::to_bytes(ctxt, self)?;
        let message_bytes = encoded.to_vec();

        // Prepend length prefix (4 bytes, little-endian)
        let mut result = (message_bytes.len() as u32).to_le_bytes().to_vec();
        result.extend_from_slice(&message_bytes);
        Ok(result)
    }
}

/// PAM listener that receives authentication secrets from the PAM module
#[derive(Clone)]
pub struct PamListener {
    pub(crate) socket_path: PathBuf,
    service: Service,
    /// Current user's secret, used to unlock their keyring <username, secret>
    user_secrets: Arc<RwLock<std::collections::HashMap<String, Secret>>>,
}

impl PamListener {
    pub fn new(service: Service) -> Self {
        let uid = rustix::process::getuid().as_raw();
        let socket_path = service
            .pam_socket
            .clone()
            .unwrap_or_else(|| PathBuf::from(format!("/run/user/{uid}/oo7-pam.sock")));

        Self {
            socket_path,
            service,
            user_secrets: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Start the PAM listener
    pub async fn start(self) -> Result<(), Error> {
        // Remove old socket if it exists
        if self.socket_path.exists() {
            tokio::fs::remove_file(&self.socket_path).await?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;

        tracing::info!("PAM listener started on {}", self.socket_path.display());

        // Set socket permissions to 0600
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&self.socket_path, perms)?;

        let listener = Arc::new(listener);

        // Accept connections in a loop
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let pam_listener = self.clone();

                    tokio::spawn(async move {
                        if let Err(e) = pam_listener.handle_connection(stream).await {
                            tracing::error!("Error handling PAM connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Error accepting PAM connection: {}", e);
                }
            }
        }
    }

    /// Handle a single PAM connection
    async fn handle_connection(&self, mut stream: UnixStream) -> Result<(), Error> {
        // Accept connections from:
        // 1. Root (UID 0) as PAM modules run as root during authentication
        // 2. Same UID as us
        let peer_cred = stream.peer_cred()?;
        let our_uid = rustix::process::getuid().as_raw();
        let peer_uid = peer_cred.uid();

        if peer_uid != 0 && peer_uid != our_uid {
            tracing::warn!(
                "Rejected PAM connection from UID {} PID {} (expected UID 0 or {})",
                peer_uid,
                peer_cred.pid().unwrap_or(0),
                our_uid
            );
            return Err(Error::IO(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Connection rejected: unauthorized UID (peer={}, daemon={}, root=0)",
                    peer_uid, our_uid
                ),
            )));
        }

        tracing::debug!(
            "Accepted PAM connection from {} (UID {}, PID {})",
            if peer_uid == 0 {
                "root/PAM"
            } else {
                "same user"
            },
            peer_uid,
            peer_cred.pid().unwrap_or(0)
        );

        // Read the message length prefix (4 bytes, little-endian)
        let mut length_bytes = [0u8; 4];
        stream.read_exact(&mut length_bytes).await?;
        let message_length = u32::from_le_bytes(length_bytes) as usize;

        let mut message_bytes = vec![0u8; message_length];
        stream.read_exact(&mut message_bytes).await?;

        let message = PamMessage::from_bytes(&message_bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        let response = match message.operation {
            PamOperation::Unlock => {
                tracing::info!("Received unlock request for user: {}", message.username);
                tracing::debug!(
                    "Received secret of length {} bytes",
                    message.new_secret.len()
                );

                let secret = Secret::from(message.new_secret.to_vec());
                self.user_secrets
                    .write()
                    .await
                    .insert(message.username.clone(), secret.clone());

                match self.try_unlock_collections(&secret).await {
                    Ok(_) => {
                        tracing::info!(
                            "Successfully unlocked collections for user: {}",
                            message.username
                        );
                        PamResponse::success()
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to unlock collections for user {}: {}",
                            message.username,
                            e
                        );
                        PamResponse::error(e.to_string())
                    }
                }
            }
            PamOperation::ChangePassword => {
                tracing::info!(
                    "Received password change request for user: {}",
                    message.username
                );
                tracing::debug!(
                    "Old secret: {} bytes, new secret: {} bytes",
                    message.old_secret.len(),
                    message.new_secret.len()
                );

                let old_secret = Secret::from(message.old_secret.to_vec());
                let new_secret = Secret::from(message.new_secret.to_vec());

                match self
                    .change_collection_passwords(&old_secret, &new_secret)
                    .await
                {
                    Ok(changed_count) => {
                        tracing::info!(
                            "Successfully changed password for {} collection(s) for user: {}",
                            changed_count,
                            message.username
                        );
                        // Update stored secret
                        self.user_secrets
                            .write()
                            .await
                            .insert(message.username.clone(), new_secret);
                        PamResponse::success()
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to change password for user {}: {}",
                            message.username,
                            e
                        );
                        PamResponse::error(e.to_string())
                    }
                }
            }
        };

        // Send response back to client
        use tokio::io::AsyncWriteExt;
        if let Ok(response_bytes) = response.to_bytes() {
            let _ = stream.write_all(&response_bytes).await;
            let _ = stream.flush().await;
        }

        Ok(())
    }

    /// Replay any secrets buffered before collections were initialized.
    pub async fn replay_buffered_secrets(&self) {
        let secrets = self.user_secrets.read().await;
        if secrets.is_empty() {
            return;
        }
        tracing::info!(
            "Replaying {} buffered secret(s) received during startup",
            secrets.len()
        );
        for (username, secret) in secrets.iter() {
            match self.try_unlock_collections(secret).await {
                Ok(_) => tracing::info!("Replayed unlock for user: {}", username),
                Err(e) => tracing::warn!("Failed to replay unlock for user {}: {}", username, e),
            }
        }
    }

    async fn try_unlock_collections(&self, secret: &Secret) -> Result<(), Error> {
        // First, try to migrate any pending v0 keyrings
        let migrated = self.service.migrate_pending_keyrings(secret).await;
        if !migrated.is_empty() {
            tracing::info!("Migrated {} v0 keyring(s): {:?}", migrated.len(), migrated);
        }

        let collections = self.service.collections.lock().await;

        for collection in collections.values() {
            if collection.is_locked().await {
                tracing::debug!("Attempting to unlock collection: {}", collection.path());

                // Try to unlock with the provided secret
                if let Err(e) = collection.set_locked(false, Some(secret.clone())).await {
                    tracing::debug!("Failed to unlock collection {}: {}", collection.path(), e);
                } else {
                    tracing::info!("Unlocked collection: {}", collection.path());
                }
            }
        }

        Ok(())
    }

    /// Change password for all collections that match the old password
    async fn change_collection_passwords(
        &self,
        old_secret: &Secret,
        new_secret: &Secret,
    ) -> Result<usize, Error> {
        let collections = self.service.collections.lock().await;
        let mut changed_count = 0;

        for (path, collection) in collections.iter() {
            // Skip session collection (it's temporary and doesn't persist)
            if collection.alias().await == oo7::dbus::Service::SESSION_COLLECTION {
                tracing::debug!("Skipping session collection: {}", path);
                continue;
            }

            // Get the keyring from the collection
            let keyring_guard = collection.keyring.read().await;
            let Some(keyring) = keyring_guard.as_ref() else {
                tracing::debug!("Collection {} has no keyring", path);
                continue;
            };

            // Track if we unlocked the collection (so we can re-lock it after)
            let was_locked = keyring.is_locked();

            // Check if the keyring is locked and unlock if needed
            if was_locked {
                // Try to unlock with old password first
                tracing::debug!(
                    "Collection {} is locked, attempting to unlock with old password",
                    path
                );
                drop(keyring_guard);

                if let Err(e) = collection.set_locked(false, Some(old_secret.clone())).await {
                    tracing::warn!(
                        "Failed to unlock collection {} with old password: {}",
                        path,
                        e
                    );
                    continue;
                }
            } else {
                drop(keyring_guard);
            }

            // Re-acquire the lock to get the unlocked keyring
            let keyring_guard = collection.keyring.read().await;
            let Some(oo7::file::Keyring::Unlocked(uk)) = keyring_guard.as_ref() else {
                tracing::warn!("Collection {} is not unlocked", path);
                continue;
            };

            // Validate that the old password can decrypt items in the keyring
            let can_decrypt = match uk.validate_secret(old_secret).await {
                Ok(valid) => valid,
                Err(e) => {
                    tracing::warn!(
                        "Failed to validate old password for collection {}: {}",
                        path,
                        e
                    );
                    continue;
                }
            };

            if !can_decrypt {
                tracing::debug!(
                    "Old password does not match keyring {} password, skipping",
                    path
                );
                continue;
            }

            // Change the keyring password
            match uk.change_secret(new_secret.clone()).await {
                Ok(_) => {
                    tracing::info!("Successfully changed password for collection: {}", path);
                    changed_count += 1;

                    // Re-lock the collection if it was locked before we unlocked it
                    drop(keyring_guard);
                    if was_locked {
                        if let Err(e) = collection.set_locked(true, None).await {
                            tracing::warn!(
                                "Failed to re-lock collection {} after password change: {}",
                                path,
                                e
                            );
                        } else {
                            tracing::debug!("Re-locked collection: {}", path);
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to change password for collection {}: {}", path, e);
                }
            }
        }

        Ok(changed_count)
    }
}

#[cfg(test)]
mod tests;
