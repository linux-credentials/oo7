// org.freedesktop.Secret.Session

use std::sync::Arc;

use oo7::{Key, dbus::ServiceError};
use zbus::{
    interface,
    names::UniqueName,
    zvariant::{ObjectPath, OwnedObjectPath},
};

use crate::Service;

#[derive(Clone)]
pub struct Session {
    aes_key: Option<Arc<Key>>,
    service: Service,
    path: OwnedObjectPath,
    sender: UniqueName<'static>,
    peer_name: Option<String>,
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    pub async fn close(&self) -> Result<(), ServiceError> {
        self.service.remove_session(&self.path).await;
        self.service
            .object_server()
            .remove::<Self, _>(&self.path)
            .await?;

        Ok(())
    }
}

impl Session {
    pub async fn new(
        aes_key: Option<Arc<Key>>,
        service: Service,
        sender: UniqueName<'static>,
        peer_name: Option<String>,
    ) -> Self {
        let index = service.session_index().await;
        Self {
            path: OwnedObjectPath::try_from(format!("/org/freedesktop/secrets/session/s{index}"))
                .unwrap(),
            aes_key,
            service,
            sender,
            peer_name,
        }
    }

    pub fn sender(&self) -> &UniqueName<'static> {
        &self.sender
    }

    pub fn peer_name(&self) -> Option<&str> {
        self.peer_name.as_deref()
    }

    pub fn path(&self) -> &ObjectPath<'_> {
        &self.path
    }

    pub fn aes_key(&self) -> Option<Arc<Key>> {
        self.aes_key.as_ref().map(Arc::clone)
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::TestServiceSetup;

    #[tokio::test]
    async fn close() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;
        let path = setup.session.inner().path().to_owned();

        // Verify session exists on the server
        let session_check = setup.server.session(&path).await;
        assert!(
            session_check.is_some(),
            "Session should exist on server before close"
        );

        // Close the session
        setup.session.close().await?;

        // Verify session no longer exists on the server
        let session_check_after = setup.server.session(&path).await;
        assert!(
            session_check_after.is_none(),
            "Session should not exist on server after close"
        );

        Ok(())
    }
}
