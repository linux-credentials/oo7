// org.freedesktop.Secret.Session

use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use oo7::{Key, dbus::ServiceError};
use tokio::sync::Mutex;
use zbus::{
    interface,
    names::UniqueName,
    zvariant::{ObjectPath, OwnedObjectPath},
};

use crate::Service;

const SESSION_STALE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    X11,
    Wayland,
    Tty,
    Unspecified,
}

impl SessionType {
    pub fn is_graphical(self) -> bool {
        matches!(self, Self::X11 | Self::Wayland)
    }

    pub async fn from_logind(pid: u32) -> Option<Self> {
        let connection = zbus::Connection::system().await.ok()?;
        let manager = LoginManagerProxy::new(&connection).await.ok()?;
        let session_path = manager.get_session_by_pid(pid).await.ok()?;
        let session = LoginSessionProxy::builder(&connection)
            .path(session_path)
            .ok()?
            .build()
            .await
            .ok()?;
        let type_str = session.type_().await.ok()?;
        Some(match type_str.as_str() {
            "x11" => Self::X11,
            "wayland" => Self::Wayland,
            "tty" => Self::Tty,
            _ => Self::Unspecified,
        })
    }
}

#[zbus::proxy(
    default_service = "org.freedesktop.login1",
    interface = "org.freedesktop.login1.Manager",
    default_path = "/org/freedesktop/login1",
    gen_blocking = false
)]
trait LoginManager {
    fn get_session_by_pid(&self, pid: u32) -> zbus::Result<OwnedObjectPath>;
}

#[zbus::proxy(
    default_service = "org.freedesktop.login1",
    interface = "org.freedesktop.login1.Session",
    gen_blocking = false
)]
trait LoginSession {
    #[zbus(property)]
    fn type_(&self) -> zbus::Result<String>;
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pid: u32,
    name: String,
    session_type: SessionType,
}

impl PeerInfo {
    pub fn new(pid: u32, name: String, session_type: SessionType) -> Self {
        Self {
            pid,
            name,
            session_type,
        }
    }

    pub fn session_type(&self) -> SessionType {
        self.session_type
    }
}

impl fmt::Display for PeerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}[{}]", self.name, self.pid)
    }
}

#[derive(Clone)]
pub struct Session {
    aes_key: Option<Arc<Key>>,
    service: Service,
    path: OwnedObjectPath,
    sender: UniqueName<'static>,
    peer_info: Option<PeerInfo>,
    disconnected_at: Arc<Mutex<Option<Instant>>>,
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    pub async fn close(&self) -> Result<(), ServiceError> {
        tracing::info!("Closing session {} for {}.", self.path, self.sender);
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
        peer_info: Option<PeerInfo>,
    ) -> Self {
        let index = service.session_index();
        Self {
            path: OwnedObjectPath::try_from(format!("/org/freedesktop/secrets/session/s{index}"))
                .unwrap(),
            aes_key,
            service,
            sender,
            peer_info,
            disconnected_at: Arc::new(Mutex::new(None)),
        }
    }

    pub fn sender(&self) -> &UniqueName<'static> {
        &self.sender
    }

    pub fn peer_info(&self) -> Option<&PeerInfo> {
        self.peer_info.as_ref()
    }

    pub fn path(&self) -> &ObjectPath<'_> {
        &self.path
    }

    pub fn aes_key(&self) -> Option<Arc<Key>> {
        self.aes_key.as_ref().map(Arc::clone)
    }

    pub async fn mark_stale(&self) {
        *self.disconnected_at.lock().await = Some(Instant::now());
    }

    pub async fn unmark_stale(&self) {
        *self.disconnected_at.lock().await = None;
    }

    pub async fn is_stale(&self) -> bool {
        self.disconnected_at
            .lock()
            .await
            .is_some_and(|t| t.elapsed() > SESSION_STALE_TIMEOUT)
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
