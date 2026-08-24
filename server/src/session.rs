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

    /// Fall back to the peer's own environment, for compositors run as a
    /// systemd `--user` service (e.g. niri, sway), which `logind` can't
    /// place in a session at all. Often blocked by Yama's `ptrace_scope`,
    /// since the daemon isn't an ancestor of its peers; see
    /// [`Self::from_systemd_user_environment`] for the last resort.
    async fn from_environ(pid: u32) -> Option<Self> {
        let environ = tokio::fs::read(format!("/proc/{pid}/environ")).await.ok()?;
        Self::from_display_vars(environ.split(|&b| b == 0))
    }

    /// Last resort: the systemd `--user` manager's own exported
    /// environment. Systemd-integrated compositors import
    /// `WAYLAND_DISPLAY`/`DISPLAY` into it on startup (e.g. via
    /// `dbus-update-activation-environment`), and it's readable over
    /// D-Bus with no `ptrace_scope` restriction. Coarser than the other
    /// checks since it's session-wide rather than peer-specific, so it's
    /// only consulted once `logind` can't place the peer anywhere.
    async fn from_systemd_user_environment() -> Option<Self> {
        let connection = zbus::Connection::session().await.ok()?;
        let manager = SystemdManagerProxy::new(&connection).await.ok()?;
        let environment = manager.environment().await.ok()?;

        Self::from_display_vars(environment.iter().map(String::as_bytes))
    }

    /// Shared `WAYLAND_DISPLAY`/`DISPLAY` lookup over a set of `NAME=value`
    /// entries, as found in both `/proc/<pid>/environ` and the systemd
    /// `--user` manager's exported environment.
    fn from_display_vars<'a>(vars: impl Iterator<Item = &'a [u8]>) -> Option<Self> {
        let mut wayland = false;
        let mut x11 = false;
        for entry in vars {
            if let Some(value) = entry.strip_prefix(b"WAYLAND_DISPLAY=") {
                wayland |= !value.is_empty();
            } else if let Some(value) = entry.strip_prefix(b"DISPLAY=") {
                x11 |= !value.is_empty();
            }
        }

        if wayland {
            Some(Self::Wayland)
        } else if x11 {
            Some(Self::X11)
        } else {
            None
        }
    }

    /// Best-effort session type detection, cascading `logind` ->
    /// [`Self::from_environ`] -> [`Self::from_systemd_user_environment`].
    /// Stops at the first check that places the peer in a session at
    /// all, even a non-graphical one.
    pub async fn detect(pid: u32) -> Self {
        if let Some(session_type) = Self::from_logind(pid).await {
            return session_type;
        }

        if let Some(session_type) = Self::from_environ(pid).await {
            return session_type;
        }

        Self::from_systemd_user_environment()
            .await
            .unwrap_or(Self::Unspecified)
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

#[zbus::proxy(
    default_service = "org.freedesktop.systemd1",
    interface = "org.freedesktop.systemd1.Manager",
    default_path = "/org/freedesktop/systemd1",
    gen_blocking = false
)]
trait SystemdManager {
    #[zbus(property)]
    fn environment(&self) -> zbus::Result<Vec<String>>;
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
    use super::SessionType;
    use crate::tests::TestServiceSetup;

    /// Spawn a short-lived child process with a controlled environment, to
    /// exercise `SessionType::from_environ` against a real
    /// `/proc/<pid>/environ`.
    fn spawn_with_env(vars: &[(&str, &str)]) -> std::process::Child {
        let mut command = std::process::Command::new("sleep");
        command.arg("5").env_clear();
        for (key, value) in vars {
            command.env(key, value);
        }
        command.spawn().expect("failed to spawn test child process")
    }

    #[tokio::test]
    async fn from_environ_detects_wayland() {
        let mut child = spawn_with_env(&[("WAYLAND_DISPLAY", "wayland-test")]);

        let session_type = SessionType::from_environ(child.id()).await;

        let _ = child.kill();
        let _ = child.wait();

        assert_eq!(session_type, Some(SessionType::Wayland));
    }

    #[tokio::test]
    async fn from_environ_detects_x11() {
        let mut child = spawn_with_env(&[("DISPLAY", ":0")]);

        let session_type = SessionType::from_environ(child.id()).await;

        let _ = child.kill();
        let _ = child.wait();

        assert_eq!(session_type, Some(SessionType::X11));
    }

    #[tokio::test]
    async fn from_environ_none_without_display() {
        let mut child = spawn_with_env(&[]);

        let session_type = SessionType::from_environ(child.id()).await;

        let _ = child.kill();
        let _ = child.wait();

        assert_eq!(session_type, None);
    }

    #[test]
    fn from_display_vars_detects_wayland() {
        let vars = [b"WAYLAND_DISPLAY=wayland-test".as_slice(), b"FOO=bar"];

        assert_eq!(
            SessionType::from_display_vars(vars.into_iter()),
            Some(SessionType::Wayland)
        );
    }

    #[test]
    fn from_display_vars_detects_x11() {
        let vars = [b"DISPLAY=:0".as_slice(), b"FOO=bar"];

        assert_eq!(
            SessionType::from_display_vars(vars.into_iter()),
            Some(SessionType::X11)
        );
    }

    #[test]
    fn from_display_vars_prefers_wayland_over_x11() {
        let vars = [b"DISPLAY=:0".as_slice(), b"WAYLAND_DISPLAY=wayland-test"];

        assert_eq!(
            SessionType::from_display_vars(vars.into_iter()),
            Some(SessionType::Wayland)
        );
    }

    #[test]
    fn from_display_vars_ignores_empty_values() {
        let vars = [b"WAYLAND_DISPLAY=".as_slice(), b"DISPLAY="];

        assert_eq!(SessionType::from_display_vars(vars.into_iter()), None);
    }

    #[test]
    fn from_display_vars_none_without_display() {
        let vars = [b"FOO=bar".as_slice()];

        assert_eq!(SessionType::from_display_vars(vars.into_iter()), None);
    }

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
