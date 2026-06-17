use std::{
    io::{self, IoSlice, Read},
    mem::MaybeUninit,
    os::{fd::AsFd, unix::fs::PermissionsExt},
    path::PathBuf,
    sync::LazyLock,
};

use rustix::{
    fs::{MemfdFlags, SealFlags},
    net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags},
};

const HELPER_TIMEOUT_SECS: u64 = 120;
const BINARY_NAME: &str = env!("CARGO_BIN_NAME");

pub static SOCKET_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    let uid = rustix::process::getuid().as_raw();
    PathBuf::from(format!("/run/user/{uid}/oo7-daemon-login.sock"))
});

fn main() {
    tracing_subscriber::fmt::init();

    let mut secret = vec![];
    io::stdin()
        .lock()
        .read_to_end(&mut secret)
        .unwrap_or_else(|e| {
            tracing::error!("Failed to read secret from stdin: {e}");
            std::process::exit(1);
        });

    if secret.is_empty() {
        tracing::error!("No secret provided on stdin");
        std::process::exit(1);
    }

    tracing::info!("Starting {BINARY_NAME}");

    let socket_path = &*SOCKET_PATH;

    let _ = std::fs::remove_file(socket_path);

    let listener = std::os::unix::net::UnixListener::bind(socket_path).unwrap_or_else(|e| {
        tracing::error!("Failed to bind {}: {e}", socket_path.display());
        std::process::exit(1);
    });

    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600)).unwrap_or_else(
        |e| {
            tracing::error!("Failed to set socket permissions: {e}");
            std::process::exit(1);
        },
    );

    let uid = rustix::process::getuid();

    listener.set_nonblocking(false).ok();
    tracing::info!("Listening on {}", socket_path.display());

    // Poll with timeout
    let timeout = rustix::event::Timespec {
        tv_sec: HELPER_TIMEOUT_SECS as i64,
        tv_nsec: 0,
    };
    let poll_ret = rustix::event::poll(
        &mut [rustix::event::PollFd::from_borrowed_fd(
            listener.as_fd(),
            rustix::event::PollFlags::IN,
        )],
        Some(&timeout),
    );
    match poll_ret {
        Ok(0) => {
            tracing::info!("Timed out after {HELPER_TIMEOUT_SECS}s, no daemon connected");
            let _ = std::fs::remove_file(socket_path);
            std::process::exit(0);
        }
        Err(e) => {
            tracing::error!("Poll failed: {e}");
            let _ = std::fs::remove_file(socket_path);
            std::process::exit(1);
        }
        _ => {}
    }

    let (stream, _addr) = listener.accept().unwrap_or_else(|e| {
        tracing::error!("Failed to accept connection: {e}");
        let _ = std::fs::remove_file(socket_path);
        std::process::exit(1);
    });

    let peer_cred = rustix::net::sockopt::socket_peercred(&stream).unwrap_or_else(|e| {
        tracing::error!("Failed to get peer credentials: {e}");
        let _ = std::fs::remove_file(socket_path);
        std::process::exit(1);
    });
    if peer_cred.uid != uid {
        tracing::error!(
            "Rejected connection from UID {} (expected {})",
            peer_cred.uid.as_raw(),
            uid.as_raw()
        );
        let _ = std::fs::remove_file(socket_path);
        std::process::exit(1);
    }

    // Create memfd, write secret, seal it
    let memfd = rustix::fs::memfd_create(
        c"oo7-login-secret",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )
    .unwrap_or_else(|e| {
        tracing::error!("Failed to create memfd: {e}");
        let _ = std::fs::remove_file(socket_path);
        std::process::exit(1);
    });

    rustix::io::write(&memfd, &secret).unwrap_or_else(|e| {
        tracing::error!("Failed to write to memfd: {e}");
        let _ = std::fs::remove_file(socket_path);
        std::process::exit(1);
    });

    zeroize::Zeroize::zeroize(&mut secret);

    rustix::fs::fcntl_add_seals(
        &memfd,
        SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL,
    )
    .unwrap_or_else(|e| {
        tracing::error!("Failed to seal memfd: {e}");
        let _ = std::fs::remove_file(socket_path);
        std::process::exit(1);
    });

    // Send the memfd via SCM_RIGHTS
    let fds = [std::os::fd::AsFd::as_fd(&memfd)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut cmsg_buf = SendAncillaryBuffer::new(&mut space);
    cmsg_buf.push(SendAncillaryMessage::ScmRights(&fds));

    let iov = [IoSlice::new(&[0u8])];
    rustix::net::sendmsg(&stream, &iov, &mut cmsg_buf, SendFlags::empty()).unwrap_or_else(|e| {
        tracing::error!("Failed to send memfd: {e}");
        let _ = std::fs::remove_file(socket_path);
        std::process::exit(1);
    });

    tracing::info!("Secret delivered to daemon");
    let _ = std::fs::remove_file(socket_path);
}
