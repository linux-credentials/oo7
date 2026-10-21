#![deny(unsafe_code)]
#[cfg(target_os = "linux")]
mod capability;
mod collection;
mod error;
#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
mod gnome;
mod item;
mod migration;
mod pam_listener;
#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
mod plasma;
mod prompt;
mod service;
mod session;
#[cfg(test)]
mod tests;

use std::{
    io::{IoSliceMut, IsTerminal, Read},
    mem::MaybeUninit,
    path::{Path, PathBuf},
    sync::LazyLock,
    time::{Duration, Instant},
};

use clap::Parser;
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags};
use service::Service;

use crate::error::Error;

const BINARY_NAME: &str = env!("CARGO_BIN_NAME");

static LOGIN_HELPER_SOCKET: LazyLock<PathBuf> = LazyLock::new(|| {
    let uid = rustix::process::getuid().as_raw();
    PathBuf::from(format!("/run/user/{uid}/oo7-daemon-login.sock"))
});

/// How long to wait for `oo7-daemon-login` to bind its socket before giving up.
const LOGIN_HELPER_WAIT: Duration = Duration::from_millis(500);

/// Interval between connect attempts while waiting for the helper.
const LOGIN_HELPER_POLL: Duration = Duration::from_millis(10);

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(
        short = 'l',
        long,
        default_value_t = false,
        help = "Read a password from stdin, and use it to unlock the login keyring."
    )]
    login: bool,
    #[arg(short, long, help = "Replace a running instance.")]
    replace: bool,
    #[arg(
        short = 'v',
        long = "verbose",
        help = "Print debug information during command processing."
    )]
    is_verbose: bool,
}

/// Bounded wait for the transient `oo7-daemon-login` helper to bind its socket.
///
/// `pam_oo7.so auto_start` spawns the helper from the same PAM session stack
/// that starts this daemon, one module after `pam_systemd.so`, so the two race
/// by a few tens of milliseconds and either can win. A single connect attempt
/// silently drops the login secret whenever the daemon wins, leaving the login
/// collection locked for the whole session with no error logged anywhere.
async fn connect_to_login_helper(socket_path: &Path) -> Option<tokio::net::UnixStream> {
    let deadline = Instant::now() + LOGIN_HELPER_WAIT;

    loop {
        match tokio::net::UnixStream::connect(socket_path).await {
            Ok(stream) => return Some(stream),
            Err(e) if Instant::now() >= deadline => {
                tracing::debug!(
                    "No login helper at {} after {} ms: {e}",
                    socket_path.display(),
                    LOGIN_HELPER_WAIT.as_millis(),
                );
                return None;
            }
            Err(_) => tokio::time::sleep(LOGIN_HELPER_POLL).await,
        }
    }
}

async fn read_secret_from_login_helper() -> Option<oo7::Secret> {
    let socket_path = &*LOGIN_HELPER_SOCKET;

    let stream = connect_to_login_helper(socket_path).await?;

    tracing::info!("Connected to login helper at {}", socket_path.display());

    let mut buf = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut cmsg_buf = RecvAncillaryBuffer::new(&mut space);

    let received = stream
        .async_io(tokio::io::Interest::READABLE, || {
            rustix::net::recvmsg(&stream, &mut iov, &mut cmsg_buf, RecvFlags::empty())
                .map_err(Into::into)
        })
        .await;
    if let Err(e) = received {
        tracing::warn!("Failed to receive from login helper: {e}");
        return None;
    }

    for msg in cmsg_buf.drain() {
        if let RecvAncillaryMessage::ScmRights(fds) = msg {
            for fd in fds {
                // Seek to start and read the secret
                if rustix::fs::seek(&fd, rustix::fs::SeekFrom::Start(0)).is_err() {
                    continue;
                }
                let mut secret = Vec::new();
                let mut file = std::fs::File::from(fd);
                if file.read_to_end(&mut secret).is_ok() && !secret.is_empty() {
                    tracing::info!("Received login secret from helper");
                    return Some(oo7::Secret::from(secret));
                }
            }
        }
    }

    tracing::warn!("Login helper sent no usable secret");
    None
}

async fn read_secret_from_credentials_directory() -> Option<oo7::Secret> {
    let credential_dir = std::env::var("CREDENTIALS_DIRECTORY").ok()?;
    let cred_path = std::path::Path::new(&credential_dir).join("oo7.keyring-encryption-password");

    match tokio::fs::File::open(&cred_path).await {
        Ok(mut cred_file) => {
            let mut contents = Vec::new();
            match tokio::io::AsyncReadExt::read_to_end(&mut cred_file, &mut contents).await {
                Ok(_) => {
                    tracing::info!("Unlocking session keyring with systemd credential");
                    Some(oo7::Secret::from(contents))
                }
                Err(e) => {
                    tracing::error!("Failed to read credential: {e}");
                    None
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            tracing::error!("Failed to open credential: {e}");
            None
        }
    }
}

async fn inner_main(args: Args) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    capability::drop_unnecessary_capabilities()?;

    let secret = if args.login {
        let mut stdin = std::io::stdin().lock();
        if stdin.is_terminal() {
            let password = rpassword::prompt_password("Enter the login password: ")?;
            if password.is_empty() {
                tracing::error!("Login password can't be empty.");
                return Err(Error::EmptyPassword);
            }
            Some(oo7::Secret::text(password))
        } else {
            let mut buff = vec![];
            stdin.read_to_end(&mut buff)?;
            Some(oo7::Secret::from(buff))
        }
    } else {
        match read_secret_from_login_helper().await {
            Some(secret) => Some(secret),
            None => read_secret_from_credentials_directory().await,
        }
    };

    tracing::info!("Starting {BINARY_NAME}");

    let connection = match Service::run(secret, args.replace).await {
        Ok(connection) => connection,
        Err(Error::File(oo7::file::Error::IncorrectSecret)) if !args.login => {
            tracing::warn!("Failed to unlock session keyring: credential contains wrong password");
            return Ok(());
        }
        Err(Error::Zbus(zbus::Error::NameTaken)) if !args.replace => {
            tracing::error!(
                "There is an instance already running. Run with --replace to replace it."
            );
            return Err(Error::Zbus(zbus::Error::NameTaken));
        }
        Err(err) => return Err(err),
    };

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    tokio::select! {
        _ = connection.closed() => tracing::info!("D-Bus connection lost, shutting down"),
        _ = tokio::signal::ctrl_c() => tracing::info!("Received SIGINT, shutting down"),
        _ = sigterm.recv() => tracing::info!("Received SIGTERM, shutting down"),
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::parse();

    if args.is_verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG)
            .init();
        tracing::debug!("Running in verbose mode");
    } else {
        tracing_subscriber::fmt::init();
    }

    inner_main(args).await.inspect_err(|err| {
        tracing::error!("{err:#}");
    })
}

#[cfg(test)]
mod login_helper_tests {
    use super::*;

    #[tokio::test]
    async fn connect_waits_for_late_bind() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempfile::tempdir()?;
        let socket_path = temp_dir.path().join("oo7-daemon-login.sock");

        // The helper binds after the daemon's first connect attempt has failed.
        let helper_path = socket_path.clone();
        let helper = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            let listener = tokio::net::UnixListener::bind(&helper_path)?;
            listener.accept().await?;
            std::io::Result::Ok(())
        });

        assert!(connect_to_login_helper(&socket_path).await.is_some());
        helper.await??;
        Ok(())
    }

    #[tokio::test]
    async fn connect_gives_up_without_helper() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempfile::tempdir()?;
        let socket_path = temp_dir.path().join("oo7-daemon-login.sock");

        let start = Instant::now();
        assert!(connect_to_login_helper(&socket_path).await.is_none());
        assert!(start.elapsed() >= LOGIN_HELPER_WAIT);
        Ok(())
    }
}
