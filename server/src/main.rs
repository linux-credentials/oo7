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
    io::{IsTerminal, Read},
    path::Path,
};

use clap::Parser;
use service::Service;
use tokio::io::AsyncReadExt;

use crate::error::Error;

const BINARY_NAME: &str = env!("CARGO_BIN_NAME");

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

/// Whether the daemon should exit if the password provided for unlocking the
/// session keyring is incorrect.
enum ShouldErrorOut {
    Yes,
    No,
}

async fn inner_main(args: Args) -> Result<(), Error> {
    capability::drop_unnecessary_capabilities()?;

    let secret_info = if args.login {
        let mut stdin = std::io::stdin().lock();
        if stdin.is_terminal() {
            let password = rpassword::prompt_password("Enter the login password: ")?;
            if password.is_empty() {
                tracing::error!("Login password can't be empty.");
                return Err(Error::EmptyPassword);
            }

            Some((oo7::Secret::text(password), ShouldErrorOut::Yes))
        } else {
            let mut buff = vec![];
            stdin.read_to_end(&mut buff)?;

            Some((oo7::Secret::from(buff), ShouldErrorOut::No))
        }
    } else if let Ok(credential_dir) = std::env::var("CREDENTIALS_DIRECTORY") {
        // We try to unlock the login keyring with a system credential.
        let mut contents = Vec::new();
        let cred_path = Path::new(&credential_dir).join("oo7.keyring-encryption-password");

        match tokio::fs::File::open(&cred_path).await {
            Ok(mut cred_file) => {
                tracing::info!("Unlocking session keyring with user's systemd credentials");
                cred_file.read_to_end(&mut contents).await?;
                let secret = oo7::Secret::from(contents);
                Some((secret, ShouldErrorOut::No))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                tracing::error!("Failed to open system credential {err:?}");
                Err(err)?
            }
        }
    } else {
        None
    };

    tracing::info!("Starting {BINARY_NAME}");

    if let Some((secret, should_error_out)) = secret_info {
        let res = Service::run(Some(secret), args.replace).await;
        match res {
            Ok(()) => (),
            // Wrong password provided via system credentials
            Err(Error::File(oo7::file::Error::IncorrectSecret))
                if matches!(should_error_out, ShouldErrorOut::No) =>
            {
                tracing::warn!(
                    "Failed to unlock session keyring: credential contains wrong password"
                )
            }
            Err(Error::Zbus(zbus::Error::NameTaken)) if !args.replace => {
                tracing::error!(
                    "There is an instance already running. Run with --replace to replace it."
                );
                Err(Error::Zbus(zbus::Error::NameTaken))?
            }
            Err(err) => Err(err)?,
        }
    } else {
        Service::run(None, args.replace).await?;
    }

    tracing::debug!("Starting loop");

    std::future::pending::<()>().await;

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
