use std::io::BufRead;

use oo7::{SecretSchema, dbus::Collection};

enum Error {
    Oo7(oo7::dbus::Error),
    Io(std::io::Error),
    InvalidInput(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Oo7(e) => write!(f, "{e}"),
            Error::Io(e) => write!(f, "{e}"),
            Error::InvalidInput(msg) => write!(f, "{msg}"),
        }
    }
}

impl From<oo7::dbus::Error> for Error {
    fn from(e: oo7::dbus::Error) -> Self {
        Error::Oo7(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

#[derive(SecretSchema, Debug, Default)]
#[schema(name = "org.git.Password")]
struct GitSchema {
    user: Option<String>,
    object: Option<String>,
    protocol: Option<String>,
    port: Option<u16>,
    server: Option<String>,
}

struct Credential {
    schema: GitSchema,
    password: Option<String>,
    password_expiry_utc: Option<String>,
    oauth_refresh_token: Option<String>,
}

impl Credential {
    fn from_stdin() -> Result<Self, Error> {
        let mut schema = GitSchema::default();
        let mut password = None;
        let mut password_expiry_utc = None;
        let mut oauth_refresh_token = None;

        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let line = line?;
            if line.is_empty() {
                break;
            }

            let Some((key, value)) = line.split_once('=') else {
                return Err(Error::InvalidInput(format!(
                    "invalid credential line: {line}"
                )));
            };

            match key {
                "protocol" => schema.protocol = Some(value.to_owned()),
                "host" => {
                    if let Some((host, port_str)) = value.rsplit_once(':') {
                        if let Ok(port) = port_str.parse::<u16>() {
                            schema.server = Some(host.to_owned());
                            schema.port = Some(port);
                        } else {
                            schema.server = Some(value.to_owned());
                        }
                    } else {
                        schema.server = Some(value.to_owned());
                    }
                }
                "path" => schema.object = Some(value.to_owned()),
                "username" => schema.user = Some(value.to_owned()),
                "password" => password = Some(value.to_owned()),
                "password_expiry_utc" => {
                    password_expiry_utc = Some(value.to_owned());
                }
                "oauth_refresh_token" => {
                    oauth_refresh_token = Some(value.to_owned());
                }
                _ => {}
            }
        }

        Ok(Self {
            schema,
            password,
            password_expiry_utc,
            oauth_refresh_token,
        })
    }

    fn validate_get(&self) -> Result<(), Error> {
        if self.schema.protocol.is_none()
            || (self.schema.server.is_none() && self.schema.object.is_none())
        {
            return Err(Error::InvalidInput(
                "get requires protocol and host or path".into(),
            ));
        }
        Ok(())
    }

    fn validate_store(&self) -> Result<(), Error> {
        if self.schema.protocol.is_none()
            || (self.schema.server.is_none() && self.schema.object.is_none())
            || self.schema.user.is_none()
            || self.password.is_none()
        {
            return Err(Error::InvalidInput(
                "store requires protocol, host/path, username, and password".into(),
            ));
        }
        Ok(())
    }

    fn validate_erase(&self) -> Result<(), Error> {
        if self.schema.protocol.is_none()
            && self.schema.server.is_none()
            && self.schema.object.is_none()
            && self.schema.user.is_none()
        {
            return Err(Error::InvalidInput(
                "erase requires at least protocol, host, path, or username".into(),
            ));
        }
        Ok(())
    }

    fn make_label(&self) -> String {
        let protocol = self.schema.protocol.as_deref().unwrap_or_default();
        let host = self.schema.server.as_deref().unwrap_or_default();
        let path = self.schema.object.as_deref().unwrap_or_default();
        match self.schema.port {
            Some(port) => format!("Git: {protocol}://{host}:{port}/{path}"),
            None => format!("Git: {protocol}://{host}/{path}"),
        }
    }

    fn make_secret(&self) -> String {
        let mut secret = self.password.clone().unwrap_or_default();
        if let Some(ref expiry) = self.password_expiry_utc {
            secret.push_str(&format!("\npassword_expiry_utc={expiry}"));
        }
        if let Some(ref token) = self.oauth_refresh_token {
            secret.push_str(&format!("\noauth_refresh_token={token}"));
        }
        secret
    }
}

fn parse_secret(secret: &oo7::Secret) -> (String, Option<String>, Option<String>) {
    let text = secret.as_str().unwrap_or_default();
    let mut lines = text.split('\n');
    let password = lines.next().unwrap_or_default().to_owned();
    let mut password_expiry_utc = None;
    let mut oauth_refresh_token = None;
    for line in lines {
        if let Some(val) = line.strip_prefix("password_expiry_utc=") {
            password_expiry_utc = Some(val.to_owned());
        } else if let Some(val) = line.strip_prefix("oauth_refresh_token=") {
            oauth_refresh_token = Some(val.to_owned());
        }
    }
    (password, password_expiry_utc, oauth_refresh_token)
}

async fn run(action: &str, credential: &Credential, collection: &Collection) -> Result<(), Error> {
    match action {
        "get" => {
            credential.validate_get()?;

            let items = collection.search_items(&credential.schema).await?;
            if let Some(item) = items.first() {
                let attrs = item.attributes_as::<GitSchema>().await?;
                let secret = item.secret().await?;
                let (password, expiry, oauth) = parse_secret(&secret);

                if let Some(user) = &attrs.user {
                    println!("username={user}");
                }
                println!("password={password}");
                if let Some(expiry) = expiry {
                    println!("password_expiry_utc={expiry}");
                }
                if let Some(oauth) = oauth {
                    println!("oauth_refresh_token={oauth}");
                }
            }
        }
        "store" => {
            credential.validate_store()?;

            collection
                .create_item(
                    &credential.make_label(),
                    &credential.schema,
                    credential.make_secret(),
                    true,
                    None,
                )
                .await?;
        }
        "erase" => {
            credential.validate_erase()?;

            let items = collection.search_items(&credential.schema).await?;

            if let Some(ref password) = credential.password
                && let Some(item) = items.first()
            {
                let secret = item.secret().await?;
                let (stored_password, ..) = parse_secret(&secret);
                if stored_password != *password {
                    return Ok(());
                }
            }

            for item in &items {
                item.delete(None).await?;
            }
        }
        _ => {}
    }

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 || args[1].is_empty() {
        let name = args
            .first()
            .map(String::as_str)
            .unwrap_or("git-credential-oo7");
        eprintln!("usage: {name} <get|store|erase>");
        std::process::exit(1);
    }

    let credential = match Credential::from_stdin() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    let action = args[1].as_str();
    if !matches!(action, "get" | "store" | "erase") {
        return;
    }

    let result = async {
        let service = oo7::dbus::Service::new().await?;
        let collection = service.default_collection().await?;
        if collection.is_locked().await? {
            collection.unlock(None).await?;
        }

        run(action, &credential, &collection).await
    }
    .await;

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
