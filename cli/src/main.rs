use std::{
    collections::HashMap,
    fmt,
    io::{BufRead, IsTerminal, Write},
    path::PathBuf,
    process::{ExitCode, Termination},
    time::Duration,
};

use clap::{Args, Parser, Subcommand};
use oo7::dbus::Service;
use serde::Serialize;
use time::{OffsetDateTime, UtcOffset};

const BINARY_NAME: &str = env!("CARGO_BIN_NAME");
const H_STYLE: anstyle::Style = anstyle::Style::new().bold().underline();

enum Error {
    Owned(String),
    Borrowed(&'static str),
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Owned(s) => f.write_str(s),
            Self::Borrowed(s) => f.write_str(s),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Self::Owned(err.to_string())
    }
}

impl From<oo7::file::Error> for Error {
    fn from(err: oo7::file::Error) -> Error {
        Self::Owned(err.to_string())
    }
}

impl From<oo7::dbus::Error> for Error {
    fn from(err: oo7::dbus::Error) -> Error {
        Self::Owned(err.to_string())
    }
}

impl Error {
    fn new(s: &'static str) -> Self {
        Self::Borrowed(s)
    }
}

impl Termination for Error {
    fn report(self) -> ExitCode {
        ExitCode::FAILURE
    }
}

#[derive(Serialize)]
struct ItemOutput {
    label: String,
    secret: String,
    created_at: String,
    modified_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    schema: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    attributes: HashMap<String, String>,
}

impl ItemOutput {
    fn new(
        secret: &oo7::Secret,
        label: &str,
        mut attributes: HashMap<String, String>,
        created: Duration,
        modified: Duration,
        as_hex: bool,
    ) -> Self {
        let bytes = secret.as_bytes();
        let local_offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);

        let created = OffsetDateTime::from_unix_timestamp(created.as_secs() as i64)
            .unwrap()
            .to_offset(local_offset);
        let modified = OffsetDateTime::from_unix_timestamp(modified.as_secs() as i64)
            .unwrap()
            .to_offset(local_offset);

        let format = time::format_description::parse_borrowed::<2>(
            "[year]-[month]-[day] [hour]:[minute]:[second]",
        )
        .unwrap();

        let secret_str = if as_hex {
            hex::encode(bytes)
        } else {
            match std::str::from_utf8(bytes) {
                Ok(s) => s.to_string(),
                Err(_) => hex::encode(bytes),
            }
        };

        let schema = attributes.remove(oo7::XDG_SCHEMA_ATTRIBUTE);
        let content_type = attributes.remove(oo7::CONTENT_TYPE_ATTRIBUTE);

        Self {
            label: label.to_string(),
            secret: secret_str,
            created_at: created.format(&format).unwrap(),
            modified_at: modified.format(&format).unwrap(),
            schema,
            content_type,
            attributes,
        }
    }

    fn from_file_item(item: &oo7::file::Item, as_hex: bool) -> Self {
        let unlocked = item.as_unlocked();
        Self::new(
            &unlocked.secret(),
            unlocked.label(),
            unlocked
                .attributes()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            unlocked.created(),
            unlocked.modified(),
            as_hex,
        )
    }

    async fn from_dbus_item(item: &oo7::dbus::Item, as_hex: bool) -> Result<Self, Error> {
        Ok(Self::new(
            &item.secret().await?,
            &item.label().await?,
            item.attributes().await?,
            item.created().await?,
            item.modified().await?,
            as_hex,
        ))
    }
}

impl fmt::Display for ItemOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "[{}]", self.label)?;
        writeln!(f, "secret = {}", self.secret)?;
        writeln!(f, "created = {}", self.created_at)?;
        writeln!(f, "modified = {}", self.modified_at)?;
        if let Some(schema) = &self.schema {
            writeln!(f, "schema = {schema}")?;
        }
        if let Some(content_type) = &self.content_type {
            writeln!(f, "content_type = {content_type}")?;
        }
        writeln!(f, "attributes = {:?}", self.attributes)?;
        Ok(())
    }
}

enum Keyring {
    File(oo7::file::UnlockedKeyring),
    Collection(oo7::dbus::Collection),
}

enum Output {
    None,
    SecretOnly(Vec<oo7::Secret>, bool), // secrets and hex flag
    Items(Vec<ItemOutput>, bool),       // items and json flag
}

#[derive(Subcommand)]
enum Commands {
    #[command(
        name = "delete",
        about = "Delete a secret",
        after_help = format!("Will delete all secrets with matching attributes.\n\n{H_STYLE}Example:{H_STYLE:#}\n  {} delete smtp-port=1025", BINARY_NAME)
    )]
    Delete {
        #[arg(
            help = "List of attributes. This is a space-separated list of pairs key=value",
            value_parser = parse_key_val::<String, String>,
            required = true, num_args = 1
        )]
        attributes: Vec<(String, String)>,
    },

    #[command(
        name = "lookup",
        about = "Retrieve a secret",
        after_help = format!("{H_STYLE}Examples:{H_STYLE:#}\n  {} lookup smtp-port=1025\n  {0} lookup --secret-only mysql-port=1234 | systemd-creds encrypt --name=mysql-password -p - -", BINARY_NAME)
    )]
    Lookup {
        #[arg(
            help = "List of attributes. This is a space-separated list of pairs key=value",
            value_parser = parse_key_val::<String, String>,
            required = true,
            num_args = 1
        )]
        attributes: Vec<(String, String)>,
        #[arg(long, help = "Print only the secret.")]
        secret_only: bool,
        #[arg(long, help = "Print the secret in hexadecimal.")]
        hex: bool,
        #[arg(long, help = "Format the output as json.")]
        json: bool,
    },

    #[command(
        name = "search",
        about = "Search entries with matching attributes",
        after_help = format!("{H_STYLE}Example:{H_STYLE:#}\n  {} search --all smtp-port=1025", BINARY_NAME)
    )]
    Search {
        #[arg(
            short,
            long,
            help = "Whether to list all possible matches or only the first result"
        )]
        all: bool,
        #[arg(
            help = "List of attributes. This is a space-separated list of pairs key=value",
            value_parser = parse_key_val::<String, String>
        )]
        attributes: Vec<(String, String)>,
        #[arg(long, help = "Print only the secret.")]
        secret_only: bool,
        #[arg(long, help = "Print the secret in hexadecimal.")]
        hex: bool,
        #[arg(long, help = "Format the output as json.")]
        json: bool,
    },

    #[command(
        name = "store",
        about = "Store a secret",
        after_help = format!("The contents of the secret will be asked afterwards or read from stdin.\n\n{H_STYLE}Examples:{H_STYLE:#}\n  {} store 'My Personal Mail' smtp-port=1025 imap-port=143\n  systemd-ask-password -n | {0} store 'My Secret' lang=en", BINARY_NAME)
    )]
    Store {
        #[arg(help = "Description for the secret")]
        label: String,
        #[arg(
            help = "List of attributes. This is a space-separated list of pairs key=value",
            value_parser = parse_key_val::<String, String>,
            required = true, num_args = 1
        )]
        attributes: Vec<(String, String)>,
    },

    #[command(name = "list", about = "List all the items in the keyring")]
    List {
        #[arg(long, help = "Print the secret in hexadecimal.")]
        hex: bool,
        #[arg(long, help = "Format the output as json.")]
        json: bool,
    },

    #[command(name = "lock", about = "Lock the keyring")]
    Lock,

    #[command(name = "unlock", about = "Unlock the keyring")]
    Unlock,

    #[command(name = "repair", about = "Repair the keyring")]
    Repair,
}

impl Commands {
    async fn execute(self, args: Arguments) -> Result<(), Error> {
        let service = Service::new().await?;
        if args.app_id.is_some() && args.keyring.is_some() {
            return Err(Error::new(
                "Only one of application ID or keyring can be specified at a time.",
            ));
        }
        // We get the secret first from the app-id, then if the --keyring is set, we try
        // to use the --secret variable.
        let (secret, path) = if let Some(app_id) = &args.app_id {
            let default_collection = service.default_collection().await?;
            let secret = if let Some(item) = default_collection
                .search_items(&[("app_id", app_id)])
                .await?
                .first()
            {
                item.secret().await?
            } else {
                return Err(Error::new(
                    "The application doesn't have a stored key on the host keyring.",
                ));
            };

            // That is the path used by libsecret/oo7, how does it work with kwallet for
            // example?
            let path = home().map(|mut path| {
                path.push(".var/app");
                path.push(app_id.to_string());
                path.push("data/keyrings/default.keyring");
                path
            });
            (Some(secret), path)
        } else if let Some(keyring) = args.keyring {
            (args.secret, Some(keyring))
        } else if let Some(secret) = args.secret {
            (
                Some(secret),
                data_dir().map(|mut path| {
                    path.push("keyrings/default.keyring");
                    path
                }),
            )
        } else {
            (None, None)
        };

        let keyring = match (path, secret) {
            (Some(path), Some(secret)) => unsafe {
                Keyring::File(oo7::file::UnlockedKeyring::load_unchecked(path, secret).await?)
            },
            (Some(_), None) => {
                return Err(Error::new("A keyring requires a secret."));
            }
            (None, Some(_)) => {
                return Err(Error::new("A secret requires a keyring."));
            }
            _ => {
                let collection = if let Some(alias) = &args.collection {
                    service
                        .with_alias(alias)
                        .await?
                        .ok_or_else(|| Error::Owned(format!("Collection '{alias}' not found")))?
                } else {
                    service.default_collection().await?
                };
                Keyring::Collection(collection)
            }
        };

        let output = match self {
            Commands::Delete { attributes } => {
                match keyring {
                    Keyring::Collection(collection) => {
                        let items = collection.search_items(&attributes).await?;
                        for item in items {
                            item.delete(None).await?;
                        }
                    }
                    Keyring::File(keyring) => {
                        keyring.delete(&attributes).await?;
                    }
                }
                Output::None
            }
            Commands::Lookup {
                attributes,
                secret_only,
                hex,
                json,
            } => match keyring {
                Keyring::Collection(collection) => {
                    let items = collection.search_items(&attributes).await?;
                    if let Some(item) = items.first() {
                        if secret_only {
                            Output::SecretOnly(vec![item.secret().await?], hex)
                        } else {
                            Output::Items(vec![ItemOutput::from_dbus_item(item, hex).await?], json)
                        }
                    } else {
                        Output::None
                    }
                }
                Keyring::File(keyring) => {
                    let items = keyring.search_items(&attributes).await?;
                    if let Some(item) = items.first() {
                        if secret_only {
                            Output::SecretOnly(vec![item.as_unlocked().secret().clone()], hex)
                        } else {
                            Output::Items(vec![ItemOutput::from_file_item(item, hex)], json)
                        }
                    } else {
                        Output::None
                    }
                }
            },
            Commands::Search {
                all,
                attributes,
                secret_only,
                hex,
                json,
            } => match keyring {
                Keyring::File(keyring) => {
                    let items = keyring.search_items(&attributes).await?;
                    let items_to_print: Vec<_> = if all {
                        items.iter().collect()
                    } else {
                        items.first().into_iter().collect()
                    };

                    if secret_only {
                        let secrets = items_to_print
                            .into_iter()
                            .map(|item| item.as_unlocked().secret().clone())
                            .collect();

                        Output::SecretOnly(secrets, hex)
                    } else {
                        let outputs = items_to_print
                            .into_iter()
                            .map(|item| ItemOutput::from_file_item(item, hex))
                            .collect();
                        Output::Items(outputs, json)
                    }
                }
                Keyring::Collection(collection) => {
                    let items = collection.search_items(&attributes).await?;
                    let items_to_print: Vec<_> = if all {
                        items.iter().collect()
                    } else {
                        items.first().into_iter().collect()
                    };

                    if secret_only {
                        let mut secrets = Vec::new();
                        for item in items_to_print {
                            secrets.push(item.secret().await?);
                        }

                        Output::SecretOnly(secrets, hex)
                    } else {
                        let mut outputs = Vec::new();
                        for item in items_to_print {
                            outputs.push(ItemOutput::from_dbus_item(item, hex).await?);
                        }
                        Output::Items(outputs, json)
                    }
                }
            },
            Commands::Store { label, attributes } => {
                let mut stdin = std::io::stdin().lock();
                let secret = if stdin.is_terminal() {
                    print!("Type a secret: ");
                    std::io::stdout()
                        .flush()
                        .map_err(|_| Error::new("Could not flush stdout"))?;
                    rpassword::read_password().map_err(|_| Error::new("Can't read password"))?
                } else {
                    let mut secret = String::new();
                    stdin.read_line(&mut secret)?;
                    secret
                };

                match keyring {
                    Keyring::File(keyring) => {
                        keyring
                            .create_item(&label, &attributes, secret, true)
                            .await?;
                    }
                    Keyring::Collection(collection) => {
                        collection
                            .create_item(&label, &attributes, secret, true, None)
                            .await?;
                    }
                }
                Output::None
            }
            Commands::List { hex, json } => {
                let items = match keyring {
                    Keyring::File(keyring) => {
                        let items = keyring.items().await?;
                        let mut outputs = Vec::new();
                        for item in items {
                            if let Ok(item) = item {
                                outputs.push(ItemOutput::from_file_item(&item, hex));
                            } else if !json {
                                // Only print error message in text mode, skip in JSON mode
                                println!("Item is not valid and cannot be decrypted");
                            }
                        }
                        outputs
                    }
                    Keyring::Collection(collection) => {
                        let items = collection.items().await?;
                        let mut outputs = Vec::new();
                        for item in items {
                            outputs.push(ItemOutput::from_dbus_item(&item, hex).await?);
                        }
                        outputs
                    }
                };
                Output::Items(items, json)
            }
            Commands::Lock => {
                match keyring {
                    Keyring::File(_) => {
                        return Err(Error::new("Keyring file doesn't support locking."));
                    }
                    Keyring::Collection(collection) => {
                        collection.lock(None).await?;
                    }
                }
                Output::None
            }
            Commands::Unlock => {
                match keyring {
                    Keyring::File(_) => {
                        return Err(Error::new("Keyring file doesn't support unlocking."));
                    }
                    Keyring::Collection(collection) => {
                        collection.unlock(None).await?;
                    }
                }
                Output::None
            }
            Commands::Repair => {
                match keyring {
                    Keyring::File(keyring) => {
                        let deleted_items = keyring.delete_broken_items().await?;
                        println!("{deleted_items} broken items were deleted");
                    }
                    Keyring::Collection(_) => {
                        return Err(Error::new("Only a keyring file can be repaired."));
                    }
                }
                Output::None
            }
        };

        // Unified output printing
        match output {
            Output::None => {}
            Output::SecretOnly(secrets, hex) => {
                for secret in secrets {
                    print_secret_only(&secret, hex)?;
                }
            }
            Output::Items(items, json) => {
                if json {
                    println!("{}", serde_json::to_string_pretty(&items).unwrap());
                } else {
                    for item in items {
                        print!("{}", item);
                    }
                }
            }
        }

        Ok(())
    }
}

#[derive(Parser)]
#[clap(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[command(flatten)]
    args: Arguments,
}

#[derive(Args)]
struct Arguments {
    #[arg(
        name = "collection",
        short,
        long,
        global = true,
        help = "Specify a collection. The default collection will be used if not specified"
    )]
    collection: Option<String>,
    #[arg(
        name = "keyring",
        short,
        long,
        global = true,
        help = "Specify a keyring. The default collection will be used if not specified"
    )]
    keyring: Option<PathBuf>,
    #[arg(
        name = "secret",
        short,
        long,
        global = true,
        help = "Specify the keyring secret. The default collection will be used if not specified"
    )]
    secret: Option<oo7::Secret>,
    #[arg(
        name = "app-id",
        long,
        global = true,
        help = "Specify a sandboxed application ID. The default collection will be used if not specified"
    )]
    app_id: Option<oo7::ashpd::AppID>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    cli.command.execute(cli.args).await
}

// Source <https://github.com/clap-rs/clap/blob/master/examples/typed-derive.rs#L48>
fn parse_key_val<T, U>(
    s: &str,
) -> Result<(T, U), Box<dyn std::error::Error + Send + Sync + 'static>>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
    U: std::str::FromStr,
    U::Err: std::error::Error + Send + Sync + 'static,
{
    let pos = s
        .find('=')
        .ok_or_else(|| format!("Invalid KEY=value: no `=` found in `{s}`"))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
}

fn print_secret_only(secret: &oo7::Secret, as_hex: bool) -> Result<(), Error> {
    let bytes = secret.as_bytes();
    let mut stdout = std::io::stdout().lock();
    if as_hex {
        let hex = hex::encode(bytes);
        stdout.write_all(hex.as_bytes())?;
    } else {
        stdout.write_all(bytes)?;
    }
    // Add a new line if we are writing to a tty
    if stdout.is_terminal() {
        stdout.write_all(b"\n")?;
    }
    Ok(())
}

// Copy from /client/src/file/api/mod.rs
fn data_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_DATA_HOME")
        .and_then(|h| if h.is_empty() { None } else { Some(h) })
        .map(PathBuf::from)
        .and_then(|p| if p.is_absolute() { Some(p) } else { None })
        .or_else(|| home().map(|p| p.join(".local/share")))
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .and_then(|h| if h.is_empty() { None } else { Some(h) })
        .map(PathBuf::from)
}
