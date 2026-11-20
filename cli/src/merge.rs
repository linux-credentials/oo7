//! The `merge` command: combine the items of two keyrings or collections.

use std::{
    collections::HashMap,
    io::{IsTerminal as _, Write as _},
};

use oo7::dbus::Service;

use crate::{CliPrompter, Error, resolve_secret};

/// What to do with an item that exists on both sides of a merge
#[derive(Clone, Copy, clap::ValueEnum)]
pub(crate) enum OnConflict {
    /// Replace the destination item with the origin one
    Override,
    /// Keep the destination item
    Skip,
}

/// A side of a merge, either a keyring file or a collection of the
/// running service
enum MergeSource {
    File(oo7::file::UnlockedKeyring),
    Collection(oo7::dbus::Collection),
}

/// The parts of an item needed for a merge
struct MergeItem {
    label: String,
    attributes: HashMap<String, String>,
    secret: oo7::Secret,
}

/// The user's answer to a conflicting item
enum ConflictChoice {
    Override,
    Skip,
    OverrideAll,
    Quit,
}

pub(crate) async fn run(
    origin: &str,
    destination: &str,
    origin_secret: Option<String>,
    destination_secret: Option<String>,
    on_conflict: Option<OnConflict>,
) -> Result<(), Error> {
    let needs_service =
        !std::path::Path::new(origin).is_file() || !std::path::Path::new(destination).is_file();
    let service = if needs_service {
        Some(Service::new().await?)
    } else {
        None
    };
    // Register the prompter so the daemon can ask for collection
    // secrets
    let prompter_conn = if needs_service {
        let conn = zbus::Connection::session().await?;
        conn.object_server()
            .at("/org/freedesktop/secrets/CliPrompter", CliPrompter)
            .await?;
        conn.request_name("org.freedesktop.secrets.CliPrompter")
            .await?;
        Some(conn)
    } else {
        None
    };

    let origin = merge_source(origin, origin_secret, service.as_ref()).await?;
    let destination = merge_source(destination, destination_secret, service.as_ref()).await?;

    // A locked collection can't be read from or written to, unlock it
    // through the daemon, which prompts for its secret
    for source in [&origin, &destination] {
        if let MergeSource::Collection(collection) = source
            && collection.is_locked().await?
        {
            let raw_service = oo7::dbus::api::Service::new(prompter_conn.as_ref().unwrap()).await?;
            raw_service
                .unlock(&[collection.path().to_owned()], None)
                .await?;
        }
    }

    let origin_items = origin.items().await?;
    let destination_items = destination.items().await?;
    let mut created = 0;
    let mut overridden = 0;
    let mut skipped = 0;
    let mut identical = 0;
    let mut conflict_action = on_conflict;

    'items: for item in &origin_items {
        let Some(conflict) = find_conflict(&destination_items, item) else {
            destination.create_item(item, false).await?;
            created += 1;
            continue;
        };

        if conflict.secret == item.secret && conflict.label == item.label {
            identical += 1;
            continue;
        }

        let choice = match conflict_action {
            Some(OnConflict::Override) => ConflictChoice::Override,
            Some(OnConflict::Skip) => ConflictChoice::Skip,
            None => prompt_conflict(item, conflict)?,
        };
        match choice {
            ConflictChoice::Override => {
                destination.create_item(item, true).await?;
                overridden += 1;
            }
            ConflictChoice::Skip => skipped += 1,
            ConflictChoice::OverrideAll => {
                conflict_action = Some(OnConflict::Override);
                destination.create_item(item, true).await?;
                overridden += 1;
            }
            ConflictChoice::Quit => {
                println!("Quitting, keeping the items merged so far.");
                break 'items;
            }
        }
    }

    if let MergeSource::File(keyring) = &destination {
        keyring.write().await?;
    }

    println!(
        "Merged {created} new item(s), overrode {overridden}, skipped {skipped}, {identical} already identical."
    );

    Ok(())
}

async fn merge_source(
    spec: &str,
    secret: Option<String>,
    service: Option<&Service>,
) -> Result<MergeSource, Error> {
    let path = std::path::Path::new(spec);
    if path.is_file() {
        let secret = match resolve_secret(secret)? {
            Some(secret) => Some(secret),
            None if std::io::stdin().is_terminal() => {
                let password = rpassword::prompt_password(format!("'{spec}' secret: "))
                    .map_err(|_| Error::new("Can't read secret"))?;
                Some(password.into())
            }
            None => None,
        };
        // Same loading semantics as the other keyring file commands
        #[allow(unsafe_code)]
        let keyring = unsafe {
            match secret {
                Some(secret) => oo7::file::UnlockedKeyring::load_unchecked(path, secret).await?,
                None => oo7::file::UnlockedKeyring::load(path, None).await?,
            }
        };
        Ok(MergeSource::File(keyring))
    } else {
        let service = service.ok_or_else(|| Error::new("No service"))?;
        let collection = match service.with_alias(spec).await? {
            Some(collection) => collection,
            // Not an alias, look the collection up by name or label
            None => {
                let mut found = None;
                for collection in service.collections().await? {
                    if collection.path().rsplit('/').next() == Some(spec)
                        || collection
                            .label()
                            .await
                            .is_ok_and(|label| label.eq_ignore_ascii_case(spec))
                    {
                        found = Some(collection);
                        break;
                    }
                }
                found.ok_or_else(|| {
                    Error::Owned(format!(
                        "'{spec}' is neither a keyring file nor a collection"
                    ))
                })?
            }
        };
        Ok(MergeSource::Collection(collection))
    }
}

impl MergeSource {
    async fn items(&self) -> Result<Vec<MergeItem>, Error> {
        match self {
            Self::File(keyring) => Ok(keyring
                .items()
                .await?
                .into_iter()
                .map(|item| MergeItem {
                    label: item.label().to_owned(),
                    attributes: item.attributes().clone(),
                    secret: item.secret(),
                })
                .collect()),
            Self::Collection(collection) => {
                let mut items = Vec::new();
                for item in collection.items().await? {
                    items.push(MergeItem {
                        label: item.label().await?,
                        attributes: item.attributes().await?,
                        secret: item.secret().await?,
                    });
                }
                Ok(items)
            }
        }
    }

    async fn create_item(&self, item: &MergeItem, replace: bool) -> Result<(), Error> {
        match self {
            Self::File(keyring) => {
                keyring
                    .create_item(&item.label, &item.attributes, item.secret.clone(), replace)
                    .await?;
            }
            Self::Collection(collection) => {
                collection
                    .create_item(
                        &item.label,
                        &item.attributes,
                        item.secret.clone(),
                        replace,
                        None,
                    )
                    .await?;
            }
        }
        Ok(())
    }
}

/// The destination item an origin item would replace, if any
fn find_conflict<'a>(destination: &'a [MergeItem], origin: &MergeItem) -> Option<&'a MergeItem> {
    destination.iter().find(|dest| {
        origin.attributes.iter().all(|(key, value)| {
            dest.attributes.get(key).map(String::as_str) == Some(value.as_str())
        })
    })
}

fn prompt_conflict(origin: &MergeItem, destination: &MergeItem) -> Result<ConflictChoice, Error> {
    print_conflict(origin, destination);

    if !std::io::stdin().is_terminal() {
        println!("Not a terminal, skipping the item. Use --on-conflict to decide.");
        return Ok(ConflictChoice::Skip);
    }

    loop {
        print!("[o]verride, [s]kip, override [a]ll, [q]uit: ");
        std::io::stdout()
            .flush()
            .map_err(|_| Error::new("Could not flush stdout"))?;
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(|_| Error::new("Can't read the answer"))?;
        match answer.trim().to_lowercase().as_str() {
            "o" | "override" => return Ok(ConflictChoice::Override),
            "s" | "skip" => return Ok(ConflictChoice::Skip),
            "a" | "all" => return Ok(ConflictChoice::OverrideAll),
            "q" | "quit" => return Ok(ConflictChoice::Quit),
            "" => {
                println!("No answer, skipping the item.");
                return Ok(ConflictChoice::Skip);
            }
            _ => println!("Please answer o, s, a or q."),
        }
    }
}

fn print_conflict(origin: &MergeItem, destination: &MergeItem) {
    let minus = anstyle::AnsiColor::Red.on_default();
    let plus = anstyle::AnsiColor::Green.on_default();

    println!("Item \"{}\"", origin.label);
    let mut keys: Vec<String> = origin.attributes.keys().cloned().collect();
    keys.sort();
    for key in &keys {
        if destination.attributes.get(key) == origin.attributes.get(key) {
            println!("  {key} = {}", origin.attributes[key]);
        }
    }
    if origin.label != destination.label {
        println!(
            "{}-{} destination label: {}",
            minus.render(),
            minus.render_reset(),
            destination.label
        );
        println!(
            "{}+{} origin label: {}",
            plus.render(),
            plus.render_reset(),
            origin.label
        );
    }
    for key in &keys {
        if destination.attributes.get(key) != origin.attributes.get(key) {
            println!(
                "{}-{} destination {key} = {}",
                minus.render(),
                minus.render_reset(),
                destination
                    .attributes
                    .get(key)
                    .map(String::as_str)
                    .unwrap_or("")
            );
            println!(
                "{}+{} origin {key} = {}",
                plus.render(),
                plus.render_reset(),
                origin.attributes[key]
            );
        }
    }
    println!(
        "{}-{} destination secret: {}",
        minus.render(),
        minus.render_reset(),
        String::from_utf8_lossy(destination.secret.as_bytes())
    );
    println!(
        "{}+{} origin secret: {}",
        plus.render(),
        plus.render_reset(),
        String::from_utf8_lossy(origin.secret.as_bytes())
    );
}
