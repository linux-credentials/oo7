use oo7::{Secret, XDG_SCHEMA_ATTRIBUTE, file::*};

fn strong_key() -> Secret {
    Secret::from([1, 2].into_iter().cycle().take(64).collect::<Vec<_>>())
}

async fn check_items(keyring: &UnlockedKeyring) -> Result<(), Error> {
    assert_eq!(keyring.n_items().await, 1);
    let items = keyring.items().await?;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].label(), "foo");
    assert_eq!(items[0].secret(), Secret::blob("foo"));
    let attributes = items[0].attributes();
    assert_eq!(attributes.len(), 2);
    assert_eq!(
        attributes.get(XDG_SCHEMA_ATTRIBUTE).map(|v| v.as_ref()),
        Some("org.gnome.keyring.Note")
    );

    Ok(())
}

mod errors;
mod items;
mod lifecycle;
mod migration;
mod persistence;
