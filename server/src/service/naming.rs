use std::collections::HashMap;

use zbus::wire::OwnedObjectPath;

use crate::collection::Collection;

pub(crate) async fn has_alias(
    collections: &HashMap<OwnedObjectPath, Collection>,
    alias: &str,
) -> bool {
    if alias.is_empty() {
        return false;
    }
    for collection in collections.values() {
        if collection.alias().await == alias {
            return true;
        }
    }
    false
}

pub(crate) async fn make_unique_label_and_alias(
    collections: &HashMap<OwnedObjectPath, Collection>,
    label: &str,
    alias: &str,
) -> (String, String) {
    let base_path = crate::collection::collection_path(label)
        .expect("Sanitized label should always produce valid object path");
    if !collections.contains_key(&base_path) && !has_alias(collections, alias).await {
        return (label.to_owned(), alias.to_owned());
    }

    let mut counter = 2;
    loop {
        let new_label = format!("{label}{counter}");
        let path = crate::collection::collection_path(&new_label)
            .expect("Sanitized label should always produce valid object path");
        let new_alias = format!("{alias}{counter}");

        if !collections.contains_key(&path) && !has_alias(collections, &new_alias).await {
            return (new_label, new_alias);
        }
        counter += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::TestServiceSetup;

    #[tokio::test]
    async fn has_alias_empty_is_false() {
        let collections = HashMap::new();
        assert!(!has_alias(&collections, "").await);
    }

    #[tokio::test]
    async fn has_alias_empty_collections() {
        let collections = HashMap::new();
        assert!(!has_alias(&collections, "default").await);
    }

    #[tokio::test]
    async fn unique_when_no_collections() {
        let collections = HashMap::new();
        let (label, alias) = make_unique_label_and_alias(&collections, "Work", "work").await;
        assert_eq!(label, "Work");
        assert_eq!(alias, "work");
    }

    #[tokio::test]
    async fn has_alias_finds_match() {
        let setup = TestServiceSetup::plain_session(true).await.unwrap();
        let collections = setup.server.collections.lock().await;
        assert!(has_alias(&collections, "default").await);
        assert!(!has_alias(&collections, "nonexistent").await);
    }

    #[tokio::test]
    async fn appends_counter_on_alias_conflict() {
        let setup = TestServiceSetup::plain_session(true).await.unwrap();
        let collections = setup.server.collections.lock().await;

        let (label, alias) = make_unique_label_and_alias(&collections, "Fresh", "default").await;
        assert_eq!(label, "Fresh2");
        assert_eq!(alias, "default2");
    }

    #[tokio::test]
    async fn appends_counter_on_path_conflict() {
        let setup = TestServiceSetup::plain_session(true).await.unwrap();
        let collections = setup.server.collections.lock().await;

        let (label, alias) = make_unique_label_and_alias(&collections, "Login", "fresh").await;
        assert_eq!(label, "Login2");
        assert_eq!(alias, "fresh2");
    }
}
