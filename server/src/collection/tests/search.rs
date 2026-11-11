use crate::tests::TestServiceSetup;

#[tokio::test]
async fn search_items_after_creation() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Create two items with different attributes
    setup
        .create_item(
            "Firefox Password",
            &[("application", "firefox"), ("username", "user1")],
            "password1",
            false,
        )
        .await?;

    setup
        .create_item(
            "Chrome Password",
            &[("application", "chrome"), ("username", "user2")],
            "password2",
            false,
        )
        .await?;

    // Search for firefox item
    let firefox_attrs = &[("application", "firefox")];
    let firefox_items = setup.collections[0].search_items(firefox_attrs).await?;

    assert_eq!(firefox_items.len(), 1, "Should find one firefox item");

    // Search for chrome item
    let chrome_items = setup.collections[0]
        .search_items(&[("application", "chrome")])
        .await?;

    assert_eq!(chrome_items.len(), 1, "Should find one chrome item");

    // Search for non-existent item
    let nonexistent_items = setup.collections[0]
        .search_items(&[("application", "nonexistent")])
        .await?;

    assert_eq!(
        nonexistent_items.len(),
        0,
        "Should find no nonexistent items"
    );

    Ok(())
}

#[tokio::test]
async fn search_items_subset_matching() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Create an item with multiple attributes (url and username)
    setup
        .create_item(
            "Zed Login",
            &[("url", "https://zed.dev"), ("username", "alice")],
            "my-password",
            false,
        )
        .await?;

    // Search with only the url attribute (subset of stored attributes)
    let results = setup.collections[0]
        .search_items(&[("url", "https://zed.dev")])
        .await?;

    assert_eq!(
        results.len(),
        1,
        "Should find item when searching with subset of its attributes"
    );

    // Search with only the username attribute (another subset)
    let results = setup.collections[0]
        .search_items(&[("username", "alice")])
        .await?;

    assert_eq!(
        results.len(),
        1,
        "Should find item when searching with different subset of its attributes"
    );

    // Search with both attributes (exact match)
    let results = setup.collections[0]
        .search_items(&[("url", "https://zed.dev"), ("username", "alice")])
        .await?;

    assert_eq!(
        results.len(),
        1,
        "Should find item when searching with all its attributes"
    );

    // Search with superset of attributes (should not match)
    let results = setup.collections[0]
        .search_items(&[
            ("url", "https://zed.dev"),
            ("username", "alice"),
            ("extra", "attribute"),
        ])
        .await?;

    assert_eq!(
        results.len(),
        0,
        "Should not find item when searching with superset of its attributes"
    );

    Ok(())
}
