use crate::tests::TestServiceSetup;

#[tokio::test]
async fn open_session_plain() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    assert!(
        setup.aes_key.is_none(),
        "Plain session should not have AES key"
    );

    // Should have 2 collections: default + session
    assert_eq!(
        setup.collections.len(),
        2,
        "Expected default and session collections"
    );
    Ok(())
}

#[tokio::test]
async fn open_session_encrypted() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::encrypted_session(false).await?;
    assert!(
        setup.server_public_key.is_some(),
        "Encrypted session should have server public key"
    );
    let key = setup.aes_key.as_deref().unwrap();
    assert_eq!(key.as_ref().len(), 16, "AES key should be 16 bytes");
    Ok(())
}

#[tokio::test]
async fn session_collection_only() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(false).await?;

    // Should have only session collection (no default)
    assert_eq!(
        setup.collections.len(),
        1,
        "Should have exactly one collection"
    );
    Ok(())
}
