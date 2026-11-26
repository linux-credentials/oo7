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

// The stale session machinery: a disconnected client's session is marked,
// ignored while in use, and closed once it outlives the timeout
#[tokio::test]
async fn stale_session_state() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(false).await?;

    let path = setup.session.inner().path().to_owned();
    let session = setup
        .server
        .session(&path)
        .await
        .expect("session should exist");

    assert!(!session.is_stale().await, "A live session is not stale");

    // The client disconnected, but not long enough ago
    session.mark_stale().await;
    assert!(session.is_marked_stale().await);
    assert!(!session.is_stale().await, "The timeout did not pass yet");

    // Using the session rescues it
    setup.server.session(&path).await;
    assert!(!session.is_marked_stale().await);
    assert!(!session.is_stale().await);

    Ok(())
}

#[tokio::test]
async fn stale_session_cleaned_up() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(false).await?;

    let path = setup.session.inner().path().to_owned();
    let session = setup
        .server
        .session(&path)
        .await
        .expect("session should exist");
    session.force_stale().await;
    assert!(session.is_stale().await);

    setup.server.cleanup_stale_sessions_tick().await;

    assert!(
        setup.server.session(&path).await.is_none(),
        "The stale session should be closed"
    );

    Ok(())
}

#[tokio::test]
async fn owner_lost_marks_session_stale() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(false).await?;

    let path = setup.session.inner().path().to_owned();
    let session = setup
        .server
        .session(&path)
        .await
        .expect("session should exist");
    let sender = session.sender().to_owned();

    // A well-known name being released doesn't mean the client left
    setup
        .server
        .handle_owner_lost("org.example.Client", &sender)
        .await;
    assert!(!session.is_marked_stale().await);

    // The client's unique name disappearing does
    setup
        .server
        .handle_owner_lost(sender.as_str(), &sender)
        .await;
    assert!(session.is_marked_stale().await);

    // An unknown client is not an error
    let stranger = zbus::names::UniqueName::from_str_unchecked(":1.42");
    setup.server.handle_owner_lost(":1.42", &stranger).await;

    Ok(())
}

// A client may open several sessions on one connection, e.g. libsecret
// clients that open one per item they read. All of them go when it leaves.
#[tokio::test]
async fn owner_lost_marks_all_its_sessions_stale() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(false).await?;

    let (_, second) = setup.service_api.open_session(None).await?;
    let mut sessions = Vec::new();
    for path in [setup.session.inner().path(), second.inner().path()] {
        let path = path.to_owned();
        sessions.push(
            setup
                .server
                .session(&path)
                .await
                .expect("session should exist"),
        );
    }
    let sender = sessions[0].sender().to_owned();
    assert_eq!(sessions[1].sender(), &sender);

    setup
        .server
        .handle_owner_lost(sender.as_str(), &sender)
        .await;
    for session in &sessions {
        assert!(
            session.is_marked_stale().await,
            "{} should be marked stale",
            session.path()
        );
    }

    Ok(())
}
