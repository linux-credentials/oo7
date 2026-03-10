use crate::tests::{TestServiceSetup, gnome_prompter_test, plasma_prompter_test};

gnome_prompter_test!(prompt_called_twice_error_gnome, prompt_called_twice_error);
plasma_prompter_test!(prompt_called_twice_error_plasma, prompt_called_twice_error);

async fn prompt_called_twice_error() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Lock the collection to create a prompt scenario
    let collection = setup
        .server
        .collection_from_path(setup.collections[0].inner().path())
        .await
        .expect("Collection should exist");
    collection
        .set_locked(true, setup.keyring_secret.clone())
        .await?;

    // Get a prompt path by calling unlock (which creates a prompt but doesn't
    // auto-trigger it)
    let (_unlocked, prompt_path) = setup
        .server
        .unlock(vec![setup.collections[0].inner().path().to_owned().into()])
        .await?;

    // Verify we got a prompt path
    assert!(!prompt_path.is_empty(), "Should have a prompt path");

    // Create a Prompt proxy manually
    let prompt = oo7::dbus::api::Prompt::new(&setup.client_conn, prompt_path.clone())
        .await?
        .unwrap();

    // First call to prompt() should succeed
    prompt.prompt(None).await?;

    // Give the prompt a moment to register the callback
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Second call to prompt() should fail with "callback is ongoing already" error
    assert!(
        prompt.prompt(None).await.is_err(),
        "Second call to prompt() should fail"
    );
    Ok(())
}

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[tokio::test]
async fn prompt_not_found_error() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Lock the collection to create a prompt scenario
    let collection = setup
        .server
        .collection_from_path(setup.collections[0].inner().path())
        .await
        .expect("Collection should exist");
    collection
        .set_locked(true, setup.keyring_secret.clone())
        .await?;

    // Create a prompt using server API
    let (_unlocked, prompt_path) = setup
        .server
        .unlock(vec![setup.collections[0].inner().path().to_owned().into()])
        .await?;

    assert!(!prompt_path.is_empty(), "Should have a prompt path");

    // Remove the prompt from the service before MockPrompter tries to process it
    setup.server.remove_prompt(&prompt_path).await;

    // Manually serve a callback to trigger the error path
    let callback = crate::gnome::prompter::GNOMEPrompterCallback::new(
        None,
        setup.server.clone(),
        prompt_path.clone(),
    )
    .await?;

    let callback_path = super::OwnedObjectPath::from(callback.path().clone());
    setup
        .server
        .object_server()
        .at(&callback_path, callback.clone())
        .await?;

    // Now call prompt_ready which should fail because the prompt doesn't exist
    let result = callback
        .prompt_ready(
            zbus::zvariant::Optional::from(None),
            crate::gnome::prompter::Properties::default(),
            "",
        )
        .await;

    assert!(result.is_err(), "Should fail when prompt doesn't exist");

    // Verify it's the specific error we expect
    assert!(
        matches!(result, Err(oo7::dbus::ServiceError::NoSuchObject(_))),
        "Should be NoSuchObject error"
    );

    Ok(())
}

#[tokio::test]
async fn dismiss_prompt_cleanup() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Lock the collection to create a prompt scenario
    let collection = setup
        .server
        .collection_from_path(setup.collections[0].inner().path())
        .await
        .expect("Collection should exist");
    collection
        .set_locked(true, setup.keyring_secret.clone())
        .await?;

    // Get a prompt path by calling unlock
    let (_unlocked, prompt_path) = setup
        .server
        .unlock(vec![setup.collections[0].inner().path().to_owned().into()])
        .await?;

    assert!(!prompt_path.is_empty(), "Should have a prompt path");

    // Verify prompt exists in service before dismissal
    let prompt_exists_before = setup.server.prompt(&prompt_path).await;
    assert!(
        prompt_exists_before.is_some(),
        "Prompt should exist in service before dismissal"
    );

    // Verify prompt is accessible via D-Bus
    let prompt = oo7::dbus::api::Prompt::new(&setup.client_conn, prompt_path.clone()).await?;
    assert!(
        prompt.is_some(),
        "Prompt should be accessible via D-Bus before dismissal"
    );

    // Dismiss the prompt
    prompt.unwrap().dismiss().await?;

    // Give it a moment to process the dismissal
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Verify prompt is removed from service
    let prompt_exists_after = setup.server.prompt(&prompt_path).await;
    assert!(
        prompt_exists_after.is_none(),
        "Prompt should be removed from service after dismissal"
    );

    Ok(())
}
