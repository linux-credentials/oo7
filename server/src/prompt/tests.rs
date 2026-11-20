use crate::tests::TestServiceSetup;

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
#[tokio::test]
async fn prompt_not_found_error() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;

    // Lock the collection to create a prompt scenario
    setup.lock_collection(&setup.collections[0]).await?;

    // Create a prompt using server API
    let (_unlocked, prompt_path) = setup
        .server
        .unlock(vec![setup.collections[0].inner().path().to_owned().into()])
        .await?;

    assert!(!prompt_path.is_empty(), "Should have a prompt path");

    // Remove the prompt from the service before MockPrompter tries to process
    // it
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
            zbus::wire::Optional::from(None),
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
    setup.lock_collection(&setup.collections[0]).await?;

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

/// Mock of the terminal prompter the CLI registers
#[derive(Clone, Default)]
struct MockCliPrompter {
    password: Arc<tokio::sync::Mutex<Option<oo7::Secret>>>,
    accept: Arc<tokio::sync::Mutex<bool>>,
    /// Passwords handed out one per prompt, for retry testing
    password_queue: Arc<tokio::sync::Mutex<Vec<oo7::Secret>>>,
}

#[zbus::interface(name = "org.freedesktop.secrets.CliPrompter")]
impl MockCliPrompter {
    async fn prompt(
        &self,
        _label: &str,
        _description: &str,
    ) -> zbus::fdo::Result<(zbus::wire::OwnedFd, bool)> {
        if !*self.accept.lock().await {
            let (read_end, _) = std::os::unix::net::UnixStream::pair()
                .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
            return Ok((
                zbus::wire::OwnedFd::from(std::os::fd::OwnedFd::from(read_end)),
                false,
            ));
        }

        let password = self
            .password
            .lock()
            .await
            .clone()
            .unwrap_or_else(|| oo7::Secret::from(""));
        let queued = {
            let mut queue = self.password_queue.lock().await;
            if queue.is_empty() {
                None
            } else {
                Some(queue.remove(0))
            }
        };
        let password = queued.unwrap_or(password);
        let (read_end, mut write_end) = std::os::unix::net::UnixStream::pair()
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        write_end
            .write_all(password.as_bytes())
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        drop(write_end);
        Ok((
            zbus::wire::OwnedFd::from(std::os::fd::OwnedFd::from(read_end)),
            true,
        ))
    }
}

use std::{io::Write as _, sync::Arc};

#[tokio::test]
async fn unlock_with_cli_prompter() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    setup
        .server
        .set_prompter_type(crate::service::PrompterType::Cli)
        .await;

    let mock = MockCliPrompter::default();
    *mock.password.lock().await = setup.keyring_secret.clone();
    *mock.accept.lock().await = true;
    setup
        .client_conn
        .object_server()
        .at("/org/freedesktop/secrets/CliPrompter", mock)
        .await?;

    setup.lock_collection(&setup.collections[0]).await?;
    assert!(setup.collections[0].is_locked().await?);

    let unlocked = setup
        .service_api
        .unlock(&[setup.collections[0].inner().path()], None)
        .await?;
    assert_eq!(unlocked.len(), 1);
    assert!(!setup.collections[0].is_locked().await?);

    Ok(())
}

#[tokio::test]
async fn unlock_with_cli_prompter_dismissed() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    setup
        .server
        .set_prompter_type(crate::service::PrompterType::Cli)
        .await;

    let mock = MockCliPrompter::default();
    *mock.accept.lock().await = false;
    setup
        .client_conn
        .object_server()
        .at("/org/freedesktop/secrets/CliPrompter", mock)
        .await?;

    setup.lock_collection(&setup.collections[0]).await?;

    let result = setup
        .service_api
        .unlock(&[setup.collections[0].inner().path()], None)
        .await;
    assert!(result.is_err(), "A dismissed prompt should fail the unlock");
    assert!(
        setup.collections[0].is_locked().await?,
        "Collection should remain locked"
    );

    Ok(())
}

#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
#[tokio::test]
async fn dismiss_prompt_cleanup_plasma() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    setup
        .server
        .set_prompter_type(crate::service::PrompterType::Plasma)
        .await;

    setup.lock_collection(&setup.collections[0]).await?;

    let (_unlocked, prompt_path) = setup
        .server
        .unlock(vec![setup.collections[0].inner().path().to_owned().into()])
        .await?;
    assert!(!prompt_path.is_empty(), "Should have a prompt path");

    // Dismissing the prompt tells the plasma prompter to close its
    // dialog and drops the prompt
    let prompt = oo7::dbus::api::Prompt::new(&setup.client_conn, prompt_path.clone())
        .await?
        .expect("prompt should be accessible");
    prompt.dismiss().await?;

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert!(
        setup.server.prompt(&prompt_path).await.is_none(),
        "Prompt should be removed from service after dismissal"
    );

    Ok(())
}

#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
#[tokio::test]
async fn plasma_prompter_callback_dismissed() -> Result<(), Box<dyn std::error::Error>> {
    use crate::plasma::prompter::PlasmaPrompterCallback;

    let setup = TestServiceSetup::plain_session(true).await?;

    setup.lock_collection(&setup.collections[0]).await?;

    let (_unlocked, prompt_path) = setup
        .server
        .unlock(vec![setup.collections[0].inner().path().to_owned().into()])
        .await?;
    assert!(!prompt_path.is_empty(), "Should have a prompt path");
    assert!(setup.server.prompt(&prompt_path).await.is_some());

    // Serve a callback like the plasma prompter would see one
    let callback = PlasmaPrompterCallback::new(setup.server.clone(), prompt_path.clone()).await;
    let callback_path: zbus::wire::OwnedObjectPath = callback.path().to_owned().into();
    setup
        .server
        .object_server()
        .at(&callback_path, callback)
        .await?;

    // The prompter dismissing its dialog drops the prompt and the callback
    setup
        .client_conn
        .call_method(
            None::<()>,
            &callback_path,
            Some("org.kde.secretprompter.request"),
            "Dismissed",
            &(),
        )
        .await?;

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert!(
        setup.server.prompt(&prompt_path).await.is_none(),
        "Prompt should be removed from service"
    );
    assert!(
        setup
            .server
            .object_server()
            .interface::<_, PlasmaPrompterCallback>(&callback_path)
            .await
            .is_err(),
        "Callback should be removed from the object server"
    );

    Ok(())
}

#[tokio::test]
async fn unlock_with_cli_prompter_retry() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    setup
        .server
        .set_prompter_type(crate::service::PrompterType::Cli)
        .await;

    let mock = MockCliPrompter::default();
    *mock.accept.lock().await = true;
    *mock.password_queue.lock().await = vec![
        oo7::Secret::from("wrong-password"),
        setup.keyring_secret.clone().unwrap(),
    ];
    setup
        .client_conn
        .object_server()
        .at("/org/freedesktop/secrets/CliPrompter", mock)
        .await?;

    // An item makes the keyring validate the secret
    setup
        .create_item(
            "Test Item",
            &[("app", "cli-prompter")],
            "item-secret",
            false,
        )
        .await?;
    setup.lock_collection(&setup.collections[0]).await?;

    let unlocked = setup
        .service_api
        .unlock(&[setup.collections[0].inner().path()], None)
        .await?;
    assert_eq!(unlocked.len(), 1, "Should unlock after the retry");
    assert!(!setup.collections[0].is_locked().await?);

    Ok(())
}

#[tokio::test]
async fn unlock_with_cli_prompter_max_attempts() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    setup
        .server
        .set_prompter_type(crate::service::PrompterType::Cli)
        .await;

    let mock = MockCliPrompter::default();
    *mock.accept.lock().await = true;
    *mock.password_queue.lock().await =
        vec![oo7::Secret::from("wrong-password"); crate::prompt::MAX_UNLOCK_ATTEMPTS as usize];
    setup
        .client_conn
        .object_server()
        .at("/org/freedesktop/secrets/CliPrompter", mock)
        .await?;

    // An item makes the keyring validate the secret
    setup
        .create_item(
            "Test Item",
            &[("app", "cli-prompter")],
            "item-secret",
            false,
        )
        .await?;
    setup.lock_collection(&setup.collections[0]).await?;

    let result = setup
        .service_api
        .unlock(&[setup.collections[0].inner().path()], None)
        .await;
    assert!(
        matches!(result, Err(oo7::dbus::Error::Dismissed)),
        "Expected Dismissed after max attempts, got: {result:?}"
    );
    assert!(
        setup.collections[0].is_locked().await?,
        "Collection should remain locked"
    );

    Ok(())
}
