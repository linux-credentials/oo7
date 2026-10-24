use std::{
    error::Error,
    fs,
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{fs::PermissionsExt, net::UnixListener},
    },
    time::Duration,
};

use super::{
    common::{Artifacts, Caller, Fixture, WAIT, current_username},
    protocol::{PamMessage, PamResponse},
};

type TestResult = Result<(), Box<dyn Error>>;

fn read_exact(
    caller: &Caller,
    stream: &mut std::os::unix::net::UnixStream,
    size: usize,
) -> io::Result<Vec<u8>> {
    let mut data = vec![0; size];
    let mut offset = 0;
    while offset < size {
        caller.assert_pending(stream.as_raw_fd(), WAIT)?;
        let length = stream.read(&mut data[offset..])?;
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "caller disconnected before completing its request",
            ));
        }
        offset += length;
    }
    Ok(data)
}

fn check_delivery(operation: &str, respond: bool) -> TestResult {
    let artifacts = Artifacts::discover()?;
    let fixture = Fixture::new(&artifacts)?;
    let listener = UnixListener::bind(&fixture.socket_path)?;
    fs::set_permissions(&fixture.socket_path, fs::Permissions::from_mode(0o600))?;
    let mut caller = Caller::spawn(fixture.caller_command(operation))?;
    caller.wait_calling()?;
    caller.assert_pending(listener.as_raw_fd(), WAIT)?;
    let (mut stream, _) = listener.accept()?;
    stream.set_read_timeout(Some(WAIT))?;
    stream.set_write_timeout(Some(WAIT))?;
    let length = read_exact(&caller, &mut stream, 4)?;
    let length = u32::from_le_bytes(length.try_into().unwrap()) as usize;
    assert!(length < 4096, "unexpected request length: {length}");
    let bytes = read_exact(&caller, &mut stream, length)?;
    let message = PamMessage::from_bytes(&bytes)?;
    let username = current_username()?;
    let expected = if operation == "session" {
        PamMessage::unlock(username, b"oo7-test-old-password".to_vec())
    } else {
        PamMessage::change_password(
            username,
            b"oo7-test-old-password".to_vec(),
            b"oo7-test-new-password".to_vec(),
        )
    };
    assert_eq!(message.username, expected.username);
    assert_eq!(message.old_secret, expected.old_secret);
    assert_eq!(message.new_secret, expected.new_secret);
    // Compare the full payload to validate the operation and reject trailing
    // bytes.
    assert_eq!(bytes, expected.to_bytes()?);

    // Even a detached sender that transmitted the full request must not allow
    // PAM to return before the daemon responds.
    caller.assert_blocked(Duration::from_millis(100))?;
    if respond {
        let response = PamResponse {
            success: true,
            error_message: String::new(),
        }
        .to_bytes()?;
        stream.write_all(&(response.len() as u32).to_le_bytes())?;
        stream.write_all(&response)?;
    }
    // Keep the peer connected while checking the existing response timeout.
    caller.wait_success(if respond {
        WAIT
    } else {
        Duration::from_secs(10)
    })?;
    Ok(())
}

#[test]
fn open_session_waits_for_delivery() -> TestResult {
    check_delivery("session", true)
}

#[test]
fn password_change_waits_for_delivery() -> TestResult {
    check_delivery("password", true)
}

#[test]
fn unresponsive_daemon_still_returns_success() -> TestResult {
    check_delivery("session", false)
}

#[test]
fn unavailable_daemon_still_returns_success() -> TestResult {
    let artifacts = Artifacts::discover()?;
    for operation in ["session", "password"] {
        let fixture = Fixture::new(&artifacts)?;
        let mut caller = Caller::spawn(fixture.caller_command(operation))?;
        caller.wait_calling()?;
        caller.wait_success(WAIT)?;
    }
    Ok(())
}
