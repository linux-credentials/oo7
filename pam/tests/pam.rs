#![cfg(target_os = "linux")]

mod common;
#[allow(dead_code)]
#[path = "../src/protocol.rs"]
mod protocol;

use std::{
    io::Read,
    os::unix::net::UnixListener,
    time::{Duration, Instant},
};

use common::PAM_SUCCESS;
use protocol::PamMessage;

/// The request must be fully written by the time PAM returns, the caller may
/// exit right after.
fn take_request(listener: &UnixListener) -> Vec<u8> {
    let (mut stream, _) = listener
        .accept()
        .expect("PAM returned before connecting to the daemon");
    stream.set_nonblocking(true).unwrap();
    let mut bytes = Vec::new();
    stream
        .read_to_end(&mut bytes)
        .expect("PAM returned before sending the whole request");
    let (length, message) = bytes.split_at(4);
    assert_eq!(
        u32::from_le_bytes(length.try_into().unwrap()) as usize,
        message.len()
    );
    message.to_vec()
}

/// The daemon never answers, PAM must not wait for it.
fn assert_quick(start: Instant) {
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn open_session_delivers_unlock() {
    let fixture = common::fixture();
    let mut pam = fixture.start();
    let listener = fixture.listen();

    assert_eq!(pam.authenticate(), PAM_SUCCESS);
    let start = Instant::now();
    assert_eq!(pam.open_session(), PAM_SUCCESS);
    assert_quick(start);

    let expected = PamMessage::unlock(fixture.username.clone(), b"old-password".to_vec());
    assert_eq!(take_request(&listener), expected.to_bytes().unwrap());
    assert_eq!(pam.close_session(), PAM_SUCCESS);
}

#[test]
fn chauthtok_delivers_password_change() {
    let fixture = common::fixture();
    let mut pam = fixture.start();
    let listener = fixture.listen();

    let start = Instant::now();
    assert_eq!(pam.chauthtok(), PAM_SUCCESS);
    assert_quick(start);

    let expected = PamMessage::change_password(
        fixture.username.clone(),
        b"old-password".to_vec(),
        b"new-password".to_vec(),
    );
    assert_eq!(take_request(&listener), expected.to_bytes().unwrap());
}

#[test]
fn missing_daemon_is_not_fatal() {
    let fixture = common::fixture();
    let mut pam = fixture.start();

    assert_eq!(pam.authenticate(), PAM_SUCCESS);
    assert_eq!(pam.open_session(), PAM_SUCCESS);
    assert_eq!(pam.close_session(), PAM_SUCCESS);
    assert_eq!(pam.chauthtok(), PAM_SUCCESS);
}
