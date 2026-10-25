#![cfg(target_os = "linux")]

mod common;
#[allow(dead_code)]
#[path = "../src/protocol.rs"]
mod protocol;

use std::{
    fs,
    io::{self, Read},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{PermissionsExt, chown},
            net::{UnixListener, UnixStream},
        },
    },
    time::{Duration, Instant},
};

use common::PAM_SUCCESS;
use protocol::PamMessage;

/// The request must be fully written by the time PAM returns, the caller may
/// exit right after.
fn take_request(listener: &UnixListener) -> Vec<u8> {
    let (stream, _) = listener
        .accept()
        .expect("PAM returned before connecting to the daemon");
    read_request(stream)
}

fn read_request(mut stream: UnixStream) -> Vec<u8> {
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

// Linux SO_PEERGROUPS is not exposed by libc 0.2.190.
const SO_PEERGROUPS: libc::c_int = 59;

fn original_credentials() -> io::Result<()> {
    let mut group: libc::gid_t = !0;
    // SAFETY: group is valid storage for the single requested gid_t.
    let unchanged = unsafe {
        libc::getuid() == 0
            && libc::geteuid() == 0
            && libc::getgid() == 0
            && libc::getegid() == 0
            && libc::getgroups(1, &mut group) == 1
            && group == 0
    };
    if !unchanged {
        return Err(io::Error::other(
            "expected caller UID/GID 0 and supplementary groups [0]",
        ));
    }
    Ok(())
}

fn check_peer(username: &str, uid: libc::uid_t, expected_groups: &[libc::gid_t]) -> io::Result<()> {
    let group: libc::gid_t = 0;
    // SAFETY: only this private worker process has its groups initialized.
    if unsafe { libc::setgroups(1, &group) } != 0 {
        return Err(io::Error::last_os_error());
    }
    original_credentials()?;
    let fixture = common::fixture();
    let mut pam = fixture.start_for(username);
    let listener = fixture.listen();
    fs::set_permissions(
        fixture.socket_path.parent().unwrap(),
        fs::Permissions::from_mode(0o755),
    )?;
    fs::set_permissions(&fixture.socket_path, fs::Permissions::from_mode(0o600))?;
    chown(&fixture.socket_path, Some(uid), Some(uid))?;
    assert_eq!(pam.authenticate(), PAM_SUCCESS);
    assert_eq!(pam.open_session(), PAM_SUCCESS);
    assert_eq!(pam.close_session(), PAM_SUCCESS);
    drop(pam);
    original_credentials()?;

    let (peer, _) = listener.accept()?;
    // SAFETY: ucred consists entirely of integer fields.
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: both output pointers have the specified valid storage sizes.
    if unsafe {
        libc::getsockopt(
            peer.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    assert_eq!(length as usize, size_of::<libc::ucred>());
    let mut groups = [0 as libc::gid_t; 64];
    let mut length = size_of_val(&groups) as libc::socklen_t;
    // SAFETY: groups and length are valid output storage of the specified
    // sizes.
    if unsafe {
        libc::getsockopt(
            peer.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_PEERGROUPS,
            groups.as_mut_ptr().cast(),
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let length = length as usize;
    assert!(length <= size_of_val(&groups) && length.is_multiple_of(size_of::<libc::gid_t>()));
    let groups = &groups[..length / size_of::<libc::gid_t>()];
    let expected = PamMessage::unlock(username.into(), b"old-password".to_vec());
    assert_eq!(read_request(peer), expected.to_bytes().unwrap());
    if (credentials.uid, credentials.gid) != (uid, uid) || groups != expected_groups {
        return Err(io::Error::other(format!(
            "unexpected {username} peer: uid={}, gid={}, groups={groups:?}; expected uid={uid}, gid={uid}, groups={expected_groups:?}",
            credentials.uid, credentials.gid,
        )));
    }
    Ok(())
}

#[test]
#[ignore = "requires OO7_PAM_PRIVILEGED_TESTS=1 and root-capable bubblewrap"]
fn root_to_user_discards_inherited_groups() -> io::Result<()> {
    common::namespace::run("root_to_user_discards_inherited_groups", || {
        check_peer("oo7-test", 65534, &[])
    })
}

#[test]
#[ignore = "requires OO7_PAM_PRIVILEGED_TESTS=1 and root-capable bubblewrap"]
fn same_user_preserves_groups() -> io::Result<()> {
    common::namespace::run("same_user_preserves_groups", || check_peer("root", 0, &[0]))
}
