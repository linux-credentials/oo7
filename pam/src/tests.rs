//! A PAM-handle fixture exercises the exported hooks and real private sockets.
use std::{
    ffi::{CStr, CString, c_void},
    io::{Read, Write},
    os::unix::net::UnixListener,
    sync::Mutex,
    time::{Duration, Instant},
};

use super::{ffi::*, protocol::PamMessage, *};

static ENVIRONMENT: Mutex<()> = Mutex::new(());
type Cleanup = Option<unsafe extern "C" fn(*mut pam_handle_t, *mut c_void, c_int)>;

struct Handle {
    user: CString,
    token: Option<CString>,
    password: Option<(*mut c_void, Cleanup)>,
}

impl Handle {
    fn new(token: Option<&str>) -> Self {
        let user = unsafe { libc::getpwuid(libc::getuid()) };
        assert!(!user.is_null());
        Self {
            user: unsafe { CStr::from_ptr((*user).pw_name) }.to_owned(),
            token: token.map(|s| CString::new(s).unwrap()),
            password: None,
        }
    }
    fn pointer(&mut self) -> *mut pam_handle_t {
        (self as *mut Self).cast()
    }
    fn authenticate(&mut self) {
        assert_eq!(
            unsafe { pam_sm_authenticate(self.pointer(), 0, 0, std::ptr::null_mut()) },
            PAM_SUCCESS
        );
    }
    fn credentials(&mut self, flags: c_int) {
        assert_eq!(
            unsafe { pam_sm_setcred(self.pointer(), flags, 0, std::ptr::null_mut()) },
            PAM_SUCCESS
        );
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        if let Some((data, Some(cleanup))) = self.password.take() {
            unsafe { cleanup(self.pointer(), data, PAM_SUCCESS) };
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn pam_get_user(
    handle: *mut pam_handle_t,
    user: *mut *const c_char,
    _: *const c_char,
) -> c_int {
    unsafe {
        *user = (&*handle.cast::<Handle>()).user.as_ptr();
    }
    PAM_SUCCESS
}
#[unsafe(no_mangle)]
unsafe extern "C" fn pam_get_item(
    handle: *const pam_handle_t,
    item: c_int,
    value: *mut *const c_void,
) -> c_int {
    if item != PAM_AUTHTOK {
        return PAM_SYSTEM_ERR;
    }
    unsafe {
        *value = (&*handle.cast::<Handle>())
            .token
            .as_ref()
            .map_or(std::ptr::null(), |s| s.as_ptr().cast());
    }
    PAM_SUCCESS
}
#[unsafe(no_mangle)]
unsafe extern "C" fn pam_get_data(
    handle: *const pam_handle_t,
    _: *const c_char,
    value: *mut *const c_void,
) -> c_int {
    unsafe {
        *value = (&*handle.cast::<Handle>())
            .password
            .map_or(std::ptr::null(), |(p, _)| p.cast_const());
    }
    PAM_SUCCESS
}
#[unsafe(no_mangle)]
unsafe extern "C" fn pam_set_data(
    handle: *mut pam_handle_t,
    _: *const c_char,
    value: *mut c_void,
    cleanup: Cleanup,
) -> c_int {
    let fixture = unsafe { &mut *handle.cast::<Handle>() };
    if let Some((old, Some(cleanup))) = fixture.password.take() {
        unsafe { cleanup(handle, old, PAM_SUCCESS) };
    }
    fixture.password = (!value.is_null()).then_some((value, cleanup));
    PAM_SUCCESS
}

#[test]
fn credential_refresh_hands_off_once_and_preserves_cold_login_stash() {
    let _guard = ENVIRONMENT.lock().unwrap();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("pam.sock");
    // This test owns the only process-environment mutation in this crate.
    let previous = std::env::var_os("OO7_PAM_SOCKET");
    unsafe { std::env::set_var("OO7_PAM_SOCKET", &path) };
    let mut handle = Handle::new(Some("synthetic-keyring-password"));
    handle.authenticate();
    handle.credentials(PAM_REFRESH_CRED); // Daemon absent.
    assert!(
        handle.password.is_some(),
        "cold-login password must remain available"
    );
    let listener = UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    handle.credentials(if cfg!(target_os = "linux") { 0x2 } else { 0x1 }); // PAM_ESTABLISH_CRED
    assert!(listener.accept().is_err());
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut length = [0; 4];
                    stream.read_exact(&mut length).unwrap();
                    let mut bytes = vec![0; u32::from_le_bytes(length) as usize];
                    stream.read_exact(&mut bytes).unwrap();
                    let message = PamMessage::from_bytes(&bytes).unwrap();
                    assert_eq!(message.new_secret, b"synthetic-keyring-password");
                    let response = zgvariant::to_bytes(
                        zgvariant::serialized::Context::new(zgvariant::LE, 0),
                        &(true, ""),
                    )
                    .unwrap()
                    .to_vec();
                    stream
                        .write_all(&(response.len() as u32).to_le_bytes())
                        .unwrap();
                    stream.write_all(&response).unwrap();
                    return true;
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => return false,
            }
        }
    });
    handle.credentials(PAM_REINITIALIZE_CRED); // After auth/account success.
    let delivered = server.join().unwrap();
    unsafe {
        if let Some(value) = previous {
            std::env::set_var("OO7_PAM_SOCKET", value);
        } else {
            std::env::remove_var("OO7_PAM_SOCKET");
        }
    }
    assert!(
        delivered,
        "lockscreen credential refresh must send the captured password"
    );
    assert!(
        handle.password.is_none(),
        "successful handoff must erase the stash"
    );
    handle.credentials(PAM_REFRESH_CRED); // No retained password to replay.
    let mut deleted = Handle::new(Some("synthetic-deleted-password"));
    deleted.authenticate();
    deleted.credentials(PAM_DELETE_CRED | PAM_REFRESH_CRED);
    assert!(
        deleted.password.is_none(),
        "deleting credentials must erase the stash"
    );
    for token in [None, Some("")] {
        let mut handle = Handle::new(token);
        handle.authenticate();
        handle.credentials(PAM_REFRESH_CRED);
        assert!(handle.password.is_none());
    }
    let mut retry = Handle::new(Some("synthetic-old-attempt"));
    retry.authenticate();
    retry.token = None;
    retry.authenticate();
    assert!(
        retry.password.is_none(),
        "passwordless retry must erase an earlier token"
    );
}
