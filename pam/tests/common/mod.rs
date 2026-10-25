//! Drives the built PAM module through a private Linux-PAM configuration.

pub mod namespace;

use std::{
    ffi::{CStr, CString, c_char, c_int, c_void},
    fs,
    os::unix::{fs::symlink, net::UnixListener},
    path::PathBuf,
    sync::{LazyLock, Mutex, MutexGuard, PoisonError},
};

pub const PAM_SUCCESS: c_int = 0;
const PAM_CONV_ERR: c_int = 19;

#[repr(C)]
struct PamConv {
    conv: unsafe extern "C" fn(c_int, *mut *const c_void, *mut *mut c_void, *mut c_void) -> c_int,
    appdata_ptr: *mut c_void,
}

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_start_confdir(
        service_name: *const c_char,
        user: *const c_char,
        pam_conversation: *const PamConv,
        confdir: *const c_char,
        pamh: *mut *mut c_void,
    ) -> c_int;
    fn pam_end(pamh: *mut c_void, pam_status: c_int) -> c_int;
    fn pam_authenticate(pamh: *mut c_void, flags: c_int) -> c_int;
    fn pam_open_session(pamh: *mut c_void, flags: c_int) -> c_int;
    fn pam_close_session(pamh: *mut c_void, flags: c_int) -> c_int;
    fn pam_chauthtok(pamh: *mut c_void, flags: c_int) -> c_int;
}

unsafe extern "C" fn no_conversation(
    _num_msg: c_int,
    _msg: *mut *const c_void,
    _resp: *mut *mut c_void,
    _appdata_ptr: *mut c_void,
) -> c_int {
    PAM_CONV_ERR
}

pub struct Fixture {
    dir: tempfile::TempDir,
    pub socket_path: PathBuf,
    pub username: String,
}

/// The module reads the socket path from the environment, so tests sharing
/// the fixture run one at a time.
pub fn fixture() -> MutexGuard<'static, Fixture> {
    static FIXTURE: LazyLock<Mutex<Fixture>> = LazyLock::new(|| Mutex::new(Fixture::new()));
    FIXTURE.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Fixture {
    fn new() -> Self {
        let deps = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_owned();
        let module = deps.join("libpam_oo7.so");
        let tokens = deps
            .parent()
            .unwrap()
            .join("examples/libpam_test_tokens.so");
        assert!(
            module.is_file() && tokens.is_file(),
            "missing PAM modules, build them with `cargo test -p oo7-pam`"
        );

        let dir = tempfile::tempdir().unwrap();
        // PAM configuration lines can't contain spaces
        symlink(module, dir.path().join("pam_oo7.so")).unwrap();
        symlink(tokens, dir.path().join("tokens.so")).unwrap();
        fs::write(
            dir.path().join("oo7-test"),
            format!(
                "auth required {dir}/tokens.so\n\
                 auth required {dir}/pam_oo7.so\n\
                 session required {dir}/pam_oo7.so\n\
                 password required {dir}/tokens.so\n\
                 password required {dir}/pam_oo7.so\n",
                dir = dir.path().display()
            ),
        )
        .unwrap();

        let socket_path = dir.path().join("pam.sock");
        // SAFETY: set once, before any test drives the PAM module.
        unsafe { std::env::set_var("OO7_PAM_SOCKET", &socket_path) };

        // The module only delivers without forking when running as the user.
        let pw = unsafe { libc::getpwuid(libc::getuid()) };
        assert!(!pw.is_null());
        assert_eq!(
            unsafe { (*pw).pw_gid },
            unsafe { libc::getgid() },
            "tests must run with the user's primary group"
        );
        let username = unsafe { CStr::from_ptr((*pw).pw_name) }
            .to_str()
            .unwrap()
            .to_owned();

        Self {
            dir,
            socket_path,
            username,
        }
    }

    /// Start a transaction for the current user, without a daemon listening.
    pub fn start(&self) -> Pam {
        self.start_for(&self.username)
    }

    pub fn start_for(&self, username: &str) -> Pam {
        let _ = fs::remove_file(&self.socket_path);
        let conv = Box::new(PamConv {
            conv: no_conversation,
            appdata_ptr: std::ptr::null_mut(),
        });
        let user = CString::new(username).unwrap();
        let confdir = CString::new(self.dir.path().as_os_str().as_encoded_bytes()).unwrap();
        let mut handle = std::ptr::null_mut();
        let ret = unsafe {
            pam_start_confdir(
                c"oo7-test".as_ptr(),
                user.as_ptr(),
                &*conv,
                confdir.as_ptr(),
                &mut handle,
            )
        };
        assert_eq!(ret, PAM_SUCCESS, "pam_start_confdir failed");
        Pam {
            handle,
            status: PAM_SUCCESS,
            _conv: conv,
        }
    }

    pub fn listen(&self) -> UnixListener {
        let listener = UnixListener::bind(&self.socket_path).unwrap();
        listener.set_nonblocking(true).unwrap();
        listener
    }
}

pub struct Pam {
    handle: *mut c_void,
    status: c_int,
    _conv: Box<PamConv>,
}

impl Pam {
    fn call(&mut self, f: unsafe extern "C" fn(*mut c_void, c_int) -> c_int) -> c_int {
        self.status = unsafe { f(self.handle, 0) };
        self.status
    }

    pub fn authenticate(&mut self) -> c_int {
        self.call(pam_authenticate)
    }

    pub fn open_session(&mut self) -> c_int {
        self.call(pam_open_session)
    }

    pub fn close_session(&mut self) -> c_int {
        self.call(pam_close_session)
    }

    pub fn chauthtok(&mut self) -> c_int {
        self.call(pam_chauthtok)
    }
}

impl Drop for Pam {
    fn drop(&mut self) {
        unsafe { pam_end(self.handle, self.status) };
    }
}
