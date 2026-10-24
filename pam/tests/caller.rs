//! Short-lived Linux-PAM application for tests using only synthetic passwords.

use std::{
    ffi::{CStr, CString, OsStr, c_int, c_void},
    io::Write,
    os::{
        fd::AsFd,
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    ptr,
};

#[path = "../src/ffi.rs"]
mod ffi;

unsafe extern "C" fn no_conversation(
    _count: c_int,
    _messages: *mut *const ffi::PamMessage,
    _responses: *mut *mut ffi::PamResponse,
    _data: *mut c_void,
) -> c_int {
    // Never ask for or read a real password.
    ffi::PAM_CONV_ERR
}

struct Pam {
    handle: *mut ffi::pam_handle_t,
    status: c_int,
}

impl Pam {
    fn new(confdir: &CStr, user: &CStr) -> Result<Self, c_int> {
        let conversation = ffi::PamConversation {
            conversation: no_conversation,
            data: ptr::null_mut(),
        };
        let mut handle = ptr::null_mut();
        // SAFETY: all C strings are terminated and live throughout the call.
        // PAM copies the strings and conversation; handle is a valid
        // out-pointer, and the callback requires no borrowed state.
        let status = unsafe {
            ffi::pam_start_confdir(
                c"oo7-test".as_ptr(),
                user.as_ptr(),
                &conversation,
                confdir.as_ptr(),
                &mut handle,
            )
        };
        if status != ffi::PAM_SUCCESS {
            return Err(status);
        }
        Ok(Self { handle, status })
    }
}

impl Drop for Pam {
    fn drop(&mut self) {
        // SAFETY: constructed only after pam_start_confdir succeeds; this is
        // the sole owner and pam_end runs exactly once.
        unsafe { ffi::pam_end(self.handle, self.status) };
    }
}

fn run(confdir: &OsStr, operation: &OsStr, control: &mut UnixStream) -> Result<(), String> {
    if operation != "session" && operation != "password" {
        return Err("PAM operation must be session or password".into());
    }
    let confdir = CString::new(confdir.as_bytes()).map_err(|error| error.to_string())?;
    let session = operation == "session";

    // SAFETY: the libc calls require no caller-owned storage. This
    // single-threaded caller performs no concurrent passwd lookups.
    let user = unsafe { libc::getpwuid(libc::getuid()) };
    if user.is_null() {
        return Err("current uid has no passwd entry".into());
    }
    // SAFETY: user was checked for null and points to libc's passwd record.
    if unsafe { (*user).pw_gid != libc::getgid() } {
        return Err("current gid does not match the passwd entry".into());
    }

    // SAFETY: the passwd entry contains a terminated username. No further
    // passwd calls occur before PAM copies it in Pam::new.
    let username = unsafe { CStr::from_ptr((*user).pw_name) }.to_owned();
    let mut pam = Pam::new(&confdir, &username)
        .map_err(|status| format!("pam_start_confdir failed with status {status}"))?;

    if session {
        // SAFETY: pam owns a successfully initialized, live PAM transaction.
        pam.status = unsafe { ffi::pam_authenticate(pam.handle, 0) };
        if pam.status != ffi::PAM_SUCCESS {
            return Err(format!(
                "pam_authenticate failed with status {}",
                pam.status
            ));
        }
    }

    writeln!(control, "calling").map_err(|error| error.to_string())?;
    control.flush().map_err(|error| error.to_string())?;
    // SAFETY: pam remains the sole owner of this live transaction. Its test
    // configuration supplies synthetic authentication tokens without prompting.
    pam.status = unsafe {
        if session {
            ffi::pam_open_session(pam.handle, 0)
        } else {
            ffi::pam_chauthtok(pam.handle, 0)
        }
    };
    writeln!(control, "returned {}", pam.status).map_err(|error| error.to_string())?;
    control.flush().map_err(|error| error.to_string())?;
    if pam.status != ffi::PAM_SUCCESS {
        let operation = if session {
            "pam_open_session"
        } else {
            "pam_chauthtok"
        };
        return Err(format!("{operation} failed with status {}", pam.status));
    }
    if session {
        // SAFETY: the same transaction successfully opened this session.
        pam.status = unsafe { ffi::pam_close_session(pam.handle, 0) };
        if pam.status != ffi::PAM_SUCCESS {
            return Err(format!(
                "pam_close_session failed with status {}",
                pam.status
            ));
        }
    }
    Ok(())
}

fn main() {
    let config = std::env::var_os("OO7_PAM_TEST_CONFIG").expect("caller configuration");
    let operation = std::env::var_os("OO7_PAM_TEST_OPERATION").expect("caller operation");
    let descriptor = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .expect("caller control socket");
    let mut control = UnixStream::from(descriptor);
    let result = match run(&config, &operation, &mut control) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("PAM test caller: {error}");
            1
        }
    };
    std::process::exit(result);
}
