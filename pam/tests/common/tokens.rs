//! PAM module setting synthetic tokens, as only modules can set them.
#![cfg(target_os = "linux")]

use std::ffi::{c_char, c_int, c_void};

const PAM_SUCCESS: c_int = 0;
const PAM_AUTHTOK: c_int = 6;
const PAM_OLDAUTHTOK: c_int = 7;
const PAM_PRELIM_CHECK: c_int = 0x4000;

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_set_item(pamh: *mut c_void, item_type: c_int, item: *const c_void) -> c_int;
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *mut *const c_char,
) -> c_int {
    unsafe { pam_set_item(pamh, PAM_AUTHTOK, c"old-password".as_ptr().cast()) }
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_chauthtok(
    pamh: *mut c_void,
    flags: c_int,
    _argc: c_int,
    _argv: *mut *const c_char,
) -> c_int {
    if flags & PAM_PRELIM_CHECK != 0 {
        return PAM_SUCCESS;
    }
    let ret = unsafe { pam_set_item(pamh, PAM_OLDAUTHTOK, c"old-password".as_ptr().cast()) };
    if ret != PAM_SUCCESS {
        return ret;
    }
    unsafe { pam_set_item(pamh, PAM_AUTHTOK, c"new-password".as_ptr().cast()) }
}
