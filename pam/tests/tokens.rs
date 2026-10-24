//! Test-only PAM module supplying synthetic tokens without user interaction.

use std::ffi::{c_char, c_int};

#[path = "../src/ffi.rs"]
mod ffi;

/// Supply a synthetic authentication token.
///
/// # Safety
/// Called by Linux-PAM with a live transaction handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    handle: *mut ffi::pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *mut *const c_char,
) -> c_int {
    // SAFETY: Linux-PAM provides the live handle and copies the static token.
    unsafe {
        ffi::pam_set_item(
            handle,
            ffi::PAM_AUTHTOK,
            c"oo7-test-old-password".as_ptr().cast(),
        )
    }
}

/// Supply synthetic old and new password-change tokens.
///
/// # Safety
/// Called by Linux-PAM with a live transaction handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_chauthtok(
    handle: *mut ffi::pam_handle_t,
    flags: c_int,
    _argc: c_int,
    _argv: *mut *const c_char,
) -> c_int {
    if flags & ffi::PAM_PRELIM_CHECK != 0 {
        return ffi::PAM_SUCCESS;
    }
    // SAFETY: Linux-PAM provides the live handle and copies both static tokens.
    unsafe {
        let status = ffi::pam_set_item(
            handle,
            ffi::PAM_OLDAUTHTOK,
            c"oo7-test-old-password".as_ptr().cast(),
        );
        if status != ffi::PAM_SUCCESS {
            return status;
        }
        ffi::pam_set_item(
            handle,
            ffi::PAM_AUTHTOK,
            c"oo7-test-new-password".as_ptr().cast(),
        )
    }
}
