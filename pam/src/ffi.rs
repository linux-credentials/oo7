//! PAM bindings shared by the module and its integration test fixtures.

// Each target uses a different subset of these bindings.
#![allow(dead_code)]

use std::os::raw::{c_char, c_int, c_void};

// PAM return codes
pub const PAM_SUCCESS: c_int = 0;
pub const PAM_SYSTEM_ERR: c_int = 4;
pub const PAM_CONV_ERR: c_int = 19;
pub const PAM_AUTHTOK_RECOVER_ERR: c_int = 20;
pub const PAM_IGNORE: c_int = 25;

// PAM item types
pub const PAM_AUTHTOK: c_int = 6;
pub const PAM_OLDAUTHTOK: c_int = 7;

// PAM chauthtok flags
// Solaris/Illumos use different values than Linux
#[cfg(any(target_os = "solaris", target_os = "illumos"))]
pub const PAM_PRELIM_CHECK: c_int = 0x1;

#[cfg(any(target_os = "solaris", target_os = "illumos"))]
pub const PAM_UPDATE_AUTHTOK: c_int = 0x2;

#[cfg(not(any(target_os = "solaris", target_os = "illumos")))]
pub const PAM_PRELIM_CHECK: c_int = 0x4000;

#[cfg(not(any(target_os = "solaris", target_os = "illumos")))]
pub const PAM_UPDATE_AUTHTOK: c_int = 0x2000;

// Opaque PAM handle type
#[repr(C)]
pub struct pam_handle_t {
    _private: [u8; 0],
}

// Conversation messages and responses are only passed through as pointers.
#[repr(C)]
pub struct PamMessage {
    _private: [u8; 0],
}

#[repr(C)]
pub struct PamResponse {
    _private: [u8; 0],
}

#[repr(C)]
pub struct PamConversation {
    pub conversation: unsafe extern "C" fn(
        c_int,
        *mut *const PamMessage,
        *mut *mut PamResponse,
        *mut c_void,
    ) -> c_int,
    pub data: *mut c_void,
}

unsafe extern "C" {
    /// Start a transaction with a private Linux-PAM configuration directory
    pub fn pam_start_confdir(
        service: *const c_char,
        user: *const c_char,
        conversation: *const PamConversation,
        confdir: *const c_char,
        handle: *mut *mut pam_handle_t,
    ) -> c_int;

    pub fn pam_authenticate(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
    pub fn pam_open_session(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
    pub fn pam_close_session(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
    pub fn pam_chauthtok(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
    pub fn pam_end(pamh: *mut pam_handle_t, status: c_int) -> c_int;

    /// Get the username
    pub fn pam_get_user(
        pamh: *mut pam_handle_t,
        user: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;

    /// Get a PAM item
    pub fn pam_get_item(
        pamh: *const pam_handle_t,
        item_type: c_int,
        item: *mut *const c_void,
    ) -> c_int;

    /// Set a PAM item
    pub fn pam_set_item(pamh: *mut pam_handle_t, item_type: c_int, item: *const c_void) -> c_int;

    /// Store data in PAM context with a cleanup function
    pub fn pam_set_data(
        pamh: *mut pam_handle_t,
        module_data_name: *const c_char,
        data: *mut c_void,
        cleanup: Option<unsafe extern "C" fn(*mut pam_handle_t, *mut c_void, c_int)>,
    ) -> c_int;

    /// Retrieve data from PAM context
    pub fn pam_get_data(
        pamh: *const pam_handle_t,
        module_data_name: *const c_char,
        data: *mut *const c_void,
    ) -> c_int;
}
