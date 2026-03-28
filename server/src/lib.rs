// Library interface for oo7_server
// Only expose test utilities when the test-util feature is enabled

pub(crate) mod collection;
pub(crate) mod error;
#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
pub(crate) mod gnome;
pub(crate) mod item;
pub(crate) mod pam_listener;
#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
pub(crate) mod plasma;
pub(crate) mod prompt;
pub(crate) mod service;
pub(crate) mod session;

pub(crate) use service::Service;

#[cfg(feature = "test-util")]
pub mod tests;

#[cfg(all(test, not(feature = "test-util")))]
mod tests;
