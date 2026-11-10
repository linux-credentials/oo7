#[cfg(feature = "native_crypto")]
use cbc::cipher;

/// Cryptography specific errors.
#[derive(Debug)]
pub enum Error {
    #[cfg(feature = "openssl_crypto")]
    Openssl(openssl::error::ErrorStack),
    #[cfg(feature = "native_crypto")]
    PadError(cipher::inout::PadError),
    Getrandom(getrandom::Error),
    Other(String),
}

#[cfg(feature = "openssl_crypto")]
impl From<openssl::error::ErrorStack> for Error {
    fn from(value: openssl::error::ErrorStack) -> Self {
        Self::Openssl(value)
    }
}

#[cfg(feature = "native_crypto")]
impl From<cipher::inout::PadError> for Error {
    fn from(value: cipher::inout::PadError) -> Self {
        Self::PadError(value)
    }
}

impl From<getrandom::Error> for Error {
    fn from(value: getrandom::Error) -> Self {
        Self::Getrandom(value)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[cfg(feature = "openssl_crypto")]
            Self::Openssl(e) => Some(e),
            #[cfg(feature = "native_crypto")]
            Self::PadError(_) => None,
            Self::Getrandom(_) => None,
            Self::Other(_) => None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "openssl_crypto")]
            Self::Openssl(e) => f.write_fmt(format_args!("Openssl error: {e}")),
            #[cfg(feature = "native_crypto")]
            Self::PadError(e) => f.write_fmt(format_args!("Wrong padding error: {e}")),
            Self::Getrandom(e) => f.write_fmt(format_args!("Random number generation error: {e}")),
            Self::Other(e) => f.write_str(e),
        }
    }
}

#[cfg(feature = "native_crypto")]
impl From<cipher::block_padding::Error> for Error {
    fn from(_value: cipher::block_padding::Error) -> Self {
        Self::PadError(cipher::inout::PadError)
    }
}
