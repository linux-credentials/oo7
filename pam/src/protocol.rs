use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use zeroize::{Zeroize, ZeroizeOnDrop};
use zvariant::{Type, serialized::Context, to_bytes};

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, Type, PartialEq, Eq)]
#[repr(u8)]
pub enum PamOperation {
    Unlock = 0,
    ChangePassword = 1,
}

#[derive(Debug, Serialize, Deserialize, Type, Zeroize, ZeroizeOnDrop)]
pub struct PamMessage {
    #[zeroize(skip)]
    operation: PamOperation,
    pub username: String,
    pub old_secret: Vec<u8>,
    pub new_secret: Vec<u8>,
}

impl PamMessage {
    /// Create an unlock message
    pub fn unlock(username: String, secret: Vec<u8>) -> Self {
        Self {
            operation: PamOperation::Unlock,
            username,
            old_secret: Vec::new(),
            new_secret: secret,
        }
    }

    /// Create a password change message
    pub fn change_password(username: String, old_secret: Vec<u8>, new_secret: Vec<u8>) -> Self {
        Self {
            operation: PamOperation::ChangePassword,
            username,
            old_secret,
            new_secret,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, zvariant::Error> {
        let ctxt = Context::new_dbus(zvariant::LE, 0);
        to_bytes(ctxt, self).map(|data| data.to_vec())
    }

    #[cfg(test)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, zvariant::Error> {
        let ctxt = Context::new_dbus(zvariant::LE, 0);
        let data = zvariant::serialized::Data::new(bytes, ctxt);
        data.deserialize().map(|(msg, _)| msg)
    }
}

#[derive(Debug, Deserialize, Type)]
pub struct PamResponse {
    pub success: bool,
    pub error_message: String,
}

impl PamResponse {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, zvariant::Error> {
        let ctxt = Context::new_dbus(zvariant::LE, 0);
        let data = zvariant::serialized::Data::new(bytes, ctxt);
        data.deserialize().map(|(msg, _)| msg)
    }
}
