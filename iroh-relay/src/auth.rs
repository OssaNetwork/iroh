//! Pieces of client authentication shared by the relay and its clients.
//!
//! A client presents opaque credentials in the first message on its control channel. What
//! the credentials contain is up to the relay's authenticator. Two building blocks are
//! provided here:
//!
//! - [`channel_binding`] derives a secret from the TLS session of the control channel.
//!   A client proves possession of a key by signing it. The signature can not be replayed
//!   on another connection, and no challenge round trip is needed.
//! - [`SharedToken`] is the credential format of the relay's built-in authenticator.

use bytes::{BufMut, Bytes, BytesMut};
use n0_error::{e, ensure, stack_error};

use crate::ExportKeyingMaterial;

/// The length of the [`channel_binding`] value.
pub const CHANNEL_BINDING_LEN: usize = 32;

/// The TLS exporter label of the [`channel_binding`] value.
const CHANNEL_BINDING_LABEL: &[u8] = b"transparent-relay control channel binding v1";

/// Derives a value that is unique to the TLS session `io` runs on.
///
/// Both ends of the control channel derive the same value, and nobody else can. It is
/// the TLS exporter of RFC 5705 with a label specific to this protocol.
///
/// Returns `None` if `io` does not run on TLS.
pub fn channel_binding(io: &impl ExportKeyingMaterial) -> Option<[u8; CHANNEL_BINDING_LEN]> {
    io.export_keying_material([0u8; CHANNEL_BINDING_LEN], CHANNEL_BINDING_LABEL, None)
}

/// The credentials of the relay's built-in shared token authenticator.
///
/// A client names itself and presents a token that all clients of the relay share. The
/// name becomes the client's identity. Anyone who knows the token can use any name, so
/// this is meant for tests and private relays.
///
/// Encoded as one length byte, the name, and the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedToken {
    /// The name the client chooses for itself, at most 255 bytes.
    pub name: Bytes,
    /// The token shared by all clients.
    pub token: Bytes,
}

/// The shared token credentials are malformed.
#[stack_error(derive, add_meta)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum SharedTokenError {
    #[error("the name is longer than 255 bytes")]
    NameTooLong,
    #[error("the credentials are cut short")]
    TooShort,
}

impl SharedToken {
    /// Creates credentials from a name and a token.
    pub fn new(name: impl Into<Bytes>, token: impl Into<Bytes>) -> Self {
        Self {
            name: name.into(),
            token: token.into(),
        }
    }

    /// Encodes the credentials.
    pub fn to_bytes(&self) -> Result<Bytes, SharedTokenError> {
        let name_len =
            u8::try_from(self.name.len()).map_err(|_| e!(SharedTokenError::NameTooLong))?;
        let mut dst = BytesMut::with_capacity(1 + self.name.len() + self.token.len());
        dst.put_u8(name_len);
        dst.put_slice(&self.name);
        dst.put_slice(&self.token);
        Ok(dst.freeze())
    }

    /// Decodes the credentials.
    pub fn from_bytes(mut bytes: Bytes) -> Result<Self, SharedTokenError> {
        ensure!(!bytes.is_empty(), SharedTokenError::TooShort);
        let name_len = usize::from(bytes.split_to(1)[0]);
        ensure!(bytes.len() >= name_len, SharedTokenError::TooShort);
        let name = bytes.split_to(name_len);
        Ok(Self { name, token: bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_token_round_trip() {
        let credentials = SharedToken::new("bob", "secret");
        let bytes = credentials.to_bytes().unwrap();
        assert_eq!(&bytes[..], b"\x03bobsecret");
        assert_eq!(SharedToken::from_bytes(bytes).unwrap(), credentials);

        let empty = SharedToken::new("", "");
        assert_eq!(
            SharedToken::from_bytes(empty.to_bytes().unwrap()).unwrap(),
            empty
        );
    }

    #[test]
    fn shared_token_rejects_malformed() {
        assert!(SharedToken::new(vec![0u8; 256], "t").to_bytes().is_err());
        assert!(SharedToken::from_bytes(Bytes::new()).is_err());
        assert!(SharedToken::from_bytes(Bytes::from_static(b"\x05bob")).is_err());
    }
}
