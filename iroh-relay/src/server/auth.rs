//! Authentication of clients on the control channel.
//!
//! Who may use a relay, and what identifies a client, is the relay operator's decision.
//! It sits behind the [`Authenticator`] trait. The relay only needs the resulting
//! [`ClientId`].

use std::{future::Future, pin::Pin};

use bytes::Bytes;
use http::{HeaderMap, Uri};
use n0_error::stack_error;

use super::ClientId;
use crate::auth::{CHANNEL_BINDING_LEN, SharedToken};

/// What a client presented when it opened its control channel.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AuthRequest {
    /// The opaque credentials from the client's first message.
    pub credentials: Bytes,
    /// A value unique to the TLS session of the control channel, see
    /// [`channel_binding`](crate::auth::channel_binding).
    ///
    /// `None` if the control channel does not run on TLS that the relay terminates
    /// itself. An authenticator that verifies a signature over this value must reject
    /// the request in that case.
    pub channel_binding: Option<[u8; CHANNEL_BINDING_LEN]>,
    /// The URI of the HTTP request that opened the control channel.
    pub uri: Uri,
    /// The headers of the HTTP request that opened the control channel.
    pub headers: HeaderMap,
}

impl AuthRequest {
    /// Creates a request.
    pub fn new(
        credentials: Bytes,
        channel_binding: Option<[u8; CHANNEL_BINDING_LEN]>,
        uri: Uri,
        headers: HeaderMap,
    ) -> Self {
        Self {
            credentials,
            channel_binding,
            uri,
            headers,
        }
    }
}

/// The authenticator did not accept a client.
#[stack_error(derive, add_meta)]
#[error("client rejected: {reason}")]
pub struct Rejected {
    /// Told to the client. Do not put secrets here.
    pub reason: String,
}

/// Decides whether a client may open a control channel, and which identity it gets.
///
/// Consulted once per control channel, before a port is allocated.
///
/// A client that presents the identity of a connected client takes over that client's
/// port. The authenticator must therefore only return an identity the client has proven
/// to own.
pub trait Authenticator: std::fmt::Debug + Send + Sync + 'static {
    /// Returns the identity of the client, or rejects it.
    fn authenticate(
        &self,
        request: &AuthRequest,
    ) -> impl Future<Output = Result<ClientId, Rejected>> + Send;
}

/// Dyn-compatible version of [`Authenticator`].
///
/// Implemented for every [`Authenticator`], there is no need to implement it directly.
pub trait DynAuthenticator: std::fmt::Debug + Send + Sync + 'static {
    /// See [`Authenticator::authenticate`].
    fn authenticate_dyn<'a>(
        &'a self,
        request: &'a AuthRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ClientId, Rejected>> + Send + 'a>>;
}

impl<T: Authenticator> DynAuthenticator for T {
    fn authenticate_dyn<'a>(
        &'a self,
        request: &'a AuthRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ClientId, Rejected>> + Send + 'a>> {
        Box::pin(Authenticator::authenticate(self, request))
    }
}

/// Accepts clients that present one of a set of shared tokens.
///
/// The credentials are a [`SharedToken`]. The name in the credentials becomes the
/// client's identity. Anyone who knows a token can use any name, and thereby take over
/// the port of another client, so this is meant for tests and private relays.
#[derive(derive_more::Debug)]
pub struct SharedTokenAuthenticator {
    #[debug("{} tokens", tokens.len())]
    tokens: Vec<Bytes>,
}

impl SharedTokenAuthenticator {
    /// Creates an authenticator that accepts the given tokens.
    ///
    /// Empty tokens are ignored. Without any token no client is accepted.
    pub fn new(tokens: impl IntoIterator<Item = impl Into<Bytes>>) -> Self {
        Self {
            tokens: tokens
                .into_iter()
                .map(Into::into)
                .filter(|token: &Bytes| !token.is_empty())
                .collect(),
        }
    }
}

/// Compares two byte strings in time that depends only on their lengths.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

impl Authenticator for SharedTokenAuthenticator {
    async fn authenticate(&self, request: &AuthRequest) -> Result<ClientId, Rejected> {
        let credentials = SharedToken::from_bytes(request.credentials.clone())
            .map_err(|_| Rejected::new("malformed credentials".to_string()))?;
        if credentials.name.is_empty() {
            return Err(Rejected::new("empty name".to_string()));
        }
        // Check every token, so that timing does not tell which one matched.
        let known = self.tokens.iter().fold(false, |known, token| {
            known | constant_time_eq(token, &credentials.token)
        });
        if !known {
            return Err(Rejected::new("unknown token".to_string()));
        }
        Ok(ClientId::new(credentials.name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(credentials: Bytes) -> AuthRequest {
        AuthRequest::new(
            credentials,
            None,
            Uri::from_static("/control"),
            HeaderMap::new(),
        )
    }

    #[tokio::test]
    async fn shared_token() {
        let auth = SharedTokenAuthenticator::new(["one", "two", ""]);
        let creds = |name: &'static str, token: &'static str| {
            request(SharedToken::new(name, token).to_bytes().unwrap())
        };
        let id = auth.authenticate(&creds("bob", "two")).await.unwrap();
        assert_eq!(id, ClientId::new("bob"));
        assert!(auth.authenticate(&creds("bob", "three")).await.is_err());
        // The empty token was ignored.
        assert!(auth.authenticate(&creds("bob", "")).await.is_err());
        assert!(auth.authenticate(&creds("", "one")).await.is_err());
        assert!(auth.authenticate(&request(Bytes::new())).await.is_err());
    }

    #[tokio::test]
    async fn no_tokens_accepts_nobody() {
        let auth = SharedTokenAuthenticator::new(Vec::<Bytes>::new());
        let req = request(SharedToken::new("bob", "").to_bytes().unwrap());
        assert!(auth.authenticate(&req).await.is_err());
    }
}
