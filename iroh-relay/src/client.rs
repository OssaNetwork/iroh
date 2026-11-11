//! Client-side connection establishment to a relay server.
//!
//! [`WsDialer`] opens a WebSocket to one of the relay's endpoints. It handles DNS
//! resolution, happy-eyeballs dialing, HTTP proxies and TLS.

use std::{
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use bytes::Bytes;
use http::header::SEC_WEBSOCKET_PROTOCOL;
use iroh_dns::dns::{DnsError, DnsResolver};
use n0_error::{AnyError, StdResultExt, e, stack_error};
use n0_future::{Sink, Stream, time};
use tracing::{debug, trace};
use url::Url;

use self::streams::{MaybeTlsStream, ProxyStream};
use crate::{
    ExportKeyingMaterial,
    protos::streams::{StreamError, WsBytesFramed},
};

pub(crate) mod streams;
mod tls;
mod util;

/// Connection errors.
///
/// `ConnectError` contains `DialError`, errors that can occur while dialing the
/// relay, as well as errors that occur while creating or maintaining a connection.
#[stack_error(derive, add_meta, from_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum ConnectError {
    #[error("Invalid URL for websocket: {url}")]
    InvalidWebsocketUrl { url: Url },
    #[error("Invalid relay URL: {url}")]
    InvalidRelayUrl { url: Url },
    /// Error returned from the underlying WebSocket stream while establishing the connection.
    ///
    /// The concrete error type is `tokio_websockets::Error`. Use [`AnyError::downcast_ref`]
    /// to recover it. Note that the concrete downcast type is not covered by any semver
    /// guarantees and may change between releases.
    #[error(transparent)]
    Websocket { source: AnyError },
    #[error(
        "Server replied with an unexpected websocket subprotocol: {}",
        server_protocol.as_deref().unwrap_or("<empty>")
    )]
    BadSubprotocol { server_protocol: Option<String> },
    #[error(transparent)]
    Dial { source: DialError },
    #[error("Unexpected status during upgrade: {code}")]
    UnexpectedUpgradeStatus { code: hyper::StatusCode },
    #[error("Failed to upgrade response")]
    Upgrade {
        #[error(std_err)]
        source: hyper::Error,
    },
    #[error("Invalid TLS servername")]
    InvalidTlsServername {},
    #[error("No local address available")]
    NoLocalAddr {},
    #[error("tls connection failed")]
    Tls {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[error(
        "No rustls crypto provider configured while both ring and aws-lc-rs feature flags are disabled"
    )]
    MissingCryptoProvider,
}

/// Errors that can occur while dialing the relay server.
#[stack_error(derive, add_meta, from_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum DialError {
    #[error("Invalid target port")]
    InvalidTargetPort {},
    #[error(transparent)]
    Dns { source: DnsError },
    #[error(transparent)]
    Timeout {
        #[error(std_err)]
        source: time::Elapsed,
    },
    #[error(transparent)]
    Io {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[error("Invalid URL: {url}")]
    InvalidUrl { url: Url },
    #[error("Failed proxy connection: {status}")]
    ProxyConnectInvalidStatus { status: hyper::StatusCode },
    #[error("Invalid Proxy URL {proxy_url}")]
    ProxyInvalidUrl { proxy_url: Url },
    #[error("failed to establish proxy connection")]
    ProxyConnect {
        #[error(std_err)]
        source: hyper::Error,
    },
    #[error("Invalid proxy TLS servername: {proxy_hostname}")]
    ProxyInvalidTlsServername { proxy_hostname: String },
    #[error("Invalid proxy target port")]
    ProxyInvalidTargetPort {},
}

/// Dials WebSocket connections to a relay server.
#[derive(derive_more::Debug, Clone)]
pub struct WsDialer {
    #[debug("address family selector: {}", address_family_selector.is_some())]
    address_family_selector: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    /// The base URL of the relay server.
    url: Url,
    tls_config: Option<rustls::ClientConfig>,
    /// HTTP Proxy
    proxy_url: Option<Url>,
    dns_resolver: DnsResolver,
    /// Maximum WebSocket payload length accepted from the server.
    max_payload_len: usize,
}

impl WsDialer {
    /// Creates a new [`WsDialer`] for the relay server at `url`.
    ///
    /// `max_payload_len` bounds the size of a single WebSocket message accepted from the
    /// server.
    pub fn new(url: Url, dns_resolver: DnsResolver, max_payload_len: usize) -> Self {
        Self {
            address_family_selector: None,
            url,
            tls_config: None,
            proxy_url: None,
            dns_resolver,
            max_payload_len,
        }
    }

    /// Sets a custom TLS config.
    ///
    /// This is a required option.
    ///
    /// You can construct a [`rustls::ClientConfig`] by combining a [`rustls::crypto::CryptoProvider`]
    /// with a [`tls::CaTlsConfig`] using [`tls::CaTlsConfig::client_config`], for example:
    ///
    /// ```no_run
    /// use std::sync::Arc;
    ///
    /// use iroh_relay::tls::CaTlsConfig;
    ///
    /// let crypto_provider: rustls::crypto::CryptoProvider = todo!();
    /// let client_config = CaTlsConfig::default().client_config(Arc::new(crypto_provider));
    /// ```
    ///
    /// If you enable the tls-ring or tls-aws-lc-rs feature, you can use the enabled crypto provider
    /// by using [`tls::default_provider`].
    ///
    /// [`tls::CaTlsConfig`]: crate::tls::CaTlsConfig
    /// [`tls::CaTlsConfig::client_config`]: crate::tls::CaTlsConfig::client_config
    /// [`tls::default_provider`]: crate::tls::default_provider
    pub fn tls_client_config(mut self, tls_config: rustls::ClientConfig) -> Self {
        self.tls_config = Some(tls_config);
        self
    }

    /// Sets a callback hinting whether to prefer IPv6 when dialing the relay.
    ///
    /// The callback runs on each dial. When it returns `true`, IPv6 addresses
    /// are tried first and IPv4 dials are held back slightly, biasing the
    /// happy-eyeballs race towards IPv6; when it returns `false`, IPv4 is
    /// preferred. Only return `true` when IPv6 is expected to work, since
    /// otherwise the bias just delays the connection.
    pub fn address_family_selector<S>(mut self, selector: S) -> Self
    where
        S: Fn() -> bool + Send + Sync + 'static,
    {
        self.address_family_selector = Some(Arc::new(selector));
        self
    }

    /// Set an explicit proxy url to proxy all HTTP(S) traffic through.
    pub fn proxy_url(mut self, url: Url) -> Self {
        self.proxy_url.replace(url);
        self
    }

    /// Opens a WebSocket at `path`, relative to the relay URL, speaking `subprotocol`.
    ///
    /// The relay URL is given with the `http` or `https` scheme; the matching `ws` or
    /// `wss` scheme is used for the connection. The server must confirm `subprotocol`.
    pub async fn connect(
        &self,
        path: &str,
        subprotocol: &'static str,
    ) -> Result<WsConnection, ConnectError> {
        let mut dial_url = self.url.join(path).map_err(|_| {
            e!(ConnectError::InvalidRelayUrl {
                url: self.url.clone()
            })
        })?;
        dial_url
            .set_scheme(match self.url.scheme() {
                "http" => "ws",
                "ws" => "ws",
                _ => "wss",
            })
            .map_err(|_| {
                e!(ConnectError::InvalidWebsocketUrl {
                    url: dial_url.clone()
                })
            })?;

        debug!(%dial_url, "Dialing relay by websocket");

        let tls_config = self
            .tls_config
            .clone()
            .ok_or_else(|| e!(ConnectError::MissingCryptoProvider))?;

        let builder = tls::MaybeTlsStreamBuilder::new(
            dial_url.clone(),
            self.dns_resolver.clone(),
            tls_config,
        )
        .prefer_ipv6(self.prefer_ipv6())
        .proxy_url(self.proxy_url.clone());

        let stream = builder.connect().await?;
        let local_addr = stream
            .as_ref()
            .local_addr()
            .map_err(|_| e!(ConnectError::NoLocalAddr))?;

        let builder = tokio_websockets::ClientBuilder::new()
            .uri(dial_url.as_str())
            .map_err(|_| {
                e!(ConnectError::InvalidRelayUrl {
                    url: dial_url.clone()
                })
            })?
            .add_header(
                SEC_WEBSOCKET_PROTOCOL,
                http::HeaderValue::from_static(subprotocol),
            )
            .expect("valid header name and value")
            .limits(tokio_websockets::Limits::default().max_payload_len(Some(self.max_payload_len)))
            // Automatic flushing after a threshold is turned off (the default would be
            // after 8KB). Users of the connection flush explicitly.
            .config(tokio_websockets::Config::default().flush_threshold(usize::MAX));

        let (conn, response) = builder.connect_on(stream).await.anyerr()?;

        n0_error::ensure!(
            response.status() == hyper::StatusCode::SWITCHING_PROTOCOLS,
            ConnectError::UnexpectedUpgradeStatus {
                code: response.status()
            }
        );

        let server_protocol = response
            .headers()
            .get(SEC_WEBSOCKET_PROTOCOL)
            .and_then(|s| s.to_str().ok());
        n0_error::ensure!(
            server_protocol == Some(subprotocol),
            ConnectError::BadSubprotocol {
                server_protocol: server_protocol.map(ToOwned::to_owned)
            }
        );

        trace!("connect done");

        Ok(WsConnection {
            io: WsBytesFramed { io: conn },
            local_addr,
        })
    }

    /// Reports whether IPv4 dials should be slightly
    /// delayed to give IPv6 a better chance of winning dial races.
    /// Implementations should only return true if IPv6 is expected
    /// to succeed. (otherwise delaying IPv4 will delay the connection
    /// overall)
    fn prefer_ipv6(&self) -> bool {
        match self.address_family_selector {
            Some(ref selector) => selector(),
            None => false,
        }
    }
}

/// An established WebSocket connection to a relay server.
///
/// This is a [`Stream`] and a [`Sink`] of binary messages. Messages are not flushed
/// automatically.
#[derive(Debug)]
pub struct WsConnection {
    io: WsBytesFramed<MaybeTlsStream<ProxyStream>>,
    local_addr: SocketAddr,
}

impl WsConnection {
    /// Returns the local address of the underlying TCP connection.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl ExportKeyingMaterial for WsConnection {
    fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Option<T> {
        self.io.export_keying_material(output, label, context)
    }
}

impl Stream for WsConnection {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.io).poll_next(cx)
    }
}

impl Sink<Bytes> for WsConnection {
    type Error = StreamError;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.io).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        Pin::new(&mut self.io).start_send(item)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.io).poll_close(cx)
    }
}
