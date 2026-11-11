//! Low-level HTTP server components for embedding the relay service.
//!
//! This module provides [`RelayService`] which can be used to embed the relay's HTTP
//! endpoints into an existing HTTP server.
//!
//! For a complete relay server implementation, see the parent [`server`](super) module.

use std::{collections::HashMap, convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use derive_more::Debug;
use http::{
    header::{CONNECTION, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL, SEC_WEBSOCKET_VERSION},
    response::Builder as ResponseBuilder,
};
use hyper::{
    HeaderMap, Method, Request, Response, StatusCode,
    body::Incoming,
    header::{HeaderValue, SEC_WEBSOCKET_ACCEPT, UPGRADE},
    service::Service,
    upgrade::Upgraded,
};
use n0_error::{e, ensure, stack_error};
use tokio::{
    net::{TcpListener, TcpStream},
    time::Instant,
};
use tokio_rustls_acme::AcmeAcceptor;
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{Instrument, debug, error, info, info_span, warn};

use super::{
    SpawnError,
    relay::{Relay, TunnelError},
};
use crate::{
    http::{SUPPORTED_WEBSOCKET_VERSION, WEBSOCKET_UPGRADE_PROTOCOL},
    protos::{
        relay::{
            CONTROL_RELATIVE_PATH, CONTROL_SUBPROTOCOL, MAX_FRAME_SIZE, MAX_TUNNEL_FRAME_SIZE,
            TUNNEL_RELATIVE_PATH_PREFIX, TUNNEL_SUBPROTOCOL,
        },
        streams::WsBytesFramed,
    },
    server::{metrics::Metrics, streams::MaybeTlsStream},
};

/// Boxed HTTP response body produced by [`RelayService`].
pub type BytesBody = Box<
    dyn 'static + Send + Unpin + hyper::body::Body<Data = hyper::body::Bytes, Error = Infallible>,
>;
/// Boxed error type returned from [`RelayService`]'s [`hyper::service::Service`] impl.
pub type HyperError = Box<dyn std::error::Error + Send + Sync>;
/// Result alias for HTTP responses produced by [`RelayService`].
pub type HyperResult<T> = std::result::Result<T, HyperError>;
pub(super) type HyperHandler = Box<
    dyn Fn(Request<Incoming>, ResponseBuilder) -> HyperResult<Response<BytesBody>>
        + Send
        + Sync
        + 'static,
>;

/// WebSocket GUID needed for accepting websocket connections, see RFC 6455 (<https://www.rfc-editor.org/rfc/rfc6455>) section 1.3
const SEC_WEBSOCKET_ACCEPT_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Timeout for a connection to become established.
///
/// A plain HTTP connection is aborted if it is still open after this timeout. A
/// connection that is upgraded to a WebSocket has this long, counted from the upgrade
/// request, for the client to authenticate and get its allocation.
const ESTABLISH_TIMEOUT: Duration = Duration::from_secs(30);

/// Derives the accept key for WebSocket handshake according to RFC 6455.
/// Takes the client's Sec-WebSocket-Key value and returns the calculated accept key.
fn derive_accept_key(client_key: &HeaderValue) -> String {
    use sha1::Digest;

    let mut sha1 = sha1::Sha1::new();
    sha1.update(client_key.as_bytes());
    sha1.update(SEC_WEBSOCKET_ACCEPT_GUID);
    data_encoding::BASE64.encode(&sha1.finalize())
}

fn downcast_upgrade(upgraded: Upgraded) -> Option<(MaybeTlsStream, Bytes)> {
    let parts = upgraded
        .downcast::<hyper_util::rt::TokioIo<MaybeTlsStream>>()
        .ok()?;
    Some((parts.io.into_inner(), parts.read_buf))
}

/// Creates a new [`BytesBody`] with given content.
fn body_full(content: impl Into<hyper::body::Bytes>) -> BytesBody {
    Box::new(http_body_util::Full::new(content.into()))
}

/// The Relay HTTP server.
///
/// A running HTTP server serving the relay endpoint and optionally a number of additional
/// HTTP services added with [`ServerBuilder::request_handler`].  If configured using
/// [`ServerBuilder::tls_config`] the server will handle TLS as well.
///
/// Created using [`ServerBuilder::spawn`].
#[derive(Debug)]
pub(super) struct Server {
    addr: SocketAddr,
    http_server_task: AbortOnDropHandle<()>,
    cancel_server_loop: CancellationToken,
    service: RelayService,
}

impl Server {
    /// Returns a handle for this server.
    ///
    /// The server runs in the background as several async tasks.  This allows controlling
    /// the server, in particular it allows gracefully shutting down the server.
    pub(super) fn handle(&self) -> ServerHandle {
        ServerHandle {
            cancel_token: self.cancel_server_loop.clone(),
        }
    }

    /// Closes the underlying relay server and the HTTP(S) server tasks.
    pub(super) fn shutdown(&self) {
        self.cancel_server_loop.cancel();
    }

    /// Returns the [`AbortOnDropHandle`] for the supervisor task managing the server.
    ///
    /// This is the root of all the tasks for the server.  Aborting it will abort all the
    /// other tasks for the server.  Awaiting it will complete when all the server tasks are
    /// completed.
    pub(super) fn task_handle(&mut self) -> &mut AbortOnDropHandle<()> {
        &mut self.http_server_task
    }

    /// Returns the local address of this server.
    pub(super) fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Returns the [`RelayService`] driving this server.
    pub(super) fn service(&self) -> &RelayService {
        &self.service
    }
}

/// A handle for the [`Server`].
///
/// This does not allow access to the task but can communicate with it.
#[derive(Debug, Clone)]
pub(super) struct ServerHandle {
    cancel_token: CancellationToken,
}

impl ServerHandle {
    /// Gracefully shut down the server.
    pub(super) fn shutdown(&self) {
        self.cancel_token.cancel()
    }
}

/// Configuration to use for the TLS connection
///
/// This struct wraps a rustls server configuration and TLS acceptor for use with
/// [`RelayService::handle_connection`].
///
/// # Example
///
/// ```
/// use std::sync::Arc;
///
/// use iroh_relay::server::http_server::TlsConfig;
/// use rustls::ServerConfig;
/// use webpki_types::{CertificateDer, PrivateKeyDer};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Set ring as the process-level default crypto provider
/// rustls::crypto::ring::default_provider()
///     .install_default()
///     .ok();
/// // Generate a self-signed certificate for testing
/// let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
/// let cert_der = cert.cert.der().to_vec();
/// let private_key_der = cert.signing_key.serialize_der();
///
/// // Create rustls types
/// let cert_chain = vec![CertificateDer::from(cert_der)];
/// let private_key = PrivateKeyDer::try_from(private_key_der)?;
///
/// // Create a rustls ServerConfig
/// let server_config = Arc::new(
///     ServerConfig::builder()
///         .with_no_client_auth()
///         .with_single_cert(cert_chain, private_key)?,
/// );
///
/// // Create TlsConfig for use with RelayService
/// let tls_config = TlsConfig::new(server_config);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// The server config
    pub(super) config: Arc<rustls::ServerConfig>,
    /// The kind
    pub(super) acceptor: TlsAcceptor,
}

impl TlsConfig {
    /// Creates a new `TlsConfig` from a rustls `ServerConfig`.
    ///
    /// This creates a manual TLS acceptor using the provided server configuration.
    /// The acceptor will handle TLS handshakes for incoming connections.
    ///
    /// # Example
    ///
    /// ```
    /// use std::sync::Arc;
    ///
    /// use iroh_relay::server::http_server::TlsConfig;
    /// use rustls::ServerConfig;
    /// use webpki_types::{CertificateDer, PrivateKeyDer};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Set ring as the process-level default crypto provider
    /// rustls::crypto::ring::default_provider()
    ///     .install_default()
    ///     .ok();
    /// // Generate a self-signed certificate for testing
    /// let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    /// let cert_der = cert.cert.der().to_vec();
    /// let private_key_der = cert.signing_key.serialize_der();
    ///
    /// // Create rustls types
    /// let cert_chain = vec![CertificateDer::from(cert_der)];
    /// let private_key = PrivateKeyDer::try_from(private_key_der)?;
    ///
    /// let server_config = Arc::new(
    ///     ServerConfig::builder()
    ///         .with_no_client_auth()
    ///         .with_single_cert(cert_chain, private_key)?,
    /// );
    ///
    /// let tls_config = TlsConfig::new(server_config);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(config: Arc<rustls::ServerConfig>) -> Self {
        let acceptor = tokio_rustls::TlsAcceptor::from(config.clone());
        Self {
            config,
            acceptor: TlsAcceptor::Manual(acceptor),
        }
    }
}

/// Errors when attempting to upgrade and
#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum ServeConnectionError {
    #[error("TLS[acme] handshake")]
    TlsHandshake {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[error("TLS[acme] serve connection")]
    ServeConnection {
        #[error(std_err)]
        source: hyper::Error,
    },
    #[error("TLS[manual] accept")]
    ManualAccept {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[error("TLS[acme] accept")]
    LetsEncryptAccept {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[error("HTTPS connection")]
    Https {
        #[error(std_err)]
        source: hyper::Error,
    },
    #[error("HTTP connection")]
    Http {
        #[error(std_err)]
        source: hyper::Error,
    },
    #[error("Connection did not reach established state within timeout")]
    EstablishTimeout,
}

/// Builder for the Relay HTTP Server.
///
/// HTTP endpoints are added using [`ServerBuilder::request_handler`].
#[derive(derive_more::Debug)]
pub(super) struct ServerBuilder {
    /// The ip + port combination for this server.
    addr: SocketAddr,
    /// Optional tls configuration/TlsAcceptor combination.
    ///
    /// When `None`, the server will serve HTTP, otherwise it will serve HTTPS.
    tls_config: Option<TlsConfig>,
    /// A map of request handlers to routes.
    ///
    /// Used when certain routes in your server should be made available at the same port as
    /// the relay server, and so must be handled along side requests to the relay endpoint.
    handlers: Handlers,
    /// Headers to use for HTTP responses.
    headers: HeaderMap,
    /// The relay to serve on the control endpoint, if any.
    relay: Option<Relay>,
    metrics: Option<Arc<Metrics>>,
    establish_timeout: Duration,
}

impl ServerBuilder {
    /// Creates a new [ServerBuilder].
    pub(super) fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            tls_config: None,
            handlers: Default::default(),
            headers: HeaderMap::new(),
            relay: None,
            metrics: None,
            establish_timeout: ESTABLISH_TIMEOUT,
        }
    }

    /// Sets the metrics collector.
    pub(super) fn metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Serves the control channels of `relay`.
    pub(super) fn relay(mut self, relay: Option<Relay>) -> Self {
        self.relay = relay;
        self
    }

    /// Serves all requests content using TLS.
    pub(super) fn tls_config(mut self, config: Option<TlsConfig>) -> Self {
        self.tls_config = config;
        self
    }

    /// Adds a custom handler for a specific Method & URI.
    pub(super) fn request_handler(
        mut self,
        method: Method,
        uri_path: &'static str,
        handler: HyperHandler,
    ) -> Self {
        self.handlers.insert((method, uri_path), handler);
        self
    }

    /// Adds HTTP headers to responses.
    pub(super) fn headers(mut self, headers: HeaderMap) -> Self {
        for (k, v) in headers.iter() {
            self.headers.insert(k.clone(), v.clone());
        }
        self
    }

    /// Builds and spawns an HTTP(S) Relay Server.
    pub(super) async fn spawn(self) -> Result<Server, SpawnError> {
        let cancel_token = CancellationToken::new();

        let service = RelayService::new(
            self.handlers,
            self.headers,
            self.relay,
            self.metrics.unwrap_or_default(),
        );

        let addr = self.addr;
        let tls_config = self.tls_config;

        // Bind a TCP listener on `addr` and handles content using HTTPS.

        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|err| e!(super::SpawnError::BindTcpListener { addr }, err))?;

        let addr = listener
            .local_addr()
            .map_err(|err| e!(super::SpawnError::NoLocalAddr, err))?;
        let http_str = tls_config.as_ref().map_or("HTTP/WS", |_| "HTTPS/WSS");
        info!("[{http_str}] relay: serving on {addr}");

        let cancel = cancel_token.clone();
        let loop_service = service.clone();
        let task = tokio::task::spawn(
            async move {
                let service = loop_service;
                // create a join set to track all our connection tasks
                let mut set = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => {
                            break;
                        }
                        Some(res) = set.join_next() => {
                            if let Err(err) = res
                                && err.is_panic()
                            {
                                panic!("task panicked: {err:#?}");
                            }
                        }
                        res = listener.accept() => match res {
                            Ok((stream, peer_addr)) => {
                                debug!("connection opened from {peer_addr}");
                                let tls_config = tls_config.clone();
                                let service = service.clone();
                                // spawn a task to handle the connection
                                set.spawn(async move {
                                    service
                                        .handle_connection(stream, tls_config, self.establish_timeout)
                                        .await
                                }.instrument(info_span!("conn", peer = %peer_addr)));
                            }
                            Err(err) => {
                                error!("failed to accept connection: {err}");
                            }
                        }
                    }
                }
                service.shutdown();
                set.shutdown().await;
                debug!("server has been shutdown.");
            }
            .instrument(info_span!("relay-http-serve")),
        );

        Ok(Server {
            addr,
            http_server_task: AbortOnDropHandle::new(task),
            cancel_server_loop: cancel_token,
            service,
        })
    }
}

/// The hyper Service that serves the relay's HTTP endpoints.
///
/// This service can be used standalone or embedded into an existing HTTP server. Note
/// that the service has to be called with hyper's `io` argument set to a
/// [`MaybeTlsStream`] wrapped by [`hyper_util::rt::TokioIo`], otherwise WebSocket
/// requests fail after the upgrade.
#[derive(Clone, Debug)]
pub struct RelayService(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    handlers: Handlers,
    headers: HeaderMap,
    relay: Option<Relay>,
    metrics: Arc<Metrics>,
}

#[stack_error(derive, add_meta)]
enum UpgradeReqError {
    #[error("missing header: {header}")]
    MissingHeader { header: http::HeaderName },
    #[error("invalid header value for {header}: {details}")]
    InvalidHeader {
        header: http::HeaderName,
        details: String,
    },
    #[error(
        "invalid header value for {SEC_WEBSOCKET_VERSION}: unsupported websocket version, only supporting {SUPPORTED_WEBSOCKET_VERSION}"
    )]
    UnsupportedWebsocketVersion,
    #[error(
        "invalid header value for {SEC_WEBSOCKET_PROTOCOL}: unsupported subprotocol: we support {we_support} but you only provide {you_support}"
    )]
    UnsupportedSubprotocol {
        we_support: &'static str,
        you_support: String,
    },
}

/// Checks that `req` asks for a WebSocket speaking `subprotocol`.
///
/// Returns the client's key for the handshake.
fn check_ws_upgrade(
    req: &Request<Incoming>,
    subprotocol: &'static str,
) -> Result<HeaderValue, UpgradeReqError> {
    fn expect_header(
        req: &Request<Incoming>,
        header: http::HeaderName,
    ) -> Result<&HeaderValue, UpgradeReqError> {
        req.headers()
            .get(&header)
            .ok_or_else(|| e!(UpgradeReqError::MissingHeader { header }))
    }

    let upgrade_header = expect_header(req, UPGRADE)?;
    ensure!(
        upgrade_header
            .as_bytes()
            .eq_ignore_ascii_case(WEBSOCKET_UPGRADE_PROTOCOL.as_bytes()),
        UpgradeReqError::InvalidHeader {
            header: UPGRADE,
            details: format!("value must be {WEBSOCKET_UPGRADE_PROTOCOL}")
        }
    );

    let key = expect_header(req, SEC_WEBSOCKET_KEY)?.clone();
    let version = expect_header(req, SEC_WEBSOCKET_VERSION)?;
    ensure!(
        version.as_bytes() == SUPPORTED_WEBSOCKET_VERSION.as_bytes(),
        UpgradeReqError::UnsupportedWebsocketVersion
    );

    let subprotocols = expect_header(req, SEC_WEBSOCKET_PROTOCOL)?
        .to_str()
        .map_err(|_| {
            e!(UpgradeReqError::InvalidHeader {
                header: SEC_WEBSOCKET_PROTOCOL,
                details: "header value is not ascii".to_string()
            })
        })?;
    ensure!(
        subprotocols.split(',').any(|s| s.trim() == subprotocol),
        UpgradeReqError::UnsupportedSubprotocol {
            we_support: subprotocol,
            you_support: subprotocols.to_string()
        }
    );
    Ok(key)
}

impl RelayService {
    fn build_response(&self) -> ResponseBuilder {
        self.0.default_response()
    }

    /// Answers a WebSocket upgrade request.
    ///
    /// Once the connection is upgraded `serve` is called with the WebSocket and what is
    /// known about the request.
    fn handle_ws_upgrade<F, Fut>(
        &self,
        mut req: Request<Incoming>,
        subprotocol: &'static str,
        max_payload_len: usize,
        serve: F,
    ) -> HyperResult<Response<BytesBody>>
    where
        F: FnOnce(WsBytesFramed<MaybeTlsStream>, UpgradedRequest) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send,
    {
        let key = match check_ws_upgrade(&req, subprotocol) {
            Ok(key) => key,
            // It's convention to send back the version(s) we *do* support
            Err(err @ UpgradeReqError::UnsupportedWebsocketVersion { .. }) => {
                return Ok(self
                    .build_response()
                    .status(StatusCode::BAD_REQUEST)
                    .header(SEC_WEBSOCKET_VERSION, SUPPORTED_WEBSOCKET_VERSION)
                    .body(body_full(err.to_string()))?);
            }
            Err(err) => {
                return Ok(self
                    .build_response()
                    .status(StatusCode::BAD_REQUEST)
                    .body(body_full(err.to_string()))?);
            }
        };

        // Setup a future that will eventually receive the upgraded
        // connection and talk a new protocol, and spawn the future
        // into the runtime.
        //
        // Note: This can't possibly be fulfilled until the 101 response
        // is returned below, so it's better to spawn this future instead
        // waiting for it to complete to then return a response.
        let deadline = Instant::now() + ESTABLISH_TIMEOUT;
        tokio::task::spawn(
            async move {
                let upgraded =
                    match tokio::time::timeout_at(deadline, hyper::upgrade::on(&mut req)).await {
                        Ok(Ok(upgraded)) => upgraded,
                        Ok(Err(err)) => {
                            warn!("upgrade error: {err:#}");
                            return;
                        }
                        Err(_) => {
                            debug!("upgrade timed out");
                            return;
                        }
                    };
                let Some((io, read_buf)) = downcast_upgrade(upgraded) else {
                    warn!("could not downcast the upgraded connection to MaybeTlsStream");
                    return;
                };
                if !read_buf.is_empty() {
                    // The client must wait for the upgrade response before it sends
                    // WebSocket frames.
                    warn!("client sent data before the upgrade completed");
                    return;
                }
                io.disable_nagle();
                let peer = io.peer_addr().ok();
                let websocket = tokio_websockets::ServerBuilder::new()
                    .limits(
                        tokio_websockets::Limits::default().max_payload_len(Some(max_payload_len)),
                    )
                    // Serve will create a WebSocketStream on an already upgraded connection
                    .serve(io);
                let (parts, _) = req.into_parts();
                let request = UpgradedRequest {
                    parts,
                    deadline,
                    peer,
                };
                serve(WsBytesFramed { io: websocket }, request).await;
            }
            .instrument(info_span!("handler")),
        );

        // Now return a 101 Response saying we agree to the upgrade to the
        // websocket upgrade protocol
        Ok(self
            .build_response()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(
                UPGRADE,
                HeaderValue::from_static(WEBSOCKET_UPGRADE_PROTOCOL),
            )
            .header(SEC_WEBSOCKET_ACCEPT, derive_accept_key(&key))
            .header(
                SEC_WEBSOCKET_PROTOCOL,
                HeaderValue::from_static(subprotocol),
            )
            .header(CONNECTION, "upgrade")
            .body(body_full("switching to websocket protocol"))?)
    }

    /// Upgrades the connection to the control channel of a client.
    fn handle_control(
        &self,
        relay: Relay,
        req: Request<Incoming>,
    ) -> HyperResult<Response<BytesBody>> {
        self.handle_ws_upgrade(
            req,
            CONTROL_SUBPROTOCOL,
            MAX_FRAME_SIZE,
            move |io, request| async move {
                let accept = relay.accept_control(io, request.parts.uri, request.parts.headers);
                match tokio::time::timeout_at(request.deadline, accept).await {
                    Ok(Ok(connection)) => connection.run().await,
                    Ok(Err(err)) => debug!("control channel not accepted: {err:#}"),
                    Err(_) => debug!("control channel establishment timed out"),
                }
            },
        )
    }
}

impl RelayService {
    /// Upgrades the connection to the tunnel of a dialer to the allocation on `port`.
    fn handle_tunnel(
        &self,
        relay: Relay,
        port: u16,
        req: Request<Incoming>,
    ) -> HyperResult<Response<BytesBody>> {
        // Refuse before the upgrade. A dialer takes a rejected upgrade to mean that
        // there is no fallback at this address.
        match relay.check_tunnel(port) {
            Ok(()) => {}
            Err(TunnelError::TooManyTunnels { .. }) => {
                return Ok(self
                    .build_response()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(body_full("too many tunnels"))?);
            }
            Err(_) => return self.0.not_found_fn(req, self.0.default_response()),
        }
        self.handle_ws_upgrade(
            req,
            TUNNEL_SUBPROTOCOL,
            MAX_TUNNEL_FRAME_SIZE,
            move |io, request| async move {
                let Some(peer) = request.peer else {
                    debug!("tunnel without a peer address");
                    return;
                };
                match relay.open_tunnel(port, peer) {
                    Ok(tunnel) => tunnel.run(io).await,
                    Err(err) => debug!("tunnel not opened: {err:#}"),
                }
            },
        )
    }
}

/// What is known about a request once its connection was upgraded to a WebSocket.
struct UpgradedRequest {
    /// The head of the request.
    parts: http::request::Parts,
    /// Until when whatever is served on the WebSocket has to be established.
    deadline: Instant,
    /// The address of the remote end of the connection.
    peer: Option<SocketAddr>,
}

impl Service<Request<Incoming>> for RelayService {
    type Response = Response<BytesBody>;
    type Error = HyperError;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let uri = req.uri().clone();
        if let Some(relay) = &self.0.relay
            && req.method() == Method::GET
            && uri.path().strip_prefix('/') == Some(CONTROL_RELATIVE_PATH)
        {
            return std::future::ready(self.handle_control(relay.clone(), req));
        }
        if let Some(relay) = &self.0.relay
            && req.method() == Method::GET
            && let Some(port) = uri
                .path()
                .strip_prefix('/')
                .and_then(|path| path.strip_prefix(TUNNEL_RELATIVE_PATH_PREFIX))
        {
            // Only the canonical decimal form names a port.
            return std::future::ready(match port.parse::<u16>() {
                Ok(parsed) if parsed != 0 && parsed.to_string() == port => {
                    self.handle_tunnel(relay.clone(), parsed, req)
                }
                _ => self.0.not_found_fn(req, self.0.default_response()),
            });
        }

        if let Some(handler) = self.0.handlers.get(&(req.method().clone(), uri.path())) {
            let response = handler(req, self.0.default_response());
            return std::future::ready(response);
        }

        // Otherwise return 404
        let response = self.0.not_found_fn(req, self.0.default_response());
        std::future::ready(response)
    }
}

impl Inner {
    fn default_response(&self) -> ResponseBuilder {
        let mut response = Response::builder();
        for (key, value) in self.headers.iter() {
            response = response.header(key.clone(), value.clone());
        }
        response
    }

    fn not_found_fn(
        &self,
        _req: Request<Incoming>,
        res: ResponseBuilder,
    ) -> HyperResult<Response<BytesBody>> {
        let body = body_full("Not Found");
        let r = res.status(StatusCode::NOT_FOUND).body(body)?;
        HyperResult::Ok(r)
    }
}

/// TLS Certificate Authority acceptor.
#[derive(Clone, derive_more::Debug)]
pub(super) enum TlsAcceptor {
    /// Uses Let's Encrypt as the Certificate Authority. This is used in production.
    LetsEncrypt(#[debug("tokio_rustls_acme::AcmeAcceptor")] AcmeAcceptor),
    /// Manually added tls acceptor. Generally used for tests or for when we've passed in
    /// a certificate via a file.
    Manual(#[debug("tokio_rustls::TlsAcceptor")] tokio_rustls::TlsAcceptor),
}

impl RelayService {
    /// Creates a new RelayService.
    ///
    /// This allows embedding the relay service into an existing HTTP server. If `relay`
    /// is given its control channels are served, otherwise only `handlers` are.
    pub fn new(
        handlers: Handlers,
        headers: HeaderMap,
        relay: Option<Relay>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self(Arc::new(Inner {
            handlers,
            headers,
            relay,
            metrics,
        }))
    }

    /// Returns the relay whose control channels this service serves.
    pub fn relay(&self) -> Option<&Relay> {
        self.0.relay.as_ref()
    }

    /// Closes all control channels and releases all allocations.
    pub fn shutdown(&self) {
        if let Some(relay) = &self.0.relay {
            relay.shutdown();
        }
    }

    /// Handle the incoming connection.
    ///
    /// If a `tls_config` is given, will serve the connection using HTTPS, otherwise HTTP.
    ///
    /// A plain HTTP connection is aborted if it is still open after `establish_timeout`.
    /// A connection that was upgraded to a WebSocket is not affected. Its client has 30
    /// seconds from the upgrade request to authenticate.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::{sync::Arc, time::Duration};
    /// # use tokio::net::TcpStream;
    /// # use http::HeaderMap;
    /// # use iroh_relay::server::http_server::{Handlers, RelayService, TlsConfig};
    /// # use iroh_relay::server::Metrics;
    /// # use webpki_types::{CertificateDer, PrivateKeyDer};
    /// # async fn example(stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    /// // Create a relay service
    /// let handlers = Handlers::default();
    /// let headers = HeaderMap::new();
    /// let metrics = Arc::new(Metrics::default());
    /// let relay_service = RelayService::new(handlers, headers, None, metrics);
    ///
    /// // Generate a self-signed certificate for HTTPS
    /// let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    /// let cert_der = cert.cert.der().to_vec();
    /// let private_key_der = cert.signing_key.serialize_der();
    /// let cert_chain = vec![CertificateDer::from(cert_der)];
    /// let private_key = PrivateKeyDer::try_from(private_key_der)?;
    ///
    /// // Serve with HTTPS
    /// let server_config = Arc::new(
    ///     rustls::ServerConfig::builder()
    ///         .with_no_client_auth()
    ///         .with_single_cert(cert_chain, private_key)?,
    /// );
    /// let tls_config = TlsConfig::new(server_config);
    /// relay_service
    ///     .clone()
    ///     .handle_connection(stream, Some(tls_config), Duration::from_secs(30))
    ///     .await;
    ///
    /// // Or serve with plain HTTP
    /// # let stream = TcpStream::connect("127.0.0.1:0").await?;
    /// relay_service
    ///     .handle_connection(stream, None, Duration::from_secs(30))
    ///     .await;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn handle_connection(
        self,
        stream: TcpStream,
        tls_config: Option<TlsConfig>,
        establish_timeout: Duration,
    ) {
        let metrics = self.0.metrics.clone();
        metrics.http_connections.inc();
        let service = self;

        // This is the main connection future, driving the connection to completion.
        let serve_fut = async move {
            match tls_config {
                Some(tls_config) => {
                    debug!("HTTPS: serve connection");
                    service.tls_serve_connection(stream, tls_config).await
                }
                None => {
                    debug!("HTTP: serve connection");
                    let stream = MaybeTlsStream::Plain(stream);
                    service.serve_connection(stream).await
                }
            }
        };

        let res = tokio::time::timeout(establish_timeout, serve_fut)
            .await
            .map_err(|_elapsed| e!(ServeConnectionError::EstablishTimeout))
            .flatten();

        metrics.http_connections_closed.inc();

        if let Err(error) = res {
            match error {
                ServeConnectionError::ManualAccept { source, .. }
                | ServeConnectionError::LetsEncryptAccept { source, .. }
                    if source.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    debug!(reason=?source, "peer disconnected");
                }
                // From hyper: <https://github.com/hyperium/hyper/commit/271bba16672ff54a44e043c5cc1ae6b9345bb172>
                // `hyper::Error::IncompleteMessage` is hyper's equivalent of UnexpectedEof
                ServeConnectionError::Https { source, .. }
                | ServeConnectionError::Http { source, .. }
                    if source.is_incomplete_message() =>
                {
                    debug!(reason=?source, "peer disconnected");
                }
                _ => {
                    metrics.http_connections_errored.inc();
                    error!(?error, "failed to handle connection");
                }
            }
        }
    }
}

impl RelayService {
    /// Serves a TLS connection.
    async fn tls_serve_connection(
        self,
        stream: TcpStream,
        tls_config: TlsConfig,
    ) -> Result<(), ServeConnectionError> {
        let TlsConfig { acceptor, config } = tls_config;
        let stream = match acceptor {
            TlsAcceptor::LetsEncrypt(a) => {
                match a
                    .accept(stream)
                    .await
                    .map_err(|err| e!(ServeConnectionError::LetsEncryptAccept, err))?
                {
                    None => {
                        info!("TLS[acme]: received TLS-ALPN-01 validation request");
                        return Ok(());
                    }
                    Some(start_handshake) => {
                        debug!("TLS[acme]: start handshake");
                        let tls_stream = start_handshake
                            .into_stream(config)
                            .await
                            .map_err(|err| e!(ServeConnectionError::TlsHandshake, err))?;
                        MaybeTlsStream::Tls(tls_stream)
                    }
                }
            }
            TlsAcceptor::Manual(a) => {
                debug!("TLS[manual]: accept");
                let tls_stream = a
                    .accept(stream)
                    .await
                    .map_err(|err| e!(ServeConnectionError::ManualAccept, err))?;
                MaybeTlsStream::Tls(tls_stream)
            }
        };
        self.serve_connection(stream).await
    }

    /// Wrapper for the actual http connection (with upgrades)
    async fn serve_connection(self, io: MaybeTlsStream) -> Result<(), ServeConnectionError> {
        hyper::server::conn::http1::Builder::new()
            .serve_connection(hyper_util::rt::TokioIo::new(io), self)
            .with_upgrades()
            .await
            .map_err(|err| e!(ServeConnectionError::ServeConnection, err))
    }
}

/// A collection of HTTP request handlers for custom endpoints.
#[derive(Default)]
pub struct Handlers(HashMap<(Method, &'static str), HyperHandler>);

impl std::fmt::Debug for Handlers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.0.keys().fold(String::new(), |curr, next| {
            let (method, uri) = next;
            format!("{curr}\n({method},{uri}): Box<Fn(ResponseBuilder) -> Result<Response<Body>> + Send + Sync + 'static>")
        });
        write!(f, "HashMap<{s}>")
    }
}

impl std::ops::Deref for Handlers {
    type Target = HashMap<(Method, &'static str), HyperHandler>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Handlers {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
