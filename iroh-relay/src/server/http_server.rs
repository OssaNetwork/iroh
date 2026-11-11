//! Low-level HTTP server components for embedding the relay service.
//!
//! This module provides [`RelayService`] which can be used to embed the relay's HTTP
//! endpoints into an existing HTTP server.
//!
//! For a complete relay server implementation, see the parent [`server`](super) module.

use std::{collections::HashMap, convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};

use derive_more::Debug;
use http::response::Builder as ResponseBuilder;
use hyper::{HeaderMap, Method, Request, Response, StatusCode, body::Incoming, service::Service};
use n0_error::{e, stack_error};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls_acme::AcmeAcceptor;
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{Instrument, debug, error, info, info_span};

use super::SpawnError;
use crate::server::{metrics::Metrics, streams::MaybeTlsStream};

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

/// Timeout for a connection to finish the TLS and WebSocket upgrade handshakes.
///
/// The connection is aborted if it is still open after this timeout.
const ESTABLISH_TIMEOUT: Duration = Duration::from_secs(30);

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
            metrics: None,
            establish_timeout: ESTABLISH_TIMEOUT,
        }
    }

    /// Sets the metrics collector.
    pub(super) fn metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = Some(metrics);
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
/// This service can be used standalone or embedded into an existing HTTP server.
#[derive(Clone, Debug)]
pub struct RelayService(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    handlers: Handlers,
    headers: HeaderMap,
    metrics: Arc<Metrics>,
}

impl Service<Request<Incoming>> for RelayService {
    type Response = Response<BytesBody>;
    type Error = HyperError;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let uri = req.uri().clone();
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
        mut res: ResponseBuilder,
    ) -> HyperResult<Response<BytesBody>> {
        for (k, v) in self.headers.iter() {
            res = res.header(k.clone(), v.clone());
        }
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
    /// This allows embedding the relay service into an existing HTTP server.
    pub fn new(handlers: Handlers, headers: HeaderMap, metrics: Arc<Metrics>) -> Self {
        Self(Arc::new(Inner {
            handlers,
            headers,
            metrics,
        }))
    }

    /// Handle the incoming connection.
    ///
    /// If a `tls_config` is given, will serve the connection using HTTPS, otherwise HTTP.
    ///
    /// The connection is aborted if it is still open after `establish_timeout`.
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
    /// let relay_service = RelayService::new(handlers, headers, metrics);
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
