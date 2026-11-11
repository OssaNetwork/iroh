//! A dialer's TCP tunnel to a peer behind a relay.

use std::{
    net::{SocketAddr, SocketAddrV4},
    sync::{Arc, Weak},
    time::Duration,
};

use bytes::Bytes;
use n0_future::{SinkExt, StreamExt, time};

use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info_span, trace};
use url::Url;

use super::{
    HostResolver, WsConnection, WsDialer, addr::PathAddr, link::Inbound, socket::TunnelRegistration,
};
use crate::protos::{
    relay::{MAX_TUNNEL_FRAME_SIZE, TUNNEL_RELATIVE_PATH_PREFIX, TUNNEL_SUBPROTOCOL},
    streams::write_batch,
};

/// The TCP port a relay serves tunnels on.
pub(super) const TUNNEL_TCP_PORT: u16 = 443;

/// How many packets are held back while the tunnel is being opened.
const OUTBOUND_QUEUE_DEPTH: usize = 64;

/// How many queued packets are written to the tunnel before it is flushed.
const WRITE_BATCH: usize = 64;

/// How long a single write to the tunnel may take.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long opening the tunnel may take, from the TCP connection to the upgrade.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How to open a [`TunnelLink`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TunnelConfig {
    /// The TLS configuration for the connection to the relay.
    ///
    /// The relay presents a certificate for its IP address, which is verified against the
    /// IP address of the tunnel's target. The root certificates in here decide which
    /// issuers are trusted.
    pub tls_config: rustls::ClientConfig,
    /// The TCP port the relay serves tunnels on. This is 443, change it for tests only.
    pub tcp_port: u16,
    /// An HTTP proxy to connect through.
    pub proxy_url: Option<Url>,
    /// Resolves the host of the proxy. The relay itself is addressed by IP.
    pub resolver: HostResolver,
}

impl TunnelConfig {
    /// Creates a configuration with the given TLS configuration.
    pub fn new(tls_config: rustls::ClientConfig) -> Self {
        Self {
            tls_config,
            tcp_port: TUNNEL_TCP_PORT,
            proxy_url: None,
            resolver: HostResolver::default(),
        }
    }
}

/// The state of a [`TunnelLink`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TunnelState {
    /// The tunnel is being opened.
    Connecting,
    /// The tunnel is open.
    Connected,
    /// The tunnel could not be opened, or it closed. It does not reconnect.
    ///
    /// A tunnel that can not be opened means there is no fallback at the target: the peer
    /// is not behind a relay, or the relay does not serve tunnels. A refused connection,
    /// a failed certificate check and a rejected upgrade all end here.
    Closed(String),
}

/// A TCP tunnel to a peer behind a relay.
///
/// Created with [`RelaySocketHandle::open_tunnel`]. Clones refer to the same tunnel, which
/// is closed in the background when the last of them is dropped.
///
/// The relay closes a tunnel that carries no packets for two minutes. The QUIC connection
/// inside needs a keep-alive interval, or an idle timeout, shorter than that. A tunnel
/// that closed is not opened again, see [`TunnelState::Closed`].
///
/// [`RelaySocketHandle::open_tunnel`]: super::RelaySocketHandle::open_tunnel
#[derive(Debug, Clone)]
pub struct TunnelLink {
    inner: Arc<Inner>,
}

#[derive(Debug)]
pub(super) struct Inner {
    target: SocketAddrV4,
    state: watch::Receiver<TunnelState>,
    /// Stops the task. The task is not aborted, so that it can close the tunnel properly.
    cancel: CancellationToken,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl TunnelLink {
    /// Starts opening a tunnel. `registration` is dropped when the tunnel is over.
    pub(super) fn spawn(
        target: SocketAddrV4,
        config: TunnelConfig,
        inbound: mpsc::Sender<Inbound>,
        outbound: mpsc::Receiver<Bytes>,
        registration: TunnelRegistration,
    ) -> Self {
        let (state_tx, state_rx) = watch::channel(TunnelState::Connecting);
        let cancel = CancellationToken::new();
        let actor = Actor {
            target,
            config,
            inbound,
            outbound,
            state: state_tx,
            cancel: cancel.clone(),
            _registration: registration,
        };
        n0_future::task::spawn(actor.run().instrument(info_span!("tunnel", %target)));
        Self {
            inner: Arc::new(Inner {
                target,
                state: state_rx,
                cancel,
            }),
        }
    }

    /// Creates the queue of packets for a tunnel.
    pub(super) fn outbound_queue() -> (mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) {
        mpsc::channel(OUTBOUND_QUEUE_DEPTH)
    }

    /// Returns a link to the tunnel behind `inner`, if it is still usable.
    pub(super) fn upgrade(inner: &Weak<Inner>) -> Option<Self> {
        let inner = inner.upgrade()?;
        let closed = matches!(*inner.state.borrow(), TunnelState::Closed(_));
        (!closed).then_some(Self { inner })
    }

    pub(super) fn downgrade(&self) -> Weak<Inner> {
        Arc::downgrade(&self.inner)
    }

    /// Returns the address the peer advertises, which the tunnel leads to.
    pub fn target(&self) -> SocketAddrV4 {
        self.inner.target
    }

    /// Returns the address to dial the peer at with the QUIC stack, to reach it through
    /// the tunnel.
    pub fn addr(&self) -> SocketAddr {
        PathAddr::Tunnel {
            target: self.inner.target,
        }
        .to_socket_addr()
    }

    /// Returns the current state of the tunnel.
    pub fn state(&self) -> TunnelState {
        self.inner.state.borrow().clone()
    }

    /// Returns a receiver that is notified when the state of the tunnel changes.
    pub fn watch_state(&self) -> watch::Receiver<TunnelState> {
        self.inner.state.clone()
    }

    /// Waits until the tunnel is open. Returns the reason if it could not be opened.
    pub async fn connected(&self) -> Result<(), String> {
        let mut state = self.inner.state.clone();
        let res = state
            .wait_for(|state| !matches!(state, TunnelState::Connecting))
            .await;
        match res.as_deref() {
            Ok(TunnelState::Connected) => Ok(()),
            Ok(TunnelState::Closed(reason)) => Err(reason.clone()),
            Ok(TunnelState::Connecting) | Err(_) => Err("the tunnel was closed".to_string()),
        }
    }
}

struct Actor {
    target: SocketAddrV4,
    config: TunnelConfig,
    inbound: mpsc::Sender<Inbound>,
    outbound: mpsc::Receiver<Bytes>,
    state: watch::Sender<TunnelState>,
    cancel: CancellationToken,
    /// Removes the tunnel from the socket when the actor is done, so that packets are
    /// not queued for a tunnel that is gone.
    _registration: TunnelRegistration,
}

impl Actor {
    async fn run(mut self) {
        let conn = tokio::select! {
            _ = self.cancel.cancelled() => {
                self.state.send_replace(TunnelState::Closed("closed".to_string()));
                return;
            }
            res = time::timeout(CONNECT_TIMEOUT, self.connect()) => {
                res.unwrap_or_else(|_| Err("timed out".to_string()))
            }
        };
        let reason = match conn {
            Ok(conn) => {
                debug!("tunnel open");
                self.state.send_replace(TunnelState::Connected);
                self.serve(conn).await
            }
            Err(reason) => reason,
        };
        debug!("tunnel closed: {reason}");
        self.state.send_replace(TunnelState::Closed(reason));
    }

    async fn connect(&self) -> Result<WsConnection, String> {
        // The relay is addressed by IP. Its certificate is verified against that IP.
        let url = format!("https://{}:{}/", self.target.ip(), self.config.tcp_port);
        let url = Url::parse(&url).map_err(|err| err.to_string())?;
        let mut dialer = WsDialer::new(url, MAX_TUNNEL_FRAME_SIZE)
            .resolver(self.config.resolver.clone())
            .tls_client_config(self.config.tls_config.clone());
        if let Some(proxy_url) = &self.config.proxy_url {
            dialer = dialer.proxy_url(proxy_url.clone());
        }
        let path = format!("{TUNNEL_RELATIVE_PATH_PREFIX}{}", self.target.port());
        dialer
            .connect(&path, TUNNEL_SUBPROTOCOL)
            .await
            .map_err(|err| format!("{err:#}"))
    }

    async fn serve(&mut self, mut conn: WsConnection) -> String {
        let from = PathAddr::Tunnel {
            target: self.target,
        };
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    let _ = time::timeout(WRITE_TIMEOUT, conn.close()).await;
                    return "closed".to_string();
                }
                first = self.outbound.recv() => {
                    // The socket holds a sender for as long as the tunnel is registered.
                    let Some(first) = first else {
                        return "closed".to_string();
                    };
                    let write = write_batch(&mut conn, first, &mut self.outbound, WRITE_BATCH);
                    if !matches!(time::timeout(WRITE_TIMEOUT, write).await, Ok(Ok(()))) {
                        return "write failed".to_string();
                    }
                }
                packet = conn.next() => {
                    let payload = match packet {
                        Some(Ok(payload)) => payload,
                        Some(Err(err)) => return format!("read failed: {err:#}"),
                        None => return "closed by the relay".to_string(),
                    };
                    if self.inbound.try_send(Inbound { from, payload }).is_err() {
                        trace!("inbound queue full, dropping packet");
                    }
                }
            }
        }
    }
}
