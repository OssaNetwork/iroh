//! A dialer's TCP tunnel to a peer behind a relay.

use std::{
    net::{SocketAddr, SocketAddrV4},
    sync::Weak,
    time::Duration,
};

use bytes::Bytes;
use iroh_dns::dns::DnsResolver;
use n0_future::{SinkExt, StreamExt, time};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info_span, trace};
use url::Url;

use super::{
    WsConnection, WsDialer,
    addr::PathAddr,
    link::Inbound,
    socket::{Shared, TunnelRegistration},
};
use crate::protos::relay::{
    MAX_TUNNEL_FRAME_SIZE, TUNNEL_RELATIVE_PATH_PREFIX, TUNNEL_SUBPROTOCOL,
};

/// The TCP port a relay serves tunnels on.
pub(super) const TUNNEL_TCP_PORT: u16 = 443;

/// How many packets are held back while the tunnel is being opened.
const OUTBOUND_QUEUE_DEPTH: usize = 64;

/// How many queued packets are written to the tunnel before it is flushed.
const WRITE_BATCH: usize = 64;

/// How long a single write to the tunnel may take.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

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
}

impl TunnelConfig {
    /// Creates a configuration with the given TLS configuration.
    pub fn new(tls_config: rustls::ClientConfig) -> Self {
        Self {
            tls_config,
            tcp_port: TUNNEL_TCP_PORT,
            proxy_url: None,
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
/// Created with [`RelaySocketHandle::open_tunnel`]. Dropping the link closes the tunnel in
/// the background.
///
/// [`RelaySocketHandle::open_tunnel`]: super::RelaySocketHandle::open_tunnel
#[derive(Debug)]
pub struct TunnelLink {
    target: SocketAddrV4,
    state: watch::Receiver<TunnelState>,
    /// Stops the task. The task is not aborted, so that it can close the tunnel properly.
    cancel: CancellationToken,
    _registration: TunnelRegistration,
}

impl TunnelLink {
    pub(super) fn spawn(
        target: SocketAddrV4,
        config: TunnelConfig,
        inbound: mpsc::Sender<Inbound>,
        shared: Weak<Shared>,
    ) -> (Self, mpsc::Sender<Bytes>) {
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_QUEUE_DEPTH);
        let (state_tx, state_rx) = watch::channel(TunnelState::Connecting);
        let cancel = CancellationToken::new();
        let actor = Actor {
            target,
            config,
            inbound,
            outbound: outbound_rx,
            state: state_tx,
            cancel: cancel.clone(),
        };
        n0_future::task::spawn(actor.run().instrument(info_span!("tunnel", %target)));
        let link = Self {
            target,
            state: state_rx,
            cancel,
            _registration: TunnelRegistration::new(shared, target, outbound_tx.clone()),
        };
        (link, outbound_tx)
    }

    /// Returns the address the peer advertises, which the tunnel leads to.
    pub fn target(&self) -> SocketAddrV4 {
        self.target
    }

    /// Returns the address to dial the peer at with the QUIC stack, to reach it through
    /// the tunnel.
    pub fn addr(&self) -> SocketAddr {
        PathAddr::Tunnel {
            target: self.target,
        }
        .to_socket_addr()
    }

    /// Returns the current state of the tunnel.
    pub fn state(&self) -> TunnelState {
        self.state.borrow().clone()
    }

    /// Returns a receiver that is notified when the state of the tunnel changes.
    pub fn watch_state(&self) -> watch::Receiver<TunnelState> {
        self.state.clone()
    }

    /// Waits until the tunnel is open. Returns the reason if it could not be opened.
    pub async fn connected(&self) -> Result<(), String> {
        let mut state = self.state.clone();
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

impl Drop for TunnelLink {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

struct Actor {
    target: SocketAddrV4,
    config: TunnelConfig,
    inbound: mpsc::Sender<Inbound>,
    outbound: mpsc::Receiver<Bytes>,
    state: watch::Sender<TunnelState>,
    cancel: CancellationToken,
}

impl Actor {
    async fn run(mut self) {
        let conn = tokio::select! {
            _ = self.cancel.cancelled() => {
                self.state.send_replace(TunnelState::Closed("closed".to_string()));
                return;
            }
            res = self.connect() => res,
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
        let mut dialer = WsDialer::new(url, DnsResolver::new(), MAX_TUNNEL_FRAME_SIZE)
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
                    // The registration holds a sender, this does not end.
                    let Some(first) = first else {
                        return "closed".to_string();
                    };
                    let write = async {
                        conn.feed(first).await?;
                        for _ in 1..WRITE_BATCH {
                            match self.outbound.try_recv() {
                                Ok(packet) => conn.feed(packet).await?,
                                Err(_) => break,
                            }
                        }
                        conn.flush().await
                    };
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
