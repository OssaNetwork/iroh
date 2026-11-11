//! The relay: allocations and the control channels of their clients.
//!
//! A client authenticates on a control channel and gets an *allocation*: a UDP socket on
//! a public port of the relay. Packets arriving on that socket are forwarded to the
//! client on its control channel, tagged with their source address. Packets the client
//! sends on the control channel are emitted from the socket.
//!
//! An allocation outlives the control channel by the release timeout. A client that
//! reconnects in time keeps its port, and the socket stays bound in between so that no
//! one else can take it. Packets arriving for a client that is not connected are dropped.
//!
//! A dialer whose network blocks UDP reaches an allocation through a *tunnel* instead: a
//! WebSocket to the relay on which every message is one QUIC packet. To the client a
//! tunnelled dialer is one more remote party, marked as tunnelled.
//!
//! [`Relay`] is the entry point. [`Relay::accept_control`] takes a WebSocket that a client
//! opened and returns a [`ControlConnection`] once the client is authenticated and has
//! its allocation. [`Relay::open_tunnel`] attaches a dialer's WebSocket to an allocation.

use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    ops::RangeInclusive,
    sync::{
        Arc, Mutex, MutexGuard, Weak,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use bytes::{BufMut, Bytes, BytesMut};
use http::{HeaderMap, Uri};
use n0_error::{e, stack_error};
use n0_future::{
    SinkExt, StreamExt,
    time::{self, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::{Notify, mpsc},
};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{Instrument, debug, info_span, trace, warn};

use super::{
    ClientId, Metrics,
    allocator::{
        DEFAULT_PORT_RANGE, DEFAULT_RELEASE_TIMEOUT, InvalidPortRange, PortAllocator, Released,
    },
    auth::{AuthRequest, DynAuthenticator},
    policy::{AllocationPolicy, Direction, Packet, TrafficPolicy, Verdict},
};
use crate::{
    ExportKeyingMaterial, PingTracker,
    auth::channel_binding,
    protos::{
        relay::{
            ClientControl, ClientFrame, DATAGRAM_HEADER_LEN, Datagram, DhtStatus, ErrorCode,
            MAX_PACKET_SIZE, RelayControl, RelayFrame, RemoteAddr,
        },
        streams::BytesStreamSink,
    },
};

/// The default largest QUIC packet the relay forwards.
///
/// QUIC packets do not exceed the path MTU, which is 1500 bytes on almost every path.
pub const DEFAULT_MAX_PACKET_SIZE: usize = 1500;

/// How many packets wait for a client's control channel before the relay drops packets.
const INBOUND_QUEUE_DEPTH: usize = 512;

/// How many queued packets are written to the control channel before it is flushed.
const WRITE_BATCH: usize = 64;

/// How many ports are tried when binding the socket of a new allocation fails.
const MAX_BIND_ATTEMPTS: usize = 8;

/// How long to wait for a socket the relay is closing to release its port, and how often
/// to look.
const CLOSING_WAIT: Duration = Duration::from_secs(1);
const CLOSING_POLL: Duration = Duration::from_millis(5);

/// How long the reader of an allocation pauses after its socket reported an error.
const READ_ERROR_BACKOFF: Duration = Duration::from_millis(20);

/// The default number of tunnels that can be open to one allocation.
pub const DEFAULT_MAX_TUNNELS: usize = 64;

/// How many packets wait for a tunnel before the relay drops packets.
const TUNNEL_QUEUE_DEPTH: usize = 128;

/// How long a tunnel may carry no packets before the relay closes it.
///
/// A QUIC connection with keep-alives never lets its tunnel idle this long.
const TUNNEL_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// The size of the buffers packets are received into.
///
/// One buffer serves several packets. It is released once all of them left the relay.
const RECV_CHUNK: usize = 8 * 1024;

/// How long a client has to present its credentials after opening the control channel.
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a single write to the control channel may take.
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// How often the relay pings an idle client.
const PING_INTERVAL: Duration = Duration::from_secs(15);

/// Configuration of the allocations a [`Relay`] hands out.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AllocationConfig {
    /// The public IPv4 address of the relay. Clients advertise it as their own.
    pub public_ip: Ipv4Addr,
    /// The local address the sockets of the allocations are bound to.
    ///
    /// This differs from [`Self::public_ip`] on hosts that sit behind a 1:1 NAT, as is
    /// common with cloud providers. Defaults to [`Self::public_ip`].
    pub bind_ip: Ipv4Addr,
    /// The ports handed out to clients. Defaults to [`DEFAULT_PORT_RANGE`].
    pub ports: RangeInclusive<u16>,
    /// How long a port stays reserved for its client after the control channel closed.
    /// Defaults to [`DEFAULT_RELEASE_TIMEOUT`].
    pub release_timeout: Duration,
    /// The largest QUIC packet the relay forwards, larger packets are dropped. Defaults
    /// to [`DEFAULT_MAX_PACKET_SIZE`].
    pub max_packet_size: usize,
    /// How many tunnels can be open to one allocation at a time. Defaults to
    /// [`DEFAULT_MAX_TUNNELS`]. With 0 the relay does not serve tunnels.
    pub max_tunnels: usize,
    /// Decides which clients may open a control channel, and their identity.
    pub authenticator: Arc<dyn DynAuthenticator>,
    /// Decides which packets are forwarded.
    pub policy: Arc<dyn TrafficPolicy>,
}

impl AllocationConfig {
    /// Creates a configuration with default settings for a relay at `public_ip`.
    pub fn new(
        public_ip: Ipv4Addr,
        authenticator: Arc<dyn DynAuthenticator>,
        policy: Arc<dyn TrafficPolicy>,
    ) -> Self {
        Self {
            public_ip,
            bind_ip: public_ip,
            ports: DEFAULT_PORT_RANGE,
            release_timeout: DEFAULT_RELEASE_TIMEOUT,
            max_packet_size: DEFAULT_MAX_PACKET_SIZE,
            max_tunnels: DEFAULT_MAX_TUNNELS,
            authenticator,
            policy,
        }
    }
}

/// Errors when accepting a control channel.
#[stack_error(derive, add_meta)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum AcceptError {
    #[error("the client did not authenticate in time")]
    AuthTimeout,
    #[error("the control channel closed before the client authenticated")]
    Closed,
    #[error("the client violated the protocol: {reason}")]
    Protocol { reason: String },
    #[error("the client was rejected: {reason}")]
    Rejected { reason: String },
    #[error("no port is available")]
    NoPortAvailable,
    #[error("failed to bind the socket of the allocation")]
    Bind {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[error("the relay is shutting down")]
    Shutdown,
}

/// Errors when opening a tunnel.
#[stack_error(derive, add_meta)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum TunnelError {
    #[error("no allocation has port {port}")]
    UnknownPort { port: u16 },
    #[error("too many tunnels are open to the allocation")]
    TooManyTunnels,
}

/// The configuration of a [`Relay`] is not usable.
#[stack_error(derive, add_meta, from_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum InvalidConfig {
    #[error(transparent)]
    PortRange { source: InvalidPortRange },
    #[error("max_packet_size must be between 1 and {MAX_PACKET_SIZE}, got {max_packet_size}")]
    MaxPacketSize { max_packet_size: usize },
}

/// The relay.
///
/// Cheap to clone, all clones refer to the same relay. Dropping the last clone releases
/// all allocations.
#[derive(Debug, Clone)]
pub struct Relay(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    config: AllocationConfig,
    state: Mutex<State>,
    /// Wakes the expiry task when the earliest release deadline may have changed.
    expiry_changed: Arc<Notify>,
    /// Cancelled when the relay shuts down.
    shutdown: CancellationToken,
    metrics: Arc<Metrics>,
    /// Frees allocations when their release timeout passes.
    expiry_task: Mutex<Option<AbortOnDropHandle<()>>>,
    /// Counts the addresses made up for tunnels.
    next_tunnel_name: AtomicU32,
}

#[derive(Debug)]
struct State {
    allocator: PortAllocator,
    allocations: HashMap<ClientId, Allocation>,
    /// Allocations that were released but whose socket may still be open.
    ///
    /// A socket closes once the reader task and the last control channel have let go of
    /// it, which is shortly after the allocation is released, not at that moment. Until
    /// then its port can not be bound again.
    closing: Vec<(u16, Weak<AllocationShared>)>,
    /// Set by [`Relay::shutdown`], no allocations are created afterwards.
    shutdown: bool,
}

impl State {
    /// Removes the allocation of `identity`. Its socket closes shortly after.
    fn remove_allocation(&mut self, identity: &ClientId) {
        if let Some(allocation) = self.allocations.remove(identity) {
            allocation.shared.released.cancel();
            self.closing
                .push((allocation.shared.port, Arc::downgrade(&allocation.shared)));
        }
    }

    /// Returns whether the relay is still closing a socket on `port`.
    fn is_closing(&mut self, port: u16) -> bool {
        self.closing.retain(|(_, shared)| shared.strong_count() > 0);
        self.closing.iter().any(|(closing, _)| *closing == port)
    }
}

/// One client's UDP socket on a public port.
#[derive(Debug)]
struct Allocation {
    shared: Arc<AllocationShared>,
    /// Reads from the socket. Stops when the allocation is dropped.
    _reader: AbortOnDropHandle<()>,
}

#[derive(Debug)]
struct AllocationShared {
    identity: ClientId,
    port: u16,
    socket: UdpSocket,
    max_packet_size: usize,
    policy: Mutex<Box<dyn AllocationPolicy>>,
    /// The control channel of the client, if it is connected.
    attached: Mutex<Option<Attachment>>,
    /// The tunnels of dialers that can not reach the socket over UDP, by the address that
    /// identifies each to the client.
    tunnels: Mutex<HashMap<SocketAddrV4, mpsc::Sender<Bytes>>>,
    max_tunnels: usize,
    /// Cancelled when the allocation is released. Closes its tunnels.
    released: CancellationToken,
    metrics: Arc<Metrics>,
}

/// The link from an allocation to the control channel that currently serves it.
#[derive(Debug)]
struct Attachment {
    generation: u64,
    /// Encoded frames for the client.
    inbound: mpsc::Sender<Bytes>,
    /// Cancelled when another control channel takes over the allocation.
    superseded: CancellationToken,
    /// Cancelled when the relay disconnects the client.
    disconnected: CancellationToken,
}

/// Locks a mutex, ignoring poisoning.
///
/// The state behind the relay's mutexes is consistent between statements, a panic while
/// holding one of them does not leave it half updated.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl AllocationShared {
    /// Checks `payload` against the allocation's policy.
    fn allowed(&self, direction: Direction, remote: RemoteAddr, payload: &[u8]) -> bool {
        let packet = Packet {
            direction,
            remote,
            payload,
            now: Instant::now(),
        };
        let verdict = lock(&self.policy).check(&packet);
        if verdict == Verdict::Drop {
            self.metrics.packets_dropped_policy.inc();
        }
        verdict == Verdict::Forward
    }

    /// Queues an encoded datagram frame for the client.
    ///
    /// The frame is dropped if the client is not connected or its queue is full.
    fn deliver(&self, frame: Bytes) {
        let attached = lock(&self.attached);
        let Some(attachment) = attached.as_ref() else {
            self.metrics.packets_dropped_detached.inc();
            return;
        };
        let len = frame.len();
        match attachment.inbound.try_send(frame) {
            Ok(()) => {
                self.metrics.packets_inbound.inc();
                self.metrics
                    .bytes_inbound
                    .inc_by((len - DATAGRAM_HEADER_LEN) as u64);
            }
            Err(_) => {
                self.metrics.packets_dropped_queue_full.inc();
            }
        }
    }

    /// Sends a packet of the client from the allocation's socket.
    fn send(&self, datagram: Datagram) {
        let Datagram { remote, payload } = datagram;
        let addr = remote.addr;
        // Destinations that can not be a remote party. The policy does not get to see
        // them.
        let invalid = addr.port() == 0
            || addr.ip().is_unspecified()
            || addr.ip().is_broadcast()
            || addr.ip().is_multicast();
        if payload.is_empty() || payload.len() > self.max_packet_size {
            self.metrics.packets_dropped_invalid.inc();
            return;
        }
        if remote.tunnel {
            self.send_to_tunnel(remote, payload);
            return;
        }
        if invalid {
            self.metrics.packets_dropped_invalid.inc();
            return;
        }
        if !self.allowed(Direction::Outbound, remote, &payload) {
            return;
        }
        match self.socket.try_send_to(&payload, SocketAddr::V4(addr)) {
            Ok(_) => {
                self.metrics.packets_outbound.inc();
                self.metrics.bytes_outbound.inc_by(payload.len() as u64);
            }
            Err(err) => {
                // A full send buffer is treated like any other loss on the path.
                trace!(%addr, "failed to send packet: {err:#}");
                self.metrics.packets_dropped_send_failed.inc();
            }
        }
    }

    /// Writes a packet of the client to the tunnel of a remote party.
    fn send_to_tunnel(&self, remote: RemoteAddr, payload: Bytes) {
        let tunnels = lock(&self.tunnels);
        // The address of a tunnelled remote party is only a name for its tunnel. Without
        // the tunnel there is nothing to send to.
        let Some(tunnel) = tunnels.get(&remote.addr) else {
            self.metrics.packets_dropped_invalid.inc();
            return;
        };
        if !self.allowed(Direction::Outbound, remote, &payload) {
            return;
        }
        let len = payload.len();
        match tunnel.try_send(payload) {
            Ok(()) => {
                self.metrics.packets_outbound.inc();
                self.metrics.bytes_outbound.inc_by(len as u64);
            }
            Err(_) => {
                self.metrics.packets_dropped_send_failed.inc();
            }
        }
    }

    /// Checks a packet that arrived for the client. Returns whether to deliver it.
    fn accepts_inbound(&self, remote: RemoteAddr, payload: &[u8]) -> bool {
        if payload.is_empty() || payload.len() > self.max_packet_size {
            self.metrics.packets_dropped_invalid.inc();
            return false;
        }
        // A packet for a client that is away is dropped before the policy sees it. It
        // must not use up the client's rate limit, or count as contact with the sender.
        if lock(&self.attached).is_none() {
            self.metrics.packets_dropped_detached.inc();
            return false;
        }
        self.allowed(Direction::Inbound, remote, payload)
    }

    /// Reads packets from the socket and queues them for the client.
    async fn read_loop(self: Arc<Self>) {
        let mut buf = BytesMut::new();
        loop {
            if let Err(err) = self.socket.readable().await {
                warn!("allocation socket failed: {err:#}");
                return;
            }
            // One byte more than the largest packet, to tell an oversized packet from a
            // packet of exactly the largest size.
            let needed = DATAGRAM_HEADER_LEN + self.max_packet_size + 1;
            if buf.capacity() < needed {
                buf = BytesMut::with_capacity(needed.max(RECV_CHUNK));
            }
            // The header is filled in once the sender is known.
            buf.put_bytes(0, DATAGRAM_HEADER_LEN);
            let res = {
                let mut limited = (&mut buf).limit(self.max_packet_size + 1);
                self.socket.try_recv_buf_from(&mut limited)
            };
            let (len, from) = match res {
                Ok(res) => res,
                Err(err) => {
                    buf.clear();
                    if err.kind() != std::io::ErrorKind::WouldBlock {
                        // The socket stays readable after an error. Pause, so that an
                        // error that persists does not spin this task.
                        trace!("failed to receive packet: {err:#}");
                        time::sleep(READ_ERROR_BACKOFF).await;
                    }
                    continue;
                }
            };
            // Takes the header and the packet, `buf` keeps the unused capacity.
            let mut frame = buf.split();
            let SocketAddr::V4(from) = from else {
                continue;
            };
            debug_assert_eq!(frame.len(), DATAGRAM_HEADER_LEN + len);
            let remote = RemoteAddr::udp(from);
            if !self.accepts_inbound(remote, &frame[DATAGRAM_HEADER_LEN..]) {
                continue;
            }
            frame[..DATAGRAM_HEADER_LEN].copy_from_slice(&Datagram::header(remote));
            self.deliver(frame.freeze());
        }
    }
}

impl Relay {
    /// Creates a relay.
    ///
    /// Must be called from within a tokio runtime.
    pub fn new(config: AllocationConfig, metrics: Arc<Metrics>) -> Result<Self, InvalidConfig> {
        n0_error::ensure!(
            (1..=MAX_PACKET_SIZE).contains(&config.max_packet_size),
            InvalidConfig::MaxPacketSize {
                max_packet_size: config.max_packet_size
            }
        );
        let allocator = PortAllocator::new(config.ports.clone(), config.release_timeout)?;
        let inner = Arc::new(Inner {
            config,
            state: Mutex::new(State {
                allocator,
                allocations: HashMap::new(),
                closing: Vec::new(),
                shutdown: false,
            }),
            expiry_changed: Arc::new(Notify::new()),
            shutdown: CancellationToken::new(),
            metrics,
            expiry_task: Mutex::new(None),
            next_tunnel_name: AtomicU32::new(0),
        });
        // The task only holds a weak reference, it must not keep the relay alive.
        let weak = Arc::downgrade(&inner);
        let expiry_changed = inner.expiry_changed.clone();
        let shutdown = inner.shutdown.clone();
        let task = tokio::spawn(
            async move {
                loop {
                    let notified = expiry_changed.notified();
                    tokio::pin!(notified);
                    // Register before reading the deadline, so that a change in between
                    // is not missed.
                    notified.as_mut().enable();
                    let next = match weak.upgrade() {
                        Some(inner) => lock(&inner.state).allocator.next_expiry(),
                        None => return,
                    };
                    let sleep = async {
                        match next {
                            Some(deadline) => time::sleep_until(deadline).await,
                            None => std::future::pending().await,
                        }
                    };
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = &mut notified => {}
                        _ = sleep => {
                            let Some(inner) = weak.upgrade() else { return };
                            let mut state = lock(&inner.state);
                            inner.expire(&mut state, Instant::now());
                        }
                    }
                }
            }
            .instrument(info_span!("relay-expiry")),
        );
        *lock(&inner.expiry_task) = Some(AbortOnDropHandle::new(task));
        Ok(Self(inner))
    }

    /// Returns the public IPv4 address clients of this relay advertise.
    pub fn public_ip(&self) -> Ipv4Addr {
        self.0.config.public_ip
    }

    /// Never hands out `port` to a client.
    ///
    /// Use this for UDP ports in the configured range that the relay itself listens on.
    pub fn exclude_port(&self, port: u16) {
        lock(&self.0.state).allocator.exclude_port(port);
    }

    /// Returns the number of allocations, including those held for a disconnected client.
    pub fn allocation_count(&self) -> usize {
        lock(&self.0.state).allocations.len()
    }

    /// Returns the public port of the allocation of `identity`, if it has one.
    pub fn port_of(&self, identity: &ClientId) -> Option<u16> {
        lock(&self.0.state).allocator.port_of(identity)
    }

    /// Returns whether an allocation has the public port `port`.
    ///
    /// This includes the allocation of a client that is away and whose port is held.
    pub fn has_port(&self, port: u16) -> bool {
        lock(&self.0.state).allocator.owner_of(port).is_some()
    }

    /// Attaches the tunnel of a dialer to the allocation with the public port `port`.
    ///
    /// `peer` is the source address of the dialer's connection to the relay. It names the
    /// dialer to the client, which sees a remote party at that address, marked as
    /// tunnelled.
    ///
    /// Run the returned tunnel with [`Tunnel::run`]. Anyone may open a tunnel, as anyone
    /// may send UDP packets to the port. The traffic policy applies to both alike.
    pub fn open_tunnel(&self, port: u16, peer: SocketAddr) -> Result<Tunnel, TunnelError> {
        let inner = &self.0;
        let state = lock(&inner.state);
        let shared = state
            .allocator
            .owner_of(port)
            .and_then(|identity| state.allocations.get(identity))
            .map(|allocation| allocation.shared.clone())
            .ok_or_else(|| e!(TunnelError::UnknownPort { port }))?;
        drop(state);

        let mut tunnels = lock(&shared.tunnels);
        if tunnels.len() >= shared.max_tunnels {
            inner.metrics.tunnels_rejected.inc();
            return Err(e!(TunnelError::TooManyTunnels));
        }
        let addr = match peer {
            SocketAddr::V4(addr) if !tunnels.contains_key(&addr) => addr,
            SocketAddr::V6(addr) => match addr.ip().to_ipv4_mapped() {
                Some(ip) if !tunnels.contains_key(&SocketAddrV4::new(ip, addr.port())) => {
                    SocketAddrV4::new(ip, addr.port())
                }
                _ => inner.made_up_tunnel_addr(&tunnels),
            },
            SocketAddr::V4(_) => inner.made_up_tunnel_addr(&tunnels),
        };
        let (outbound_tx, outbound_rx) = mpsc::channel(TUNNEL_QUEUE_DEPTH);
        tunnels.insert(addr, outbound_tx);
        drop(tunnels);
        inner.metrics.tunnels_opened.inc();
        Ok(Tunnel {
            remote: RemoteAddr::tunnel(addr),
            allocation: Arc::downgrade(&shared),
            released: shared.released.clone(),
            shutdown: inner.shutdown.clone(),
            outbound: outbound_rx,
            metrics: inner.metrics.clone(),
        })
    }

    /// Closes the control channel of `identity`, if it is connected.
    ///
    /// Returns whether a control channel was closed. The client's port stays reserved for
    /// the release timeout, and nothing keeps the client from connecting again. To keep a
    /// client out, have the authenticator reject it.
    pub fn disconnect(&self, identity: &ClientId) -> bool {
        let state = lock(&self.0.state);
        let Some(allocation) = state.allocations.get(identity) else {
            return false;
        };
        match lock(&allocation.shared.attached).as_ref() {
            Some(attachment) => {
                attachment.disconnected.cancel();
                true
            }
            None => false,
        }
    }

    /// Closes all control channels and releases all allocations.
    ///
    /// No allocations are created afterwards.
    pub fn shutdown(&self) {
        let mut state = lock(&self.0.state);
        state.shutdown = true;
        self.0.shutdown.cancel();
        let released = state.allocations.len();
        for allocation in state.allocations.values() {
            allocation.shared.released.cancel();
        }
        state.allocations.clear();
        state.allocator.clear();
        self.0.metrics.allocations_released.inc_by(released as u64);
    }

    /// Accepts a control channel that a client opened.
    ///
    /// `io` is the WebSocket, `uri` and `headers` are those of the HTTP request that
    /// opened it. Reads the client's credentials, authenticates the client and gives it
    /// its allocation. The client has been told the outcome when this returns.
    ///
    /// Run the returned connection with [`ControlConnection::run`]. Dropping it releases
    /// the allocation.
    pub async fn accept_control<S>(
        &self,
        mut io: S,
        uri: Uri,
        headers: HeaderMap,
    ) -> Result<ControlConnection<S>, AcceptError>
    where
        S: BytesStreamSink + ExportKeyingMaterial,
    {
        self.0.metrics.control_connections.inc();
        match self.establish(&mut io, uri, headers).await {
            Ok(attached) => Ok(ControlConnection {
                io,
                attached,
                relay: self.clone(),
            }),
            Err(err) => {
                let code = match &err {
                    AcceptError::Rejected { .. } => Some(ErrorCode::Unauthorized),
                    AcceptError::Protocol { .. } => Some(ErrorCode::Protocol),
                    AcceptError::NoPortAvailable { .. } => Some(ErrorCode::NoPortAvailable),
                    AcceptError::Bind { .. } | AcceptError::Shutdown { .. } => {
                        Some(ErrorCode::Internal)
                    }
                    _ => None,
                };
                if let Some(code) = code {
                    let reason = match &err {
                        AcceptError::Rejected { reason, .. }
                        | AcceptError::Protocol { reason, .. } => reason.clone(),
                        _ => String::new(),
                    };
                    send_error(&mut io, code, reason).await;
                }
                Err(err)
            }
        }
    }

    async fn establish<S>(
        &self,
        io: &mut S,
        uri: Uri,
        headers: HeaderMap,
    ) -> Result<Attached, AcceptError>
    where
        S: BytesStreamSink + ExportKeyingMaterial,
    {
        let first = time::timeout(AUTH_TIMEOUT, io.next())
            .await
            .map_err(|_| e!(AcceptError::AuthTimeout))?;
        let bytes = match first {
            Some(Ok(bytes)) => bytes,
            Some(Err(_)) | None => return Err(e!(AcceptError::Closed)),
        };
        let credentials = match ClientFrame::from_bytes(bytes) {
            Ok(ClientFrame::Control(ClientControl::Auth { credentials })) => credentials,
            Ok(_) => {
                return Err(e!(AcceptError::Protocol {
                    reason: "the first message must present credentials".to_string()
                }));
            }
            Err(err) => {
                return Err(e!(AcceptError::Protocol {
                    reason: err.to_string()
                }));
            }
        };

        let request = AuthRequest::new(credentials, channel_binding(io), uri, headers);
        let identity = match self.0.config.authenticator.authenticate_dyn(&request).await {
            Ok(identity) => identity,
            Err(rejected) => {
                self.0.metrics.auth_rejected.inc();
                return Err(e!(AcceptError::Rejected {
                    reason: rejected.reason
                }));
            }
        };

        let attached = self.attach_when_free(&identity).await?;
        let addr = SocketAddrV4::new(self.0.config.public_ip, attached.shared.port);
        debug!(%identity, %addr, "client attached");
        // If this fails `attached` is dropped, which detaches the client again.
        let frame = RelayFrame::Control(RelayControl::Allocated { addr });
        if !send_frame(io, &frame).await {
            return Err(e!(AcceptError::Closed));
        }
        Ok(attached)
    }

    /// Like [`Self::attach`], but waits for a port the relay is still closing.
    async fn attach_when_free(&self, identity: &ClientId) -> Result<Attached, AcceptError> {
        let deadline = Instant::now() + CLOSING_WAIT;
        loop {
            match self.attach(identity) {
                Ok(Some(attached)) => return Ok(attached),
                Ok(None) if Instant::now() < deadline => time::sleep(CLOSING_POLL).await,
                Ok(None) => {
                    let err = std::io::Error::from(std::io::ErrorKind::AddrInUse);
                    return Err(e!(AcceptError::Bind, err));
                }
                Err(err) => return Err(err),
            }
        }
    }

    /// Gives `identity` its allocation and makes a new control channel its owner.
    ///
    /// Returns `None` if the port of the identity belonged to an allocation that was
    /// just released and whose socket is not closed yet. Try again shortly.
    fn attach(&self, identity: &ClientId) -> Result<Option<Attached>, AcceptError> {
        let inner = &self.0;
        let mut state = lock(&inner.state);
        if state.shutdown {
            return Err(e!(AcceptError::Shutdown));
        }
        let now = Instant::now();
        inner.expire(&mut state, now);

        let mut last_error = None;
        for _ in 0..MAX_BIND_ATTEMPTS {
            let lease = match state.allocator.acquire(identity, now) {
                Ok(lease) => lease,
                Err(_) => {
                    inner.metrics.ports_exhausted.inc();
                    return Err(e!(AcceptError::NoPortAvailable));
                }
            };
            let shared = match state.allocations.get(identity) {
                // The allocation of a returning client, or of a client that is taken over.
                Some(allocation) => {
                    inner.metrics.allocations_resumed.inc();
                    allocation.shared.clone()
                }
                None => {
                    // Look before binding: the socket may close between a failed bind
                    // and a look afterwards.
                    let closing = state.is_closing(lease.port);
                    match inner.bind(identity, lease.port) {
                        Ok(allocation) => {
                            inner.metrics.allocations_created.inc();
                            let shared = allocation.shared.clone();
                            state.allocations.insert(identity.clone(), allocation);
                            shared
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {
                            if closing {
                                // The port is taken by a socket of ours that is about to
                                // close. It is the identity's preferred port, wait for it.
                                state.allocator.abandon(identity, lease.generation);
                                return Ok(None);
                            }
                            // Somebody else uses the port, try the next one.
                            debug!(port = lease.port, "port of new allocation is in use");
                            state
                                .allocator
                                .mark_unusable(identity, lease.generation, now);
                            last_error = Some(err);
                            continue;
                        }
                        Err(err) => {
                            // Not the port's fault, another port would fail the same way.
                            warn!(port = lease.port, "failed to bind allocation: {err:#}");
                            state.allocator.abandon(identity, lease.generation);
                            inner.metrics.allocations_bind_failed.inc();
                            return Err(e!(AcceptError::Bind, err));
                        }
                    }
                }
            };

            let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE_DEPTH);
            let superseded = CancellationToken::new();
            let disconnected = CancellationToken::new();
            let previous = lock(&shared.attached).replace(Attachment {
                generation: lease.generation,
                inbound: inbound_tx,
                superseded: superseded.clone(),
                disconnected: disconnected.clone(),
            });
            if let Some(previous) = previous {
                previous.superseded.cancel();
            }
            // Resuming a held port cancels its release.
            inner.expiry_changed.notify_one();
            return Ok(Some(Attached {
                shared,
                generation: lease.generation,
                inbound: inbound_rx,
                superseded,
                disconnected,
                relay: self.clone(),
            }));
        }
        inner.metrics.allocations_bind_failed.inc();
        let err = last_error.unwrap_or_else(|| std::io::ErrorKind::AddrInUse.into());
        Err(e!(AcceptError::Bind, err))
    }

    /// Ends the ownership of a control channel over its allocation.
    fn detach(&self, identity: &ClientId, generation: u64) {
        let inner = &self.0;
        let mut state = lock(&inner.state);
        match state
            .allocator
            .release(identity, generation, Instant::now())
        {
            Released::Held(_) => {
                if let Some(allocation) = state.allocations.get(identity) {
                    let mut attached = lock(&allocation.shared.attached);
                    if attached
                        .as_ref()
                        .is_some_and(|attachment| attachment.generation == generation)
                    {
                        *attached = None;
                    }
                }
                inner.expiry_changed.notify_one();
            }
            Released::Freed => {
                state.remove_allocation(identity);
                inner.metrics.allocations_released.inc();
            }
            // A newer control channel owns the allocation.
            Released::Stale => {}
        }
    }
}

impl Inner {
    /// Makes up an address to name a tunnel whose dialer has no usable IPv4 address.
    ///
    /// The address lies in 240.0.0.0/4, which is reserved and never the source of a real
    /// packet.
    fn made_up_tunnel_addr(
        &self,
        tunnels: &HashMap<SocketAddrV4, mpsc::Sender<Bytes>>,
    ) -> SocketAddrV4 {
        loop {
            let n = self.next_tunnel_name.fetch_add(1, Ordering::Relaxed);
            let ip = Ipv4Addr::from(0xf000_0000 | (n & 0x0fff_ffff));
            let addr = SocketAddrV4::new(ip, 1);
            if !tunnels.contains_key(&addr) {
                return addr;
            }
        }
    }

    /// Frees the allocations whose release timeout has passed.
    fn expire(&self, state: &mut State, now: Instant) {
        for (identity, port) in state.allocator.expire(now) {
            debug!(%identity, port, "allocation released");
            state.remove_allocation(&identity);
            self.metrics.allocations_released.inc();
        }
    }

    /// Binds the socket of a new allocation and starts reading from it.
    fn bind(&self, identity: &ClientId, port: u16) -> std::io::Result<Allocation> {
        let socket = std::net::UdpSocket::bind(SocketAddrV4::new(self.config.bind_ip, port))?;
        socket.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(socket)?;
        let shared = Arc::new(AllocationShared {
            identity: identity.clone(),
            port,
            socket,
            max_packet_size: self.config.max_packet_size,
            policy: Mutex::new(self.config.policy.allocation(identity)),
            attached: Mutex::new(None),
            tunnels: Mutex::new(HashMap::new()),
            max_tunnels: self.config.max_tunnels,
            released: CancellationToken::new(),
            metrics: self.metrics.clone(),
        });
        let reader = tokio::spawn(
            shared
                .clone()
                .read_loop()
                .instrument(info_span!("allocation", port)),
        );
        Ok(Allocation {
            shared,
            _reader: AbortOnDropHandle::new(reader),
        })
    }
}

/// A control channel's ownership of an allocation. Detaches when dropped.
#[derive(Debug)]
struct Attached {
    shared: Arc<AllocationShared>,
    generation: u64,
    inbound: mpsc::Receiver<Bytes>,
    superseded: CancellationToken,
    disconnected: CancellationToken,
    relay: Relay,
}

impl Drop for Attached {
    fn drop(&mut self) {
        self.relay.detach(&self.shared.identity, self.generation);
    }
}

/// The control channel of an authenticated client that owns an allocation.
#[derive(Debug)]
pub struct ControlConnection<S> {
    io: S,
    attached: Attached,
    relay: Relay,
}

/// Sends a frame, returns whether it was written within the write timeout.
async fn send_frame<S: BytesStreamSink>(io: &mut S, frame: &RelayFrame) -> bool {
    let Ok(bytes) = frame.to_bytes() else {
        debug_assert!(false, "the relay built a frame it can not encode");
        return false;
    };
    matches!(
        time::timeout(WRITE_TIMEOUT, io.send(bytes)).await,
        Ok(Ok(()))
    )
}

/// Tells the client why the control channel is being closed. Best effort.
async fn send_error<S: BytesStreamSink>(io: &mut S, code: ErrorCode, reason: String) {
    let frame = RelayFrame::Control(RelayControl::Error { code, reason });
    send_frame(io, &frame).await;
    let _ = time::timeout(WRITE_TIMEOUT, io.close()).await;
}

impl<S: BytesStreamSink> ControlConnection<S> {
    /// Returns the identity of the client.
    pub fn identity(&self) -> &ClientId {
        &self.attached.shared.identity
    }

    /// Returns the public address of the client's allocation.
    pub fn public_addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.relay.public_ip(), self.attached.shared.port)
    }

    /// Serves the control channel until it closes.
    ///
    /// The client's port stays reserved for the release timeout afterwards.
    pub async fn run(self) {
        let Self {
            mut io,
            mut attached,
            relay,
        } = self;
        let identity = attached.shared.identity.clone();
        let span = info_span!("control", %identity, port = attached.shared.port);
        async {
            let exit = serve(&mut io, &mut attached, &relay).await;
            debug!("control channel closed: {}", exit.reason);
            // Let go of the allocation before saying goodbye, which can take a while if
            // the client is slow or gone.
            drop(attached);
            match exit.goodbye {
                Goodbye::None => {}
                Goodbye::Close => {
                    let _ = time::timeout(WRITE_TIMEOUT, io.close()).await;
                }
                Goodbye::Error(code, reason) => send_error(&mut io, code, reason).await,
            }
        }
        .instrument(span)
        .await;
    }
}

/// How a control channel ended.
struct Exit {
    /// For the log.
    reason: &'static str,
    /// What to tell the client.
    goodbye: Goodbye,
}

enum Goodbye {
    /// The connection is broken or the client closed it.
    None,
    /// Close the WebSocket.
    Close,
    /// Tell the client why, then close the WebSocket.
    Error(ErrorCode, String),
}

impl Exit {
    fn silent(reason: &'static str) -> Self {
        Self {
            reason,
            goodbye: Goodbye::None,
        }
    }

    fn superseded() -> Self {
        Self {
            reason: "superseded by a newer control channel",
            goodbye: Goodbye::Error(ErrorCode::Superseded, String::new()),
        }
    }

    fn protocol(reason: String) -> Self {
        Self {
            reason: "protocol violation",
            goodbye: Goodbye::Error(ErrorCode::Protocol, reason),
        }
    }
}

/// Runs the control channel, returns why it ended.
async fn serve<S: BytesStreamSink>(io: &mut S, attached: &mut Attached, relay: &Relay) -> Exit {
    let shared = attached.shared.clone();
    let mut ping_tracker = PingTracker::default();
    let mut ping_interval = time::interval(PING_INTERVAL);
    ping_interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    // The first tick completes immediately.
    ping_interval.tick().await;

    loop {
        tokio::select! {
            _ = attached.superseded.cancelled() => return Exit::superseded(),
            _ = attached.disconnected.cancelled() => {
                return Exit {
                    reason: "disconnected by the relay",
                    goodbye: Goodbye::Close,
                };
            }
            _ = relay.0.shutdown.cancelled() => {
                return Exit {
                    reason: "relay is shutting down",
                    goodbye: Goodbye::Close,
                };
            }
            _ = ping_tracker.timeout() => return Exit::silent("ping timed out"),
            _ = ping_interval.tick() => {
                let frame = RelayFrame::Control(RelayControl::Ping(ping_tracker.new_ping()));
                if !send_frame(io, &frame).await {
                    return Exit::silent("write failed");
                }
            }
            first = attached.inbound.recv() => {
                // The sender lives in the allocation, which `attached` keeps alive. It is
                // only dropped when another control channel replaces it, which can be
                // seen here before the cancellation is.
                let Some(first) = first else {
                    return Exit::superseded();
                };
                let write = async {
                    io.feed(first).await?;
                    for _ in 1..WRITE_BATCH {
                        match attached.inbound.try_recv() {
                            Ok(frame) => io.feed(frame).await?,
                            Err(_) => break,
                        }
                    }
                    io.flush().await
                };
                if !matches!(time::timeout(WRITE_TIMEOUT, write).await, Ok(Ok(()))) {
                    return Exit::silent("write failed");
                }
            }
            frame = io.next() => {
                let bytes = match frame {
                    Some(Ok(bytes)) => bytes,
                    Some(Err(_)) => return Exit::silent("read failed"),
                    None => return Exit::silent("closed by the client"),
                };
                let reply = match ClientFrame::from_bytes(bytes) {
                    Ok(ClientFrame::Datagram(datagram)) => {
                        shared.send(datagram);
                        None
                    }
                    Ok(ClientFrame::Control(control)) => match control {
                        ClientControl::Ping(payload) => Some(RelayControl::Pong(payload)),
                        ClientControl::Pong(payload) => {
                            ping_tracker.pong_received(payload);
                            None
                        }
                        ClientControl::Auth { .. } => {
                            return Exit::protocol("already authenticated".to_string());
                        }
                        // The relay does not offer the DHT service.
                        ClientControl::DhtAnnounce { info_hash } => {
                            Some(RelayControl::DhtAnnounceResult {
                                info_hash,
                                status: DhtStatus::Unavailable,
                            })
                        }
                        ClientControl::DhtFindPeers { request_id, .. } => {
                            Some(RelayControl::DhtFindPeersDone {
                                request_id,
                                status: DhtStatus::Unavailable,
                            })
                        }
                        ClientControl::DhtStop { .. } => None,
                    },
                    Err(err) if err.is_unknown_control() => None,
                    Err(err) => return Exit::protocol(err.to_string()),
                };
                if let Some(control) = reply
                    && !send_frame(io, &RelayFrame::Control(control)).await
                {
                    return Exit::silent("write failed");
                }
            }
        }
    }
}

/// The tunnel of a dialer to an allocation.
///
/// Created with [`Relay::open_tunnel`].
#[derive(Debug)]
pub struct Tunnel {
    remote: RemoteAddr,
    allocation: Weak<AllocationShared>,
    released: CancellationToken,
    shutdown: CancellationToken,
    /// Packets of the client for the dialer.
    outbound: mpsc::Receiver<Bytes>,
    metrics: Arc<Metrics>,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        if let Some(allocation) = self.allocation.upgrade() {
            lock(&allocation.tunnels).remove(&self.remote.addr);
        }
        self.metrics.tunnels_closed.inc();
    }
}

impl Tunnel {
    /// Returns how the dialer appears to the client.
    pub fn remote(&self) -> RemoteAddr {
        self.remote
    }

    /// Serves the tunnel on the dialer's WebSocket `io` until it closes.
    ///
    /// Every message on `io` is one QUIC packet.
    pub async fn run<S: BytesStreamSink>(mut self, mut io: S) {
        let span = info_span!("tunnel", remote = %self.remote.addr);
        async {
            let reason = self.serve(&mut io).await;
            debug!("tunnel closed: {reason}");
            let _ = time::timeout(WRITE_TIMEOUT, io.close()).await;
        }
        .instrument(span)
        .await;
    }

    async fn serve<S: BytesStreamSink>(&mut self, io: &mut S) -> &'static str {
        let idle = time::sleep(TUNNEL_IDLE_TIMEOUT);
        tokio::pin!(idle);
        loop {
            tokio::select! {
                _ = self.released.cancelled() => return "the allocation was released",
                _ = self.shutdown.cancelled() => return "relay is shutting down",
                _ = &mut idle => return "idle",
                first = self.outbound.recv() => {
                    // The sender lives in the allocation.
                    let Some(first) = first else {
                        return "the allocation was released";
                    };
                    let write = async {
                        io.feed(first).await?;
                        for _ in 1..WRITE_BATCH {
                            match self.outbound.try_recv() {
                                Ok(packet) => io.feed(packet).await?,
                                Err(_) => break,
                            }
                        }
                        io.flush().await
                    };
                    if !matches!(time::timeout(WRITE_TIMEOUT, write).await, Ok(Ok(()))) {
                        return "write failed";
                    }
                    idle.as_mut().reset(Instant::now() + TUNNEL_IDLE_TIMEOUT);
                }
                packet = io.next() => {
                    let packet = match packet {
                        Some(Ok(packet)) => packet,
                        Some(Err(_)) => return "read failed",
                        None => return "closed by the dialer",
                    };
                    idle.as_mut().reset(Instant::now() + TUNNEL_IDLE_TIMEOUT);
                    // The tunnel must not keep the allocation alive.
                    let Some(allocation) = self.allocation.upgrade() else {
                        return "the allocation was released";
                    };
                    if !allocation.accepts_inbound(self.remote, &packet) {
                        continue;
                    }
                    let mut frame = BytesMut::with_capacity(DATAGRAM_HEADER_LEN + packet.len());
                    frame.put_slice(&Datagram::header(self.remote));
                    frame.put_slice(&packet);
                    allocation.deliver(frame.freeze());
                }
            }
        }
    }
}
