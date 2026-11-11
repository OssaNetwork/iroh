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
        atomic::{AtomicBool, AtomicU32, Ordering},
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
    task::JoinSet,
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
            InfoHash, MAX_PACKET_SIZE, RelayControl, RelayFrame, RemoteAddr,
        },
        streams::{BytesStreamSink, write_batch},
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
/// Only packets that were forwarded count, in either direction. A QUIC connection with
/// keep-alives never lets its tunnel idle this long.
const TUNNEL_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// How long a new tunnel has to deliver its first packet to the client.
const TUNNEL_FIRST_PACKET_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// The mainline DHT service for clients. Defaults to `None`, the relay then answers
    /// DHT requests with [`DhtStatus::Unavailable`].
    #[cfg(feature = "dht")]
    pub dht: Option<super::dht::DhtConfig>,
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
            #[cfg(feature = "dht")]
            dht: None,
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
    #[error("the relay does not serve tunnels")]
    Disabled,
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
    #[error("failed to start the DHT node")]
    Dht {
        #[error(std_err)]
        source: std::io::Error,
    },
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
    /// The mainline DHT service, if the relay offers it.
    #[cfg(feature = "dht")]
    dht: Option<DhtService>,
}

/// The relay's node on the mainline DHT, and what goes with it.
#[cfg(feature = "dht")]
#[derive(derive_more::Debug)]
struct DhtService {
    #[debug("Dht")]
    dht: n0_mainline::Dht,
    policy: Arc<dyn super::dht::DhtPolicy>,
    /// Limits how many announcements are on their way to the DHT at a time, for all
    /// clients together. Without it a relay that all clients reconnect to at once would
    /// flood its own DHT node.
    announce_slots: Arc<tokio::sync::Semaphore>,
    /// Counts the announce requests, to tell entries for the same infohash apart.
    next_request: std::sync::atomic::AtomicU64,
    /// Refreshes the announcements of all clients.
    refresh_task: Mutex<Option<AbortOnDropHandle<()>>>,
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
    tunnels: Mutex<HashMap<SocketAddrV4, TunnelEntry>>,
    max_tunnels: usize,
    /// Cancelled when the allocation is released. Closes its tunnels.
    released: CancellationToken,
    /// The infohashes the relay announces for the client on the mainline DHT.
    ///
    /// They live and die with the allocation: the relay refreshes them while the client
    /// is away during the release timeout, and forgets them when the port is released.
    announces: Mutex<HashMap<InfoHash, Announce>>,
    metrics: Arc<Metrics>,
}

/// An infohash the relay announces for a client.
#[derive(Debug, Clone, Copy)]
struct Announce {
    /// Tells this entry from an earlier one for the same infohash that was stopped.
    #[cfg_attr(not(feature = "dht"), allow(dead_code))]
    request: u64,
    /// Whether an announcement went out at least once. Until then the client was not
    /// told that the infohash is announced.
    #[cfg_attr(not(feature = "dht"), allow(dead_code))]
    announced: bool,
}

/// What an allocation knows about one of its tunnels.
#[derive(Debug)]
struct TunnelEntry {
    /// Packets of the client for the dialer.
    outbound: mpsc::Sender<Bytes>,
    /// When the tunnel was opened.
    opened: Instant,
    /// Whether the client ever sent a packet into the tunnel.
    answered: Arc<AtomicBool>,
    /// Cancelled to close the tunnel in favour of a newer one.
    evicted: CancellationToken,
}

/// Returns the tunnel to close to make room for a new one: the oldest one the client
/// never answered. `None` if the client answered all of them.
///
/// Anyone can open tunnels, without authenticating. Tunnels the client is talking
/// through are kept, the others have to make room, so that tunnels that carry nothing
/// can not keep real dialers out.
fn evictable_tunnel(tunnels: &HashMap<SocketAddrV4, TunnelEntry>) -> Option<SocketAddrV4> {
    tunnels
        .iter()
        .filter(|(_, tunnel)| !tunnel.answered.load(Ordering::Relaxed))
        .min_by_key(|(_, tunnel)| tunnel.opened)
        .map(|(addr, _)| *addr)
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
        // The address of a tunnelled remote party is only a name for its tunnel. Without
        // the tunnel there is nothing to send to.
        let tunnel = lock(&self.tunnels)
            .get(&remote.addr)
            .map(|tunnel| (tunnel.outbound.clone(), tunnel.answered.clone()));
        let Some((outbound, answered)) = tunnel else {
            self.metrics.packets_dropped_invalid.inc();
            return;
        };
        if !self.allowed(Direction::Outbound, remote, &payload) {
            return;
        }
        let len = payload.len();
        match outbound.try_send(payload) {
            Ok(()) => {
                answered.store(true, Ordering::Relaxed);
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
        #[cfg(feature = "dht")]
        let dht = match &config.dht {
            Some(dht_config) => Some(DhtService {
                dht: dht_config
                    .build(config.public_ip)
                    .map_err(|err| e!(InvalidConfig::Dht, err))?,
                policy: dht_config.policy.clone(),
                announce_slots: Arc::new(tokio::sync::Semaphore::new(
                    super::dht::ANNOUNCE_CONCURRENCY,
                )),
                next_request: Default::default(),
                refresh_task: Mutex::new(None),
            }),
            None => None,
        };
        #[cfg(feature = "dht")]
        let refresh_interval = config.dht.as_ref().map(|dht| dht.refresh_interval);
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
            #[cfg(feature = "dht")]
            dht,
        });
        #[cfg(feature = "dht")]
        if let (Some(service), Some(interval)) = (&inner.dht, refresh_interval) {
            // The DHT node has a UDP port of its own. Keep it out of the hands of
            // clients. A port the operating system chose is only known to the node, the
            // refresh task asks for it.
            if let Some(port) = inner.config.dht.as_ref().and_then(|dht| dht.port) {
                lock(&inner.state).allocator.exclude_port(port);
            }
            let task = tokio::spawn(
                refresh_announces(
                    Arc::downgrade(&inner),
                    service.dht.clone(),
                    service.announce_slots.clone(),
                    interval,
                )
                .instrument(info_span!("relay-dht-refresh")),
            );
            *lock(&service.refresh_task) = Some(AbortOnDropHandle::new(task));
        }
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

    /// Returns the infohashes the relay announces on the mainline DHT for `identity`.
    pub fn announced(&self, identity: &ClientId) -> Vec<InfoHash> {
        let state = lock(&self.0.state);
        match state.allocations.get(identity) {
            Some(allocation) => lock(&allocation.shared.announces).keys().copied().collect(),
            None => Vec::new(),
        }
    }

    /// Returns whether an allocation has the public port `port`.
    ///
    /// This includes the allocation of a client that is away and whose port is held.
    pub fn has_port(&self, port: u16) -> bool {
        lock(&self.0.state).allocator.owner_of(port).is_some()
    }

    /// Returns the allocation with the public port `port`.
    fn allocation_on(&self, port: u16) -> Result<Arc<AllocationShared>, TunnelError> {
        let state = lock(&self.0.state);
        let shared = state
            .allocator
            .owner_of(port)
            .and_then(|identity| state.allocations.get(identity))
            .map(|allocation| allocation.shared.clone())
            .ok_or_else(|| e!(TunnelError::UnknownPort { port }))?;
        if shared.max_tunnels == 0 {
            return Err(e!(TunnelError::Disabled));
        }
        Ok(shared)
    }

    /// Returns whether a tunnel to the allocation with the public port `port` could be
    /// opened right now.
    ///
    /// Call this before agreeing to a tunnel, so that a dialer is told that there is no
    /// tunnel for it before it starts using one.
    pub fn check_tunnel(&self, port: u16) -> Result<(), TunnelError> {
        let shared = self.allocation_on(port)?;
        let tunnels = lock(&shared.tunnels);
        if tunnels.len() >= shared.max_tunnels && evictable_tunnel(&tunnels).is_none() {
            return Err(e!(TunnelError::TooManyTunnels));
        }
        Ok(())
    }

    /// Attaches the tunnel of a dialer to the allocation with the public port `port`.
    ///
    /// `peer` is the source address of the dialer's connection to the relay. It names the
    /// dialer to the client, which sees a remote party at that address, marked as
    /// tunnelled. Behind a proxy that is the address of the proxy.
    ///
    /// Run the returned tunnel with [`Tunnel::run`]. Anyone may open a tunnel, as anyone
    /// may send UDP packets to the port. The traffic policy applies to both alike.
    ///
    /// When the allocation has as many tunnels as it may have, the oldest tunnel the
    /// client never sent a packet into is closed to make room. If the client answered
    /// all of them the new tunnel is refused.
    pub fn open_tunnel(&self, port: u16, peer: SocketAddr) -> Result<Tunnel, TunnelError> {
        let inner = &self.0;
        let shared = self.allocation_on(port)?;

        let mut tunnels = lock(&shared.tunnels);
        if tunnels.len() >= shared.max_tunnels {
            let evicted = evictable_tunnel(&tunnels).and_then(|addr| tunnels.remove(&addr));
            match evicted {
                Some(tunnel) => {
                    tunnel.evicted.cancel();
                    inner.metrics.tunnels_evicted.inc();
                }
                None => {
                    inner.metrics.tunnels_rejected.inc();
                    return Err(e!(TunnelError::TooManyTunnels));
                }
            }
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
        let evicted = CancellationToken::new();
        tunnels.insert(
            addr,
            TunnelEntry {
                outbound: outbound_tx.clone(),
                opened: Instant::now(),
                answered: Arc::default(),
                evicted: evicted.clone(),
            },
        );
        drop(tunnels);
        inner.metrics.tunnels_opened.inc();
        Ok(Tunnel {
            remote: RemoteAddr::tunnel(addr),
            allocation: Arc::downgrade(&shared),
            released: shared.released.clone(),
            evicted,
            shutdown: inner.shutdown.clone(),
            outbound: outbound_rx,
            entry: outbound_tx,
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
    fn made_up_tunnel_addr(&self, tunnels: &HashMap<SocketAddrV4, TunnelEntry>) -> SocketAddrV4 {
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
            announces: Mutex::new(HashMap::new()),
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
    // The DHT requests of the client run on their own tasks and report here. The tasks
    // end with the control channel.
    let mut dht = DhtSession::new();

    loop {
        tokio::select! {
            _ = attached.superseded.cancelled() => return Exit::superseded(),
            Some(control) = dht.results.recv() => {
                if !send_frame(io, &RelayFrame::Control(control)).await {
                    return Exit::silent("write failed");
                }
            }
            // Take finished tasks out of the set, it would keep them around otherwise.
            Some(_) = dht.tasks.join_next() => {}
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
                let write = write_batch(io, first, &mut attached.inbound, WRITE_BATCH);
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
                        ClientControl::DhtAnnounce { info_hash } => {
                            dht.announce(relay, &shared, info_hash)
                        }
                        ClientControl::DhtFindPeers { request_id, info_hash } => {
                            dht.find_peers(relay, &shared, request_id, info_hash)
                        }
                        ClientControl::DhtStop { info_hash } => {
                            lock(&shared.announces).remove(&info_hash);
                            Some(RelayControl::DhtStopped { info_hash })
                        }
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
    /// Cancelled when the tunnel has to make room for a newer one.
    evicted: CancellationToken,
    shutdown: CancellationToken,
    /// Packets of the client for the dialer.
    outbound: mpsc::Receiver<Bytes>,
    /// The sending end of `outbound`, to recognise this tunnel's entry in the allocation.
    entry: mpsc::Sender<Bytes>,
    metrics: Arc<Metrics>,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        if let Some(allocation) = self.allocation.upgrade() {
            let mut tunnels = lock(&allocation.tunnels);
            // After an eviction the name can belong to a newer tunnel already.
            if tunnels
                .get(&self.remote.addr)
                .is_some_and(|tunnel| tunnel.outbound.same_channel(&self.entry))
            {
                tunnels.remove(&self.remote.addr);
            }
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
        // A tunnel that delivers nothing is closed soon. Only forwarded packets count:
        // a dialer can not keep its tunnel open with packets the relay drops.
        let idle = time::sleep(TUNNEL_FIRST_PACKET_TIMEOUT);
        tokio::pin!(idle);
        loop {
            tokio::select! {
                _ = self.released.cancelled() => return "the allocation was released",
                _ = self.evicted.cancelled() => return "made room for a newer tunnel",
                _ = self.shutdown.cancelled() => return "relay is shutting down",
                _ = &mut idle => return "idle",
                first = self.outbound.recv() => {
                    // `self.entry` is a sender, so this does not end.
                    let Some(first) = first else {
                        return "the allocation was released";
                    };
                    let write = write_batch(io, first, &mut self.outbound, WRITE_BATCH);
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
                    // The tunnel must not keep the allocation alive.
                    let Some(allocation) = self.allocation.upgrade() else {
                        return "the allocation was released";
                    };
                    if !allocation.accepts_inbound(self.remote, &packet) {
                        continue;
                    }
                    idle.as_mut().reset(Instant::now() + TUNNEL_IDLE_TIMEOUT);
                    let mut frame = BytesMut::with_capacity(DATAGRAM_HEADER_LEN + packet.len());
                    frame.put_slice(&Datagram::header(self.remote));
                    frame.put_slice(&packet);
                    allocation.deliver(frame.freeze());
                }
            }
        }
    }
}

/// The DHT requests of one control channel.
struct DhtSession {
    /// The tasks that run the requests. Dropping the session aborts them.
    #[cfg_attr(not(feature = "dht"), allow(dead_code))]
    tasks: JoinSet<()>,
    /// Where the tasks report, and where the control channel reads the reports.
    #[cfg_attr(not(feature = "dht"), allow(dead_code))]
    report: mpsc::Sender<RelayControl>,
    results: mpsc::Receiver<RelayControl>,
    /// How many lookups are running.
    #[cfg_attr(not(feature = "dht"), allow(dead_code))]
    lookups: Arc<std::sync::atomic::AtomicUsize>,
}

impl DhtSession {
    fn new() -> Self {
        let (report, results) = mpsc::channel(64);
        Self {
            tasks: JoinSet::new(),
            report,
            results,
            lookups: Arc::default(),
        }
    }
}

#[cfg(not(feature = "dht"))]
impl DhtSession {
    /// The relay is built without the DHT service.
    fn announce(
        &mut self,
        _relay: &Relay,
        _shared: &Arc<AllocationShared>,
        info_hash: InfoHash,
    ) -> Option<RelayControl> {
        Some(RelayControl::DhtAnnounceResult {
            info_hash,
            status: DhtStatus::Unavailable,
        })
    }

    /// The relay is built without the DHT service.
    fn find_peers(
        &mut self,
        _relay: &Relay,
        _shared: &Arc<AllocationShared>,
        request_id: u32,
        _info_hash: InfoHash,
    ) -> Option<RelayControl> {
        Some(RelayControl::DhtFindPeersDone {
            request_id,
            status: DhtStatus::Unavailable,
        })
    }
}

#[cfg(feature = "dht")]
impl DhtSession {
    /// Handles a request to announce `info_hash`. Returns the answer if it is known
    /// right away.
    fn announce(
        &mut self,
        relay: &Relay,
        shared: &Arc<AllocationShared>,
        info_hash: InfoHash,
    ) -> Option<RelayControl> {
        use std::sync::atomic::Ordering;

        use super::dht::{DhtRequest, DhtRequestKind, MAX_ANNOUNCES_PER_CLIENT};

        let answer = |status| Some(RelayControl::DhtAnnounceResult { info_hash, status });
        let Some(service) = &relay.0.dht else {
            return answer(DhtStatus::Unavailable);
        };
        let (known, announced) = {
            let announces = lock(&shared.announces);
            (announces.get(&info_hash).copied(), announces.len())
        };
        let request = match known {
            // Announced, and kept fresh. This is what a client sees that reconnected
            // within the release timeout and announces again.
            Some(Announce {
                announced: true, ..
            }) => return answer(DhtStatus::Ok),
            // Asked for before, but no announcement went out yet: the request is still
            // on its way, or its task ended with the control channel that made it.
            // Announce for this request as well, so that it gets a true answer.
            Some(Announce { request, .. }) => request,
            None => {
                // The policy is not called with the lock held, it may want to look at
                // the relay.
                let request = DhtRequest {
                    identity: &shared.identity,
                    kind: DhtRequestKind::Announce,
                    info_hash: &info_hash,
                    announced,
                    lookups: self.lookups.load(Ordering::Relaxed),
                };
                if announced >= MAX_ANNOUNCES_PER_CLIENT || !service.policy.allow(&request) {
                    shared.metrics.dht_requests_denied.inc();
                    return answer(DhtStatus::Denied);
                }
                let request = service.next_request.fetch_add(1, Ordering::Relaxed);
                let mut announces = lock(&shared.announces);
                // Requests of one client are handled one after the other, the entry can
                // not have appeared in between. The limit may have been reached by
                // another control channel that took over, which then lost this request.
                announces.entry(info_hash).or_insert(Announce {
                    request,
                    announced: false,
                });
                request
            }
        };

        let dht = service.dht.clone();
        let slots = service.announce_slots.clone();
        let shared = shared.clone();
        let report = self.report.clone();
        self.tasks.spawn(async move {
            let Ok(_slot) = slots.acquire().await else {
                return;
            };
            let ok = announce(&dht, &shared.metrics, info_hash, shared.port).await;
            let status = {
                let mut announces = lock(&shared.announces);
                match announces.get_mut(&info_hash) {
                    // Still the entry this request is about.
                    Some(entry) if entry.request == request => {
                        if ok {
                            entry.announced = true;
                            DhtStatus::Ok
                        } else if entry.announced {
                            // Another request for the entry got through.
                            DhtStatus::Ok
                        } else {
                            // The client is told that it failed, so do not keep trying
                            // behind its back. It can ask again.
                            announces.remove(&info_hash);
                            DhtStatus::Failed
                        }
                    }
                    // The client stopped the announcement meanwhile, and maybe asked
                    // for it again. This answer is not about what it has now.
                    _ => return,
                }
            };
            let _ = report
                .send(RelayControl::DhtAnnounceResult { info_hash, status })
                .await;
        });
        None
    }

    /// Handles a request to look up the peers of `info_hash`. Returns the answer if it
    /// is known right away.
    fn find_peers(
        &mut self,
        relay: &Relay,
        shared: &Arc<AllocationShared>,
        request_id: u32,
        info_hash: InfoHash,
    ) -> Option<RelayControl> {
        use std::sync::atomic::Ordering;

        use super::dht::{DhtRequest, DhtRequestKind, MAX_LOOKUPS_PER_CLIENT};
        use crate::protos::relay::MAX_DHT_PEERS_PER_FRAME;

        let answer = |status| Some(RelayControl::DhtFindPeersDone { request_id, status });
        let Some(service) = &relay.0.dht else {
            return answer(DhtStatus::Unavailable);
        };
        let lookups = self.lookups.load(Ordering::Relaxed);
        let request = DhtRequest {
            identity: &shared.identity,
            kind: DhtRequestKind::FindPeers,
            info_hash: &info_hash,
            announced: lock(&shared.announces).len(),
            lookups,
        };
        if lookups >= MAX_LOOKUPS_PER_CLIENT || !service.policy.allow(&request) {
            shared.metrics.dht_requests_denied.inc();
            return answer(DhtStatus::Denied);
        }

        /// Counts a lookup as running until dropped.
        struct Running(Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for Running {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::Relaxed);
            }
        }
        self.lookups.fetch_add(1, Ordering::Relaxed);
        let running = Running(self.lookups.clone());

        let dht = service.dht.clone();
        let metrics = shared.metrics.clone();
        let report = self.report.clone();
        self.tasks.spawn(async move {
            let _running = running;
            metrics.dht_lookups.inc();
            let id = n0_mainline::Id::from_bytes(info_hash).expect("an infohash is 20 bytes");
            let status = match dht.get_peers(id).await {
                Ok(mut batches) => {
                    while let Some(batch) = batches.next().await {
                        for peers in batch.chunks(MAX_DHT_PEERS_PER_FRAME) {
                            let peers = RelayControl::DhtPeers {
                                request_id,
                                peers: peers.to_vec(),
                            };
                            if report.send(peers).await.is_err() {
                                return;
                            }
                        }
                    }
                    DhtStatus::Ok
                }
                Err(_) => DhtStatus::Failed,
            };
            let _ = report
                .send(RelayControl::DhtFindPeersDone { request_id, status })
                .await;
        });
        None
    }
}

/// Announces `port` for `info_hash` on the DHT. Returns whether it worked.
#[cfg(feature = "dht")]
async fn announce(
    dht: &n0_mainline::Dht,
    metrics: &Metrics,
    info_hash: InfoHash,
    port: u16,
) -> bool {
    let id = n0_mainline::Id::from_bytes(info_hash).expect("an infohash is 20 bytes");
    // The port is given explicitly. The DHT must not take the source port of the
    // relay's DHT node for the client's port.
    match dht.announce_peer(id, Some(port)).await {
        Ok(_) => {
            metrics.dht_announces.inc();
            true
        }
        Err(err) => {
            debug!(port, "failed to announce on the DHT: {err:#}");
            metrics.dht_announces_failed.inc();
            false
        }
    }
}

/// Announces the infohashes of all clients again, every `interval`.
#[cfg(feature = "dht")]
async fn refresh_announces(
    relay: Weak<Inner>,
    dht: n0_mainline::Dht,
    slots: Arc<tokio::sync::Semaphore>,
    interval: Duration,
) {
    // The DHT node has a UDP port of its own. Keep it out of the hands of clients.
    match dht.info().await {
        Ok(info) => {
            if let Some(inner) = relay.upgrade() {
                lock(&inner.state)
                    .allocator
                    .exclude_port(info.local_addr().port());
            }
        }
        Err(err) => warn!("failed to learn the port of the DHT node: {err:#}"),
    }
    // Ticks are counted from when a pass starts, not from when it ends. A pass that
    // takes long does not push the next one back by as much.
    let mut ticks = time::interval(interval);
    ticks.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    // The first tick completes immediately.
    ticks.tick().await;
    loop {
        ticks.tick().await;
        let Some(inner) = relay.upgrade() else { return };
        if inner.shutdown.is_cancelled() {
            return;
        }
        // Allocations that are held for a client that is away are refreshed as well.
        let announces: Vec<(Weak<AllocationShared>, InfoHash)> = lock(&inner.state)
            .allocations
            .values()
            .flat_map(|allocation| {
                let shared = Arc::downgrade(&allocation.shared);
                let hashes: Vec<InfoHash> =
                    lock(&allocation.shared.announces).keys().copied().collect();
                hashes.into_iter().map(move |hash| (shared.clone(), hash))
            })
            .collect();
        // Do not keep the relay alive while announcing.
        drop(inner);

        let mut tasks = JoinSet::new();
        for (allocation, info_hash) in announces {
            // The slots are shared with the announce requests of clients.
            let Ok(slot) = slots.clone().acquire_owned().await else {
                return;
            };
            // A pass can take a while. Look again whether the client still has the port
            // and still wants the announcement: the port may belong to somebody else by
            // now.
            let Some(shared) = allocation.upgrade() else {
                continue;
            };
            if shared.released.is_cancelled() || !lock(&shared.announces).contains_key(&info_hash) {
                continue;
            }
            let dht = dht.clone();
            tasks.spawn(async move {
                let _slot = slot;
                if announce(&dht, &shared.metrics, info_hash, shared.port).await
                    && let Some(entry) = lock(&shared.announces).get_mut(&info_hash)
                {
                    entry.announced = true;
                }
            });
            // Take finished tasks out of the set.
            while tasks.try_join_next().is_some() {}
        }
        while tasks.join_next().await.is_some() {}
    }
}
