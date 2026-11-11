//! A UDP socket for a QUIC stack that can also be reached through relays.

use std::{
    collections::HashMap,
    fmt,
    io::{self, IoSliceMut},
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    pin::Pin,
    sync::{Arc, RwLock, Weak},
    task::{Context, Poll},
};

use bytes::Bytes;
use noq::{
    AsyncUdpSocket, UdpSender,
    udp::{RecvMeta, Transmit},
};
use tokio::sync::mpsc;
use tracing::trace;

use super::{
    WsDialer,
    addr::{PathAddr, RelayIndex, is_synthetic},
    link::{Credentials, Inbound, RelayLink},
};
use crate::protos::relay::Datagram;

/// How many packets from relays wait for the QUIC stack before packets are dropped.
const INBOUND_QUEUE_DEPTH: usize = 1024;

/// State shared between the socket, its senders, its handles and its links.
struct Shared {
    /// Where to send packets for each connected relay.
    links: RwLock<HashMap<RelayIndex, mpsc::Sender<Datagram>>>,
    /// Given to every link to deliver the packets it receives.
    inbound: mpsc::Sender<Inbound>,
}

impl fmt::Debug for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shared").finish_non_exhaustive()
    }
}

impl Shared {
    fn links(&self) -> std::sync::RwLockReadGuard<'_, HashMap<RelayIndex, mpsc::Sender<Datagram>>> {
        self.links.read().unwrap_or_else(|err| err.into_inner())
    }

    fn links_mut(
        &self,
    ) -> std::sync::RwLockWriteGuard<'_, HashMap<RelayIndex, mpsc::Sender<Datagram>>> {
        self.links.write().unwrap_or_else(|err| err.into_inner())
    }
}

/// Removes a link from its socket when dropped.
#[derive(Debug)]
pub(super) struct Registration {
    shared: Weak<Shared>,
    index: RelayIndex,
}

impl Drop for Registration {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.upgrade() {
            shared.links_mut().remove(&self.index);
        }
    }
}

/// A UDP socket for a QUIC stack that is also reachable through relays.
///
/// This implements [`noq::AsyncUdpSocket`] on top of a real UDP socket and any number of
/// [`RelayLink`]s. To the QUIC stack it is a single socket:
///
/// - Packets that arrive on the real socket, and packets sent to ordinary addresses, pass
///   through unchanged.
/// - A packet that a relay forwards appears to come from a synthetic address that names
///   the relay and the sender, see [`PathAddr`]. A packet sent to such an address goes
///   back through that relay.
///
/// One socket therefore serves direct and relayed peers at once, and a QUIC connection
/// can use both kinds of path.
///
/// The socket presents itself as an IPv6 socket, because the synthetic addresses are
/// IPv6 addresses. Peers reached directly over IPv4 appear with their IPv4-mapped
/// address, as on a dual-stack socket. Use [`PathAddr::from_socket_addr`] to interpret
/// an address the QUIC stack reports.
///
/// Pass the socket to [`noq::Endpoint::new_with_abstract_socket`], and use the
/// [`RelaySocketHandle`] to connect it to relays.
#[derive(Debug)]
pub struct RelaySocket {
    inner: Box<dyn AsyncUdpSocket>,
    inbound: mpsc::Receiver<Inbound>,
    shared: Arc<Shared>,
    /// Which source [`AsyncUdpSocket::poll_recv`] looks at first. Alternates, so that
    /// neither can starve the other.
    relay_first: bool,
}

/// Connects a [`RelaySocket`] to relays.
///
/// The socket itself is handed to the QUIC stack. The handle stays with the application.
#[derive(Debug, Clone)]
pub struct RelaySocketHandle {
    shared: Arc<Shared>,
}

impl RelaySocket {
    /// Creates a socket on top of `inner`, the real UDP socket.
    ///
    /// `inner` is usually obtained from the QUIC stack's runtime, for example with
    /// `noq::Runtime::wrap_udp_socket`. It must be an IPv4 socket: relays hand out IPv4
    /// addresses only.
    pub fn new(inner: Box<dyn AsyncUdpSocket>) -> (Self, RelaySocketHandle) {
        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE_DEPTH);
        let shared = Arc::new(Shared {
            links: RwLock::new(HashMap::new()),
            inbound: inbound_tx,
        });
        let socket = Self {
            inner,
            inbound: inbound_rx,
            shared: shared.clone(),
            relay_first: false,
        };
        (socket, RelaySocketHandle { shared })
    }

    /// Receives packets that relays forwarded.
    fn poll_recv_relay(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut filled = 0;
        while filled < bufs.len().min(meta.len()) {
            let Poll::Ready(Some(Inbound { relay, datagram })) = self.inbound.poll_recv(cx) else {
                break;
            };
            let len = datagram.payload.len();
            if len > bufs[filled].len() {
                trace!(
                    len,
                    "relayed packet does not fit the receive buffer, dropping"
                );
                continue;
            }
            bufs[filled][..len].copy_from_slice(&datagram.payload);
            let path = PathAddr::Relayed {
                relay,
                remote: datagram.remote,
            };
            let mut packet_meta = RecvMeta::default();
            packet_meta.addr = path.to_socket_addr();
            packet_meta.len = len;
            packet_meta.stride = len;
            meta[filled] = packet_meta;
            filled += 1;
        }
        if filled > 0 {
            Poll::Ready(Ok(filled))
        } else {
            Poll::Pending
        }
    }

    /// Receives packets from the real socket.
    fn poll_recv_inner(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let res = self.inner.poll_recv(cx, bufs, meta);
        if let Poll::Ready(Ok(count)) = res {
            // The socket presents itself as an IPv6 socket.
            for meta in &mut meta[..count] {
                meta.addr = PathAddr::Direct(meta.addr).to_socket_addr();
                meta.dst_ip = meta.dst_ip.map(to_ipv6);
            }
        }
        res
    }
}

/// Returns `ip` as an IPv6 address, mapping an IPv4 address.
fn to_ipv6(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(ip) => IpAddr::V6(ip.to_ipv6_mapped()),
        IpAddr::V6(_) => ip,
    }
}

impl RelaySocketHandle {
    /// Connects the socket to a relay.
    ///
    /// `dialer` dials the relay and must accept messages of
    /// [`MAX_FRAME_SIZE`](crate::protos::relay::MAX_FRAME_SIZE) bytes. `credentials` are
    /// presented on every control channel the link opens.
    ///
    /// The link connects in the background and reconnects when its control channel
    /// breaks. See [`RelayLink`] for how to learn the public address.
    ///
    /// Must be called from within a tokio runtime.
    pub fn connect_relay(&self, dialer: WsDialer, credentials: Arc<dyn Credentials>) -> RelayLink {
        let mut links = self.shared.links_mut();
        // Indices are reused once their link is gone. There can not be more links than
        // indices, a link holds a connection and a task.
        let index = (0..=u16::MAX)
            .map(RelayIndex)
            .find(|index| !links.contains_key(index))
            .expect("fewer than 65536 relay links");
        let registration = Registration {
            shared: Arc::downgrade(&self.shared),
            index,
        };
        let (link, outbound) = RelayLink::spawn(
            index,
            dialer,
            credentials,
            self.shared.inbound.clone(),
            registration,
        );
        links.insert(index, outbound);
        link
    }
}

impl AsyncUdpSocket for RelaySocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(RelaySender {
            inner: self.inner.create_sender(),
            shared: self.shared.clone(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let relay_first = self.relay_first;
        self.relay_first = !relay_first;
        // Both sources are polled before returning `Pending`, so both wake the task.
        if relay_first {
            if let Poll::Ready(res) = self.poll_recv_relay(cx, bufs, meta) {
                return Poll::Ready(res);
            }
            self.poll_recv_inner(cx, bufs, meta)
        } else {
            if let Poll::Ready(res) = self.poll_recv_inner(cx, bufs, meta) {
                return Poll::Ready(res);
            }
            self.poll_recv_relay(cx, bufs, meta)
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        let addr = self.inner.local_addr()?;
        Ok(PathAddr::Direct(addr).to_socket_addr())
    }

    fn max_receive_segments(&self) -> NonZeroUsize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

/// Sends packets of a [`RelaySocket`].
#[derive(Debug)]
struct RelaySender {
    inner: Pin<Box<dyn UdpSender>>,
    shared: Arc<Shared>,
}

impl UdpSender for RelaySender {
    fn poll_send(
        mut self: Pin<&mut Self>,
        transmit: &Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match PathAddr::from_socket_addr(transmit.destination) {
            PathAddr::Relayed { relay, remote } => {
                let links = self.shared.links();
                let Some(link) = links.get(&relay) else {
                    // The link is gone, and with it the path. The QUIC stack notices
                    // from the loss.
                    return Poll::Ready(Ok(()));
                };
                // A transmit can carry several packets of `segment_size` bytes.
                let segment_size = transmit
                    .segment_size
                    .unwrap_or(transmit.contents.len())
                    .max(1);
                for segment in transmit.contents.chunks(segment_size) {
                    let datagram = Datagram {
                        remote,
                        payload: Bytes::copy_from_slice(segment),
                    };
                    // A full queue is loss like any other.
                    if link.try_send(datagram).is_err() {
                        trace!("relay link queue full, dropping packet");
                    }
                }
                Poll::Ready(Ok(()))
            }
            // A synthetic address this version does not understand. There is nowhere to
            // send the packet.
            PathAddr::Direct(addr) if is_synthetic(&addr) => Poll::Ready(Ok(())),
            PathAddr::Direct(addr) => {
                // The real socket is an IPv4 socket and wants IPv4 addresses.
                let transmit = Transmit {
                    destination: addr,
                    ecn: transmit.ecn,
                    contents: transmit.contents,
                    segment_size: transmit.segment_size,
                    src_ip: transmit.src_ip.map(|ip| ip.to_canonical()),
                };
                self.inner.as_mut().poll_send(&transmit, cx)
            }
        }
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        self.inner.max_transmit_segments()
    }
}
