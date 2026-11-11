//! End-to-end tests of the TCP fallback: QUIC connections through a tunnel to the relay.

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    time::Duration,
};

use iroh_dns::dns::DnsResolver;
use iroh_relay::{
    auth::SharedToken,
    client::{
        PathAddr, RelayLink, RelaySocket, RelaySocketHandle, TunnelConfig, TunnelLink, TunnelState,
        Winner, WsDialer, race_udp_and_tunnel,
    },
    protos::relay::MAX_FRAME_SIZE,
    server::{
        AllocationConfig, AllocationPolicy, CertConfig, ClientId, DefaultPolicy, Direction, Packet,
        RelayConfig, Server, ServerConfig, SharedTokenAuthenticator, TlsConfig, TrafficPolicy,
        Verdict, testing,
    },
    tls::make_dangerous_client_config,
};
use noq::{
    Endpoint, EndpointConfig, Runtime, TokioRuntime,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use tokio::time::timeout;

const TOKEN: &str = "secret";
const TIMEOUT: Duration = Duration::from_secs(10);
const ALPN: &[u8] = b"relay-test";
const BASE_PORT: u16 = 22_000;

/// Returns a port range no other test relay uses.
///
/// The same identity prefers the same port on every relay with the same range, so relays
/// that share a range take ports from one another. Tests can run in parallel in one
/// process or in one process each, hence both a counter and the process id. The ranges
/// lie below the ports operating systems pick for outgoing sockets.
fn port_range() -> std::ops::RangeInclusive<u16> {
    static NEXT_RANGE: AtomicU16 = AtomicU16::new(0);
    let per_process = (std::process::id() % 20) as u16 * 500;
    let per_test = NEXT_RANGE.fetch_add(1, Ordering::Relaxed) % 25 * 20;
    let start = BASE_PORT + per_process + per_test;
    start..=start + 19
}

/// Drops the packets that reach an allocation over UDP while `blocked` is set, as if the
/// network between the dialer and the relay did not let UDP through.
#[derive(Debug)]
struct BlockUdp {
    inner: DefaultPolicy,
    blocked: Arc<AtomicBool>,
}

#[derive(Debug)]
struct BlockUdpAllocation {
    inner: Box<dyn AllocationPolicy>,
    blocked: Arc<AtomicBool>,
}

impl TrafficPolicy for BlockUdp {
    fn allocation(&self, identity: &ClientId) -> Box<dyn AllocationPolicy> {
        Box::new(BlockUdpAllocation {
            inner: self.inner.allocation(identity),
            blocked: self.blocked.clone(),
        })
    }
}

impl AllocationPolicy for BlockUdpAllocation {
    fn check(&mut self, packet: &Packet<'_>) -> Verdict {
        if packet.direction == Direction::Inbound
            && !packet.remote.tunnel
            && self.blocked.load(Ordering::Relaxed)
        {
            return Verdict::Drop;
        }
        self.inner.check(packet)
    }
}

struct TestRelay {
    server: Server,
    /// Set to drop UDP packets to allocations.
    udp_blocked: Arc<AtomicBool>,
    /// Trusts the relay's certificate, which is valid for its IP address.
    tls_config: rustls::ClientConfig,
}

fn ring() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A TLS client configuration that trusts exactly `certs`.
fn trusting(certs: Vec<rustls::pki_types::CertificateDer<'static>>) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert).unwrap();
    }
    rustls::ClientConfig::builder_with_provider(ring())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

async fn spawn_relay(configure: impl FnOnce(&mut AllocationConfig)) -> TestRelay {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let udp_blocked = Arc::new(AtomicBool::new(false));
    let mut allocations = AllocationConfig::new(
        Ipv4Addr::LOCALHOST,
        Arc::new(SharedTokenAuthenticator::new([TOKEN])),
        Arc::new(BlockUdp {
            inner: DefaultPolicy::default(),
            blocked: udp_blocked.clone(),
        }),
    );
    allocations.ports = port_range();
    configure(&mut allocations);

    let (certs, server_tls) = testing::self_signed_tls_certs_and_config();
    let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
    relay.tls = Some(TlsConfig::new(
        (Ipv4Addr::LOCALHOST, 0),
        CertConfig::Manual {
            server_config: server_tls,
        },
    ));
    relay.allocations = Some(allocations);
    let mut config = ServerConfig::default();
    config.relay = Some(relay);
    let server = Server::spawn(config).await.unwrap();
    TestRelay {
        server,
        udp_blocked,
        tls_config: trusting(certs),
    }
}

impl TestRelay {
    fn dialer(&self) -> WsDialer {
        let url = format!("https://{}", self.server.https_addr().unwrap())
            .parse()
            .unwrap();
        WsDialer::new(url, DnsResolver::new(), MAX_FRAME_SIZE)
            .tls_client_config(make_dangerous_client_config())
    }

    /// The configuration of a tunnel to this relay. The relay does not listen on port
    /// 443 in tests.
    fn tunnel_config(&self) -> TunnelConfig {
        let mut config = TunnelConfig::new(self.tls_config.clone());
        config.tcp_port = self.server.https_addr().unwrap().port();
        config
    }
}

/// The TLS configuration of QUIC endpoints with a shared self-signed certificate.
fn quic_configs() -> (noq::ServerConfig, noq::ClientConfig) {
    let (certs, mut server_tls) = testing::self_signed_tls_certs_and_config();
    server_tls.alpn_protocols = vec![ALPN.to_vec()];
    let server =
        noq::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap()));
    let mut client_tls = trusting(certs);
    client_tls.alpn_protocols = vec![ALPN.to_vec()];
    let client = noq::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls).unwrap()));
    (server, client)
}

/// A QUIC endpoint on a relay socket.
struct Peer {
    endpoint: Endpoint,
    handle: RelaySocketHandle,
}

fn peer(server_config: Option<noq::ServerConfig>, client_config: noq::ClientConfig) -> Peer {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let runtime = Arc::new(TokioRuntime);
    let inner = runtime.wrap_udp_socket(socket).unwrap();
    let (socket, handle) = RelaySocket::new(inner).unwrap();
    let endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        server_config,
        Box::new(socket),
        runtime,
    )
    .unwrap();
    endpoint.set_default_client_config(client_config);
    Peer { endpoint, handle }
}

impl Peer {
    fn connect_relay(&self, relay: &TestRelay, name: &str) -> RelayLink {
        let credentials = SharedToken::new(name.to_string(), TOKEN);
        self.handle
            .connect_relay(relay.dialer(), Arc::new(credentials))
    }

    /// Accepts connections and echoes their streams, reporting each connection.
    fn serve(&self) -> tokio::sync::mpsc::UnboundedReceiver<noq::Connection> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let endpoint = self.endpoint.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let tx = tx.clone();
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    let _ = tx.send(conn.clone());
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        let data = recv.read_to_end(16 * 1024 * 1024).await.unwrap();
                        send.write_all(&data).await.unwrap();
                        send.finish().unwrap();
                    }
                });
            }
        });
        rx
    }
}

/// A relay, and Bob behind it serving an echo.
struct Setup {
    relay: TestRelay,
    bob: Peer,
    link: RelayLink,
    /// The address Bob advertises.
    target: SocketAddrV4,
    accepted: tokio::sync::mpsc::UnboundedReceiver<noq::Connection>,
    client_config: noq::ClientConfig,
}

async fn setup(configure: impl FnOnce(&mut AllocationConfig)) -> Setup {
    let relay = spawn_relay(configure).await;
    let (server_config, client_config) = quic_configs();
    let bob = peer(Some(server_config), client_config.clone());
    let link = bob.connect_relay(&relay, "bob");
    let target = timeout(TIMEOUT, link.public_addr()).await.unwrap().unwrap();
    let accepted = bob.serve();
    Setup {
        relay,
        bob,
        link,
        target,
        accepted,
        client_config,
    }
}

/// Returns the remote address of the first path of a connection.
fn remote_address(conn: &noq::Connection) -> SocketAddr {
    conn.path(noq::PathId::ZERO)
        .expect("the first path is open")
        .remote_address()
        .expect("the first path is open")
}

async fn echo(conn: &noq::Connection, data: &[u8]) {
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(data).await.unwrap();
    send.finish().unwrap();
    let echoed = timeout(TIMEOUT, recv.read_to_end(16 * 1024 * 1024))
        .await
        .expect("timeout waiting for the echo")
        .unwrap();
    assert_eq!(echoed.len(), data.len());
    assert!(echoed == data);
}

async fn eventually(what: &str, condition: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while !condition() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timeout waiting until {what}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Waits until the tunnel is closed and returns the reason.
async fn closed(tunnel: &TunnelLink) -> String {
    let mut state = tunnel.watch_state();
    let state = timeout(
        TIMEOUT,
        state.wait_for(|state| matches!(state, TunnelState::Closed(_))),
    )
    .await
    .expect("timeout waiting for the tunnel to close")
    .unwrap()
    .clone();
    match state {
        TunnelState::Closed(reason) => reason,
        other => panic!("unexpected state {other:?}"),
    }
}

#[tokio::test]
async fn quic_through_the_tunnel() {
    let mut setup = setup(|_| {}).await;
    // Nothing reaches Bob over UDP.
    setup.relay.udp_blocked.store(true, Ordering::Relaxed);
    let target = setup.target;

    let alice = peer(None, setup.client_config.clone());
    let tunnel = alice
        .handle
        .open_tunnel(target, setup.relay.tunnel_config());
    assert_eq!(tunnel.target(), target);
    // The handshake can start before the tunnel is up.
    let connecting = alice.endpoint.connect(tunnel.addr(), "localhost").unwrap();
    let conn = timeout(TIMEOUT, connecting).await.unwrap().unwrap();
    assert_eq!(tunnel.state(), TunnelState::Connected);
    assert_eq!(
        PathAddr::from_socket_addr(remote_address(&conn)),
        PathAddr::Tunnel { target }
    );

    // To Bob she is a remote party that came through the tunnel.
    let bob_conn = timeout(TIMEOUT, setup.accepted.recv())
        .await
        .unwrap()
        .unwrap();
    match PathAddr::from_socket_addr(remote_address(&bob_conn)) {
        PathAddr::Relayed { relay, remote } => {
            assert_eq!(relay, setup.link.index());
            assert!(remote.tunnel);
        }
        other => panic!("expected a relayed path, got {other:?}"),
    }

    echo(&conn, b"hello through the tunnel").await;
    let large: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
    echo(&conn, &large).await;
    let metrics = setup.relay.server.metrics();
    assert_eq!(metrics.server.tunnels_opened.get(), 1);

    // Dropping the link closes the tunnel on the relay.
    drop(tunnel);
    eventually("the tunnel is closed", || {
        metrics.server.tunnels_closed.get() == 1
    })
    .await;
    drop(setup.bob);
}

/// Dials Bob the way a dialer with the fallback does. Returns who won, and the tunnel if
/// one was opened.
async fn race(
    alice: &Peer,
    relay: &TestRelay,
    target: SocketAddrV4,
) -> (Winner<noq::Connection, noq::Connection>, Option<TunnelLink>) {
    let mut tunnel = None;
    let udp = alice.endpoint.connect(target.into(), "localhost").unwrap();
    let res = race_udp_and_tunnel(
        udp,
        || {
            let link = alice.handle.open_tunnel(target, relay.tunnel_config());
            let connecting = alice.endpoint.connect(link.addr(), "localhost").unwrap();
            tunnel = Some(link);
            connecting
        },
        Duration::from_millis(250),
    );
    let winner = timeout(TIMEOUT, res).await.unwrap().unwrap();
    (winner, tunnel)
}

#[tokio::test]
async fn race_picks_udp_when_it_works() {
    let setup = setup(|_| {}).await;
    let alice = peer(None, setup.client_config.clone());
    let (winner, tunnel) = race(&alice, &setup.relay, setup.target).await;
    let Winner::Udp(conn) = winner else {
        panic!("UDP works, the tunnel must not win");
    };
    echo(&conn, b"over udp").await;
    // The handshake was done before the tunnel was due.
    assert!(tunnel.is_none());
    assert_eq!(setup.relay.server.metrics().server.tunnels_opened.get(), 0);
}

#[tokio::test]
async fn race_falls_back_to_the_tunnel_when_udp_is_blocked() {
    let setup = setup(|_| {}).await;
    setup.relay.udp_blocked.store(true, Ordering::Relaxed);
    let alice = peer(None, setup.client_config.clone());
    let (winner, tunnel) = race(&alice, &setup.relay, setup.target).await;
    let Winner::Tunnel(conn) = winner else {
        panic!("UDP is blocked, it can not win");
    };
    echo(&conn, b"over the tunnel").await;
    assert!(tunnel.is_some());
    assert_eq!(setup.relay.server.metrics().server.tunnels_opened.get(), 1);
}

#[tokio::test]
async fn no_fallback_without_a_tunnel() {
    let setup = setup(|_| {}).await;
    let relay = &setup.relay;
    let alice = peer(None, setup.client_config.clone());

    // The relay has no allocation on this port: the upgrade is rejected.
    let unknown = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9);
    let tunnel = alice.handle.open_tunnel(unknown, relay.tunnel_config());
    let reason = closed(&tunnel).await;
    assert!(reason.contains("404"), "unexpected reason: {reason}");
    assert!(tunnel.connected().await.is_err());

    // Nothing listens on the TCP port: the connection is refused. This is what a dialer
    // sees when the peer is not behind a relay.
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let mut config = relay.tunnel_config();
    config.tcp_port = listener.local_addr().unwrap().port();
    drop(listener);
    closed(&alice.handle.open_tunnel(setup.target, config)).await;

    // A certificate that is not trusted for the IP address.
    let mut config = relay.tunnel_config();
    config.tls_config = trusting(Vec::new());
    closed(&alice.handle.open_tunnel(setup.target, config)).await;
    assert_eq!(relay.server.metrics().server.tunnels_opened.get(), 0);

    // With the right configuration the same target works.
    let tunnel = alice
        .handle
        .open_tunnel(setup.target, relay.tunnel_config());
    timeout(TIMEOUT, tunnel.connected()).await.unwrap().unwrap();
}

#[tokio::test]
async fn tunnels_are_limited_and_end_with_the_allocation() {
    let setup = setup(|config| {
        config.max_tunnels = 2;
        config.release_timeout = Duration::ZERO;
    })
    .await;
    let relay = &setup.relay;
    let metrics = relay.server.metrics();

    // Each dialer has its own socket, and with it its own tunnel to the target.
    let dialers: Vec<Peer> = (0..3)
        .map(|_| peer(None, setup.client_config.clone()))
        .collect();
    let open = |dialer: &Peer| {
        dialer
            .handle
            .open_tunnel(setup.target, relay.tunnel_config())
    };
    let first = open(&dialers[0]);
    let second = open(&dialers[1]);
    timeout(TIMEOUT, first.connected()).await.unwrap().unwrap();
    timeout(TIMEOUT, second.connected()).await.unwrap().unwrap();
    eventually("both tunnels are open", || {
        metrics.server.tunnels_opened.get() == 2
    })
    .await;

    // The third one is turned away.
    let third = open(&dialers[2]);
    closed(&third).await;
    assert_eq!(metrics.server.tunnels_rejected.get(), 1);

    // When Bob leaves, his allocation is released and its tunnels are closed.
    drop(setup.link);
    closed(&first).await;
    closed(&second).await;
    eventually("the tunnels are closed", || {
        metrics.server.tunnels_closed.get() == 2
    })
    .await;
}
