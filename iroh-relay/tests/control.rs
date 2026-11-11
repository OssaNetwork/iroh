//! Tests of the control channel and of forwarding, speaking the wire protocol directly.

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use iroh_dns::dns::DnsResolver;
use iroh_relay::{
    auth::{CHANNEL_BINDING_LEN, SharedToken, channel_binding},
    client::{WsConnection, WsDialer},
    protos::relay::{
        CONTROL_RELATIVE_PATH, CONTROL_SUBPROTOCOL, ClientControl, ClientFrame, Datagram,
        DhtStatus, ErrorCode, MAX_FRAME_SIZE, RelayControl, RelayFrame, RemoteAddr,
    },
    server::{
        AllocationConfig, AuthRequest, Authenticator, ClientId, ForwardAll, Rejected, Server,
        ServerConfig, SharedTokenAuthenticator, testing,
    },
    tls::make_dangerous_client_config,
};
use n0_future::{SinkExt, StreamExt};
use tokio::net::UdpSocket;

const TOKEN: &str = "secret";
const TIMEOUT: Duration = Duration::from_secs(5);

fn allocations(release_timeout: Duration) -> AllocationConfig {
    let mut config = AllocationConfig::new(
        Ipv4Addr::LOCALHOST,
        Arc::new(SharedTokenAuthenticator::new([TOKEN])),
        Arc::new(ForwardAll),
    );
    config.release_timeout = release_timeout;
    // Every relay gets its own ports. The tests run in parallel in one process, and the
    // same identity prefers the same port on every relay with the same range.
    static NEXT_RANGE: AtomicU16 = AtomicU16::new(0);
    let start = 20_000 + 500 * NEXT_RANGE.fetch_add(1, Ordering::Relaxed);
    config.ports = start..=start + 499;
    config
}

async fn spawn_relay(allocations: AllocationConfig) -> Server {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut relay = testing::relay_config();
    relay.allocations = Some(allocations);
    let mut config = ServerConfig::default();
    config.relay = Some(relay);
    Server::spawn(config).await.unwrap()
}

async fn open(server: &Server) -> WsConnection {
    let url = format!("https://{}", server.https_addr().unwrap())
        .parse()
        .unwrap();
    WsDialer::new(url, DnsResolver::new(), MAX_FRAME_SIZE)
        .tls_client_config(make_dangerous_client_config())
        .connect(CONTROL_RELATIVE_PATH, CONTROL_SUBPROTOCOL)
        .await
        .unwrap()
}

async fn send(conn: &mut WsConnection, frame: impl Into<ClientFrame>) {
    conn.send(frame.into().to_bytes().unwrap()).await.unwrap();
}

/// Receives the next frame, `None` if the relay closed the channel.
async fn recv(conn: &mut WsConnection) -> Option<RelayFrame> {
    let msg = tokio::time::timeout(TIMEOUT, conn.next())
        .await
        .expect("timeout waiting for a frame");
    match msg {
        Some(Ok(bytes)) => Some(RelayFrame::from_bytes(bytes).unwrap()),
        Some(Err(_)) | None => None,
    }
}

/// Receives the next frame that is not a ping.
async fn recv_control(conn: &mut WsConnection) -> RelayControl {
    loop {
        match recv(conn).await.expect("control channel closed") {
            RelayFrame::Control(RelayControl::Ping(_)) => continue,
            RelayFrame::Control(control) => return control,
            RelayFrame::Datagram(datagram) => panic!("unexpected datagram: {datagram:?}"),
        }
    }
}

async fn recv_datagram(conn: &mut WsConnection) -> Datagram {
    loop {
        match recv(conn).await.expect("control channel closed") {
            RelayFrame::Control(RelayControl::Ping(_)) => continue,
            RelayFrame::Control(control) => panic!("unexpected control message: {control:?}"),
            RelayFrame::Datagram(datagram) => return datagram,
        }
    }
}

fn auth(name: &str) -> ClientControl {
    ClientControl::Auth {
        credentials: SharedToken::new(name.to_string(), TOKEN)
            .to_bytes()
            .unwrap(),
    }
}

/// Opens a control channel as `name` and returns it with the allocated address.
async fn connect(server: &Server, name: &str) -> (WsConnection, SocketAddrV4) {
    let mut conn = open(server).await;
    send(&mut conn, auth(name)).await;
    match recv_control(&mut conn).await {
        RelayControl::Allocated { addr } => (conn, addr),
        other => panic!("expected an allocation, got {other:?}"),
    }
}

async fn expect_error(conn: &mut WsConnection, expected: ErrorCode) {
    match recv_control(conn).await {
        RelayControl::Error { code, .. } => assert_eq!(code, expected),
        other => panic!("expected an error, got {other:?}"),
    }
    // The relay closes the channel after an error.
    assert!(recv(conn).await.is_none());
}

async fn udp_socket() -> (UdpSocket, SocketAddrV4) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let SocketAddr::V4(addr) = socket.local_addr().unwrap() else {
        panic!("not an IPv4 socket");
    };
    (socket, addr)
}

async fn recv_udp(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buf = vec![0u8; 2048];
    let (len, from) = tokio::time::timeout(TIMEOUT, socket.recv_from(&mut buf))
        .await
        .expect("timeout waiting for a packet")
        .unwrap();
    buf.truncate(len);
    (buf, from)
}

/// Waits until `condition` holds.
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

#[tokio::test]
async fn forwards_in_both_directions() {
    let server = spawn_relay(allocations(Duration::from_secs(30))).await;
    let (mut bob, bob_addr) = connect(&server, "bob").await;
    assert_eq!(*bob_addr.ip(), Ipv4Addr::LOCALHOST);
    let (alice, alice_addr) = udp_socket().await;

    // Alice reaches Bob at his public address. Bob learns her address.
    alice.send_to(b"hello bob", bob_addr).await.unwrap();
    let datagram = recv_datagram(&mut bob).await;
    assert_eq!(datagram.remote, RemoteAddr::udp(alice_addr));
    assert_eq!(&datagram.payload[..], b"hello bob");

    // Bob's reply leaves from his public address.
    let reply = Datagram {
        remote: RemoteAddr::udp(alice_addr),
        payload: Bytes::from_static(b"hello alice"),
    };
    send(&mut bob, reply).await;
    let (payload, from) = recv_udp(&alice).await;
    assert_eq!(payload, b"hello alice");
    assert_eq!(from, SocketAddr::V4(bob_addr));

    // A second dialer shares the port.
    let (carol, carol_addr) = udp_socket().await;
    carol.send_to(b"hello from carol", bob_addr).await.unwrap();
    let datagram = recv_datagram(&mut bob).await;
    assert_eq!(datagram.remote, RemoteAddr::udp(carol_addr));

    let metrics = server.metrics();
    assert_eq!(metrics.server.packets_inbound.get(), 2);
    assert_eq!(metrics.server.packets_outbound.get(), 1);
    assert_eq!(metrics.server.allocations_created.get(), 1);
}

#[tokio::test]
async fn drops_invalid_packets() {
    let mut config = allocations(Duration::from_secs(30));
    config.max_packet_size = 1200;
    let server = spawn_relay(config).await;
    let (mut bob, bob_addr) = connect(&server, "bob").await;
    let (alice, alice_addr) = udp_socket().await;
    let dropped = || server.metrics().server.packets_dropped_invalid.get();

    // Inbound: too large.
    alice.send_to(&[0u8; 1201], bob_addr).await.unwrap();
    eventually("the oversized packet is dropped", || dropped() == 1).await;
    // The largest packet still passes, and nothing is left over from the dropped one.
    alice.send_to(&[7u8; 1200], bob_addr).await.unwrap();
    let datagram = recv_datagram(&mut bob).await;
    assert_eq!(datagram.payload, Bytes::from(vec![7u8; 1200]));

    // Outbound: too large, empty, and to destinations that can not be a remote party.
    let outbound = |addr: SocketAddrV4, len: usize| Datagram {
        remote: RemoteAddr::udp(addr),
        payload: vec![1u8; len].into(),
    };
    send(&mut bob, outbound(alice_addr, 1201)).await;
    send(&mut bob, outbound(alice_addr, 0)).await;
    send(
        &mut bob,
        outbound(SocketAddrV4::new(*alice_addr.ip(), 0), 10),
    )
    .await;
    send(
        &mut bob,
        outbound(SocketAddrV4::new(Ipv4Addr::BROADCAST, 9), 10),
    )
    .await;
    send(
        &mut bob,
        outbound(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 9), 10),
    )
    .await;
    send(
        &mut bob,
        outbound(SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 1), 9), 10),
    )
    .await;
    // A tunnelled remote party that does not exist.
    let mut tunnelled = outbound(alice_addr, 10);
    tunnelled.remote.tunnel = true;
    send(&mut bob, tunnelled).await;
    eventually("the invalid packets are dropped", || dropped() == 8).await;

    // The channel survived all of it.
    send(&mut bob, outbound(alice_addr, 10)).await;
    let (payload, _) = recv_udp(&alice).await;
    assert_eq!(payload, vec![1u8; 10]);
}

#[tokio::test]
async fn rejects_bad_credentials() {
    let server = spawn_relay(allocations(Duration::from_secs(30))).await;

    let mut conn = open(&server).await;
    let credentials = SharedToken::new("bob", "wrong").to_bytes().unwrap();
    send(&mut conn, ClientControl::Auth { credentials }).await;
    expect_error(&mut conn, ErrorCode::Unauthorized).await;

    // Anything but credentials as the first message is a protocol violation.
    let mut conn = open(&server).await;
    send(&mut conn, ClientControl::Ping([0; 8])).await;
    expect_error(&mut conn, ErrorCode::Protocol).await;

    let mut conn = open(&server).await;
    conn.send(Bytes::from_static(&[0x02])).await.unwrap();
    expect_error(&mut conn, ErrorCode::Protocol).await;

    assert_eq!(server.relay().unwrap().allocation_count(), 0);
    assert_eq!(server.metrics().server.auth_rejected.get(), 1);
}

#[tokio::test]
async fn control_messages() {
    let server = spawn_relay(allocations(Duration::from_secs(30))).await;
    let (mut bob, _) = connect(&server, "bob").await;

    send(&mut bob, ClientControl::Ping(*b"12345678")).await;
    assert_eq!(
        recv_control(&mut bob).await,
        RelayControl::Pong(*b"12345678")
    );

    // The DHT service is not available.
    let info_hash = [9u8; 20];
    send(&mut bob, ClientControl::DhtAnnounce { info_hash }).await;
    assert_eq!(
        recv_control(&mut bob).await,
        RelayControl::DhtAnnounceResult {
            info_hash,
            status: DhtStatus::Unavailable
        }
    );
    send(
        &mut bob,
        ClientControl::DhtFindPeers {
            request_id: 7,
            info_hash,
        },
    )
    .await;
    assert_eq!(
        recv_control(&mut bob).await,
        RelayControl::DhtFindPeersDone {
            request_id: 7,
            status: DhtStatus::Unavailable
        }
    );

    // An unknown control message is ignored.
    bob.send(Bytes::from_static(&[0x80, 0xee, 1, 2, 3]))
        .await
        .unwrap();
    send(&mut bob, ClientControl::Ping([1; 8])).await;
    assert_eq!(recv_control(&mut bob).await, RelayControl::Pong([1; 8]));

    // Authenticating twice is a protocol violation.
    send(&mut bob, auth("bob")).await;
    expect_error(&mut bob, ErrorCode::Protocol).await;
}

#[tokio::test]
async fn reconnect_within_release_timeout_keeps_the_port() {
    let server = spawn_relay(allocations(Duration::from_secs(30))).await;
    let relay = server.relay().unwrap();
    let (bob, bob_addr) = connect(&server, "bob").await;
    let (alice, alice_addr) = udp_socket().await;
    let detached = || server.metrics().server.packets_dropped_detached.get();

    drop(bob);
    // The port stays bound, packets for Bob are dropped while he is away.
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while detached() == 0 {
        assert!(tokio::time::Instant::now() < deadline, "packet not dropped");
        alice.send_to(b"anyone there?", bob_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(relay.allocation_count(), 1);
    assert_eq!(relay.port_of(&ClientId::new("bob")), Some(bob_addr.port()));

    let (mut bob, new_addr) = connect(&server, "bob").await;
    assert_eq!(new_addr, bob_addr);
    assert_eq!(server.metrics().server.allocations_created.get(), 1);
    assert_eq!(server.metrics().server.allocations_resumed.get(), 1);

    // Packets dropped in between are not delivered late.
    alice.send_to(b"welcome back", bob_addr).await.unwrap();
    let datagram = recv_datagram(&mut bob).await;
    assert_eq!(datagram.remote, RemoteAddr::udp(alice_addr));
    assert_eq!(&datagram.payload[..], b"welcome back");
}

#[tokio::test]
async fn port_is_released_after_the_release_timeout() {
    let server = spawn_relay(allocations(Duration::from_millis(200))).await;
    let relay = server.relay().unwrap();
    let (bob, bob_addr) = connect(&server, "bob").await;
    assert_eq!(relay.allocation_count(), 1);

    drop(bob);
    eventually("the allocation is released", || {
        relay.allocation_count() == 0
    })
    .await;
    assert_eq!(server.metrics().server.allocations_released.get(), 1);
    // The port can be bound again, the relay closed its socket.
    eventually("the port is free", || {
        std::net::UdpSocket::bind(bob_addr).is_ok()
    })
    .await;

    // Bob gets the same port when he returns, since nobody took it.
    let (_bob, new_addr) = connect(&server, "bob").await;
    assert_eq!(new_addr, bob_addr);
    assert_eq!(server.metrics().server.allocations_created.get(), 2);
}

#[tokio::test]
async fn zero_release_timeout_releases_immediately() {
    let server = spawn_relay(allocations(Duration::ZERO)).await;
    let relay = server.relay().unwrap();
    let (bob, _) = connect(&server, "bob").await;
    drop(bob);
    eventually("the allocation is released", || {
        relay.allocation_count() == 0
    })
    .await;
}

#[tokio::test]
async fn immediate_reconnect_gets_the_same_port() {
    // Without a release timeout the port is freed when the client disconnects, while its
    // socket closes a moment later. A client that returns in between waits for it.
    let server = spawn_relay(allocations(Duration::ZERO)).await;
    let (mut bob, addr) = connect(&server, "bob").await;
    for _ in 0..20 {
        drop(bob);
        let (conn, new_addr) = connect(&server, "bob").await;
        assert_eq!(new_addr, addr);
        bob = conn;
    }
    assert_eq!(server.metrics().server.allocations_bind_failed.get(), 0);
}

#[tokio::test]
async fn rejects_invalid_packet_size_limit() {
    let mut config = allocations(Duration::ZERO);
    config.max_packet_size = 0;
    let mut relay = testing::relay_config();
    relay.allocations = Some(config);
    let mut server_config = ServerConfig::default();
    server_config.relay = Some(relay);
    assert!(Server::spawn(server_config).await.is_err());
}

#[tokio::test]
async fn second_control_channel_takes_over() {
    let server = spawn_relay(allocations(Duration::from_secs(30))).await;
    let (mut first, addr) = connect(&server, "bob").await;
    let (mut second, second_addr) = connect(&server, "bob").await;
    assert_eq!(second_addr, addr);
    expect_error(&mut first, ErrorCode::Superseded).await;

    // The first channel going away does not release the second one's allocation.
    drop(first);
    let (alice, alice_addr) = udp_socket().await;
    alice.send_to(b"hello", addr).await.unwrap();
    let datagram = recv_datagram(&mut second).await;
    assert_eq!(datagram.remote, RemoteAddr::udp(alice_addr));
    assert_eq!(server.relay().unwrap().allocation_count(), 1);
    assert_eq!(server.metrics().server.allocations_created.get(), 1);
}

#[tokio::test]
async fn reports_port_exhaustion() {
    let mut config = allocations(Duration::from_secs(30));
    // Find a free port to use as the whole range.
    let port = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    config.ports = port..=port;
    let server = spawn_relay(config).await;

    let (_bob, addr) = connect(&server, "bob").await;
    assert_eq!(addr.port(), port);

    let mut carol = open(&server).await;
    send(&mut carol, auth("carol")).await;
    expect_error(&mut carol, ErrorCode::NoPortAvailable).await;
    assert_eq!(server.metrics().server.ports_exhausted.get(), 1);
}

#[tokio::test]
async fn skips_ports_that_are_in_use() {
    let mut config = allocations(Duration::from_secs(30));
    // Two neighbouring ports, the first of which is taken by somebody else.
    let (taken, range) = loop {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        if port == u16::MAX {
            continue;
        }
        if let Ok(next) = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port + 1)) {
            drop(next);
            break (socket, port..=port + 1);
        }
    };
    config.ports = range.clone();
    let server = spawn_relay(config).await;

    let (_bob, addr) = connect(&server, "bob").await;
    assert_eq!(addr.port(), *range.end());
    drop(taken);
}

/// An authenticator that requires the client to echo the channel binding.
#[derive(Debug)]
struct ChannelBindingAuthenticator;

impl Authenticator for ChannelBindingAuthenticator {
    async fn authenticate(&self, request: &AuthRequest) -> Result<ClientId, Rejected> {
        let binding = request
            .channel_binding
            .ok_or_else(|| Rejected::new("no TLS".to_string()))?;
        if request.credentials[..] != binding[..] {
            return Err(Rejected::new("wrong channel binding".to_string()));
        }
        assert_eq!(request.uri.path(), "/control");
        Ok(ClientId::new("bound"))
    }
}

#[tokio::test]
async fn channel_binding_matches_on_both_ends() {
    let mut config = allocations(Duration::from_secs(30));
    config.authenticator = Arc::new(ChannelBindingAuthenticator);
    let server = spawn_relay(config).await;

    let mut conn = open(&server).await;
    let binding = channel_binding(&conn).expect("the control channel runs on TLS");
    send(
        &mut conn,
        ClientControl::Auth {
            credentials: Bytes::copy_from_slice(&binding),
        },
    )
    .await;
    assert!(matches!(
        recv_control(&mut conn).await,
        RelayControl::Allocated { .. }
    ));

    // The binding of another connection is not accepted.
    let mut other = open(&server).await;
    assert_ne!(channel_binding(&other).unwrap(), binding);
    send(
        &mut other,
        ClientControl::Auth {
            credentials: Bytes::copy_from_slice(&[0u8; CHANNEL_BINDING_LEN]),
        },
    )
    .await;
    expect_error(&mut other, ErrorCode::Unauthorized).await;
}

#[tokio::test]
async fn shutdown_closes_control_channels() {
    let server = spawn_relay(allocations(Duration::from_secs(30))).await;
    let (mut bob, bob_addr) = connect(&server, "bob").await;
    let metrics = server.metrics().clone();
    server.shutdown().await.unwrap();
    assert!(recv(&mut bob).await.is_none());
    eventually("the port is free", || {
        std::net::UdpSocket::bind(bob_addr).is_ok()
    })
    .await;
    assert_eq!(metrics.server.allocations_released.get(), 1);
}
