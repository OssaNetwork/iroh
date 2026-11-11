//! End-to-end tests: QUIC connections to an endpoint that is reachable through a relay.

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};

use iroh_dns::dns::DnsResolver;
use iroh_relay::{
    auth::SharedToken,
    client::{LinkState, PathAddr, RelayLink, RelaySocket, RelaySocketHandle, WsDialer},
    protos::relay::MAX_FRAME_SIZE,
    server::{
        AllocationConfig, DefaultPolicy, Server, ServerConfig, SharedTokenAuthenticator, testing,
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

const BASE_PORT: u16 = 2_000;

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

async fn spawn_relay(release_timeout: Duration) -> Server {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut allocations = AllocationConfig::new(
        Ipv4Addr::LOCALHOST,
        Arc::new(SharedTokenAuthenticator::new([TOKEN])),
        Arc::new(DefaultPolicy::default()),
    );
    allocations.release_timeout = release_timeout;
    allocations.ports = port_range();
    let mut relay = testing::relay_config();
    relay.allocations = Some(allocations);
    let mut config = ServerConfig::default();
    config.relay = Some(relay);
    Server::spawn(config).await.unwrap()
}

fn dialer(server: &Server) -> WsDialer {
    let url = format!("https://{}", server.https_addr().unwrap())
        .parse()
        .unwrap();
    WsDialer::new(url, DnsResolver::new(), MAX_FRAME_SIZE)
        .tls_client_config(make_dangerous_client_config())
}

/// The TLS configuration of a QUIC endpoint with a self-signed certificate.
fn quic_configs() -> (noq::ServerConfig, noq::ClientConfig) {
    let (certs, mut server_tls) = testing::self_signed_tls_certs_and_config();
    server_tls.alpn_protocols = vec![ALPN.to_vec()];
    let server =
        noq::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap()));

    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert).unwrap();
    }
    let mut client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    client_tls.alpn_protocols = vec![ALPN.to_vec()];
    let client = noq::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls).unwrap()));
    (server, client)
}

/// An endpoint that can not be reached directly, only through a relay.
struct Bob {
    endpoint: Endpoint,
    handle: RelaySocketHandle,
    /// The address of Bob's real socket.
    local_addr: SocketAddrV4,
}

fn bob(server_config: noq::ServerConfig) -> Bob {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let SocketAddr::V4(local_addr) = socket.local_addr().unwrap() else {
        panic!("not an IPv4 socket");
    };
    let runtime = Arc::new(TokioRuntime);
    let inner = runtime.wrap_udp_socket(socket).unwrap();
    let (socket, handle) = RelaySocket::new(inner).unwrap();
    let endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(server_config),
        Box::new(socket),
        runtime,
    )
    .unwrap();
    Bob {
        endpoint,
        handle,
        local_addr,
    }
}

impl Bob {
    fn connect_relay(&self, server: &Server, name: &str) -> RelayLink {
        let credentials = SharedToken::new(name.to_string(), TOKEN);
        self.handle
            .connect_relay(dialer(server), Arc::new(credentials))
    }

    /// Accepts one connection and echoes one stream on it.
    async fn serve_one(&self) -> noq::Connection {
        let incoming = timeout(TIMEOUT, self.endpoint.accept())
            .await
            .expect("timeout waiting for a connection")
            .expect("endpoint closed");
        let conn = incoming.await.unwrap();
        let echo = conn.clone();
        tokio::spawn(async move {
            while let Ok((mut send, mut recv)) = echo.accept_bi().await {
                let data = recv.read_to_end(16 * 1024 * 1024).await.unwrap();
                send.write_all(&data).await.unwrap();
                send.finish().unwrap();
            }
        });
        conn
    }
}

/// A stock QUIC client on a plain UDP socket.
fn alice(client_config: noq::ClientConfig) -> Endpoint {
    let endpoint = Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    endpoint.set_default_client_config(client_config);
    endpoint
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

#[tokio::test]
async fn stock_quic_client_reaches_relayed_endpoint() {
    let server = spawn_relay(Duration::from_secs(30)).await;
    let (server_config, client_config) = quic_configs();
    let bob = bob(server_config);
    let link = bob.connect_relay(&server, "bob");
    let public_addr = timeout(TIMEOUT, link.public_addr()).await.unwrap().unwrap();
    assert_eq!(link.state(), LinkState::Connected(public_addr));
    assert_ne!(public_addr, bob.local_addr);

    // Alice knows nothing but the public address. She can not tell it is a relay.
    let alice = alice(client_config);
    let alice_addr = alice.local_addr().unwrap();
    let (alice_conn, bob_conn) = tokio::join!(
        async {
            alice
                .connect(public_addr.into(), "localhost")
                .unwrap()
                .await
                .unwrap()
        },
        bob.serve_one()
    );
    assert_eq!(remote_address(&alice_conn), SocketAddr::V4(public_addr));

    // Bob sees Alice's real address, and that she came through the relay.
    match PathAddr::from_socket_addr(remote_address(&bob_conn)) {
        PathAddr::Relayed { relay, remote } => {
            assert_eq!(relay, link.index());
            assert_eq!(SocketAddr::V4(remote.addr), alice_addr);
            assert!(!remote.tunnel);
        }
        other => panic!("expected a relayed path, got {other:?}"),
    }

    echo(&alice_conn, b"hello through the relay").await;
    // More than fits into a few packets, in both directions.
    let large: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
    echo(&alice_conn, &large).await;

    let metrics = server.metrics();
    assert!(metrics.server.packets_inbound.get() > 200);
    assert!(metrics.server.packets_outbound.get() > 200);
}

#[tokio::test]
async fn direct_and_relayed_peers_share_the_socket() {
    let server = spawn_relay(Duration::from_secs(30)).await;
    let (server_config, client_config) = quic_configs();
    let bob = bob(server_config.clone());
    let link = bob.connect_relay(&server, "bob");
    let public_addr = timeout(TIMEOUT, link.public_addr()).await.unwrap().unwrap();

    // One dialer reaches Bob through the relay, another at his real socket.
    let relayed = alice(client_config.clone());
    let direct = alice(client_config.clone());
    let (relayed_conn, bob_relayed) = tokio::join!(
        async {
            relayed
                .connect(public_addr.into(), "localhost")
                .unwrap()
                .await
                .unwrap()
        },
        bob.serve_one()
    );
    let (direct_conn, bob_direct) = tokio::join!(
        async {
            direct
                .connect(bob.local_addr.into(), "localhost")
                .unwrap()
                .await
                .unwrap()
        },
        bob.serve_one()
    );

    assert!(PathAddr::from_socket_addr(remote_address(&bob_relayed)).is_relayed());
    // The direct peer appears with its ordinary address once made canonical.
    assert_eq!(
        PathAddr::from_socket_addr(remote_address(&bob_direct)),
        PathAddr::Direct(direct.local_addr().unwrap())
    );
    echo(&relayed_conn, b"relayed").await;
    echo(&direct_conn, b"direct").await;

    // Bob dials out through the same socket, directly.
    let other = Endpoint::server(server_config, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let other_addr = other.local_addr().unwrap();
    let accept = tokio::spawn(async move {
        let conn = other.accept().await.unwrap().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let data = recv.read_to_end(1024).await.unwrap();
        send.write_all(&data).await.unwrap();
        send.finish().unwrap();
        conn.closed().await;
    });
    let conn = bob
        .endpoint
        .connect_with(client_config, other_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    assert_eq!(
        PathAddr::from_socket_addr(remote_address(&conn)),
        PathAddr::Direct(other_addr)
    );
    echo(&conn, b"outbound").await;
    conn.close(0u32.into(), b"done");
    timeout(TIMEOUT, accept).await.unwrap().unwrap();
}

#[tokio::test]
async fn link_reconnects_and_keeps_its_address() {
    let server = spawn_relay(Duration::from_secs(30)).await;
    let (server_config, client_config) = quic_configs();
    let bob = bob(server_config);
    let link = bob.connect_relay(&server, "bob");
    let public_addr = timeout(TIMEOUT, link.public_addr()).await.unwrap().unwrap();

    let alice = alice(client_config);
    let (alice_conn, _bob_conn) = tokio::join!(
        async {
            alice
                .connect(public_addr.into(), "localhost")
                .unwrap()
                .await
                .unwrap()
        },
        bob.serve_one()
    );
    echo(&alice_conn, b"before").await;

    // Another control channel with Bob's identity takes over, as a stand-in for Bob's
    // control channel breaking. It is dropped right away, Bob's link has to notice.
    let mut state = link.watch_state();
    let intruder = bob.connect_relay(&server, "bob");
    timeout(TIMEOUT, intruder.public_addr())
        .await
        .unwrap()
        .unwrap();
    // The link was told that it was superseded and does not fight over the port.
    let failed = timeout(
        TIMEOUT,
        state.wait_for(|state| matches!(state, LinkState::Failed(_))),
    )
    .await
    .unwrap()
    .unwrap()
    .clone();
    assert!(matches!(failed, LinkState::Failed(reason) if reason.contains("took over")));
    assert_eq!(intruder.state(), LinkState::Connected(public_addr));

    // The QUIC connection carries on over the new link: the address did not change, and
    // both links deliver to the same socket.
    echo(&alice_conn, b"after").await;
    assert_eq!(server.metrics().server.allocations_created.get(), 1);
}

#[tokio::test]
async fn link_reports_rejected_credentials() {
    let server = spawn_relay(Duration::from_secs(30)).await;
    let (server_config, _) = quic_configs();
    let bob = bob(server_config);
    let credentials = SharedToken::new("bob", "wrong");
    let link = bob
        .handle
        .connect_relay(dialer(&server), Arc::new(credentials));
    let err = timeout(TIMEOUT, link.public_addr())
        .await
        .unwrap()
        .unwrap_err();
    assert!(err.contains("Unauthorized"), "unexpected reason: {err}");
    assert!(matches!(link.state(), LinkState::Failed(_)));
}

#[tokio::test]
async fn link_reconnects_after_the_relay_restarts_its_connection() {
    // A relay without a release timeout: a client that reconnects gets a new allocation.
    let server = spawn_relay(Duration::ZERO).await;
    let (server_config, client_config) = quic_configs();
    let bob = bob(server_config);
    let link = bob.connect_relay(&server, "bob");
    let public_addr = timeout(TIMEOUT, link.public_addr()).await.unwrap().unwrap();
    let mut state = link.watch_state();
    state.borrow_and_update();

    // Close every control channel the relay has. The link reconnects on its own.
    let relay = server.relay().unwrap();
    assert!(relay.disconnect(&iroh_relay::server::ClientId::new("bob")));
    let reconnected = timeout(TIMEOUT, async {
        loop {
            state.changed().await.unwrap();
            if let LinkState::Connected(addr) = &*state.borrow_and_update() {
                break *addr;
            }
        }
    })
    .await
    .expect("timeout waiting for the link to reconnect");
    // The identity prefers the same port, and nobody took it.
    assert_eq!(reconnected, public_addr);
    assert_eq!(server.metrics().server.allocations_created.get(), 2);

    let alice = alice(client_config);
    let (alice_conn, _bob_conn) = tokio::join!(
        async {
            alice
                .connect(reconnected.into(), "localhost")
                .unwrap()
                .await
                .unwrap()
        },
        bob.serve_one()
    );
    echo(&alice_conn, b"after the reconnect").await;
}

#[tokio::test]
async fn dropping_the_link_releases_the_allocation() {
    let server = spawn_relay(Duration::ZERO).await;
    let (server_config, _) = quic_configs();
    let bob = bob(server_config);
    let link = bob.connect_relay(&server, "bob");
    timeout(TIMEOUT, link.public_addr()).await.unwrap().unwrap();
    let relay = server.relay().unwrap();
    assert_eq!(relay.allocation_count(), 1);
    let index = link.index();

    drop(link);
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while relay.allocation_count() != 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "allocation not released"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // The index is not handed out again right away: the QUIC stack may still hold paths
    // that name it.
    let again = bob.connect_relay(&server, "bob");
    assert_ne!(again.index(), index);
    timeout(TIMEOUT, again.public_addr())
        .await
        .unwrap()
        .unwrap();

    // Closing a link is visible in its state.
    again.close();
    let mut state = again.watch_state();
    timeout(TIMEOUT, state.wait_for(|state| *state == LinkState::Closed))
        .await
        .unwrap()
        .unwrap();
    assert!(again.public_addr().await.is_err());
}

#[tokio::test]
async fn socket_requires_an_ipv4_socket() {
    let Ok(socket) = std::net::UdpSocket::bind((std::net::Ipv6Addr::LOCALHOST, 0)) else {
        // No IPv6 on this machine.
        return;
    };
    let inner = TokioRuntime.wrap_udp_socket(socket).unwrap();
    assert!(RelaySocket::new(inner).is_err());
}
