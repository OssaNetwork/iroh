//! Tests of the mainline DHT service, against a DHT made of local nodes.

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};

use iroh_dns::dns::DnsResolver;
use iroh_relay::{
    auth::SharedToken,
    client::{DhtError, LinkState, RelayLink, RelaySocket, RelaySocketHandle, WsDialer},
    protos::relay::{InfoHash, MAX_FRAME_SIZE},
    server::{
        AllocationConfig, ClientId, DefaultPolicy, Server, ServerConfig, SharedTokenAuthenticator,
        dht::{DhtConfig, DhtPolicy, DhtRequest, DhtRequestKind},
        testing,
    },
    tls::make_dangerous_client_config,
};
use n0_future::StreamExt;
use n0_mainline::{Dht, Id, Testnet};
use noq::{Runtime, TokioRuntime};
use tokio::time::timeout;

const TOKEN: &str = "secret";
const TIMEOUT: Duration = Duration::from_secs(20);
const BASE_PORT: u16 = 32_000;

/// Returns a port range no other test relay uses, see the other integration tests.
fn port_range() -> std::ops::RangeInclusive<u16> {
    static NEXT_RANGE: AtomicU16 = AtomicU16::new(0);
    let per_process = (std::process::id() % 20) as u16 * 500;
    let per_test = NEXT_RANGE.fetch_add(1, Ordering::Relaxed) % 25 * 20;
    let start = BASE_PORT + per_process + per_test;
    start..=start + 19
}

struct Setup {
    testnet: Testnet,
    server: Server,
}

async fn setup(configure: impl FnOnce(&mut AllocationConfig)) -> Setup {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let testnet = Testnet::new(10).await.unwrap();
    let mut allocations = AllocationConfig::new(
        Ipv4Addr::LOCALHOST,
        Arc::new(SharedTokenAuthenticator::new([TOKEN])),
        Arc::new(DefaultPolicy::default()),
    );
    allocations.ports = port_range();
    let mut dht = DhtConfig::default();
    dht.bootstrap = Some(testnet.bootstrap.clone());
    allocations.dht = Some(dht);
    configure(&mut allocations);

    let mut relay = testing::relay_config();
    relay.allocations = Some(allocations);
    let mut config = ServerConfig::default();
    config.relay = Some(relay);
    let server = Server::spawn(config).await.unwrap();
    Setup { testnet, server }
}

impl Setup {
    /// A node of the DHT that has nothing to do with the relay.
    async fn other_node(&self) -> Dht {
        let node = Dht::builder()
            .bootstrap(&self.testnet.bootstrap)
            .build()
            .unwrap();
        node.bootstrapped().await.unwrap();
        node
    }

    fn relay(&self) -> &iroh_relay::server::Relay {
        self.server.relay().unwrap()
    }
}

/// A client of the relay.
struct Client {
    link: RelayLink,
    /// The public address of the client.
    addr: SocketAddrV4,
    /// Keeps the socket of the link around.
    _socket: (RelaySocket, RelaySocketHandle),
}

async fn client(setup: &Setup, name: &str) -> Client {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let inner = TokioRuntime.wrap_udp_socket(socket).unwrap();
    let (socket, handle) = RelaySocket::new(inner).unwrap();
    let url = format!("https://{}", setup.server.https_addr().unwrap())
        .parse()
        .unwrap();
    let dialer = WsDialer::new(url, DnsResolver::new(), MAX_FRAME_SIZE)
        .tls_client_config(make_dangerous_client_config());
    let credentials = SharedToken::new(name.to_string(), TOKEN);
    let link = handle.connect_relay(dialer, Arc::new(credentials));
    let addr = timeout(TIMEOUT, link.public_addr()).await.unwrap().unwrap();
    Client {
        link,
        addr,
        _socket: (socket, handle),
    }
}

fn info_hash(n: u8) -> InfoHash {
    [n; 20]
}

/// Looks up the peers of `info_hash` on `node`.
async fn peers_on(node: &Dht, info_hash: InfoHash) -> Vec<SocketAddrV4> {
    let mut batches = node
        .get_peers(Id::from_bytes(info_hash).unwrap())
        .await
        .unwrap();
    let mut peers = Vec::new();
    while let Some(batch) = batches.next().await {
        peers.extend(batch);
    }
    peers.sort();
    peers.dedup();
    peers
}

/// Looks up the peers of `info_hash` through the relay.
async fn peers_through(
    client: &Client,
    info_hash: InfoHash,
) -> Result<Vec<SocketAddrV4>, DhtError> {
    let mut batches = client.link.dht_find_peers(info_hash).await?;
    let mut peers = Vec::new();
    let collect = async {
        while let Some(batch) = batches.next().await {
            peers.extend(batch?);
        }
        Ok(())
    };
    timeout(TIMEOUT, collect).await.expect("lookup timed out")?;
    peers.sort();
    peers.dedup();
    Ok(peers)
}

async fn eventually(what: &str, condition: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while !condition() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timeout waiting until {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn relay_announces_and_looks_up_for_its_clients() {
    let setup = setup(|_| {}).await;
    let bob = client(&setup, "bob").await;
    let other = setup.other_node().await;

    // The relay announces its own address with the port of Bob's allocation. That is
    // the address Bob advertises.
    timeout(TIMEOUT, bob.link.dht_announce(info_hash(1)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(peers_on(&other, info_hash(1)).await, vec![bob.addr]);
    assert_eq!(
        setup.relay().announced(&ClientId::new("bob")),
        vec![info_hash(1)]
    );

    // Bob finds a peer that somebody else announced.
    other
        .announce_peer(Id::from_bytes(info_hash(2)).unwrap(), Some(7777))
        .await
        .unwrap();
    let expected = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7777);
    assert_eq!(
        peers_through(&bob, info_hash(2)).await.unwrap(),
        vec![expected]
    );
    // A lookup without peers ends without any.
    assert!(peers_through(&bob, info_hash(3)).await.unwrap().is_empty());

    // Another client of the relay finds Bob, at the relay's address.
    let carol = client(&setup, "carol").await;
    assert_eq!(
        peers_through(&carol, info_hash(1)).await.unwrap(),
        vec![bob.addr]
    );

    let metrics = setup.server.metrics();
    assert_eq!(metrics.server.dht_announces.get(), 1);
    assert_eq!(metrics.server.dht_lookups.get(), 3);
}

#[tokio::test]
async fn announcements_are_refreshed_while_the_allocation_lives() {
    let setup = setup(|config| {
        config.release_timeout = Duration::from_secs(600);
        config.dht.as_mut().unwrap().refresh_interval = Duration::from_millis(200);
    })
    .await;
    let relay = setup.relay();
    let metrics = setup.server.metrics();
    let announces = || metrics.server.dht_announces.get();
    let bob_id = ClientId::new("bob");

    let bob = client(&setup, "bob").await;
    bob.link.dht_announce(info_hash(1)).await.unwrap();
    bob.link.dht_announce(info_hash(2)).await.unwrap();
    assert_eq!(announces(), 2);
    eventually("the announcements are refreshed", || announces() >= 6).await;

    // Stopping one of them stops its refreshes.
    bob.link.dht_stop(info_hash(2)).await.unwrap();
    eventually("the announcement is stopped", || {
        relay.announced(&bob_id) == vec![info_hash(1)]
    })
    .await;

    // Bob goes away. His port is held, and his announcement with it.
    let addr = bob.addr;
    drop(bob);
    let before = announces();
    eventually(
        "the announcement is refreshed while the client is away",
        || announces() >= before + 3,
    )
    .await;
    assert_eq!(relay.announced(&bob_id), vec![info_hash(1)]);

    // He comes back within the release timeout and finds everything as he left it. The
    // relay answers his announce request without announcing again.
    let bob = client(&setup, "bob").await;
    assert_eq!(bob.addr, addr);
    let before = announces();
    bob.link.dht_announce(info_hash(1)).await.unwrap();
    assert!(announces() <= before + 1, "at most a refresh in between");
    assert_eq!(relay.announced(&bob_id), vec![info_hash(1)]);
}

#[tokio::test]
async fn announcements_end_with_the_allocation() {
    let setup = setup(|config| {
        config.release_timeout = Duration::ZERO;
        config.dht.as_mut().unwrap().refresh_interval = Duration::from_millis(200);
    })
    .await;
    let relay = setup.relay();
    let metrics = setup.server.metrics();
    let bob_id = ClientId::new("bob");

    let bob = client(&setup, "bob").await;
    bob.link.dht_announce(info_hash(1)).await.unwrap();
    assert_eq!(relay.announced(&bob_id), vec![info_hash(1)]);

    // The relay drops Bob's control channel. Without a release timeout that releases his
    // port and forgets his announcements. The link reconnects, gets a new allocation, and
    // asks for its announcements again on its own.
    let created = metrics.server.allocations_created.get();
    assert!(relay.disconnect(&bob_id));
    eventually("the link has a new allocation", || {
        metrics.server.allocations_created.get() == created + 1
    })
    .await;
    eventually("the link announced again", || {
        relay.announced(&bob_id) == vec![info_hash(1)]
    })
    .await;

    // When Bob leaves for good the announcements are gone, and no longer refreshed.
    drop(bob);
    eventually("the allocation is released", || {
        relay.allocation_count() == 0
    })
    .await;
    assert!(relay.announced(&bob_id).is_empty());
    tokio::time::sleep(Duration::from_millis(300)).await;
    let announces = metrics.server.dht_announces.get();
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(metrics.server.dht_announces.get(), announces);
}

#[tokio::test]
async fn stop_reaches_the_relay_across_a_reconnect() {
    let setup = setup(|config| config.release_timeout = Duration::from_secs(600)).await;
    let relay = setup.relay();
    let bob_id = ClientId::new("bob");
    let bob = client(&setup, "bob").await;
    bob.link.dht_announce(info_hash(1)).await.unwrap();
    bob.link.dht_announce(info_hash(2)).await.unwrap();

    // The control channel breaks, and the announcement is stopped right then. The relay
    // holds Bob's port and still has both announcements.
    let mut state = bob.link.watch_state();
    state.borrow_and_update();
    assert!(relay.disconnect(&bob_id));
    bob.link.dht_stop(info_hash(1)).await.unwrap();
    // Whether the link was still connected when it handled the stop or not, the relay
    // must end up without the announcement.
    eventually("the relay stopped the announcement", || {
        relay.announced(&bob_id) == vec![info_hash(2)]
    })
    .await;
    timeout(
        TIMEOUT,
        state.wait_for(|state| matches!(state, LinkState::Connected(_))),
    )
    .await
    .unwrap()
    .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(relay.announced(&bob_id), vec![info_hash(2)]);
}

/// A policy that looks at the relay, which it can only do without a deadlock if the
/// relay holds no lock while it asks the policy.
#[derive(Debug, Default)]
struct LooksAtTheRelay {
    relay: std::sync::OnceLock<iroh_relay::server::Relay>,
}

impl DhtPolicy for LooksAtTheRelay {
    fn allow(&self, request: &DhtRequest<'_>) -> bool {
        let relay = self.relay.get().expect("set by the test");
        relay.announced(request.identity).len() == request.announced
    }
}

#[tokio::test]
async fn policy_may_look_at_the_relay() {
    let policy = Arc::new(LooksAtTheRelay::default());
    let setup = setup(|config| {
        config.dht.as_mut().unwrap().policy = policy.clone();
    })
    .await;
    policy.relay.set(setup.relay().clone()).unwrap();
    let bob = client(&setup, "bob").await;
    timeout(TIMEOUT, bob.link.dht_announce(info_hash(1)))
        .await
        .expect("the relay deadlocked")
        .unwrap();
    timeout(TIMEOUT, bob.link.dht_announce(info_hash(2)))
        .await
        .expect("the relay deadlocked")
        .unwrap();
}

/// Allows a client one announcement and no lookups.
#[derive(Debug)]
struct OneAnnouncement;

impl DhtPolicy for OneAnnouncement {
    fn allow(&self, request: &DhtRequest<'_>) -> bool {
        assert_eq!(request.identity, &ClientId::new("bob"));
        match request.kind {
            DhtRequestKind::Announce => request.announced == 0,
            DhtRequestKind::FindPeers => false,
        }
    }
}

#[tokio::test]
async fn policy_decides_which_requests_are_served() {
    let setup = setup(|config| {
        config.dht.as_mut().unwrap().policy = Arc::new(OneAnnouncement);
    })
    .await;
    let bob = client(&setup, "bob").await;

    bob.link.dht_announce(info_hash(1)).await.unwrap();
    let err = bob.link.dht_announce(info_hash(2)).await.unwrap_err();
    assert!(matches!(err, DhtError::Denied { .. }), "{err:?}");
    // Asking again for what is announced already is not a new announcement.
    bob.link.dht_announce(info_hash(1)).await.unwrap();

    let err = peers_through(&bob, info_hash(1)).await.unwrap_err();
    assert!(matches!(err, DhtError::Denied { .. }), "{err:?}");

    assert_eq!(
        setup.relay().announced(&ClientId::new("bob")),
        vec![info_hash(1)]
    );
    assert_eq!(setup.server.metrics().server.dht_requests_denied.get(), 2);

    // Once the first one is stopped there is room for another.
    bob.link.dht_stop(info_hash(1)).await.unwrap();
    bob.link.dht_announce(info_hash(2)).await.unwrap();
}

#[tokio::test]
async fn relay_without_the_service_says_so() {
    let setup = setup(|config| config.dht = None).await;
    let bob = client(&setup, "bob").await;

    let err = bob.link.dht_announce(info_hash(1)).await.unwrap_err();
    assert!(matches!(err, DhtError::Unavailable { .. }), "{err:?}");
    let err = peers_through(&bob, info_hash(1)).await.unwrap_err();
    assert!(matches!(err, DhtError::Unavailable { .. }), "{err:?}");
}

#[tokio::test]
async fn requests_on_a_closed_link_fail() {
    let setup = setup(|_| {}).await;
    let bob = client(&setup, "bob").await;
    bob.link.close();
    let mut state = bob.link.watch_state();
    timeout(TIMEOUT, state.wait_for(|state| *state == LinkState::Closed))
        .await
        .unwrap()
        .unwrap();

    let err = bob.link.dht_announce(info_hash(1)).await.unwrap_err();
    assert!(matches!(err, DhtError::Closed { .. }), "{err:?}");
    assert!(bob.link.dht_find_peers(info_hash(1)).await.is_err());
}
