//! The mainline DHT service a relay offers its clients.
//!
//! A mainline DHT `announce_peer` records the source IP address of the announcement. A
//! client behind a relay can therefore not announce itself: the DHT would record the
//! client's own address, not the relay's. The relay runs one DHT node and announces for
//! its clients, always with the port of the client's allocation. It also looks up the
//! peers of an infohash for them.
//!
//! The relay keeps refreshing a client's announcements for as long as the client's
//! allocation lives, which includes the release timeout after the client disconnected.

use std::{sync::Arc, time::Duration};

use n0_mainline::{Dht, DhtBuilder};

use super::ClientId;
use crate::protos::relay::InfoHash;

/// The default interval at which the relay refreshes announcements.
///
/// Nodes of the DHT forget an announced peer after about half an hour.
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// The most infohashes the relay announces for one client, whatever the policy allows.
///
/// This bounds the memory and the DHT traffic a single client can cause.
pub const MAX_ANNOUNCES_PER_CLIENT: usize = 1024;

/// The most lookups that run at a time for one client, whatever the policy allows.
pub const MAX_LOOKUPS_PER_CLIENT: usize = 16;

/// How many announcements the relay sends at a time when refreshing.
pub(super) const REFRESH_CONCURRENCY: usize = 16;

/// Configuration of the DHT service of a relay.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DhtConfig {
    /// The nodes to join the DHT through, as `host:port`.
    ///
    /// `None` uses the well known nodes of the mainline DHT.
    pub bootstrap: Option<Vec<String>>,
    /// The UDP port of the relay's DHT node. `None` lets the operating system choose.
    ///
    /// The port must be reachable from the internet for the node to take part fully.
    pub port: Option<u16>,
    /// How often the announcements of the clients are refreshed. Defaults to
    /// [`DEFAULT_REFRESH_INTERVAL`].
    pub refresh_interval: Duration,
    /// Decides which requests of clients are served.
    pub policy: Arc<dyn DhtPolicy>,
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self {
            bootstrap: None,
            port: None,
            refresh_interval: DEFAULT_REFRESH_INTERVAL,
            policy: Arc::new(AllowAllDht),
        }
    }
}

impl DhtConfig {
    /// Starts the DHT node. `public_ip` is the address the node is reachable at.
    pub(super) fn build(&self, public_ip: std::net::Ipv4Addr) -> std::io::Result<Dht> {
        let mut builder = DhtBuilder::default();
        // The node id is derived from the address, see BEP 42.
        builder.public_ip(public_ip);
        if let Some(bootstrap) = &self.bootstrap {
            builder.bootstrap(bootstrap);
        }
        if let Some(port) = self.port {
            builder.port(port);
        }
        builder.build()
    }
}

/// What a client asks the DHT service to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhtRequestKind {
    /// Announce the client's port for an infohash, and keep the announcement fresh.
    Announce,
    /// Look up the peers of an infohash.
    FindPeers,
}

/// A request of a client to the DHT service.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct DhtRequest<'a> {
    /// The client that sent the request.
    pub identity: &'a ClientId,
    /// What the client asks for.
    pub kind: DhtRequestKind,
    /// The infohash the request is about.
    pub info_hash: &'a InfoHash,
    /// How many infohashes the relay announces for the client right now, not counting
    /// this request.
    pub announced: usize,
    /// How many lookups run for the client right now, not counting this request.
    pub lookups: usize,
}

/// Decides which DHT requests of clients the relay serves.
///
/// The relay learns every infohash a client announces or looks up, and spends its own
/// DHT traffic on them. How much of that a client may cause is the relay operator's
/// decision.
///
/// The relay also enforces [`MAX_ANNOUNCES_PER_CLIENT`] and [`MAX_LOOKUPS_PER_CLIENT`],
/// whatever the policy allows.
pub trait DhtPolicy: std::fmt::Debug + Send + Sync + 'static {
    /// Returns whether to serve `request`.
    ///
    /// Called for every announce and lookup request, on the task that serves the
    /// client's control channel. It must not block.
    fn allow(&self, request: &DhtRequest<'_>) -> bool;
}

/// A [`DhtPolicy`] that serves every request.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAllDht;

impl DhtPolicy for AllowAllDht {
    fn allow(&self, _request: &DhtRequest<'_>) -> bool {
        true
    }
}
