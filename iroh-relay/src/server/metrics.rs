use std::sync::Arc;

use iroh_metrics::{Counter, MetricsGroup, MetricsGroupSet};

/// Metrics tracked for the relay server
#[derive(Debug, Default, MetricsGroup)]
#[metrics(name = "relayserver")]
#[non_exhaustive]
pub struct Metrics {
    /*
     * Metrics about clients and their allocations
     */
    /// Number of control channels opened, including those that failed to authenticate.
    pub control_connections: Counter,
    /// Number of control channels whose credentials were rejected.
    pub auth_rejected: Counter,
    /// Number of allocations created for a client that did not have one.
    pub allocations_created: Counter,
    /// Number of times a client got its existing allocation back: by reconnecting within
    /// the release timeout, or by taking over from another control channel.
    pub allocations_resumed: Counter,
    /// Number of allocations released.
    ///
    /// The number of allocations at any time is `allocations_created` -
    /// `allocations_released`.
    pub allocations_released: Counter,
    /// Number of times a client could not get a port because none was free.
    pub ports_exhausted: Counter,
    /// Number of times a client could not get a port because binding its socket failed.
    pub allocations_bind_failed: Counter,

    /// Number of tunnels opened by dialers.
    ///
    /// The number of open tunnels at any time is `tunnels_opened` - `tunnels_closed`.
    pub tunnels_opened: Counter,
    /// Number of tunnels closed.
    pub tunnels_closed: Counter,
    /// Number of tunnels refused because too many were open to the allocation.
    pub tunnels_rejected: Counter,
    /// Number of tunnels closed to make room for a newer one.
    pub tunnels_evicted: Counter,

    /// Number of announcements sent to the mainline DHT for clients, including refreshes.
    pub dht_announces: Counter,
    /// Number of announcements to the mainline DHT that failed.
    pub dht_announces_failed: Counter,
    /// Number of lookups on the mainline DHT started for clients.
    pub dht_lookups: Counter,
    /// Number of DHT requests of clients that were refused.
    pub dht_requests_denied: Counter,

    /*
     * Metrics about packets
     */
    /// Number of packets forwarded from a remote party to a client.
    pub packets_inbound: Counter,
    /// Number of payload bytes forwarded from a remote party to a client.
    pub bytes_inbound: Counter,
    /// Number of packets forwarded from a client to a remote party.
    pub packets_outbound: Counter,
    /// Number of payload bytes forwarded from a client to a remote party.
    pub bytes_outbound: Counter,
    /// Number of packets dropped by the traffic policy, in either direction.
    pub packets_dropped_policy: Counter,
    /// Number of inbound packets dropped because the client's queue was full.
    pub packets_dropped_queue_full: Counter,
    /// Number of inbound packets dropped because the client was not connected.
    pub packets_dropped_detached: Counter,
    /// Number of packets dropped because they were empty, too large, or addressed to a
    /// destination that can not be a remote party.
    pub packets_dropped_invalid: Counter,
    /// Number of outbound packets the relay failed to send.
    pub packets_dropped_send_failed: Counter,

    /// Number of incoming QAD connections.
    ///
    /// After completion, each is counted in either `qad_incoming_error` or `qad_connections`.
    ///
    /// Thus the number of inflight incomings is `qad_incoming` - `qad_incoming_error` - `qad_connections`.
    pub qad_incoming: Counter,

    /// Number of QAD QUIC connections that aborted before completing the handshake.
    pub qad_incoming_error: Counter,

    /// Number of accepted QAD QUIC connections.
    ///
    /// The number of active connections is `qad_connections` - `qad_connections_closed`.
    pub qad_connections: Counter,

    /// Number of QAD QUIC connections that disconnected after being accepted.
    pub qad_connections_closed: Counter,

    /// Number of QAD QUIC connections that disconnected after being accepted, with an error.
    ///
    /// The number is *included* in `qad_connections_closed` (not in addition to).
    pub qad_connections_errored: Counter,

    /// Number of accepted HTTP(S) connections.
    ///
    /// The number of active connections at any time is `http_connections` - `http_connections_closed`
    pub http_connections: Counter,

    /// Number of terminated HTTP(S) connections.
    pub http_connections_closed: Counter,

    /// Number of HTTP(S) connections that terminated with an error.
    ///
    /// The number is *included* in `http_connections_closed` (not in addition to).
    pub http_connections_errored: Counter,
}

/// All metrics tracked in the relay server.
#[derive(Debug, Default, Clone, MetricsGroupSet)]
#[metrics(name = "relay")]
#[non_exhaustive]
pub struct RelayMetrics {
    /// Metrics tracked for the relay server.
    pub server: Arc<Metrics>,
}
