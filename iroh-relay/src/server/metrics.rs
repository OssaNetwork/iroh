use std::sync::Arc;

use iroh_metrics::{Counter, MetricsGroup, MetricsGroupSet};

/// Metrics tracked for the relay server
#[derive(Debug, Default, MetricsGroup)]
#[metrics(name = "relayserver")]
#[non_exhaustive]
pub struct Metrics {
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
