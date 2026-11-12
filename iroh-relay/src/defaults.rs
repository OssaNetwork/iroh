//! Default values used in the relay.

/// The default QUIC port used by the Relay server to accept QUIC connections
/// for QUIC address discovery
///
/// The port is "QUIC" typed on a phone keypad.
pub const DEFAULT_RELAY_QUIC_PORT: u16 = 7842;

/// The default HTTP port used by the Relay server.
pub const DEFAULT_HTTP_PORT: u16 = 80;

/// The default HTTPS port used by the Relay server.
pub const DEFAULT_HTTPS_PORT: u16 = 443;

/// The default metrics port used by the Relay server.
pub const DEFAULT_METRICS_PORT: u16 = 9090;

/// Contains all timeouts that we use in `iroh`.
pub mod timeouts {
    use n0_future::time::Duration;

    /// Timeout used by the relay client while connecting to the relay server,
    /// using `TcpStream::connect`
    pub(crate) const DIAL_ENDPOINT_TIMEOUT: Duration = Duration::from_millis(1500);

    /// Happy Eyeballs (RFC 8305) Connection Attempt Delay: the maximum time to
    /// wait before starting the next connection attempt. A faster failure
    /// starts the next attempt immediately.
    pub(crate) const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

    /// Happy Eyeballs (RFC 8305) Resolution Delay: when the non-preferred
    /// address family resolves first, wait this long for the preferred family
    /// before starting to connect, so the preference is honored.
    pub(crate) const RESOLUTION_DELAY: Duration = Duration::from_millis(50);

    /// Default timeout for DNS queries issued by [`DnsResolver`].
    ///
    /// [`DnsResolver`]: iroh_dns::dns::DnsResolver
    pub(crate) const DNS_TIMEOUT: Duration = Duration::from_secs(3);
}
