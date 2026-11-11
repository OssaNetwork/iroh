//! HTTP-specific constants for the relay server and client.

#[cfg(feature = "server")]
pub(crate) const WEBSOCKET_UPGRADE_PROTOCOL: &str = "websocket";
#[cfg(feature = "server")]
pub(crate) const SUPPORTED_WEBSOCKET_VERSION: &str = "13";

/// The path latency probes are made on, relative to the relay URL.
///
/// Clients join it onto the relay URL, so a relay served under a path prefix
/// keeps it: `https://example.com/prefix/` gives `https://example.com/prefix/ping`.
pub const RELAY_PROBE_RELATIVE_PATH: &str = "ping";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_join_onto_the_relay_url() {
        let join = |base: &str, path| {
            url::Url::parse(base)
                .unwrap()
                .join(path)
                .unwrap()
                .to_string()
        };
        assert_eq!(
            join("https://example.com/", RELAY_PROBE_RELATIVE_PATH),
            "https://example.com/ping"
        );
        assert_eq!(
            join("https://example.com/a/b/", RELAY_PROBE_RELATIVE_PATH),
            "https://example.com/a/b/ping"
        );
    }
}
