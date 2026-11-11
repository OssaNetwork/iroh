//! The relay server.
//!
//! This handles only the CLI and config file loading, the server implementation lives in
//! [`iroh_relay::server`].

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU64,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use clap::Parser;
use iroh_relay::{
    defaults::{
        DEFAULT_HTTP_PORT, DEFAULT_HTTPS_PORT, DEFAULT_METRICS_PORT, DEFAULT_RELAY_QUIC_PORT,
    },
    server::{
        self as relay, AcmeConfig, DEFAULT_CERT_RELOAD_INTERVAL, QuicConfig, reloading_resolver,
    },
    tls::CaTlsConfig,
};
use n0_error::{Result, StdResultExt, bail_any};
use serde::{Deserialize, Serialize};
use tracing::debug;
use tracing_subscriber::{EnvFilter, prelude::*};
use webpki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

/// The default `http_bind_port` when using `--dev`.
const DEV_MODE_HTTP_PORT: u16 = 3340;
/// Environment variable to set the token clients present to use the relay.
const ENV_SHARED_TOKEN: &str = "IROH_RELAY_SHARED_TOKEN";
/// Environment variable to override the ACME directory URL.
const ENV_ACME_URL: &str = "IROH_RELAY_ACME_URL";
/// Environment variable to trust an additional CA for the ACME server's TLS certificate.
const ENV_ACME_CA: &str = "IROH_RELAY_ACME_CA";

/// A relay server for iroh.
#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None)]
struct Cli {
    /// Run in localhost development mode over plain HTTP.
    ///
    /// Defaults to running the relay server on port 3340.
    ///
    /// Running in dev mode will ignore any config file fields pertaining to TLS.
    #[clap(long, default_value_t = false)]
    dev: bool,
    /// Path to the configuration file.
    #[clap(long, short)]
    config_path: Option<PathBuf>,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum CertMode {
    Manual,
    LetsEncrypt,
    #[cfg(feature = "server")]
    Reloading,
}

fn load_certs(
    filename: impl AsRef<Path>,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let filename = filename.as_ref();
    CertificateDer::pem_file_iter(filename)
        .with_std_context(|_| format!("failed to open certificate file at {}", filename.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_std_context(|_| format!("failed to read certificates from {}", filename.display()))
}

fn load_secret_key(
    filename: impl AsRef<Path>,
) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let filename = filename.as_ref();
    PrivateKeyDer::from_pem_file(filename)
        .with_std_context(|_| format!("failed to read secret key from {}", filename.display()))
}

/// Configuration for the relay-server.
///
/// This is (de)serialised to/from a TOML config file.
///
/// Unknown fields are rejected. The `access`, `limits` and `key_cache_capacity` fields
/// of iroh's relay no longer exist, and silently ignoring them would start a server
/// without the restrictions its config asks for.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    /// Whether to enable the Relay server.
    ///
    /// Defaults to `true`.
    ///
    /// When disabled, the relay will not proxy traffic between endpoints. This leaves only
    /// the QUIC server running (if `enable_quic_addr_discovery` is `true`), which helps
    /// with NAT traversal by reporting observed addresses but does not relay any data.
    /// This is useful for holepunching-only relay servers.
    ///
    /// When disabled, the `http_bind_addr` and `tls` configuration options are only used
    /// if `enable_quic_addr_discovery` is enabled (TLS is required for QUIC).
    #[serde(default = "cfg_defaults::enable_relay")]
    enable_relay: bool,
    /// The socket address to bind the Relay HTTP server on.
    ///
    /// Defaults to `[::]:80`.
    ///
    /// When running with `--dev` defaults to `[::]:3340`.  If specified overrides these
    /// defaults.
    ///
    /// The Relay server always starts an HTTP server, this specifies the socket this will
    /// be bound on.  If there is no `tls` configuration set all the HTTP relay services
    /// will be bound on this socket.  Otherwise most Relay HTTP services will run on the
    /// `https_bind_addr` of the `tls` configuration section and only the captive portal
    /// will be served from the HTTP socket.
    http_bind_addr: Option<SocketAddr>,
    /// TLS specific configuration.
    ///
    /// TLS is disabled if not present and the Relay server will serve all services over
    /// plain HTTP.
    ///
    /// If disabled all services will run on plain HTTP.
    ///
    /// Must exist if `enable_quic_addr_discovery` is `true`.
    tls: Option<TlsConfig>,
    /// Whether to allow QUIC connections for QUIC address discovery
    ///
    /// If no `tls` is set, this will error.
    ///
    /// Defaults to `false`
    #[serde(default = "cfg_defaults::enable_quic_addr_discovery")]
    enable_quic_addr_discovery: bool,
    /// Whether to run the metrics server.
    ///
    /// Defaults to `true`, when the metrics feature is enabled.
    #[serde(default = "cfg_defaults::enable_metrics")]
    enable_metrics: bool,
    /// Metrics serve address.
    ///
    /// Defaults to `http_bind_addr` with the port set to [`DEFAULT_METRICS_PORT`]
    /// (`[::]:9090` when `http_bind_addr` is set to the default).
    metrics_bind_addr: Option<SocketAddr>,
    /// The allocations handed out to clients.
    ///
    /// If not present the relay does not accept clients.
    allocations: Option<AllocationsConfig>,
}

/// Configuration of the public UDP ports handed out to clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllocationsConfig {
    /// The public IPv4 address of the relay. Clients advertise it as their own.
    public_ip: Ipv4Addr,
    /// The local address the clients' UDP sockets are bound to.
    ///
    /// Set this on hosts behind a 1:1 NAT, where the public address is not a local one.
    /// Defaults to `public_ip`.
    bind_ip: Option<Ipv4Addr>,
    /// The first port handed out to clients. Defaults to 1024.
    port_range_start: Option<u16>,
    /// The last port handed out to clients. Defaults to 65535.
    port_range_end: Option<u16>,
    /// How many seconds a port stays reserved for its client after the client's control
    /// channel closed. Defaults to 30. With 0 ports are released immediately.
    release_timeout_secs: Option<u64>,
    /// The largest QUIC packet forwarded, in bytes. Defaults to 1500.
    max_packet_size: Option<usize>,
    /// How many TCP tunnels can be open to one client at a time. Defaults to 64. With 0
    /// the relay does not serve tunnels.
    ///
    /// A dialer whose network blocks UDP reaches a client through a tunnel on TCP port
    /// 443 of the relay's public address. For that the relay's HTTPS server has to
    /// listen on that port, with a certificate for the public IP address.
    max_tunnels: Option<usize>,
    /// The tokens clients present to use the relay.
    ///
    /// A client names itself and presents one of these tokens. Anyone who knows a token
    /// can use any name, and take over the port of the client with that name. This is
    /// meant for tests and private relays. To authenticate clients differently, embed the
    /// relay as a library and provide an `Authenticator`.
    ///
    /// The token list can also be set with the `IROH_RELAY_SHARED_TOKEN` environment
    /// variable, which sets a single token and takes precedence over this value.
    ///
    /// Must contain at least one non-empty token.
    #[serde(default)]
    shared_tokens: Vec<String>,
    /// Which packets are forwarded. The defaults apply if not present.
    #[serde(default)]
    policy: PolicyConfig,
}

/// Configuration of which packets are forwarded for a client.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyConfig {
    /// For how many seconds after a remote party last sent to a client's port the client
    /// may send to it. Defaults to 120. Must not be 0.
    ///
    /// Connections through the relay need a keep-alive interval, or an idle timeout,
    /// shorter than this.
    reply_window_secs: Option<u64>,
    /// How many remote parties are tracked per client. Defaults to 1024. Must not be 0.
    max_remotes: Option<usize>,
    /// Whether the first packet of a remote party must look like the start of a QUIC
    /// connection. Defaults to `true`.
    require_initial: Option<bool>,
    /// The limit on bytes per second forwarded to a client. Defaults to 2097152 (2 MiB).
    /// With 0 the rate is not limited.
    inbound_bytes_per_second: Option<u64>,
    /// How many bytes may be forwarded to a client at once after a quiet period.
    /// Defaults to one second's worth. Values below 65536 are raised to 65536.
    inbound_burst_bytes: Option<u64>,
    /// The limit on bytes per second forwarded from a client. Defaults to 2097152
    /// (2 MiB). With 0 the rate is not limited.
    outbound_bytes_per_second: Option<u64>,
    /// How many bytes may be forwarded from a client at once after a quiet period.
    /// Defaults to one second's worth. Values below 65536 are raised to 65536.
    outbound_burst_bytes: Option<u64>,
}

impl PolicyConfig {
    fn into_policy_config(self) -> Result<relay::DefaultPolicyConfig> {
        fn rate_limit(
            name: &str,
            bytes_per_second: Option<u64>,
            burst_bytes: Option<u64>,
            default: Option<relay::RateLimit>,
        ) -> Result<Option<relay::RateLimit>> {
            let limit = match bytes_per_second {
                None => default,
                Some(bytes_per_second) => {
                    NonZeroU64::new(bytes_per_second).map(relay::RateLimit::new)
                }
            };
            match (limit, burst_bytes) {
                (Some(mut limit), Some(burst_bytes)) => {
                    limit.burst_bytes = burst_bytes;
                    Ok(Some(limit))
                }
                (None, Some(_)) => bail_any!(
                    "allocations.policy: {name}_burst_bytes is set but the rate is unlimited"
                ),
                (limit, None) => Ok(limit),
            }
        }

        let mut config = relay::DefaultPolicyConfig::default();
        if let Some(secs) = self.reply_window_secs {
            config.reply_window = Duration::from_secs(secs);
        }
        if let Some(max_remotes) = self.max_remotes {
            config.max_remotes = max_remotes;
        }
        if let Some(require_initial) = self.require_initial {
            config.require_initial = require_initial;
        }
        config.inbound = rate_limit(
            "inbound",
            self.inbound_bytes_per_second,
            self.inbound_burst_bytes,
            config.inbound,
        )?;
        config.outbound = rate_limit(
            "outbound",
            self.outbound_bytes_per_second,
            self.outbound_burst_bytes,
            config.outbound,
        )?;
        Ok(config)
    }
}

impl AllocationsConfig {
    fn into_allocation_config(self) -> Result<relay::AllocationConfig> {
        let mut tokens = self.shared_tokens;
        if let Ok(token) = std::env::var(ENV_SHARED_TOKEN) {
            tokens = vec![token];
        }
        if tokens.is_empty() || tokens.iter().any(|token| token.is_empty()) {
            bail_any!("allocations.shared_tokens must not be empty or contain empty strings");
        }
        let start = self
            .port_range_start
            .unwrap_or(*relay::allocator::DEFAULT_PORT_RANGE.start());
        let end = self
            .port_range_end
            .unwrap_or(*relay::allocator::DEFAULT_PORT_RANGE.end());
        if start == 0 || start > end {
            bail_any!("allocations: invalid port range {start}..={end}");
        }
        let max_packet_size = self
            .max_packet_size
            .unwrap_or(relay::relay::DEFAULT_MAX_PACKET_SIZE);
        if max_packet_size == 0 || max_packet_size > iroh_relay::protos::relay::MAX_PACKET_SIZE {
            bail_any!("allocations: invalid max_packet_size {max_packet_size}");
        }

        let policy = relay::DefaultPolicy::new(self.policy.into_policy_config()?)
            .std_context("allocations.policy")?;
        let mut config = relay::AllocationConfig::new(
            self.public_ip,
            Arc::new(relay::SharedTokenAuthenticator::new(tokens)),
            Arc::new(policy),
        );
        config.bind_ip = self.bind_ip.unwrap_or(self.public_ip);
        config.ports = start..=end;
        config.release_timeout = self
            .release_timeout_secs
            .map(Duration::from_secs)
            .unwrap_or(relay::allocator::DEFAULT_RELEASE_TIMEOUT);
        config.max_packet_size = max_packet_size;
        if let Some(max_tunnels) = self.max_tunnels {
            config.max_tunnels = max_tunnels;
        }
        Ok(config)
    }
}

impl Config {
    fn http_bind_addr(&self) -> SocketAddr {
        self.http_bind_addr
            .unwrap_or((Ipv6Addr::UNSPECIFIED, DEFAULT_HTTP_PORT).into())
    }

    fn metrics_bind_addr(&self) -> SocketAddr {
        self.metrics_bind_addr
            .unwrap_or_else(|| SocketAddr::new(self.http_bind_addr().ip(), DEFAULT_METRICS_PORT))
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enable_relay: cfg_defaults::enable_relay(),
            http_bind_addr: None,
            tls: None,
            enable_quic_addr_discovery: cfg_defaults::enable_quic_addr_discovery(),
            enable_metrics: cfg_defaults::enable_metrics(),
            metrics_bind_addr: None,
            allocations: None,
        }
    }
}

/// Defaults for fields from [`Config`] [`TlsConfig`].
///
/// These are the defaults that serde will fill in.  Other defaults depends on each other
/// and can not immediately be substituted by serde.
mod cfg_defaults {
    pub(crate) fn enable_relay() -> bool {
        true
    }

    pub(crate) fn enable_quic_addr_discovery() -> bool {
        false
    }

    pub(crate) fn enable_metrics() -> bool {
        true
    }

    pub(crate) mod tls_config {
        pub(crate) fn prod_tls() -> bool {
            true
        }

        pub(crate) fn dangerous_http_only() -> bool {
            false
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsConfig {
    /// The socket address to bind the Relay HTTPS server on.
    ///
    /// Defaults to the `http_bind_addr` with the port set to `443`.
    https_bind_addr: Option<SocketAddr>,
    /// The socket address to bind the QUIC server one.
    ///
    /// Defaults to the `https_bind_addr` with the port set to [`iroh_relay::defaults::DEFAULT_RELAY_QUIC_PORT`].
    ///
    /// If `https_bind_addr` is not set, defaults to `http_bind_addr` with the
    /// port set to [`iroh_relay::defaults::DEFAULT_RELAY_QUIC_PORT`]
    quic_bind_addr: Option<SocketAddr>,
    /// Certificate hostname when using LetsEncrypt.
    #[serde(default, deserialize_with = "string_or_seq")]
    hostname: Vec<String>,
    /// Mode for getting a cert.
    ///
    /// Possible options: 'Manual', 'LetsEncrypt'.
    cert_mode: CertMode,
    /// Directory to store LetsEncrypt certs or read manual certificates from.
    ///
    /// Defaults to the servers' current working directory.
    cert_dir: Option<PathBuf>,
    /// Path of where to read the certificate from for the `Manual` and `Reloading` `cert_mode`.
    ///
    /// Defaults to `<cert_dir>/default.crt`.
    ///
    /// Only used when `cert_mode` is `Manual`.
    manual_cert_path: Option<PathBuf>,
    /// Path of where to read the private key from for the `Manual` `cert_mode`.
    ///
    /// Defaults to `<cert_dir>/default.key`.
    ///
    /// Only used when `cert_mode` is `Manual`.
    manual_key_path: Option<PathBuf>,
    /// Whether to use the LetsEncrypt production or staging server.
    ///
    /// Default is `true`.
    ///
    /// Only used when `cert_mode` is `LetsEncrypt`.
    ///
    /// While in development, LetsEncrypt prefers you to use the staging server. However,
    /// the staging server seems to only use `ECDSA` keys. In their current set up, you can
    /// only get intermediate certificates for `ECDSA` keys if you are on their
    /// "allowlist". The production server uses `RSA` keys, which allow for issuing
    /// intermediate certificates in all normal circumstances.  So, to have valid
    /// certificates, we must use the LetsEncrypt production server.  Read more here:
    /// <https://letsencrypt.org/certificates/#intermediate-certificates>.
    #[serde(default = "cfg_defaults::tls_config::prod_tls")]
    prod_tls: bool,
    /// The contact email for the tls certificate.
    ///
    /// Used when `cert_mode` is `LetsEncrypt`.
    contact: Option<String>,
    /// **This field should never be manually set**
    ///
    /// When `true`, it will force the relay to ignore binding to https. It is only
    /// ever used internally when the `--dev` flag is used on the CLI.
    ///
    /// Default is `false`.
    #[serde(default = "cfg_defaults::tls_config::dangerous_http_only")]
    dangerous_http_only: bool,
}

impl TlsConfig {
    fn https_bind_addr(&self, cfg: &Config) -> SocketAddr {
        self.https_bind_addr
            .unwrap_or_else(|| SocketAddr::new(cfg.http_bind_addr().ip(), DEFAULT_HTTPS_PORT))
    }

    fn quic_bind_addr(&self, cfg: &Config) -> SocketAddr {
        self.quic_bind_addr.unwrap_or_else(|| {
            SocketAddr::new(self.https_bind_addr(cfg).ip(), DEFAULT_RELAY_QUIC_PORT)
        })
    }

    fn cert_dir(&self) -> PathBuf {
        self.cert_dir.clone().unwrap_or_else(|| PathBuf::from("."))
    }

    fn cert_path(&self) -> PathBuf {
        self.manual_cert_path
            .clone()
            .unwrap_or_else(|| self.cert_dir().join("default.crt"))
    }

    fn key_path(&self) -> PathBuf {
        self.manual_key_path
            .clone()
            .unwrap_or_else(|| self.cert_dir().join("default.key"))
    }
}

fn string_or_seq<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrVec {
        One(String),
        Many(Vec<String>),
    }

    Ok(match StringOrVec::deserialize(deserializer)? {
        StringOrVec::One(s) => vec![s],
        StringOrVec::Many(v) => v,
    })
}

impl Config {
    async fn load(opts: &Cli) -> Result<Self> {
        let config_path = if let Some(config_path) = &opts.config_path {
            config_path
        } else {
            return Ok(Config::default());
        };

        if config_path.exists() {
            Self::read_from_file(&config_path).await
        } else {
            Ok(Config::default())
        }
    }

    fn from_str(config: &str) -> Result<Self> {
        toml::from_str(config).std_context("config must be valid toml")
    }

    async fn read_from_file(path: impl AsRef<Path>) -> Result<Self> {
        if !path.as_ref().is_file() {
            bail_any!("config-path must be a file");
        }
        let config_ser = tokio::fs::read_to_string(&path)
            .await
            .std_context("unable to read config")?;
        Self::from_str(&config_ser)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .init();

    // Install `ring` as default crypto provider for rustls.
    // This helps when both the tls-ring and tls-aws-lc-rs features are enabled,
    // otherwise some crypto operations would panic because rustls can't determine
    // a default provider.
    // `ring` is enabled by the `tls-ring` feature, which is included in the `server` feature,
    // which is required for the main.rs binary. Therefore, this does not need any feature flags.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to set default crypto provider");

    let cli = Cli::parse();
    let mut cfg = Config::load(&cli).await?;
    if cfg.enable_quic_addr_discovery && cfg.tls.is_none() {
        bail_any!("TLS must be configured in order to spawn a QUIC endpoint");
    }
    if cli.dev {
        // When in `--dev` mode, do not use https, even when tls is configured.
        if let Some(ref mut tls) = cfg.tls {
            tls.dangerous_http_only = true;
        }
        if cfg.http_bind_addr.is_none() {
            cfg.http_bind_addr = Some((Ipv6Addr::UNSPECIFIED, DEV_MODE_HTTP_PORT).into());
        }
    }
    if cfg.tls.is_none() && cfg.enable_quic_addr_discovery {
        bail_any!("If QUIC address discovery is enabled, TLS must also be configured");
    };
    let relay_config = build_relay_config(cfg).await?;
    debug!("{relay_config:#?}");

    let mut relay = relay::Server::spawn(relay_config).await?;

    tokio::select! {
        biased;
        _ = tokio::signal::ctrl_c() => (),
        _ = relay.join() => (),
    }

    relay.shutdown().await?;
    Ok(())
}

async fn load_cert_config(tls: &TlsConfig) -> Result<relay::CertConfig> {
    let server_config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocols supported by ring")
    .with_no_client_auth();
    let cert_config = match tls.cert_mode {
        CertMode::Manual => {
            let cert_path = tls.cert_path();
            let key_path = tls.key_path();
            // Could probably just do this blocking, we're only starting up.
            let (private_key, certs) = tokio::task::spawn_blocking(move || {
                let key = load_secret_key(key_path)?;
                let certs = load_certs(cert_path)?;
                n0_error::Ok((key, certs))
            })
            .await
            .std_context("join")??;
            let server_config = server_config
                .with_single_cert(certs, private_key)
                .std_context("tls config")?;
            relay::CertConfig::Manual { server_config }
        }
        CertMode::LetsEncrypt => {
            let domains = tls.hostname.clone();
            if domains.is_empty() {
                bail_any!("LetsEncrypt needs at least one hostname");
            }
            let contact = tls
                .contact
                .clone()
                .std_context("LetsEncrypt needs a contact email")?;
            let acme_config = if let Ok(url) = std::env::var(ENV_ACME_URL) {
                AcmeConfig::new(url)
            } else {
                AcmeConfig::letsencrypt(tls.prod_tls)
            };
            let mut acme_config = acme_config
                .domains(domains)
                .contact(vec![format!("mailto:{contact}")])
                .cache_path(tls.cert_dir());
            // Trust an additional CA for the ACME server's TLS certificate. Useful for testing
            // against a local ACME server such as pebble, whose certificate is not signed by a
            // publicly trusted CA.
            if let Ok(ca_path) = std::env::var(ENV_ACME_CA) {
                let extra_roots = CertificateDer::pem_file_iter(&ca_path)
                    .std_context("failed to read IROH_RELAY_ACME_CA")?
                    .collect::<Result<Vec<_>, _>>()
                    .std_context("failed to parse IROH_RELAY_ACME_CA")?;
                acme_config =
                    acme_config.tls_config(CaTlsConfig::default().with_extra_roots(extra_roots));
            }
            relay::CertConfig::LetsEncrypt {
                acme_config,
                server_config_builder: server_config,
            }
        }
        CertMode::Reloading => {
            let resolver = reloading_resolver(
                server_config.crypto_provider(),
                tls.cert_path(),
                tls.key_path(),
                DEFAULT_CERT_RELOAD_INTERVAL,
            )
            .await?;
            let server_config = server_config.with_cert_resolver(resolver);
            relay::CertConfig::Manual { server_config }
        }
    };
    Ok(cert_config)
}

/// Convert the TOML-loaded config to the [`relay::RelayConfig`] format.
async fn build_relay_config(cfg: Config) -> Result<relay::ServerConfig> {
    let (tls_config, quic_config) = if let Some(cfg_tls) = &cfg.tls {
        let cert = load_cert_config(cfg_tls).await?;

        // Use the server config from the relay::TlsConfig
        let quic_config = cfg
            .enable_quic_addr_discovery
            .then(|| QuicConfig::new(cfg_tls.quic_bind_addr(&cfg)));

        if cfg_tls.dangerous_http_only {
            // When `dangerous_http_only` is set through the --dev argument,
            // we disable HTTPS by setting `RelayConfig::tls` to `None`.
            // We still enable the QUIC server, and thus pass the TLS config
            // from the loaded TLS config only to the QUIC server.
            let quic_config = match quic_config {
                None => None,
                Some(mut quic_config) => {
                    quic_config.server_config = match cert {
                        relay::CertConfig::Manual { server_config } => Some(server_config),
                        relay::CertConfig::LetsEncrypt { .. } => {
                            bail_any!("--dev is incompatible with cert_mode LetsEncrypt")
                        }
                        _ => bail_any!("--dev is incompatible with this cert_mode"),
                    };
                    Some(quic_config)
                }
            };
            (None, quic_config)
        } else {
            let tls_config = relay::TlsConfig::new(cfg_tls.https_bind_addr(&cfg), cert);
            (Some(tls_config), quic_config)
        }
    } else if cfg.enable_quic_addr_discovery {
        bail_any!("Must have TLS configuration to enable a QUIC server for QUIC address discovery");
    } else {
        (None, None)
    };

    let relay_config = if cfg.enable_relay {
        let mut relay_config = relay::RelayConfig::new(cfg.http_bind_addr());
        relay_config.tls = tls_config;
        relay_config.allocations = cfg
            .allocations
            .clone()
            .map(AllocationsConfig::into_allocation_config)
            .transpose()?;
        Some(relay_config)
    } else {
        None
    };

    let mut server_config = relay::ServerConfig::default();
    server_config.relay = relay_config;
    server_config.quic = quic_config;
    #[cfg(feature = "metrics")]
    {
        server_config.metrics_addr = cfg.enable_metrics.then_some(cfg.metrics_bind_addr());
    }
    Ok(server_config)
}

#[cfg(test)]
mod tests {
    use n0_error::Result;

    use super::*;

    #[test]
    fn test_removed_fields_are_rejected() {
        for config in [
            "access = \"everyone\"",
            "access.allowlist = []",
            "access.shared_token = [\"token\"]",
            "key_cache_capacity = 1024",
            "[limits.client.rx]\nbytes_per_second = 400",
        ] {
            assert!(
                Config::from_str(config).is_err(),
                "config must be rejected: {config}"
            );
        }
    }

    #[tokio::test]
    async fn test_allocations_config() -> Result {
        let config = Config::from_str("")?;
        let relay = build_relay_config(config).await?.relay.expect("relay");
        assert!(relay.allocations.is_none());

        let config = Config::from_str(
            r#"
            [allocations]
            public_ip = "203.0.113.5"
            shared_tokens = ["token"]
        "#,
        )?;
        let relay = build_relay_config(config).await?.relay.expect("relay");
        let allocations = relay.allocations.expect("allocations");
        assert_eq!(allocations.public_ip, Ipv4Addr::new(203, 0, 113, 5));
        assert_eq!(allocations.bind_ip, allocations.public_ip);
        assert_eq!(allocations.ports, 1024..=65535);
        assert_eq!(allocations.release_timeout, Duration::from_secs(30));
        assert_eq!(allocations.max_packet_size, 1500);
        assert_eq!(allocations.max_tunnels, 64);

        let config = Config::from_str(
            r#"
            [allocations]
            public_ip = "203.0.113.5"
            bind_ip = "10.0.0.5"
            port_range_start = 40000
            port_range_end = 50000
            release_timeout_secs = 0
            max_packet_size = 1400
            max_tunnels = 0
            shared_tokens = ["token"]
        "#,
        )?;
        let relay = build_relay_config(config).await?.relay.expect("relay");
        let allocations = relay.allocations.expect("allocations");
        assert_eq!(allocations.bind_ip, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(allocations.ports, 40000..=50000);
        assert_eq!(allocations.release_timeout, Duration::ZERO);
        assert_eq!(allocations.max_packet_size, 1400);
        assert_eq!(allocations.max_tunnels, 0);

        for invalid in [
            // No tokens, and an empty token.
            "[allocations]\npublic_ip = \"203.0.113.5\"",
            "[allocations]\npublic_ip = \"203.0.113.5\"\nshared_tokens = [\"\"]",
            // Unusable port ranges.
            "[allocations]\npublic_ip = \"203.0.113.5\"\nshared_tokens = [\"t\"]\nport_range_start = 0",
            "[allocations]\npublic_ip = \"203.0.113.5\"\nshared_tokens = [\"t\"]\nport_range_start = 9\nport_range_end = 8",
            "[allocations]\npublic_ip = \"203.0.113.5\"\nshared_tokens = [\"t\"]\nmax_packet_size = 0",
        ] {
            let config = Config::from_str(invalid)?;
            assert!(
                build_relay_config(config).await.is_err(),
                "config must be rejected: {invalid}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_policy_config() -> Result {
        let parse = |policy: &str| -> Result<relay::DefaultPolicyConfig> {
            let config = Config::from_str(&format!(
                "[allocations]\npublic_ip = \"203.0.113.5\"\nshared_tokens = [\"t\"]\n{policy}"
            ))?;
            config
                .allocations
                .expect("allocations")
                .policy
                .into_policy_config()
        };

        assert_eq!(parse("")?, relay::DefaultPolicyConfig::default());

        let config = parse(
            r#"
            [allocations.policy]
            reply_window_secs = 60
            max_remotes = 16
            require_initial = false
            inbound_bytes_per_second = 1000000
            inbound_burst_bytes = 500000
            outbound_bytes_per_second = 0
        "#,
        )?;
        assert_eq!(config.reply_window, Duration::from_secs(60));
        assert_eq!(config.max_remotes, 16);
        assert!(!config.require_initial);
        let inbound = config.inbound.expect("inbound limit");
        assert_eq!(inbound.bytes_per_second.get(), 1_000_000);
        assert_eq!(inbound.burst_bytes, 500_000);
        assert_eq!(config.outbound, None);

        // Checked when the policy is built.
        let build = |policy: &str| -> Result<relay::AllocationConfig> {
            let config = Config::from_str(&format!(
                "[allocations]\npublic_ip = \"203.0.113.5\"\nshared_tokens = [\"t\"]\n{policy}"
            ))?;
            config
                .allocations
                .expect("allocations")
                .into_allocation_config()
        };
        assert!(build("").is_ok());
        assert!(build("[allocations.policy]\nmax_remotes = 0").is_err());
        assert!(build("[allocations.policy]\nreply_window_secs = 0").is_err());
        assert!(
            parse("[allocations.policy]\noutbound_bytes_per_second = 0\noutbound_burst_bytes = 9")
                .is_err()
        );
        assert!(parse("[allocations.policy]\nunknown = 1").is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_enable_relay_config() -> Result {
        let config = "
            enable_relay = false
        ";
        let config = Config::from_str(config)?;
        let relay_config = build_relay_config(config).await?;
        assert!(relay_config.relay.is_none());

        let config = "
            enable_relay = true
        ";
        let config = Config::from_str(config)?;
        let relay_config = build_relay_config(config).await?;
        assert!(relay_config.relay.is_some());

        let config = "";
        let config = Config::from_str(config)?;
        let relay_config = build_relay_config(config).await?;
        assert!(relay_config.relay.is_some());

        Ok(())
    }
}
