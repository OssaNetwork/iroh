# Iroh Relay

This is a fork of [iroh]'s relay that is being reworked into a transparent QUIC
relay. A client that cannot accept inbound connections is given a public UDP
port on the relay and advertises the relay's IP and that port as its own
address. The relay forwards QUIC packets without being able to read them.

iroh's own relay protocol has been removed from this crate. It currently
provides:
- Relay Protocol: the frames exchanged between a relay and its clients.
- Relay Server: gives each authenticated client a public UDP port and forwards
  packets between that port and the client's control channel. Serves a TCP
  fallback for dialers whose network blocks UDP, and can announce and look up
  peers on the mainline DHT for its clients. Also serves latency probe and
  captive portal endpoints, and optionally a QAD endpoint and metrics.
- Relay Client: a UDP socket for a QUIC stack that is also reachable through
  relays, and the connection to a relay behind it.
- Server Binary: A CLI for running your own relay server.

## Features of the crate

- `server`: the relay server and its binary.
- `dht`: the mainline DHT service of the server.
- `dns` (default): lets the client resolve host names with a DNS resolver of
  its own. Without it the client uses the resolver of the operating system
  and the crate has fewer dependencies.
- `tls-ring` (default) and `tls-aws-lc-rs`: the cryptography provider.

## Build the server

You can build an optimised release of `iroh-relay` by running `cargo build`
with the appropriate flags from the workspace parent directory as follows.

```
cd ../
cargo build \
  --profile optimized-release \
  --package iroh-relay \
  --features server
```

You will find the optimised binary at `target/optimized-release/iroh-relay`.

## Accepting clients

The relay only accepts clients when the `allocations` section is present in
the TOML config file.

```toml
[allocations]
# The public IPv4 address of the relay. Clients advertise it as their own.
public_ip = "203.0.113.5"
# The local address the clients' UDP sockets are bound to, if it differs from
# the public address (hosts behind a 1:1 NAT). Defaults to public_ip.
# bind_ip = "10.0.0.5"
# The ports handed out to clients. Defaults to 1024 to 65535.
# port_range_start = 1024
# port_range_end = 65535
# How long a port stays reserved for a client after it disconnected.
# Defaults to 30, with 0 ports are released immediately.
# release_timeout_secs = 30
# The largest QUIC packet forwarded. Defaults to 1500.
# max_packet_size = 1500
# How many TCP tunnels can be open to one client. Defaults to 64, with 0 the
# relay does not serve tunnels.
# max_tunnels = 64
# The tokens clients present to use the relay.
shared_tokens = ["token-a", "token-b"]
```

A client that reconnects within the release timeout keeps its port. One
relay address serves at most one client per port, so the port range bounds
the number of clients.

### TCP fallback

A dialer whose network blocks UDP can not reach a client's port. It can open
a tunnel instead: a WebSocket to `/tunnel/<port>` on TCP port 443 of the same
IP address, on which every message is one QUIC packet. The QUIC connection
inside is still end to end between the dialer and the client.

For this to work the relay's HTTPS server has to listen on port 443 of the
public address, and present a certificate that is valid for that IP address.
Dialers have nothing but the IP address to verify the relay against.

The relay can obtain such a certificate from Let's Encrypt on its own:

```toml
[tls]
cert_mode = "LetsEncryptIp"
# Where the account and the certificate are kept between restarts.
cert_dir = "/var/lib/iroh-relay/certs"
# The address to obtain the certificate for. Defaults to the public_ip of the
# allocations section.
# ip = "203.0.113.5"
# Optional, for notices from the certificate authority.
# contact = "admin@example.com"
# Set to false to use Let's Encrypt's staging environment.
# prod_tls = true
```

The certificate authority verifies that the relay controls the address by
fetching a token from port 80 of it, so `http_bind_addr` has to be reachable
there. Certificates for IP addresses are valid for about six days. The relay
renews them halfway through, without a restart. It does not start until it
has a certificate.

Alternatively use `cert_mode = "Manual"` or `"Reloading"` with a certificate
issued for the IP address by other means.

Anyone can open a tunnel, as anyone can send UDP packets to the port. When a
client has `max_tunnels` tunnels, a new one replaces the oldest tunnel the
client never sent a packet into. A tunnel that carries no forwarded packets
for two minutes is closed, so the QUIC connection inside needs a keep-alive
interval shorter than that.

The dialer needs code for this, a stock QUIC client only speaks UDP. See
`RelaySocketHandle::open_tunnel` and `race_udp_and_tunnel` in the client.

### Mainline DHT

A mainline DHT `announce_peer` records the address the announcement comes
from. A client behind the relay can therefore not announce itself, the DHT
would record its own address. The relay can do it instead: it runs one DHT
node and, on request of a client, announces its own IP address with the port
of the client, keeps the announcement fresh, and looks up the peers of an
infohash.

```toml
[allocations.dht]
# The UDP port of the relay's DHT node. Chosen by the operating system if not
# set. It has to be reachable from the internet.
# port = 6881
# The nodes to join the DHT through. Defaults to the well known nodes of the
# mainline DHT.
# bootstrap = ["router.bittorrent.com:6881"]
# How often announcements are refreshed. Defaults to 900.
# refresh_interval_secs = 900
```

This needs a binary built with the `dht` feature:
`cargo build --package iroh-relay --features server,dht`.

A client's announcements live as long as its port: the relay keeps refreshing
them while the client is away during the release timeout, and stops when the
port is released. The DHT has no way to delete an announcement, entries
expire on their own.

The relay learns every infohash its clients announce or look up. Which
requests are served is decided by `iroh_relay::server::dht::DhtPolicy` when
the relay is embedded as a library. The binary serves all of them, up to 1024
announced infohashes and 16 concurrent lookups per client.

### Authentication

The binary authenticates clients with shared tokens: a client names itself
and presents one of the configured tokens. Anyone who knows a token can use
any name, and take over the port of the client with that name, so this is
meant for tests and private relays. The token list can also be set with the
`IROH_RELAY_SHARED_TOKEN` environment variable, which sets a single token and
takes precedence over the config file.

To authenticate clients differently, embed the relay as a library and
implement `iroh_relay::server::Authenticator`. It receives the credentials
the client presented and a value bound to the TLS session of the control
channel, and returns the identity of the client.

### Traffic policy

The relay carries traffic for strangers in both directions, and limits both:

- A client may only send to addresses that recently sent to its port, so it
  can not use the relay as a general UDP proxy.
- The first packet from a new address must look like the start of a QUIC
  connection: a long header packet of at least 1200 bytes.
- The bytes forwarded per client are limited in each direction.

```toml
[allocations.policy]
# For how long after an address last sent to a client's port the client may
# send to it. Defaults to 120.
# reply_window_secs = 120
# How many addresses are tracked per client. Defaults to 1024. When the table
# is full a new address replaces the one that was silent the longest.
# max_remotes = 1024
# Whether the first packet from a new address must look like the start of a
# QUIC connection. Defaults to true.
# require_initial = true
# Rate limits in bytes per second, 0 for unlimited. Default to 2097152.
# inbound_bytes_per_second = 2097152
# outbound_bytes_per_second = 2097152
# How many bytes may pass at once after a quiet period. Default to one
# second's worth. Values below 65536 are raised to 65536.
# inbound_burst_bytes = 2097152
# outbound_burst_bytes = 2097152
```

Only packets from an address extend its reply window. A connection through
the relay on which the dialer is silent for longer than the window is cut
off, so the endpoints need a keep-alive interval, or an idle timeout, shorter
than `reply_window_secs`.

With `require_initial`, a dialer whose address changes in the middle of a
connection, for example because its NAT rebinds, can not continue the
connection through the relay and has to connect again. Turn it off if that
matters more to you than making floods from spoofed addresses more expensive.

To apply a different policy, embed the relay as a library and implement
`iroh_relay::server::TrafficPolicy`.

## Local testing

Advice for testing your application that uses `iroh` with a locally running `iroh-relay` server

### dev mode
When running the relay server using the `--dev` flag, you will:
- only run the server over http, not https
- will NOT run the QUIC endpoint that enables QUIC address discovery

The relay can be contacted at "http://localhost:3340".

Both https and QUIC address discovery require TLS certificates. It's possible to run QUIC address discovery using locally generated TLS certificates, but it takes a few extra steps and so, is disabled by default for now.

### dev mode with QUIC address discovery

So you want to test out QUIC address discovery locally?

In order to do that you need TLS certificates.

The easiest get that is to generate self-signed certificates using `rcgen`
  - get rcgen (`git clone https://github.com/rustls/rcgen`)
  - cd to the `rcgen` directory
  - generate local certs using `cargo run -- -o path/to/certs`

Next, add the certificate paths to your iroh-relay config, here is an example of a config.toml file that will enable quic address discovery.
```toml
enable_quic_addr_discovery = true

[tls]
cert_mode = "Manual"
manual_cert_path = "/path/to/certs/cert.pem"
manual_key_path = "/path/to/certs/cert.key.pem"
```

Then run the server with the `--dev` flag, like you would when normally testing locally:
`cargo run --features="server" --bin iroh-relay -- --config-path=/path/to/config.toml --dev`

The relay server will run over http on port 3340, as it does using the `--dev` flag, but it will also run a QUIC server on port 7824.

The relay will use the configured TLS certificates for the QUIC connection, but use http (rather than https) for the server.

### Using iroh-relay as a library to run in-process relays in integration tests

When using iroh as a transport library in an application or other library, there is a simple way of running an in-process relay server:

- Enable `test-utils` feature of the `iroh` crate
```toml
iroh = { version = "0.95", features = ["test-utils"] }
```
- Spawn a relay server by calling [`iroh::test_utils::run_relay_server().await`](https://docs.rs/iroh/latest/iroh/test_utils/fn.run_relay_server.html)
This will start a relay server with a self-signed TLS certificate, listening on a localhost port, and return the server's URL.
- For the iroh endpoints to successfully connect to the relay, disable TLS certificate verification by calling [`Endpoint::ca_tls_config`](https://docs.rs/iroh/latest/iroh/endpoint/struct.Builder.html#method.ca_tls_config) with  `CaRootConfig::insecure_skip_verify()`.

# License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   https://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   https://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.

[iroh]: https://github.com/n0-computer/iroh
