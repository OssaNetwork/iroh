# Iroh Relay

This is a fork of [iroh]'s relay that is being reworked into a transparent QUIC
relay. A client that cannot accept inbound connections is given a public UDP
port on the relay and advertises the relay's IP and that port as its own
address. The relay forwards QUIC packets without being able to read them.

iroh's own relay protocol has been removed from this crate. It currently
provides:
- Relay Protocol: the frames exchanged between a relay and its clients.
- Relay Server: gives each authenticated client a public UDP port and forwards
  packets between that port and the client's control channel. Also serves
  latency probe and captive portal endpoints, and optionally a QAD endpoint
  and metrics.
- Relay Client: a WebSocket dialer for connecting to the relay.
- Server Binary: A CLI for running your own relay server.

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
# The tokens clients present to use the relay.
shared_tokens = ["token-a", "token-b"]
```

A client that reconnects within the release timeout keeps its port. One
relay address serves at most one client per port, so the port range bounds
the number of clients.

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
channel, and returns the identity of the client. The same goes for
`TrafficPolicy`, which decides which packets are forwarded. The binary
forwards every packet.

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
