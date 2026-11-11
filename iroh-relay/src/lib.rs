//! A relay server and client.
//!
//! This crate is being reworked into a transparent QUIC relay: a client that cannot accept
//! inbound connections is given a public UDP port on the relay, and the relay forwards QUIC
//! packets for it without being able to read them.
//!
//! It currently provides:
#![cfg_attr(
    feature = "server",
    doc = "- [`server`]: A fully-fledged iroh-relay server over HTTP or HTTPS."
)]
#![cfg_attr(
    not(feature = "server"),
    doc = "- `server`: A fully-fledged iroh-relay server over HTTP or HTTPS."
)]
//!
//!    Optionally will also expose a QAD endpoint and metrics. (requires the feature flag `server`)
//! - [`client`]: A client for establishing connections to the relay.
//! - *Server Binary*: A CLI for running your own relay server. It can be configured to also offer
//!   QAD support and expose metrics.
#![cfg_attr(iroh_docsrs, feature(doc_cfg))]
#![deny(missing_docs, rustdoc::broken_intra_doc_links, unreachable_pub)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

pub mod auth;
pub mod client;
pub mod defaults;
pub mod http;
mod ping_tracker;
pub mod protos;
pub mod quic;
#[cfg(feature = "server")]
pub mod server;
#[cfg(test)]
pub(crate) mod test_utils;
pub mod tls;

pub use crate::ping_tracker::PingTracker;

/// Trait for extracting keying material from a TLS connection.
///
/// This allows anything that ends up potentially wrapping a TLS stream to use the
/// underlying [`export_keying_material`] function. It is used during the relay handshake
/// to establish a shared secret between the client and server for authentication purposes.
///
/// [`export_keying_material`]: rustls::ConnectionCommon::export_keying_material
pub trait ExportKeyingMaterial {
    /// If this type ends up wrapping a TLS stream, then this tries
    /// to export keying material by calling the underlying [`export_keying_material`]
    /// function.
    ///
    /// However unlike that function, this returns `Option`, in case the
    /// underlying stream might not be wrapping TLS, e.g. as in the case of
    /// `MaybeTlsStream`.
    ///
    /// For more information on what this function does, see the
    /// [`export_keying_material`] documentation.
    ///
    /// [`export_keying_material`]: rustls::ConnectionCommon::export_keying_material
    fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Option<T>;
}
