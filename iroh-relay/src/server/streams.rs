//! Streams used in the server-side implementation of the relay.

use std::{
    pin::Pin,
    sync::atomic::AtomicBool,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite};
use tracing::warn;

use crate::ExportKeyingMaterial;

/// The main underlying IO stream type used for the relay server.
///
/// Allows choosing whether or not the underlying [`tokio::net::TcpStream`] is served over TLS.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
#[non_exhaustive]
pub enum MaybeTlsStream {
    /// A plain non-Tls [`tokio::net::TcpStream`]
    Plain(tokio::net::TcpStream),
    /// A Tls wrapped [`tokio::net::TcpStream`]
    Tls(tokio_rustls::server::TlsStream<tokio::net::TcpStream>),
}

impl MaybeTlsStream {
    /// Tries to disable the nagle algorithm on the TCP stream.
    ///
    /// This sets the NO_DELAY option on the TCP stream, which turns off the
    /// nagle algorithm for coalecing writes together.
    ///
    /// If this fails, this will print a warning the first time it fails.
    pub fn disable_nagle(&self) {
        let stream = match self {
            Self::Plain(stream) => stream,
            Self::Tls(tls_stream) => tls_stream.get_ref().0,
        };

        if stream.set_nodelay(true).is_err() {
            use std::sync::atomic::Ordering::Relaxed;

            static FAILED_NO_DELAY: AtomicBool = AtomicBool::new(false);
            if !FAILED_NO_DELAY.swap(true, Relaxed) {
                warn!(
                    "Failed to set TCP socket to NO_DELAY (turning off Nagle failed). This will impair relay performance."
                );
            }
        }
    }
}

impl ExportKeyingMaterial for MaybeTlsStream {
    fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Option<T> {
        let Self::Tls(tls) = self else {
            return None;
        };

        tls.get_ref()
            .1
            .export_keying_material(output, label, context)
            .ok()
    }
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        match &mut *self {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        match &mut *self {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        match &mut *self {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        match &mut *self {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            MaybeTlsStream::Plain(s) => s.is_write_vectored(),
            MaybeTlsStream::Tls(s) => s.is_write_vectored(),
        }
    }
}
