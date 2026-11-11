//! Streams used in the server-side implementation of the relay.

use std::{
    pin::Pin,
    sync::atomic::AtomicBool,
    task::{Context, Poll},
};

use n0_error::{ensure, stack_error};
use n0_future::time;
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
    /// An in-memory bidirectional pipe.
    #[cfg(test)]
    Test(tokio::io::DuplexStream),
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
            #[cfg(test)]
            Self::Test(_) => return,
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
            #[cfg(test)]
            MaybeTlsStream::Test(s) => Pin::new(s).poll_read(cx, buf),
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
            #[cfg(test)]
            MaybeTlsStream::Test(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        match &mut *self {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(test)]
            MaybeTlsStream::Test(s) => Pin::new(s).poll_shutdown(cx),
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
            #[cfg(test)]
            MaybeTlsStream::Test(s) => Pin::new(s).poll_write(cx, buf),
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
            #[cfg(test)]
            MaybeTlsStream::Test(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            MaybeTlsStream::Plain(s) => s.is_write_vectored(),
            MaybeTlsStream::Tls(s) => s.is_write_vectored(),
            #[cfg(test)]
            MaybeTlsStream::Test(s) => s.is_write_vectored(),
        }
    }
}

/// A token bucket used for rate-limiting.
///
/// The bucket holds up to `max` tokens, refilled at a fixed rate of
/// `bytes_per_second` over `refill_period` intervals. [`Bucket::consume`] drains
/// tokens and reports when the next attempt is allowed.
///
#[derive(Debug)]
pub struct Bucket {
    // The current bucket fill
    fill: i64,
    // The maximum bucket fill
    max: i64,
    // The bucket's last fill time
    last_fill: time::Instant,
    // Interval length of one refill
    refill_period: time::Duration,
    // How much we re-fill per refill period
    refill: i64,
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
pub struct InvalidBucketConfig {
    max: i64,
    bytes_per_second: i64,
    refill_period: time::Duration,
}

impl Bucket {
    /// Creates a new bucket starting full at `max` tokens, refilled at
    /// `bytes_per_second` over `refill_period` intervals.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidBucketConfig`] when `max`, `bytes_per_second`, or
    /// `refill_period` are non-positive, or when the configuration would refill
    /// less than one token per period.
    pub fn new(
        max: i64,
        bytes_per_second: i64,
        refill_period: time::Duration,
    ) -> Result<Self, InvalidBucketConfig> {
        // milliseconds is the tokio timer resolution
        let refill = bytes_per_second.saturating_mul(refill_period.as_millis() as i64) / 1000;
        ensure!(
            max > 0 && bytes_per_second > 0 && refill_period.as_millis() as u32 > 0 && refill > 0,
            InvalidBucketConfig {
                max,
                bytes_per_second,
                refill_period
            }
        );
        Ok(Self {
            fill: max,
            max,
            last_fill: time::Instant::now(),
            refill_period,
            refill,
        })
    }

    fn update_state(&mut self) {
        let now = time::Instant::now();
        // div safety: self.refill_period.as_millis() is checked to be non-null in constructor
        let refill_periods = now.saturating_duration_since(self.last_fill).as_millis() as u32
            / self.refill_period.as_millis() as u32;
        if refill_periods == 0 {
            // Nothing to do - we won't refill yet
            return;
        }

        self.fill = self
            .fill
            .saturating_add(refill_periods as i64 * self.refill);
        self.fill = std::cmp::min(self.fill, self.max);
        self.last_fill += self.refill_period * refill_periods;
    }

    /// Attempts to consume `bytes` tokens from the bucket.
    ///
    /// Returns `Ok(())` if enough tokens were available.
    ///
    /// # Errors
    ///
    /// Returns `Err(deadline)` with the [`time::Instant`] at which enough
    /// tokens will have refilled to allow the request.
    pub fn consume(&mut self, bytes: usize) -> Result<(), time::Instant> {
        let bytes = i64::try_from(bytes).unwrap_or(i64::MAX);
        self.update_state();

        self.fill = self.fill.saturating_sub(bytes);

        if self.fill > 0 {
            return Ok(());
        }

        let missing = self.fill.saturating_neg();

        let periods_needed = (missing / self.refill) + 1;
        let periods_needed = u32::try_from(periods_needed).unwrap_or(u32::MAX);

        Err(self.last_fill + periods_needed * self.refill_period)
    }
}

#[cfg(test)]
mod tests {
    use n0_error::Result;
    use n0_future::time;

    use super::Bucket;

    #[tokio::test(start_paused = true)]
    async fn test_bucket_high_refill() -> Result {
        let bytes_per_second = i64::MAX;
        let mut bucket = Bucket::new(i64::MAX, bytes_per_second, time::Duration::from_millis(100))?;
        for _ in 0..100 {
            time::sleep(time::Duration::from_millis(100)).await;
            assert!(bucket.consume(1_000_000).is_ok());
        }

        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn smoke_test_bucket_high_consume() -> Result {
        let bytes_per_second = 123_456;
        let mut bucket = Bucket::new(
            bytes_per_second / 10,
            bytes_per_second,
            time::Duration::from_millis(100),
        )?;
        for _ in 0..100 {
            let Err(until) = bucket.consume(usize::MAX) else {
                panic!("i64::MAX shouldn't be within limits");
            };
            time::sleep_until(until).await;
        }

        Ok(())
    }
}
