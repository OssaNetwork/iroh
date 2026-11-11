//! Implements logic for abstracting over a websocket stream that allows sending only [`Bytes`]-based
//! messages.
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use n0_error::AnyError;
use n0_error::anyerr;
use n0_future::{Sink, Stream, ready};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::warn;

use crate::ExportKeyingMaterial;

#[derive(derive_more::Debug)]
pub(crate) struct WsBytesFramed<T> {
    #[debug("WebSocketStream<T>")]
    pub(crate) io: tokio_websockets::WebSocketStream<T>,
}

/// Error type for WebSocket stream operations.
///
/// This is a generic [`AnyError`] and represents errors that can occur during WebSocket
/// communication. The underlying error type is `tokio_websockets::Error`.
///
/// You can use [`AnyError::downcast_ref`] to downcast to the concrete error. However, the
/// downcast is not covered by any semver guarantees and the underlying error may change.
pub type StreamError = AnyError;

/// Shorthand for a type that implements both a websocket-based stream & sink for [`Bytes`].
pub trait BytesStreamSink:
    Stream<Item = Result<Bytes, StreamError>> + Sink<Bytes, Error = StreamError> + Unpin
{
}

impl<T> BytesStreamSink for T where
    T: Stream<Item = Result<Bytes, StreamError>> + Sink<Bytes, Error = StreamError> + Unpin
{
}

impl<IO: ExportKeyingMaterial + AsyncRead + AsyncWrite + Unpin> ExportKeyingMaterial
    for WsBytesFramed<IO>
{
    fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Option<T> {
        self.io
            .get_ref()
            .export_keying_material(output, label, context)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Stream for WsBytesFramed<T> {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match ready!(Pin::new(&mut self.io).poll_next(cx)) {
                None => return Poll::Ready(None),
                Some(Err(e)) => return Poll::Ready(Some(Err(anyerr!(e)))),
                Some(Ok(msg)) => {
                    if msg.is_close() {
                        // Indicate the stream is done when we receive a close message.
                        // Note: We don't have to poll the stream to completion for it to close gracefully.
                        return Poll::Ready(None);
                    }
                    if msg.is_ping() || msg.is_pong() {
                        continue; // Responding appropriately to these is done inside of tokio_websockets/browser impls
                    }
                    if !msg.is_binary() {
                        warn!(?msg, "Got websocket message of unsupported type, skipping.");
                        continue;
                    }
                    return Poll::Ready(Some(Ok(msg.into_payload().into())));
                }
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Sink<Bytes> for WsBytesFramed<T> {
    type Error = StreamError;

    fn start_send(mut self: Pin<&mut Self>, bytes: Bytes) -> Result<(), Self::Error> {
        let msg = tokio_websockets::Message::binary(tokio_websockets::Payload::from(bytes));
        Pin::new(&mut self.io)
            .start_send(msg)
            .map_err(AnyError::from_std)
    }

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.io)
            .poll_ready(cx)
            .map_err(AnyError::from_std)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.io)
            .poll_flush(cx)
            .map_err(AnyError::from_std)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.io)
            .poll_close(cx)
            .map_err(AnyError::from_std)
    }
}

/// Writes `first` and the messages that are already waiting in `more`, at most `max`
/// messages in total, and flushes once.
///
/// Flushing once per batch instead of once per message saves system calls when messages
/// arrive faster than they are written.
pub(crate) async fn write_batch<S, T>(
    io: &mut S,
    first: T,
    more: &mut tokio::sync::mpsc::Receiver<T>,
    max: usize,
) -> Result<(), S::Error>
where
    S: Sink<T> + Unpin,
{
    use n0_future::SinkExt;

    io.feed(first).await?;
    for _ in 1..max {
        match more.try_recv() {
            Ok(message) => io.feed(message).await?,
            Err(_) => break,
        }
    }
    io.flush().await
}
