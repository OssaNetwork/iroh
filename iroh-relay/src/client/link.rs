//! A client's connection to a relay.

use std::{
    net::SocketAddrV4,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
    time::Duration,
};

use bytes::Bytes;
use n0_error::{e, stack_error};
use n0_future::{Sink, SinkExt, Stream, StreamExt, task::AbortOnDropHandle, time};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info_span, trace, warn};

use super::{ConnectError, WsConnection, WsDialer, addr::RelayIndex, socket::Registration};
use crate::{
    auth::{CHANNEL_BINDING_LEN, SharedToken, channel_binding},
    protos::{
        relay::{
            CONTROL_RELATIVE_PATH, CONTROL_SUBPROTOCOL, ClientControl, ClientFrame, Datagram,
            DecodeError, EncodeError, ErrorCode, RelayControl, RelayFrame,
        },
        streams::StreamError,
    },
};

/// How long the relay has to answer the client's credentials.
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a control channel may be silent before it is considered broken.
///
/// The relay pings an idle client every 15 seconds.
const IDLE_TIMEOUT: Duration = Duration::from_secs(40);

/// How long a single write to the control channel may take.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// The delays between attempts to reconnect.
const MIN_BACKOFF: Duration = Duration::from_millis(100);
const MAX_BACKOFF: Duration = Duration::from_secs(10);

/// How many packets wait for the control channel before packets are dropped.
const OUTBOUND_QUEUE_DEPTH: usize = 512;

/// How many queued packets are written to the control channel before it is flushed.
const WRITE_BATCH: usize = 64;

/// Produces the credentials a client presents to a relay.
///
/// What the credentials contain is agreed between the client and the relay's
/// authenticator.
pub trait Credentials: std::fmt::Debug + Send + Sync + 'static {
    /// Returns the credentials for a control channel.
    ///
    /// `channel_binding` is a value unique to the TLS session of the control channel, see
    /// [`channel_binding`]. Credentials that prove possession of a key sign it. It is
    /// `None` if the control channel does not run on TLS.
    ///
    /// Called for every control channel, so once per reconnect.
    fn credentials(
        &self,
        channel_binding: Option<&[u8; CHANNEL_BINDING_LEN]>,
    ) -> Result<Bytes, CredentialsError>;
}

/// The credentials for a control channel could not be produced.
#[stack_error(derive, add_meta)]
#[error("failed to produce credentials: {reason}")]
pub struct CredentialsError {
    /// What went wrong.
    pub reason: String,
}

impl Credentials for SharedToken {
    fn credentials(
        &self,
        _channel_binding: Option<&[u8; CHANNEL_BINDING_LEN]>,
    ) -> Result<Bytes, CredentialsError> {
        self.to_bytes()
            .map_err(|err| CredentialsError::new(err.to_string()))
    }
}

/// Errors when opening a control channel.
#[stack_error(derive, add_meta, from_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum ControlError {
    #[error(transparent)]
    Connect { source: ConnectError },
    #[error(transparent)]
    Credentials { source: CredentialsError },
    #[error(transparent)]
    Encode { source: EncodeError },
    #[error("the relay did not answer in time")]
    Timeout,
    #[error("the control channel closed")]
    Closed,
    #[error("the control channel failed")]
    Stream { source: StreamError },
    #[error("the relay sent a message that can not be decoded")]
    Decode { source: DecodeError },
    #[error("the relay sent an unexpected message")]
    UnexpectedMessage,
    /// The relay refused the client.
    #[error("the relay refused: {code:?} {reason}")]
    Refused { code: ErrorCode, reason: String },
}

impl ControlError {
    /// Returns whether trying again with the same credentials is pointless.
    fn is_permanent(&self) -> bool {
        matches!(
            self,
            Self::Credentials { .. }
                | Self::Encode { .. }
                | Self::Refused {
                    code: ErrorCode::Unauthorized | ErrorCode::Protocol,
                    ..
                }
        )
    }
}

/// An authenticated control channel to a relay.
///
/// This is a [`Stream`] of the relay's frames and a [`Sink`] for the client's frames.
/// Frames are not flushed automatically. The client must answer the relay's pings, see
/// [`RelayControl::Ping`].
///
/// Most users want a [`RelayLink`] instead, which does all of this.
#[derive(Debug)]
pub struct ControlClient {
    conn: WsConnection,
    public_addr: SocketAddrV4,
}

impl ControlClient {
    /// Opens a control channel to the relay `dialer` dials and authenticates.
    ///
    /// `dialer` must accept messages of
    /// [`MAX_FRAME_SIZE`](crate::protos::relay::MAX_FRAME_SIZE) bytes.
    pub async fn connect(
        dialer: &WsDialer,
        credentials: &dyn Credentials,
    ) -> Result<Self, ControlError> {
        let mut conn = dialer
            .connect(CONTROL_RELATIVE_PATH, CONTROL_SUBPROTOCOL)
            .await?;
        let binding = channel_binding(&conn);
        let credentials = credentials.credentials(binding.as_ref())?;
        let auth = ClientFrame::Control(ClientControl::Auth { credentials }).to_bytes()?;
        time::timeout(WRITE_TIMEOUT, conn.send(auth))
            .await
            .map_err(|_| e!(ControlError::Timeout))?
            .map_err(|err| e!(ControlError::Stream, err))?;

        let answer = async {
            loop {
                let bytes = match conn.next().await {
                    Some(Ok(bytes)) => bytes,
                    Some(Err(err)) => return Err(e!(ControlError::Stream, err)),
                    None => return Err(e!(ControlError::Closed)),
                };
                match RelayFrame::from_bytes(bytes) {
                    Ok(RelayFrame::Control(RelayControl::Allocated { addr })) => return Ok(addr),
                    Ok(RelayFrame::Control(RelayControl::Error { code, reason })) => {
                        return Err(e!(ControlError::Refused { code, reason }));
                    }
                    Ok(_) => return Err(e!(ControlError::UnexpectedMessage)),
                    Err(err) if err.is_unknown_control() => continue,
                    Err(err) => return Err(e!(ControlError::Decode, err)),
                }
            }
        };
        let public_addr = time::timeout(AUTH_TIMEOUT, answer)
            .await
            .map_err(|_| e!(ControlError::Timeout))??;
        Ok(Self { conn, public_addr })
    }

    /// Returns the public address the relay allocated for this client.
    ///
    /// Packets sent to it arrive on this control channel.
    pub fn public_addr(&self) -> SocketAddrV4 {
        self.public_addr
    }
}

impl Stream for ControlClient {
    type Item = Result<RelayFrame, ControlError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let bytes = match n0_future::ready!(Pin::new(&mut self.conn).poll_next(cx)) {
                Some(Ok(bytes)) => bytes,
                Some(Err(err)) => return Poll::Ready(Some(Err(e!(ControlError::Stream, err)))),
                None => return Poll::Ready(None),
            };
            match RelayFrame::from_bytes(bytes) {
                Ok(frame) => return Poll::Ready(Some(Ok(frame))),
                // Control messages this version does not know are skipped.
                Err(err) if err.is_unknown_control() => continue,
                Err(err) => return Poll::Ready(Some(Err(e!(ControlError::Decode, err)))),
            }
        }
    }
}

impl Sink<ClientFrame> for ControlClient {
    type Error = ControlError;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn)
            .poll_ready(cx)
            .map_err(|err| e!(ControlError::Stream, err))
    }

    fn start_send(mut self: Pin<&mut Self>, frame: ClientFrame) -> Result<(), Self::Error> {
        let bytes = frame.to_bytes()?;
        Pin::new(&mut self.conn)
            .start_send(bytes)
            .map_err(|err| e!(ControlError::Stream, err))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn)
            .poll_flush(cx)
            .map_err(|err| e!(ControlError::Stream, err))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn)
            .poll_close(cx)
            .map_err(|err| e!(ControlError::Stream, err))
    }
}

/// The state of a [`RelayLink`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkState {
    /// The link is connecting, or reconnecting after its control channel broke.
    ///
    /// The relay keeps the client's port for a while after the control channel broke. If
    /// the link reconnects in time the public address stays the same.
    Connecting,
    /// The link is up. Packets sent to this public address arrive on the socket.
    Connected(SocketAddrV4),
    /// The link gave up, for the stated reason. It does not reconnect.
    ///
    /// This happens when the relay rejects the credentials, or when another control
    /// channel with the same identity took over.
    Failed(String),
}

impl LinkState {
    /// Returns the public address if the link is up.
    pub fn public_addr(&self) -> Option<SocketAddrV4> {
        match self {
            Self::Connected(addr) => Some(*addr),
            _ => None,
        }
    }
}

/// A packet received through a relay, together with the relay it came through.
#[derive(Debug)]
pub(super) struct Inbound {
    pub(super) relay: RelayIndex,
    pub(super) datagram: Datagram,
}

/// A connection to a relay that is kept open in the background.
///
/// Created with [`RelaySocketHandle::connect_relay`]. While the link is
/// [connected](LinkState::Connected) the relay forwards packets sent to the link's public
/// address to the socket.
///
/// Dropping the link closes the control channel. The relay then releases the public
/// address after its release timeout.
///
/// [`RelaySocketHandle::connect_relay`]: super::RelaySocketHandle::connect_relay
#[derive(Debug)]
pub struct RelayLink {
    index: RelayIndex,
    state: watch::Receiver<LinkState>,
    cancel: CancellationToken,
    _task: AbortOnDropHandle<()>,
    /// Removes the link from the socket when dropped.
    _registration: Registration,
}

impl RelayLink {
    pub(super) fn spawn(
        index: RelayIndex,
        dialer: WsDialer,
        credentials: Arc<dyn Credentials>,
        inbound: mpsc::Sender<Inbound>,
        registration: Registration,
    ) -> (Self, mpsc::Sender<Datagram>) {
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_QUEUE_DEPTH);
        let (state_tx, state_rx) = watch::channel(LinkState::Connecting);
        let cancel = CancellationToken::new();
        let actor = Actor {
            index,
            dialer,
            credentials,
            inbound,
            outbound: outbound_rx,
            state: state_tx,
            cancel: cancel.clone(),
        };
        let task = n0_future::task::spawn(
            actor
                .run()
                .instrument(info_span!("relay-link", index = index.0)),
        );
        let link = Self {
            index,
            state: state_rx,
            cancel,
            _task: AbortOnDropHandle::new(task),
            _registration: registration,
        };
        (link, outbound_tx)
    }

    /// Returns the index that identifies this relay in the addresses of the socket, see
    /// [`PathAddr::Relayed`](super::PathAddr::Relayed).
    pub fn index(&self) -> RelayIndex {
        self.index
    }

    /// Returns the current state of the link.
    pub fn state(&self) -> LinkState {
        self.state.borrow().clone()
    }

    /// Returns a receiver that is notified when the state of the link changes.
    pub fn watch_state(&self) -> watch::Receiver<LinkState> {
        self.state.clone()
    }

    /// Waits until the link is up and returns its public address.
    ///
    /// Returns the reason if the link gave up.
    pub async fn public_addr(&self) -> Result<SocketAddrV4, String> {
        let mut state = self.state.clone();
        let res = state
            .wait_for(|state| !matches!(state, LinkState::Connecting))
            .await;
        match res.as_deref() {
            Ok(LinkState::Connected(addr)) => Ok(*addr),
            Ok(LinkState::Failed(reason)) => Err(reason.clone()),
            Ok(LinkState::Connecting) | Err(_) => Err("the link was closed".to_string()),
        }
    }

    /// Closes the control channel. The link does not reconnect.
    pub fn close(&self) {
        self.cancel.cancel();
    }
}

impl Drop for RelayLink {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Why a control channel ended.
enum Ended {
    /// Reconnect.
    Broken(&'static str),
    /// Do not reconnect.
    Failed(String),
    /// The link was closed.
    Cancelled,
}

struct Actor {
    index: RelayIndex,
    dialer: WsDialer,
    credentials: Arc<dyn Credentials>,
    inbound: mpsc::Sender<Inbound>,
    outbound: mpsc::Receiver<Datagram>,
    state: watch::Sender<LinkState>,
    cancel: CancellationToken,
}

impl Actor {
    async fn run(mut self) {
        let mut backoff = MIN_BACKOFF;
        loop {
            self.state.send_if_modified(|state| {
                let changed = *state != LinkState::Connecting;
                *state = LinkState::Connecting;
                changed
            });
            let connect = ControlClient::connect(&self.dialer, self.credentials.as_ref());
            let client = tokio::select! {
                _ = self.cancel.cancelled() => return,
                // Packets can not be sent while there is no control channel. Do not let
                // them queue up to be sent late.
                _ = discard(&mut self.outbound) => return,
                res = connect => res,
            };
            let ended = match client {
                Ok(client) => {
                    debug!(addr = %client.public_addr(), "relay link connected");
                    backoff = MIN_BACKOFF;
                    self.state
                        .send_replace(LinkState::Connected(client.public_addr()));
                    self.serve(client).await
                }
                Err(err) if err.is_permanent() => Ended::Failed(err.to_string()),
                Err(err) => {
                    debug!("failed to connect to relay: {err:#}");
                    Ended::Broken("connect failed")
                }
            };
            match ended {
                Ended::Cancelled => return,
                Ended::Failed(reason) => {
                    warn!("relay link gave up: {reason}");
                    self.state.send_replace(LinkState::Failed(reason));
                    return;
                }
                Ended::Broken(reason) => {
                    debug!(?backoff, "relay link broke: {reason}");
                    self.state.send_replace(LinkState::Connecting);
                }
            }
            // Wait before the next attempt, a little longer every time it fails.
            let jitter = backoff.mul_f64(rand::random::<f64>() * 0.5);
            tokio::select! {
                _ = self.cancel.cancelled() => return,
                _ = discard(&mut self.outbound) => return,
                _ = time::sleep(backoff + jitter) => {}
            }
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    /// Runs one control channel until it ends.
    async fn serve(&mut self, mut client: ControlClient) -> Ended {
        let idle = time::sleep(IDLE_TIMEOUT);
        tokio::pin!(idle);
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    let _ = time::timeout(WRITE_TIMEOUT, client.close()).await;
                    return Ended::Cancelled;
                }
                _ = &mut idle => return Ended::Broken("the relay went silent"),
                first = self.outbound.recv() => {
                    // The socket dropped its end, the link is no longer in use.
                    let Some(first) = first else {
                        return Ended::Cancelled;
                    };
                    let write = async {
                        feed(&mut client, first).await?;
                        for _ in 1..WRITE_BATCH {
                            match self.outbound.try_recv() {
                                Ok(datagram) => feed(&mut client, datagram).await?,
                                Err(_) => break,
                            }
                        }
                        client.flush().await
                    };
                    if !matches!(time::timeout(WRITE_TIMEOUT, write).await, Ok(Ok(()))) {
                        return Ended::Broken("write failed");
                    }
                }
                frame = client.next() => {
                    let frame = match frame {
                        Some(Ok(frame)) => frame,
                        Some(Err(err)) => {
                            debug!("control channel failed: {err:#}");
                            return Ended::Broken("read failed");
                        }
                        None => return Ended::Broken("closed by the relay"),
                    };
                    idle.as_mut().reset(time::Instant::now() + IDLE_TIMEOUT);
                    let reply = match frame {
                        RelayFrame::Datagram(datagram) => {
                            let inbound = Inbound { relay: self.index, datagram };
                            // A full queue means the QUIC stack is not keeping up.
                            if self.inbound.try_send(inbound).is_err() {
                                trace!("inbound queue full, dropping packet");
                            }
                            None
                        }
                        RelayFrame::Control(RelayControl::Ping(payload)) => {
                            Some(ClientControl::Pong(payload))
                        }
                        RelayFrame::Control(RelayControl::Error { code, reason }) => {
                            return match code {
                                // Somebody else uses our identity. Reconnecting would
                                // take the port back and forth between the two.
                                ErrorCode::Superseded => Ended::Failed(
                                    "another control channel with the same identity took over"
                                        .to_string(),
                                ),
                                ErrorCode::Unauthorized | ErrorCode::Protocol => {
                                    Ended::Failed(format!("the relay refused: {code:?} {reason}"))
                                }
                                _ => Ended::Broken("the relay reported an error"),
                            };
                        }
                        // The address does not change on an open control channel, and
                        // nothing here waits for the other control messages.
                        RelayFrame::Control(_) => None,
                    };
                    if let Some(control) = reply {
                        let write = client.send(ClientFrame::Control(control));
                        if !matches!(time::timeout(WRITE_TIMEOUT, write).await, Ok(Ok(()))) {
                            return Ended::Broken("write failed");
                        }
                    }
                }
            }
        }
    }
}

/// Queues a packet on the control channel. A packet that can not be encoded is skipped.
async fn feed(client: &mut ControlClient, datagram: Datagram) -> Result<(), ControlError> {
    match client.feed(ClientFrame::Datagram(datagram)).await {
        Err(ControlError::Encode { .. }) => Ok(()),
        res => res,
    }
}

/// Drops the packets that are queued for the relay, until the sender is gone.
async fn discard(outbound: &mut mpsc::Receiver<Datagram>) {
    while outbound.recv().await.is_some() {}
}
