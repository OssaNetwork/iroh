//! A client's connection to a relay.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddrV4,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
    time::Duration,
};

use bytes::Bytes;
use n0_error::{e, stack_error};
use n0_future::{Sink, SinkExt, Stream, StreamExt, time};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info_span, trace, warn};

use super::{
    ConnectError, WsConnection, WsDialer,
    addr::{PathAddr, RelayIndex},
    socket::Registration,
};
use crate::{
    auth::{CHANNEL_BINDING_LEN, SharedToken, channel_binding},
    protos::{
        relay::{
            CONTROL_RELATIVE_PATH, CONTROL_SUBPROTOCOL, ClientControl, ClientFrame, Datagram,
            DecodeError, DhtStatus, EncodeError, ErrorCode, InfoHash, RelayControl, RelayFrame,
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

/// How long a control channel has to stay up for the delay to start over.
///
/// A relay that accepts a client and drops it right away would otherwise be dialed in a
/// tight loop.
const STABLE_AFTER: Duration = Duration::from_secs(10);

/// How many packets wait for the control channel before packets are dropped.
const OUTBOUND_QUEUE_DEPTH: usize = 512;

/// How many queued packets are written to the control channel before it is flushed.
const WRITE_BATCH: usize = 64;

/// How many DHT requests wait for the link's task.
const COMMAND_QUEUE_DEPTH: usize = 64;

/// How long the link waits before it asks again for an announcement that failed.
const ANNOUNCE_RETRY_INTERVAL: Duration = Duration::from_secs(30);

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
        match self {
            Self::Credentials { .. } | Self::Encode { .. } => true,
            Self::Refused { code, .. } => is_permanent(*code),
            _ => false,
        }
    }
}

/// Returns whether the relay will refuse again when the client connects again.
fn is_permanent(code: ErrorCode) -> bool {
    matches!(
        code,
        // Reconnecting after being superseded would take the port back and forth between
        // two users of the same identity.
        ErrorCode::Unauthorized | ErrorCode::Protocol | ErrorCode::Superseded
    )
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
    /// The link was closed with [`RelayLink::close`].
    Closed,
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

/// A request to the mainline DHT service of a relay was not served.
#[stack_error(derive, add_meta)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum DhtError {
    #[error("the relay's policy refused the request")]
    Denied,
    #[error("the request failed")]
    Failed,
    #[error("the relay does not offer the DHT service")]
    Unavailable,
    #[error("the link is not connected to the relay")]
    NotConnected,
    #[error("the control channel broke before the request was done")]
    Disconnected,
    #[error("the link gave up or was closed")]
    Closed,
    #[error("the announcement was stopped before the relay answered")]
    Stopped,
    #[error("the relay answered with a status this version does not know: {status}")]
    UnknownStatus { status: u8 },
}

impl DhtError {
    /// Turns the status of an answer into a result.
    fn check(status: DhtStatus) -> Result<(), Self> {
        match status {
            DhtStatus::Ok => Ok(()),
            DhtStatus::Denied => Err(e!(Self::Denied)),
            DhtStatus::Failed => Err(e!(Self::Failed)),
            DhtStatus::Unavailable => Err(e!(Self::Unavailable)),
            DhtStatus::Unknown(status) => Err(e!(Self::UnknownStatus { status })),
        }
    }
}

/// How an announce request ended. Unlike the error this can be copied, to tell everyone
/// who waits for the same infohash.
#[derive(Debug, Clone, Copy)]
enum AnnounceOutcome {
    /// The relay answered.
    Answered(DhtStatus),
    /// The announcement was stopped before the relay answered.
    Stopped,
}

impl AnnounceOutcome {
    fn into_result(self) -> Result<(), DhtError> {
        match self {
            Self::Answered(status) => DhtError::check(status),
            Self::Stopped => Err(e!(DhtError::Stopped)),
        }
    }
}

/// The peers found by [`RelayLink::dht_find_peers`].
///
/// A [`Stream`] of batches of peer addresses, in the order the relay finds them. The
/// stream ends when the lookup is done. If the lookup fails the last item is the error.
#[derive(Debug)]
pub struct DhtPeers {
    peers: mpsc::UnboundedReceiver<Result<Vec<SocketAddrV4>, DhtError>>,
}

impl Stream for DhtPeers {
    type Item = Result<Vec<SocketAddrV4>, DhtError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        self.peers.poll_recv(cx)
    }
}

/// A DHT request for the link's task.
enum Command {
    Announce {
        info_hash: InfoHash,
        done: oneshot::Sender<AnnounceOutcome>,
    },
    Stop {
        info_hash: InfoHash,
    },
    FindPeers {
        info_hash: InfoHash,
        peers: mpsc::UnboundedSender<Result<Vec<SocketAddrV4>, DhtError>>,
    },
}

/// A packet received through a relay, together with the path it came on.
#[derive(Debug)]
pub(super) struct Inbound {
    pub(super) from: PathAddr,
    pub(super) payload: Bytes,
}

/// A connection to a relay that is kept open in the background.
///
/// Created with [`RelaySocketHandle::connect_relay`]. While the link is
/// [connected](LinkState::Connected) the relay forwards packets sent to the link's public
/// address to the socket.
///
/// Dropping the link closes the control channel in the background. The relay then
/// releases the public address after its release timeout.
///
/// [`RelaySocketHandle::connect_relay`]: super::RelaySocketHandle::connect_relay
#[derive(Debug)]
pub struct RelayLink {
    index: RelayIndex,
    state: watch::Receiver<LinkState>,
    /// Stops the task. The task is not aborted, so that it can close the control channel
    /// properly.
    cancel: CancellationToken,
    commands: mpsc::Sender<Command>,
    /// Removes the link from the socket when dropped.
    _registration: Registration,
}

impl RelayLink {
    pub(super) fn spawn(
        index: RelayIndex,
        dialer: WsDialer,
        credentials: Arc<dyn Credentials>,
        inbound: mpsc::Sender<Inbound>,
        outbound: mpsc::Receiver<Datagram>,
        registration: Registration,
    ) -> Self {
        let (state_tx, state_rx) = watch::channel(LinkState::Connecting);
        let (commands_tx, commands_rx) = mpsc::channel(COMMAND_QUEUE_DEPTH);
        let cancel = CancellationToken::new();
        let actor = Actor {
            index,
            dialer,
            credentials,
            inbound,
            outbound,
            state: state_tx,
            cancel: cancel.clone(),
            commands: commands_rx,
            dht: DhtState::default(),
        };
        n0_future::task::spawn(
            actor
                .run()
                .instrument(info_span!("relay-link", index = index.0)),
        );
        Self {
            index,
            state: state_rx,
            cancel,
            commands: commands_tx,
            _registration: registration,
        }
    }

    /// Creates the queue of packets for a link.
    pub(super) fn outbound_queue() -> (mpsc::Sender<Datagram>, mpsc::Receiver<Datagram>) {
        mpsc::channel(OUTBOUND_QUEUE_DEPTH)
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
    /// Returns the reason if the link gave up or was closed.
    pub async fn public_addr(&self) -> Result<SocketAddrV4, String> {
        let mut state = self.state.clone();
        let res = state
            .wait_for(|state| !matches!(state, LinkState::Connecting))
            .await;
        match res.as_deref() {
            Ok(LinkState::Connected(addr)) => Ok(*addr),
            Ok(LinkState::Failed(reason)) => Err(reason.clone()),
            Ok(LinkState::Connecting | LinkState::Closed) | Err(_) => {
                Err("the link was closed".to_string())
            }
        }
    }

    /// Asks the relay to announce this link's public address for `info_hash` on the
    /// mainline DHT, and to keep the announcement fresh.
    ///
    /// The DHT records the address an announcement comes from, so a client behind a relay
    /// can not announce itself. The relay announces its own IP address with the port of
    /// this link's allocation.
    ///
    /// Returns when the relay has announced. The link remembers the infohash and asks
    /// again whenever it reconnects, so one call is enough for the life of the link. If
    /// the relay later fails to announce, the link keeps asking. If the relay later
    /// refuses, because its policy changed, the link stops asking and logs a warning.
    /// While the link is not connected the call waits for it to connect.
    ///
    /// The relay learns the infohash.
    pub async fn dht_announce(&self, info_hash: InfoHash) -> Result<(), DhtError> {
        let (done, result) = oneshot::channel();
        self.commands
            .send(Command::Announce { info_hash, done })
            .await
            .map_err(|_| e!(DhtError::Closed))?;
        result
            .await
            .map_err(|_| e!(DhtError::Closed))?
            .into_result()
    }

    /// Asks the relay to stop refreshing the announcement for `info_hash`.
    ///
    /// The DHT has no way to delete an announcement. It expires on its own, after about
    /// half an hour.
    pub async fn dht_stop(&self, info_hash: InfoHash) -> Result<(), DhtError> {
        self.commands
            .send(Command::Stop { info_hash })
            .await
            .map_err(|_| e!(DhtError::Closed))
    }

    /// Asks the relay to look up the peers of `info_hash` on the mainline DHT.
    ///
    /// The peers arrive on the returned stream as the relay finds them. A peer that is
    /// itself behind a relay appears with the address of its relay. The lookup fails
    /// right away if the link is not connected.
    ///
    /// The relay learns the infohash.
    pub async fn dht_find_peers(&self, info_hash: InfoHash) -> Result<DhtPeers, DhtError> {
        let (peers_tx, peers_rx) = mpsc::unbounded_channel();
        self.commands
            .send(Command::FindPeers {
                info_hash,
                peers: peers_tx,
            })
            .await
            .map_err(|_| e!(DhtError::Closed))?;
        Ok(DhtPeers { peers: peers_rx })
    }

    /// Closes the control channel in the background. The link does not reconnect, and its
    /// state becomes [`LinkState::Closed`].
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
    commands: mpsc::Receiver<Command>,
    dht: DhtState,
}

/// What the link knows about its DHT requests.
#[derive(Default)]
struct DhtState {
    /// The infohashes the relay announces for the link, or is asked to. They are sent
    /// again on every new control channel: the relay forgets them when it releases the
    /// link's port.
    announced: HashSet<InfoHash>,
    /// Who waits for the answer to an announce request.
    waiting: HashMap<InfoHash, Vec<oneshot::Sender<AnnounceOutcome>>>,
    /// The infohashes whose announcement was stopped, until the relay acknowledges it.
    ///
    /// A stop request can get lost: there may be no control channel, or the one it is
    /// written to may be breaking. The relay would keep announcing. What is in here is
    /// sent again on the next control channel.
    unacked_stops: HashSet<InfoHash>,
    /// The infohashes the relay failed to announce when nobody waited for the answer.
    /// The link asks again after a while.
    retry: HashSet<InfoHash>,
    /// The lookups that run on the current control channel, by request id.
    lookups: HashMap<u32, mpsc::UnboundedSender<Result<Vec<SocketAddrV4>, DhtError>>>,
    next_request_id: u32,
}

impl DhtState {
    /// Handles a request while there is no control channel.
    fn handle_offline(&mut self, command: Command) {
        match command {
            // Sent once the link is connected.
            Command::Announce { info_hash, done } => {
                self.unacked_stops.remove(&info_hash);
                self.announced.insert(info_hash);
                self.waiting.entry(info_hash).or_default().push(done);
            }
            Command::Stop { info_hash } => {
                self.forget(info_hash, AnnounceOutcome::Stopped);
                self.unacked_stops.insert(info_hash);
            }
            Command::FindPeers { peers, .. } => {
                let _ = peers.send(Err(e!(DhtError::NotConnected)));
            }
        }
    }

    /// Handles a request while there is a control channel. Returns what to send.
    fn handle_online(&mut self, command: Command) -> ClientControl {
        match command {
            Command::Announce { info_hash, done } => {
                // The relay handles requests in order. A stop that is still on its way
                // comes first, and one that got lost no longer matters.
                self.unacked_stops.remove(&info_hash);
                self.announced.insert(info_hash);
                self.retry.remove(&info_hash);
                self.waiting.entry(info_hash).or_default().push(done);
                ClientControl::DhtAnnounce { info_hash }
            }
            Command::Stop { info_hash } => {
                self.forget(info_hash, AnnounceOutcome::Stopped);
                self.unacked_stops.insert(info_hash);
                ClientControl::DhtStop { info_hash }
            }
            Command::FindPeers { info_hash, peers } => {
                let request_id = self.next_request_id;
                self.next_request_id = self.next_request_id.wrapping_add(1);
                self.lookups.insert(request_id, peers);
                ClientControl::DhtFindPeers {
                    request_id,
                    info_hash,
                }
            }
        }
    }

    /// Stops announcing `info_hash` and tells everyone who waits for it `outcome`.
    fn forget(&mut self, info_hash: InfoHash, outcome: AnnounceOutcome) {
        self.announced.remove(&info_hash);
        self.retry.remove(&info_hash);
        self.answer(&info_hash, outcome);
    }

    /// Tells everyone who waits for `info_hash` `outcome`. Returns whether anyone did.
    fn answer(&mut self, info_hash: &InfoHash, outcome: AnnounceOutcome) -> bool {
        let waiting = self.waiting.remove(info_hash).unwrap_or_default();
        let any = !waiting.is_empty();
        for done in waiting {
            let _ = done.send(outcome);
        }
        any
    }

    /// Handles an answer of the relay. Returns whether it was a DHT message.
    fn handle_answer(&mut self, control: &RelayControl) -> bool {
        match control {
            RelayControl::DhtAnnounceResult { info_hash, status } => {
                // An answer to a request that was stopped meanwhile.
                if !self.announced.contains(info_hash) {
                    return true;
                }
                let outcome = AnnounceOutcome::Answered(*status);
                match status {
                    DhtStatus::Ok => {
                        self.retry.remove(info_hash);
                        self.answer(info_hash, outcome);
                    }
                    DhtStatus::Failed => {
                        // Whoever asked is told and decides. If nobody asked, this was
                        // the link asking again after a reconnect: the caller was told
                        // that the infohash is announced, so keep at it.
                        if self.answer(info_hash, outcome) {
                            self.announced.remove(info_hash);
                        } else {
                            self.retry.insert(*info_hash);
                        }
                    }
                    // The relay will not announce it however often it is asked.
                    _ => {
                        if !self.answer(info_hash, outcome) {
                            warn!(
                                ?status,
                                "the relay no longer announces an infohash on the DHT"
                            );
                        }
                        self.announced.remove(info_hash);
                        self.retry.remove(info_hash);
                    }
                }
                true
            }
            RelayControl::DhtPeers { request_id, peers } => {
                if let Some(lookup) = self.lookups.get(request_id) {
                    let _ = lookup.send(Ok(peers.clone()));
                }
                true
            }
            RelayControl::DhtFindPeersDone { request_id, status } => {
                if let Some(lookup) = self.lookups.remove(request_id)
                    && let Err(err) = DhtError::check(*status)
                {
                    let _ = lookup.send(Err(err));
                }
                true
            }
            RelayControl::DhtStopped { info_hash } => {
                self.unacked_stops.remove(info_hash);
                true
            }
            _ => false,
        }
    }

    /// The control channel is gone. Lookups do not survive it, announcements do.
    fn disconnected(&mut self) {
        for (_, lookup) in self.lookups.drain() {
            let _ = lookup.send(Err(e!(DhtError::Disconnected)));
        }
        // Everything is asked for again on the next control channel anyway.
        self.retry.clear();
    }

    /// Returns what to tell the relay about the announcements on a new control channel.
    fn resume(&mut self) -> Vec<ClientControl> {
        // The stops the relay did not acknowledge are sent again, and stay until it
        // does. An infohash can not be in both sets.
        let stops = self
            .unacked_stops
            .iter()
            .map(|info_hash| ClientControl::DhtStop {
                info_hash: *info_hash,
            });
        let announces = self
            .announced
            .iter()
            .map(|info_hash| ClientControl::DhtAnnounce {
                info_hash: *info_hash,
            });
        stops.chain(announces).collect()
    }
}

/// What happened while the link waited without a control channel.
enum Offline<T> {
    /// The future the link waited for completed.
    Done(T),
    /// The link was closed.
    Closed,
}

impl Actor {
    /// Drives `fut` while there is no control channel.
    ///
    /// Packets can not be sent meanwhile. They are dropped, so that they do not queue up
    /// to be sent late. DHT requests are answered or kept for later.
    async fn while_offline<T>(&mut self, fut: impl Future<Output = T>) -> Offline<T> {
        tokio::pin!(fut);
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => return Offline::Closed,
                res = &mut fut => return Offline::Done(res),
                packet = self.outbound.recv() => {
                    // The socket dropped its end, the link is no longer in use.
                    if packet.is_none() {
                        return Offline::Closed;
                    }
                }
                Some(command) = self.commands.recv() => self.dht.handle_offline(command),
            }
        }
    }

    async fn run(mut self) {
        let last = self.connect_and_serve().await;
        // Whoever still looks at the link sees why it is over.
        self.state.send_replace(last);
    }

    /// Keeps a control channel open until the link fails for good or is closed.
    /// Returns the last state of the link.
    async fn connect_and_serve(&mut self) -> LinkState {
        let mut backoff = MIN_BACKOFF;
        loop {
            let dialer = self.dialer.clone();
            let credentials = self.credentials.clone();
            let connect =
                async move { ControlClient::connect(&dialer, credentials.as_ref()).await };
            let client = match self.while_offline(connect).await {
                Offline::Done(res) => res,
                Offline::Closed => return LinkState::Closed,
            };
            let ended = match client {
                Ok(client) => {
                    debug!(addr = %client.public_addr(), "relay link connected");
                    self.state
                        .send_replace(LinkState::Connected(client.public_addr()));
                    let connected = time::Instant::now();
                    let ended = self.serve(client).await;
                    self.dht.disconnected();
                    if connected.elapsed() >= STABLE_AFTER {
                        backoff = MIN_BACKOFF;
                    }
                    ended
                }
                Err(err) if err.is_permanent() => Ended::Failed(err.to_string()),
                Err(err) => {
                    debug!("failed to connect to relay: {err:#}");
                    Ended::Broken("connect failed")
                }
            };
            match ended {
                Ended::Cancelled => return LinkState::Closed,
                Ended::Failed(reason) => {
                    warn!("relay link gave up: {reason}");
                    return LinkState::Failed(reason);
                }
                Ended::Broken(reason) => {
                    debug!(?backoff, "relay link broke: {reason}");
                    self.state.send_replace(LinkState::Connecting);
                }
            }
            // Wait before the next attempt, a little longer every time it fails.
            let jitter = backoff.mul_f64(rand::random::<f64>() * 0.5);
            if let Offline::Closed = self.while_offline(time::sleep(backoff + jitter)).await {
                return LinkState::Closed;
            }
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    /// Runs one control channel until it ends.
    async fn serve(&mut self, mut client: ControlClient) -> Ended {
        // The relay forgets the announcements when it releases the link's port. Ask for
        // all of them on every control channel, the relay answers at once for those it
        // still has.
        let resume = self.dht.resume();
        let write = async {
            for control in resume {
                client.feed(ClientFrame::Control(control)).await?;
            }
            client.flush().await
        };
        if !matches!(time::timeout(WRITE_TIMEOUT, write).await, Ok(Ok(()))) {
            return Ended::Broken("write failed");
        }

        let mut retry_announces = time::interval(ANNOUNCE_RETRY_INTERVAL);
        retry_announces.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        // The first tick of an interval completes immediately. Wait a full interval.
        retry_announces.reset();
        let idle = time::sleep(IDLE_TIMEOUT);
        tokio::pin!(idle);
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    let _ = time::timeout(WRITE_TIMEOUT, client.close()).await;
                    return Ended::Cancelled;
                }
                _ = &mut idle => return Ended::Broken("the relay went silent"),
                _ = retry_announces.tick(), if !self.dht.retry.is_empty() => {
                    let retry: Vec<InfoHash> = self.dht.retry.drain().collect();
                    let write = async {
                        for info_hash in retry {
                            let control = ClientControl::DhtAnnounce { info_hash };
                            client.feed(ClientFrame::Control(control)).await?;
                        }
                        client.flush().await
                    };
                    if !matches!(time::timeout(WRITE_TIMEOUT, write).await, Ok(Ok(()))) {
                        return Ended::Broken("write failed");
                    }
                }
                Some(command) = self.commands.recv() => {
                    let control = self.dht.handle_online(command);
                    let write = client.send(ClientFrame::Control(control));
                    if !matches!(time::timeout(WRITE_TIMEOUT, write).await, Ok(Ok(()))) {
                        return Ended::Broken("write failed");
                    }
                }
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
                            let inbound = Inbound {
                                from: PathAddr::Relayed {
                                    relay: self.index,
                                    remote: datagram.remote,
                                },
                                payload: datagram.payload,
                            };
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
                                ErrorCode::Superseded => Ended::Failed(
                                    "another control channel with the same identity took over"
                                        .to_string(),
                                ),
                                code if is_permanent(code) => {
                                    Ended::Failed(format!("the relay refused: {code:?} {reason}"))
                                }
                                _ => Ended::Broken("the relay reported an error"),
                            };
                        }
                        RelayFrame::Control(control) => {
                            // The address does not change on an open control channel,
                            // and nothing waits for the other control messages.
                            self.dht.handle_answer(&control);
                            None
                        }
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

#[cfg(test)]
mod tests {
    use super::*;

    const H1: InfoHash = [1; 20];
    const H2: InfoHash = [2; 20];

    fn announce(
        state: &mut DhtState,
        info_hash: InfoHash,
        online: bool,
    ) -> oneshot::Receiver<AnnounceOutcome> {
        let (done, result) = oneshot::channel();
        let command = Command::Announce { info_hash, done };
        if online {
            state.handle_online(command);
        } else {
            state.handle_offline(command);
        }
        result
    }

    fn answer(state: &mut DhtState, info_hash: InfoHash, status: DhtStatus) {
        assert!(state.handle_answer(&RelayControl::DhtAnnounceResult { info_hash, status }));
    }

    #[test]
    fn everyone_waiting_gets_the_answer() {
        let mut state = DhtState::default();
        let mut first = announce(&mut state, H1, true);
        let mut second = announce(&mut state, H1, true);
        answer(&mut state, H1, DhtStatus::Denied);
        for result in [&mut first, &mut second] {
            let err = result.try_recv().unwrap().into_result().unwrap_err();
            assert!(matches!(err, DhtError::Denied { .. }), "{err:?}");
        }
        // The caller was told, the link does not ask again.
        assert!(state.resume().is_empty());

        let mut ok = announce(&mut state, H1, true);
        answer(&mut state, H1, DhtStatus::Ok);
        assert!(ok.try_recv().unwrap().into_result().is_ok());
        assert_eq!(
            state.resume(),
            vec![ClientControl::DhtAnnounce { info_hash: H1 }]
        );
    }

    #[test]
    fn failure_after_reconnect_is_retried() {
        let mut state = DhtState::default();
        let mut done = announce(&mut state, H1, true);
        answer(&mut state, H1, DhtStatus::Ok);
        assert!(done.try_recv().unwrap().into_result().is_ok());

        // The link reconnects and asks again. Nobody waits for this answer.
        state.disconnected();
        assert_eq!(
            state.resume(),
            vec![ClientControl::DhtAnnounce { info_hash: H1 }]
        );
        answer(&mut state, H1, DhtStatus::Failed);
        // The caller was told that the infohash is announced: keep at it.
        assert!(state.retry.contains(&H1));
        assert!(state.announced.contains(&H1));
        answer(&mut state, H1, DhtStatus::Ok);
        assert!(state.retry.is_empty());

        // A failure the caller waits for is the caller's to handle.
        let mut done = announce(&mut state, H2, true);
        answer(&mut state, H2, DhtStatus::Failed);
        let err = done.try_recv().unwrap().into_result().unwrap_err();
        assert!(matches!(err, DhtError::Failed { .. }), "{err:?}");
        assert!(!state.announced.contains(&H2));
        assert!(state.retry.is_empty());

        // A refusal ends it, however it was asked.
        state.disconnected();
        state.resume();
        answer(&mut state, H1, DhtStatus::Denied);
        assert!(state.announced.is_empty());
        assert!(state.retry.is_empty());
    }

    #[test]
    fn stop_is_sent_until_the_relay_acknowledges_it() {
        let mut state = DhtState::default();
        let mut done = announce(&mut state, H1, true);
        answer(&mut state, H1, DhtStatus::Ok);
        assert!(done.try_recv().unwrap().into_result().is_ok());

        // Stopped on a control channel that breaks before the relay reads the request.
        assert_eq!(
            state.handle_online(Command::Stop { info_hash: H1 }),
            ClientControl::DhtStop { info_hash: H1 }
        );
        state.disconnected();
        // Another one is stopped while there is no control channel at all.
        let mut gone = announce(&mut state, H2, false);
        state.handle_offline(Command::Stop { info_hash: H2 });
        assert!(matches!(
            gone.try_recv().unwrap().into_result(),
            Err(DhtError::Stopped { .. })
        ));

        // Both are sent on the next control channel, and again on the one after it, until
        // the relay says it got them.
        for _ in 0..2 {
            let mut resume = state.resume();
            resume.sort_by_key(|control| format!("{control:?}"));
            assert_eq!(
                resume,
                vec![
                    ClientControl::DhtStop { info_hash: H1 },
                    ClientControl::DhtStop { info_hash: H2 },
                ]
            );
            state.disconnected();
        }
        assert!(state.handle_answer(&RelayControl::DhtStopped { info_hash: H1 }));
        assert_eq!(
            state.resume(),
            vec![ClientControl::DhtStop { info_hash: H2 }]
        );

        // Announcing again takes the stop back.
        let _again = announce(&mut state, H2, false);
        assert_eq!(
            state.resume(),
            vec![ClientControl::DhtAnnounce { info_hash: H2 }]
        );
    }

    #[test]
    fn stop_answers_whoever_waits() {
        let mut state = DhtState::default();
        let mut done = announce(&mut state, H1, true);
        state.handle_online(Command::Stop { info_hash: H1 });
        let err = done.try_recv().unwrap().into_result().unwrap_err();
        assert!(matches!(err, DhtError::Stopped { .. }), "{err:?}");
        // The relay's late answer to the stopped request changes nothing.
        answer(&mut state, H1, DhtStatus::Ok);
        assert!(state.announced.is_empty());
    }

    #[test]
    fn lookups_end_with_the_control_channel() {
        let mut state = DhtState::default();
        let (peers, mut results) = mpsc::unbounded_channel();
        let control = state.handle_online(Command::FindPeers {
            info_hash: H1,
            peers,
        });
        let ClientControl::DhtFindPeers { request_id, .. } = control else {
            panic!("wrong message");
        };
        let found = vec![SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 1)];
        state.handle_answer(&RelayControl::DhtPeers {
            request_id,
            peers: found.clone(),
        });
        assert_eq!(results.try_recv().unwrap().unwrap(), found);
        state.disconnected();
        let err = results.try_recv().unwrap().unwrap_err();
        assert!(matches!(err, DhtError::Disconnected { .. }), "{err:?}");
        // The stream ends after the error.
        assert!(matches!(
            results.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));

        // Offline, a lookup fails right away.
        let (peers, mut results) = mpsc::unbounded_channel();
        state.handle_offline(Command::FindPeers {
            info_hash: H1,
            peers,
        });
        let err = results.try_recv().unwrap().unwrap_err();
        assert!(matches!(err, DhtError::NotConnected { .. }), "{err:?}");
    }
}
