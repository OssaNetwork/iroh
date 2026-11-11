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
        done: oneshot::Sender<Result<(), DhtError>>,
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
    /// again whenever it reconnects, so one call is enough for the life of the link.
    /// While the link is not connected the call waits for it to connect.
    ///
    /// The relay learns the infohash.
    pub async fn dht_announce(&self, info_hash: InfoHash) -> Result<(), DhtError> {
        let (done, result) = oneshot::channel();
        self.commands
            .send(Command::Announce { info_hash, done })
            .await
            .map_err(|_| e!(DhtError::Closed))?;
        result.await.map_err(|_| e!(DhtError::Closed))?
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
    waiting: HashMap<InfoHash, Vec<oneshot::Sender<Result<(), DhtError>>>>,
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
                self.announced.insert(info_hash);
                self.waiting.entry(info_hash).or_default().push(done);
            }
            Command::Stop { info_hash } => self.forget(info_hash, e!(DhtError::Closed)),
            Command::FindPeers { peers, .. } => {
                let _ = peers.send(Err(e!(DhtError::NotConnected)));
            }
        }
    }

    /// Handles a request while there is a control channel. Returns what to send.
    fn handle_online(&mut self, command: Command) -> ClientControl {
        match command {
            Command::Announce { info_hash, done } => {
                self.announced.insert(info_hash);
                self.waiting.entry(info_hash).or_default().push(done);
                ClientControl::DhtAnnounce { info_hash }
            }
            Command::Stop { info_hash } => {
                self.forget(info_hash, e!(DhtError::Closed));
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

    /// Stops announcing `info_hash` and tells whoever waits for it `error`.
    fn forget(&mut self, info_hash: InfoHash, error: DhtError) {
        self.announced.remove(&info_hash);
        let mut error = Some(error);
        for done in self.waiting.remove(&info_hash).unwrap_or_default() {
            // The error can not be cloned. The first to wait gets it, the others learn
            // from their dropped sender that the request is over.
            if let Some(error) = error.take() {
                let _ = done.send(Err(error));
            }
        }
    }

    /// Handles an answer of the relay. Returns whether it was a DHT message.
    fn handle_answer(&mut self, control: &RelayControl) -> bool {
        match control {
            RelayControl::DhtAnnounceResult { info_hash, status } => {
                match DhtError::check(*status) {
                    Ok(()) => {
                        for done in self.waiting.remove(info_hash).unwrap_or_default() {
                            let _ = done.send(Ok(()));
                        }
                    }
                    // The relay does not announce it. Do not ask again on reconnect, the
                    // caller knows and decides.
                    Err(err) => self.forget(*info_hash, err),
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
            RelayControl::DhtStopped { .. } => true,
            _ => false,
        }
    }

    /// The control channel is gone. Lookups do not survive it, announcements do.
    fn disconnected(&mut self) {
        for (_, lookup) in self.lookups.drain() {
            let _ = lookup.send(Err(e!(DhtError::Disconnected)));
        }
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
        let announced: Vec<InfoHash> = self.dht.announced.iter().copied().collect();
        for info_hash in announced {
            let frame = ClientFrame::Control(ClientControl::DhtAnnounce { info_hash });
            if client.feed(frame).await.is_err() {
                return Ended::Broken("write failed");
            }
        }
        if !matches!(
            time::timeout(WRITE_TIMEOUT, client.flush()).await,
            Ok(Ok(()))
        ) {
            return Ended::Broken("write failed");
        }

        let idle = time::sleep(IDLE_TIMEOUT);
        tokio::pin!(idle);
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    let _ = time::timeout(WRITE_TIMEOUT, client.close()).await;
                    return Ended::Cancelled;
                }
                _ = &mut idle => return Ended::Broken("the relay went silent"),
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
