//! The wire protocol between a relay and its clients.
//!
//! A client holds one WebSocket to the relay, the *control channel*. After the client
//! authenticated, every binary message on it is a [`ClientFrame`] or a [`RelayFrame`],
//! depending on the direction. The first byte of each message is a [flags](Flags) byte:
//!
//! - If [`Flags::CONTROL`] is set the rest of the message is a control message, see
//!   [`ClientControl`] and [`RelayControl`].
//! - Otherwise the message is a [`Datagram`]: the address of the remote party followed by
//!   one untouched QUIC packet.
//!
//! | Field   | Size    | Meaning                                         |
//! | ------- | ------- | ----------------------------------------------- |
//! | Flags   | 1 byte  | See [`Flags`]                                   |
//! | Address | 4 bytes | Remote IPv4 address                             |
//! | Port    | 2 bytes | Remote port, big-endian                         |
//! | Payload | rest    | One QUIC packet                                 |
//!
//! Dialers that can not reach the relay over UDP open a *tunnel*, a second kind of
//! WebSocket. Each binary message on a tunnel is one QUIC packet without any header.
//!
//! # Compatibility
//!
//! A receiver must ignore a control message whose type it does not know, which
//! [`DecodeError::is_unknown_control`] reports, instead of closing the connection. This
//! allows adding control messages without a new subprotocol. All other decoding errors
//! are protocol violations.

use std::net::{Ipv4Addr, SocketAddrV4};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use n0_error::{e, ensure, stack_error};

/// The WebSocket subprotocol spoken on the control channel.
pub const CONTROL_SUBPROTOCOL: &str = "transparent-relay-control-v1";

/// The WebSocket subprotocol spoken on a tunnel.
pub const TUNNEL_SUBPROTOCOL: &str = "transparent-relay-tunnel-v1";

/// The path of the control channel, relative to the relay URL.
pub const CONTROL_RELATIVE_PATH: &str = "control";

/// The path prefix of a tunnel, relative to the relay URL.
///
/// It is followed by the decimal UDP port of the allocation to reach, as in `tunnel/41873`.
pub const TUNNEL_RELATIVE_PATH_PREFIX: &str = "tunnel/";

/// The size of the header in front of the QUIC packet in a [`Datagram`].
pub const DATAGRAM_HEADER_LEN: usize = 7;

/// The maximum size of a single relayed QUIC packet.
///
/// This is the largest payload a UDP datagram can carry over IPv4.
pub const MAX_PACKET_SIZE: usize = 65_507;

/// The maximum size of a message on the control channel.
pub const MAX_FRAME_SIZE: usize = MAX_PACKET_SIZE + DATAGRAM_HEADER_LEN;

/// The maximum size of a message on a tunnel, which carries packets without a header.
pub const MAX_TUNNEL_FRAME_SIZE: usize = MAX_PACKET_SIZE;

/// The maximum length of the credentials in [`ClientControl::Auth`].
pub const MAX_CREDENTIALS_LEN: usize = 8 * 1024;

/// The maximum length in bytes of the reason in [`RelayControl::Error`].
///
/// Longer reasons are truncated, both when encoded and when decoded.
pub const MAX_REASON_LEN: usize = 256;

/// The maximum number of peers in a single [`RelayControl::DhtPeers`].
pub const MAX_DHT_PEERS_PER_FRAME: usize = 256;

/// The length of a mainline DHT infohash.
pub const INFO_HASH_LEN: usize = 20;

/// A mainline DHT infohash.
pub type InfoHash = [u8; INFO_HASH_LEN];

/// The payload of a ping, echoed back in the pong.
pub type PingPayload = [u8; 8];

/// The flags byte every message on the control channel starts with.
///
/// Bits that are not listed here are reserved and must be zero. A message with a reserved
/// bit set is rejected, which leaves room to signal an IPv6 address later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags(u8);

impl Flags {
    /// The remote party of a datagram is connected through the TCP tunnel.
    pub const TUNNEL: u8 = 0b0000_0001;
    /// The message is a control message, not a datagram.
    pub const CONTROL: u8 = 0b1000_0000;

    const KNOWN: u8 = Self::TUNNEL | Self::CONTROL;

    fn parse(byte: u8) -> Result<Self, DecodeError> {
        ensure!(
            byte & !Self::KNOWN == 0,
            DecodeError::ReservedFlags { flags: byte }
        );
        // A control message has no remote party.
        ensure!(
            byte != Self::CONTROL | Self::TUNNEL,
            DecodeError::ReservedFlags { flags: byte }
        );
        Ok(Self(byte))
    }

    fn is_control(&self) -> bool {
        self.0 & Self::CONTROL != 0
    }

    fn is_tunnel(&self) -> bool {
        self.0 & Self::TUNNEL != 0
    }
}

/// The remote party of a relayed QUIC packet.
///
/// For a packet from the relay to the client this is the packet's sender, for a packet
/// from the client to the relay it is the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RemoteAddr {
    /// The address of the remote party.
    ///
    /// For a tunnelled party this is the source address of its TCP connection to the
    /// relay. It only identifies the tunnel, UDP packets can not be sent to it.
    pub addr: SocketAddrV4,
    /// Whether the remote party is connected through the TCP tunnel.
    pub tunnel: bool,
}

impl RemoteAddr {
    /// A remote party that talks UDP to the relay.
    pub fn udp(addr: SocketAddrV4) -> Self {
        Self {
            addr,
            tunnel: false,
        }
    }

    /// A remote party that is connected through the TCP tunnel.
    pub fn tunnel(addr: SocketAddrV4) -> Self {
        Self { addr, tunnel: true }
    }
}

/// One relayed QUIC packet together with its remote party.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    /// The remote party of the packet.
    pub remote: RemoteAddr,
    /// One QUIC packet, untouched.
    pub payload: Bytes,
}

impl Datagram {
    fn encoded_len(&self) -> usize {
        DATAGRAM_HEADER_LEN + self.payload.len()
    }

    fn write_to(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        ensure!(
            self.payload.len() <= MAX_PACKET_SIZE,
            EncodeError::PacketTooLarge {
                len: self.payload.len()
            }
        );
        dst.reserve(self.encoded_len());
        dst.put_u8(if self.remote.tunnel { Flags::TUNNEL } else { 0 });
        put_socket_addr(dst, &self.remote.addr);
        dst.put_slice(&self.payload);
        Ok(())
    }

    /// Parses a datagram, `bytes` starts after the flags byte.
    fn parse(flags: Flags, mut bytes: Bytes) -> Result<Self, DecodeError> {
        let addr = get_socket_addr(&mut bytes)?;
        ensure!(
            bytes.len() <= MAX_PACKET_SIZE,
            DecodeError::PacketTooLarge { len: bytes.len() }
        );
        Ok(Self {
            remote: RemoteAddr {
                addr,
                tunnel: flags.is_tunnel(),
            },
            payload: bytes,
        })
    }
}

/// Errors when decoding a message.
#[stack_error(derive, add_meta)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum DecodeError {
    #[error("message is too short")]
    TooShort,
    #[error("reserved flags are set: {flags:#010b}")]
    ReservedFlags { flags: u8 },
    #[error("unknown control message type {ty}")]
    UnknownControl { ty: u8 },
    #[error("packet of {len} bytes is too large")]
    PacketTooLarge { len: usize },
    #[error("field of {len} bytes is too large")]
    FieldTooLarge { len: usize },
    #[error("{len} unexpected trailing bytes")]
    TrailingBytes { len: usize },
}

impl DecodeError {
    /// Returns whether the message was a control message of a type this version does not
    /// know. Such messages must be ignored.
    pub fn is_unknown_control(&self) -> bool {
        matches!(self, Self::UnknownControl { .. })
    }
}

/// Errors when encoding a message.
///
/// The limits are the ones the receiver enforces. Encoding fails instead of producing a
/// message the receiver would reject.
#[stack_error(derive, add_meta)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum EncodeError {
    #[error("packet of {len} bytes is too large")]
    PacketTooLarge { len: usize },
    #[error("credentials of {len} bytes are too large")]
    CredentialsTooLarge { len: usize },
    #[error("{len} peers do not fit into one message")]
    TooManyPeers { len: usize },
}

/// Why the relay refused a request or closed the control channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorCode {
    /// The credentials were rejected.
    Unauthorized,
    /// The relay has no free port for the client.
    NoPortAvailable,
    /// Another control channel with the same identity took over the allocation.
    Superseded,
    /// The client violated the protocol.
    Protocol,
    /// The relay failed internally.
    Internal,
    /// A code this version does not know.
    ///
    /// Produced when decoding. Do not construct it with the value of a known code.
    Unknown(u8),
}

impl From<u8> for ErrorCode {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Unauthorized,
            2 => Self::NoPortAvailable,
            3 => Self::Superseded,
            4 => Self::Protocol,
            5 => Self::Internal,
            other => Self::Unknown(other),
        }
    }
}

impl From<ErrorCode> for u8 {
    fn from(value: ErrorCode) -> Self {
        match value {
            ErrorCode::Unauthorized => 1,
            ErrorCode::NoPortAvailable => 2,
            ErrorCode::Superseded => 3,
            ErrorCode::Protocol => 4,
            ErrorCode::Internal => 5,
            ErrorCode::Unknown(other) => other,
        }
    }
}

/// The outcome of a mainline DHT request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DhtStatus {
    /// The request succeeded.
    Ok,
    /// The relay's policy refused the request.
    Denied,
    /// The request failed.
    Failed,
    /// The relay does not offer the DHT service.
    Unavailable,
    /// A status this version does not know.
    ///
    /// Produced when decoding. Do not construct it with the value of a known status.
    Unknown(u8),
}

impl From<u8> for DhtStatus {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Ok,
            1 => Self::Denied,
            2 => Self::Failed,
            3 => Self::Unavailable,
            other => Self::Unknown(other),
        }
    }
}

impl From<DhtStatus> for u8 {
    fn from(value: DhtStatus) -> Self {
        match value {
            DhtStatus::Ok => 0,
            DhtStatus::Denied => 1,
            DhtStatus::Failed => 2,
            DhtStatus::Unavailable => 3,
            DhtStatus::Unknown(other) => other,
        }
    }
}

mod control_type {
    pub(super) const AUTH: u8 = 0;
    pub(super) const ALLOCATED: u8 = 1;
    pub(super) const ERROR: u8 = 2;
    pub(super) const PING: u8 = 3;
    pub(super) const PONG: u8 = 4;
    pub(super) const DHT_ANNOUNCE: u8 = 5;
    pub(super) const DHT_ANNOUNCE_RESULT: u8 = 6;
    pub(super) const DHT_STOP: u8 = 7;
    pub(super) const DHT_FIND_PEERS: u8 = 8;
    pub(super) const DHT_PEERS: u8 = 9;
    pub(super) const DHT_FIND_PEERS_DONE: u8 = 10;
}

/// A control message from a client to the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientControl {
    /// Presents the client's credentials.
    ///
    /// This must be the first message on the control channel and must not be sent again.
    /// The relay answers with [`RelayControl::Allocated`] or [`RelayControl::Error`].
    Auth {
        /// Opaque credentials, interpreted by the relay's authenticator.
        credentials: Bytes,
    },
    /// Asks the relay to answer with a [`RelayControl::Pong`].
    Ping(PingPayload),
    /// Answers a [`RelayControl::Ping`].
    Pong(PingPayload),
    /// Asks the relay to announce the client's allocated port for an infohash, and to keep
    /// refreshing the announcement.
    DhtAnnounce {
        /// The infohash to announce.
        info_hash: InfoHash,
    },
    /// Asks the relay to stop refreshing the announcement for an infohash.
    DhtStop {
        /// The infohash to stop announcing.
        info_hash: InfoHash,
    },
    /// Asks the relay to look up the peers of an infohash.
    DhtFindPeers {
        /// Chosen by the client, echoed in the answers.
        request_id: u32,
        /// The infohash to look up.
        info_hash: InfoHash,
    },
}

/// A control message from the relay to a client.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RelayControl {
    /// The client is authenticated and owns this public address.
    Allocated {
        /// The public address of the client's allocation.
        addr: SocketAddrV4,
    },
    /// The relay refused a request. The relay closes the control channel afterwards.
    Error {
        /// Why the relay refused.
        code: ErrorCode,
        /// A human readable explanation, possibly empty.
        reason: String,
    },
    /// Asks the client to answer with a [`ClientControl::Pong`].
    Ping(PingPayload),
    /// Answers a [`ClientControl::Ping`].
    Pong(PingPayload),
    /// The outcome of a [`ClientControl::DhtAnnounce`].
    DhtAnnounceResult {
        /// The infohash of the request.
        info_hash: InfoHash,
        /// Whether the infohash is announced.
        status: DhtStatus,
    },
    /// Peers found for a [`ClientControl::DhtFindPeers`]. Sent as they arrive.
    DhtPeers {
        /// The id of the request.
        request_id: u32,
        /// At most [`MAX_DHT_PEERS_PER_FRAME`] peer addresses. More peers are sent in
        /// further messages.
        peers: Vec<SocketAddrV4>,
    },
    /// A [`ClientControl::DhtFindPeers`] is finished, no more peers follow.
    DhtFindPeersDone {
        /// The id of the request.
        request_id: u32,
        /// How the lookup ended.
        status: DhtStatus,
    },
}

/// A message from a client to the relay on the control channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientFrame {
    /// A QUIC packet to send from the client's allocation to the remote party.
    Datagram(Datagram),
    /// A control message.
    Control(ClientControl),
}

/// A message from the relay to a client on the control channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayFrame {
    /// A QUIC packet the remote party sent to the client's allocation.
    Datagram(Datagram),
    /// A control message.
    Control(RelayControl),
}

/// Capacity reserved up front for a control message, enough for all fixed-size ones.
const CONTROL_RESERVE: usize = 32;

fn put_socket_addr(dst: &mut BytesMut, addr: &SocketAddrV4) {
    dst.put_slice(&addr.ip().octets());
    dst.put_u16(addr.port());
}

fn get_socket_addr(src: &mut Bytes) -> Result<SocketAddrV4, DecodeError> {
    ensure!(src.len() >= 6, DecodeError::TooShort);
    let ip = Ipv4Addr::from(src.get_u32());
    Ok(SocketAddrV4::new(ip, src.get_u16()))
}

fn get_array<const N: usize>(src: &mut Bytes) -> Result<[u8; N], DecodeError> {
    ensure!(src.len() >= N, DecodeError::TooShort);
    let mut out = [0u8; N];
    src.copy_to_slice(&mut out);
    Ok(out)
}

fn get_u8(src: &mut Bytes) -> Result<u8, DecodeError> {
    ensure!(!src.is_empty(), DecodeError::TooShort);
    Ok(src.get_u8())
}

fn get_u16(src: &mut Bytes) -> Result<u16, DecodeError> {
    ensure!(src.len() >= 2, DecodeError::TooShort);
    Ok(src.get_u16())
}

fn get_u32(src: &mut Bytes) -> Result<u32, DecodeError> {
    ensure!(src.len() >= 4, DecodeError::TooShort);
    Ok(src.get_u32())
}

fn expect_end(src: &Bytes) -> Result<(), DecodeError> {
    ensure!(
        src.is_empty(),
        DecodeError::TrailingBytes { len: src.len() }
    );
    Ok(())
}

/// Returns the longest prefix of `s` that is at most `max` bytes long.
fn truncate_str(s: &str, max: usize) -> &str {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

impl ClientControl {
    fn write_to(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.reserve(CONTROL_RESERVE);
        dst.put_u8(Flags::CONTROL);
        match self {
            Self::Auth { credentials } => {
                ensure!(
                    credentials.len() <= MAX_CREDENTIALS_LEN,
                    EncodeError::CredentialsTooLarge {
                        len: credentials.len()
                    }
                );
                dst.reserve(1 + credentials.len());
                dst.put_u8(control_type::AUTH);
                dst.put_slice(credentials);
            }
            Self::Ping(payload) => {
                dst.put_u8(control_type::PING);
                dst.put_slice(payload);
            }
            Self::Pong(payload) => {
                dst.put_u8(control_type::PONG);
                dst.put_slice(payload);
            }
            Self::DhtAnnounce { info_hash } => {
                dst.put_u8(control_type::DHT_ANNOUNCE);
                dst.put_slice(info_hash);
            }
            Self::DhtStop { info_hash } => {
                dst.put_u8(control_type::DHT_STOP);
                dst.put_slice(info_hash);
            }
            Self::DhtFindPeers {
                request_id,
                info_hash,
            } => {
                dst.put_u8(control_type::DHT_FIND_PEERS);
                dst.put_u32(*request_id);
                dst.put_slice(info_hash);
            }
        }
        Ok(())
    }

    /// Parses a control message, `bytes` starts after the flags byte.
    fn parse(mut bytes: Bytes) -> Result<Self, DecodeError> {
        let ty = get_u8(&mut bytes)?;
        let msg = match ty {
            control_type::AUTH => {
                ensure!(
                    bytes.len() <= MAX_CREDENTIALS_LEN,
                    DecodeError::FieldTooLarge { len: bytes.len() }
                );
                return Ok(Self::Auth { credentials: bytes });
            }
            control_type::PING => Self::Ping(get_array(&mut bytes)?),
            control_type::PONG => Self::Pong(get_array(&mut bytes)?),
            control_type::DHT_ANNOUNCE => Self::DhtAnnounce {
                info_hash: get_array(&mut bytes)?,
            },
            control_type::DHT_STOP => Self::DhtStop {
                info_hash: get_array(&mut bytes)?,
            },
            control_type::DHT_FIND_PEERS => Self::DhtFindPeers {
                request_id: get_u32(&mut bytes)?,
                info_hash: get_array(&mut bytes)?,
            },
            ty => return Err(e!(DecodeError::UnknownControl { ty })),
        };
        expect_end(&bytes)?;
        Ok(msg)
    }
}

impl RelayControl {
    fn write_to(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.reserve(CONTROL_RESERVE);
        dst.put_u8(Flags::CONTROL);
        match self {
            Self::Allocated { addr } => {
                dst.put_u8(control_type::ALLOCATED);
                put_socket_addr(dst, addr);
            }
            Self::Error { code, reason } => {
                dst.put_u8(control_type::ERROR);
                dst.put_u8((*code).into());
                dst.put_slice(truncate_str(reason, MAX_REASON_LEN).as_bytes());
            }
            Self::Ping(payload) => {
                dst.put_u8(control_type::PING);
                dst.put_slice(payload);
            }
            Self::Pong(payload) => {
                dst.put_u8(control_type::PONG);
                dst.put_slice(payload);
            }
            Self::DhtAnnounceResult { info_hash, status } => {
                dst.put_u8(control_type::DHT_ANNOUNCE_RESULT);
                dst.put_slice(info_hash);
                dst.put_u8((*status).into());
            }
            Self::DhtPeers { request_id, peers } => {
                dst.put_u8(control_type::DHT_PEERS);
                dst.put_u32(*request_id);
                ensure!(
                    peers.len() <= MAX_DHT_PEERS_PER_FRAME,
                    EncodeError::TooManyPeers { len: peers.len() }
                );
                dst.reserve(6 + 6 * peers.len());
                dst.put_u16(peers.len() as u16);
                for peer in peers {
                    put_socket_addr(dst, peer);
                }
            }
            Self::DhtFindPeersDone { request_id, status } => {
                dst.put_u8(control_type::DHT_FIND_PEERS_DONE);
                dst.put_u32(*request_id);
                dst.put_u8((*status).into());
            }
        }
        Ok(())
    }

    /// Parses a control message, `bytes` starts after the flags byte.
    fn parse(mut bytes: Bytes) -> Result<Self, DecodeError> {
        let ty = get_u8(&mut bytes)?;
        let msg = match ty {
            control_type::ALLOCATED => Self::Allocated {
                addr: get_socket_addr(&mut bytes)?,
            },
            control_type::ERROR => {
                let code = get_u8(&mut bytes)?.into();
                ensure!(
                    bytes.len() <= MAX_REASON_LEN,
                    DecodeError::FieldTooLarge { len: bytes.len() }
                );
                // Invalid UTF-8 is replaced, which can lengthen the reason.
                let reason = String::from_utf8_lossy(&bytes);
                let reason = truncate_str(&reason, MAX_REASON_LEN).to_string();
                return Ok(Self::Error { code, reason });
            }
            control_type::PING => Self::Ping(get_array(&mut bytes)?),
            control_type::PONG => Self::Pong(get_array(&mut bytes)?),
            control_type::DHT_ANNOUNCE_RESULT => Self::DhtAnnounceResult {
                info_hash: get_array(&mut bytes)?,
                status: get_u8(&mut bytes)?.into(),
            },
            control_type::DHT_PEERS => {
                let request_id = get_u32(&mut bytes)?;
                let count = usize::from(get_u16(&mut bytes)?);
                ensure!(
                    count <= MAX_DHT_PEERS_PER_FRAME,
                    DecodeError::FieldTooLarge { len: count }
                );
                let mut peers = Vec::with_capacity(count);
                for _ in 0..count {
                    peers.push(get_socket_addr(&mut bytes)?);
                }
                Self::DhtPeers { request_id, peers }
            }
            control_type::DHT_FIND_PEERS_DONE => Self::DhtFindPeersDone {
                request_id: get_u32(&mut bytes)?,
                status: get_u8(&mut bytes)?.into(),
            },
            ty => return Err(e!(DecodeError::UnknownControl { ty })),
        };
        expect_end(&bytes)?;
        Ok(msg)
    }
}

macro_rules! impl_frame {
    ($frame:ident, $control:ident) => {
        impl $frame {
            /// Encodes the frame into one WebSocket message.
            ///
            /// Fails if the frame exceeds a limit the receiver enforces.
            pub fn to_bytes(&self) -> Result<Bytes, EncodeError> {
                let mut dst = BytesMut::new();
                match self {
                    Self::Datagram(datagram) => datagram.write_to(&mut dst)?,
                    Self::Control(control) => control.write_to(&mut dst)?,
                }
                Ok(dst.freeze())
            }

            /// Decodes one WebSocket message.
            ///
            /// The payload of a datagram is a view into `bytes`, it is not copied.
            pub fn from_bytes(mut bytes: Bytes) -> Result<Self, DecodeError> {
                ensure!(!bytes.is_empty(), DecodeError::TooShort);
                let flags = Flags::parse(bytes.get_u8())?;
                if flags.is_control() {
                    Ok(Self::Control($control::parse(bytes)?))
                } else {
                    Ok(Self::Datagram(Datagram::parse(flags, bytes)?))
                }
            }
        }

        impl From<Datagram> for $frame {
            fn from(datagram: Datagram) -> Self {
                Self::Datagram(datagram)
            }
        }

        impl From<$control> for $frame {
            fn from(control: $control) -> Self {
                Self::Control(control)
            }
        }
    };
}

impl_frame!(ClientFrame, ClientControl);
impl_frame!(RelayFrame, RelayControl);

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn socket_addr() -> impl Strategy<Value = SocketAddrV4> {
        (any::<[u8; 4]>(), any::<u16>())
            .prop_map(|(ip, port)| SocketAddrV4::new(Ipv4Addr::from(ip), port))
    }

    fn datagram() -> impl Strategy<Value = Datagram> {
        (
            socket_addr(),
            any::<bool>(),
            prop::collection::vec(any::<u8>(), 0..2048),
        )
            .prop_map(|(addr, tunnel, payload)| Datagram {
                remote: RemoteAddr { addr, tunnel },
                payload: payload.into(),
            })
    }

    fn client_control() -> impl Strategy<Value = ClientControl> {
        prop_oneof![
            prop::collection::vec(any::<u8>(), 0..512).prop_map(|c| ClientControl::Auth {
                credentials: c.into()
            }),
            any::<PingPayload>().prop_map(ClientControl::Ping),
            any::<PingPayload>().prop_map(ClientControl::Pong),
            any::<InfoHash>().prop_map(|info_hash| ClientControl::DhtAnnounce { info_hash }),
            any::<InfoHash>().prop_map(|info_hash| ClientControl::DhtStop { info_hash }),
            (any::<u32>(), any::<InfoHash>()).prop_map(|(request_id, info_hash)| {
                ClientControl::DhtFindPeers {
                    request_id,
                    info_hash,
                }
            }),
        ]
    }

    fn relay_control() -> impl Strategy<Value = RelayControl> {
        prop_oneof![
            socket_addr().prop_map(|addr| RelayControl::Allocated { addr }),
            (any::<u8>(), ".{0,64}").prop_map(|(code, reason)| RelayControl::Error {
                code: code.into(),
                reason
            }),
            any::<PingPayload>().prop_map(RelayControl::Ping),
            any::<PingPayload>().prop_map(RelayControl::Pong),
            (any::<InfoHash>(), any::<u8>()).prop_map(|(info_hash, status)| {
                RelayControl::DhtAnnounceResult {
                    info_hash,
                    status: status.into(),
                }
            }),
            (any::<u32>(), prop::collection::vec(socket_addr(), 0..32))
                .prop_map(|(request_id, peers)| RelayControl::DhtPeers { request_id, peers }),
            (any::<u32>(), any::<u8>()).prop_map(|(request_id, status)| {
                RelayControl::DhtFindPeersDone {
                    request_id,
                    status: status.into(),
                }
            }),
        ]
    }

    proptest! {
        #[test]
        fn client_frame_round_trip(
            frame in prop_oneof![
                datagram().prop_map(ClientFrame::Datagram),
                client_control().prop_map(ClientFrame::Control),
            ]
        ) {
            let decoded = ClientFrame::from_bytes(frame.to_bytes().unwrap()).unwrap();
            prop_assert_eq!(decoded, frame);
        }

        #[test]
        fn relay_frame_round_trip(
            frame in prop_oneof![
                datagram().prop_map(RelayFrame::Datagram),
                relay_control().prop_map(RelayFrame::Control),
            ]
        ) {
            let decoded = RelayFrame::from_bytes(frame.to_bytes().unwrap()).unwrap();
            prop_assert_eq!(decoded, frame);
        }

        /// Decoding arbitrary bytes never panics.
        #[test]
        fn decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
            let bytes = Bytes::from(bytes);
            let _ = ClientFrame::from_bytes(bytes.clone());
            let _ = RelayFrame::from_bytes(bytes);
        }
    }

    #[test]
    fn datagram_layout() {
        let frame = ClientFrame::Datagram(Datagram {
            remote: RemoteAddr::tunnel(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 7), 0x1234)),
            payload: Bytes::from_static(b"quic"),
        });
        assert_eq!(
            &frame.to_bytes().unwrap()[..],
            &[0x01, 192, 0, 2, 7, 0x12, 0x34, b'q', b'u', b'i', b'c']
        );

        let frame = RelayFrame::Datagram(Datagram {
            remote: RemoteAddr::udp(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 7), 443)),
            payload: Bytes::new(),
        });
        assert_eq!(
            &frame.to_bytes().unwrap()[..],
            &[0x00, 192, 0, 2, 7, 0x01, 0xbb]
        );
    }

    #[test]
    fn rejects_malformed() {
        let decode = |bytes: &'static [u8]| ClientFrame::from_bytes(Bytes::from_static(bytes));
        assert!(matches!(decode(&[]), Err(DecodeError::TooShort { .. })));
        // A datagram header that is cut short.
        assert!(matches!(
            decode(&[0x00, 192, 0, 2, 7, 0x01]),
            Err(DecodeError::TooShort { .. })
        ));
        // Reserved flag bits.
        assert!(matches!(
            decode(&[0x02, 192, 0, 2, 7, 0x01, 0xbb]),
            Err(DecodeError::ReservedFlags { .. })
        ));
        // The tunnel flag makes no sense on a control message.
        assert!(matches!(
            decode(&[0x81, control_type::PING, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(DecodeError::ReservedFlags { .. })
        ));
        assert!(matches!(
            decode(&[0x80, 0xff]),
            Err(DecodeError::UnknownControl { ty: 0xff, .. })
        ));
        // A ping with a short and with a long payload.
        assert!(matches!(
            decode(&[0x80, control_type::PING, 0, 0, 0]),
            Err(DecodeError::TooShort { .. })
        ));
        assert!(matches!(
            decode(&[0x80, control_type::PING, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(DecodeError::TrailingBytes { len: 1, .. })
        ));
        // A message type only the relay sends.
        assert!(matches!(
            decode(&[0x80, control_type::ALLOCATED, 192, 0, 2, 7, 0x01, 0xbb]),
            Err(DecodeError::UnknownControl { .. })
        ));
    }

    #[test]
    fn enforces_size_limits() {
        let mut bytes = vec![0u8; DATAGRAM_HEADER_LEN + MAX_PACKET_SIZE];
        assert!(ClientFrame::from_bytes(Bytes::from(bytes.clone())).is_ok());
        bytes.push(0);
        assert!(matches!(
            ClientFrame::from_bytes(Bytes::from(bytes)),
            Err(DecodeError::PacketTooLarge { .. })
        ));

        let mut bytes = vec![Flags::CONTROL, control_type::AUTH];
        bytes.extend(std::iter::repeat_n(0u8, MAX_CREDENTIALS_LEN + 1));
        assert!(matches!(
            ClientFrame::from_bytes(Bytes::from(bytes)),
            Err(DecodeError::FieldTooLarge { .. })
        ));
    }

    #[test]
    fn truncates_long_fields() {
        let reason = "é".repeat(MAX_REASON_LEN);
        let frame = RelayFrame::Control(RelayControl::Error {
            code: ErrorCode::Internal,
            reason,
        });
        let RelayFrame::Control(RelayControl::Error { reason, .. }) =
            RelayFrame::from_bytes(frame.to_bytes().unwrap()).unwrap()
        else {
            panic!("wrong frame");
        };
        assert_eq!(reason, "é".repeat(MAX_REASON_LEN / 2));

        // Invalid UTF-8 grows when replaced, the decoded reason stays bounded.
        let mut bytes = vec![Flags::CONTROL, control_type::ERROR, 5];
        bytes.extend(std::iter::repeat_n(0xffu8, MAX_REASON_LEN));
        let RelayFrame::Control(RelayControl::Error { reason, .. }) =
            RelayFrame::from_bytes(Bytes::from(bytes)).unwrap()
        else {
            panic!("wrong frame");
        };
        assert!(reason.len() <= MAX_REASON_LEN);
    }

    #[test]
    fn encoding_enforces_the_receivers_limits() {
        let remote = RemoteAddr::udp(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1));
        let datagram = |len| {
            ClientFrame::Datagram(Datagram {
                remote,
                payload: vec![0u8; len].into(),
            })
        };
        assert!(datagram(MAX_PACKET_SIZE).to_bytes().is_ok());
        assert!(matches!(
            datagram(MAX_PACKET_SIZE + 1).to_bytes(),
            Err(EncodeError::PacketTooLarge { .. })
        ));

        let auth = |len| {
            ClientFrame::Control(ClientControl::Auth {
                credentials: vec![0u8; len].into(),
            })
        };
        assert!(auth(MAX_CREDENTIALS_LEN).to_bytes().is_ok());
        assert!(matches!(
            auth(MAX_CREDENTIALS_LEN + 1).to_bytes(),
            Err(EncodeError::CredentialsTooLarge { .. })
        ));

        let peers = |len| {
            RelayFrame::Control(RelayControl::DhtPeers {
                request_id: 1,
                peers: vec![remote.addr; len],
            })
        };
        let full = peers(MAX_DHT_PEERS_PER_FRAME);
        assert_eq!(
            RelayFrame::from_bytes(full.to_bytes().unwrap()).unwrap(),
            full
        );
        assert!(matches!(
            peers(MAX_DHT_PEERS_PER_FRAME + 1).to_bytes(),
            Err(EncodeError::TooManyPeers { .. })
        ));
    }

    #[test]
    fn unknown_control_is_distinguishable() {
        let err = RelayFrame::from_bytes(Bytes::from_static(&[0x80, 0xff])).unwrap_err();
        assert!(err.is_unknown_control());
        let err = RelayFrame::from_bytes(Bytes::from_static(&[0x80])).unwrap_err();
        assert!(!err.is_unknown_control());
    }
}
