//! Policy deciding which packets the relay forwards.
//!
//! The relay carries traffic for strangers in both directions. Which of it to forward is
//! the relay operator's decision and sits behind the [`TrafficPolicy`] trait.

use std::{collections::HashMap, num::NonZeroU64, time::Duration};

use n0_future::time::Instant;

use super::ClientId;
use crate::protos::relay::RemoteAddr;

/// The direction of a packet through the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// From a remote party to the client that owns the allocation.
    Inbound,
    /// From the client that owns the allocation to a remote party.
    Outbound,
}

/// A packet the relay is about to forward.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Packet<'a> {
    /// The direction of the packet.
    pub direction: Direction,
    /// The remote party: the sender of an inbound packet, the destination of an outbound
    /// one.
    pub remote: RemoteAddr,
    /// The QUIC packet. The relay can not decrypt it, only its unprotected header bits
    /// and its length mean anything.
    pub payload: &'a [u8],
    /// The time the relay handled the packet.
    pub now: Instant,
}

/// What to do with a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Forward the packet.
    Forward,
    /// Drop the packet silently.
    Drop,
}

/// Creates the per-allocation policies of a relay.
pub trait TrafficPolicy: std::fmt::Debug + Send + Sync + 'static {
    /// Creates the policy for the allocation of `identity`.
    ///
    /// Called when the allocation is created. The returned policy lives as long as the
    /// allocation, including the release timeout after the client disconnected, and
    /// across reconnects of the client within it.
    fn allocation(&self, identity: &ClientId) -> Box<dyn AllocationPolicy>;
}

/// Decides which packets of one allocation are forwarded.
///
/// [`Self::check`] runs for every packet in both directions while the relay holds a lock
/// on the policy. It must be cheap and must not block.
pub trait AllocationPolicy: std::fmt::Debug + Send + 'static {
    /// Returns whether to forward `packet`.
    fn check(&mut self, packet: &Packet<'_>) -> Verdict;
}

/// A [`TrafficPolicy`] that forwards every packet.
///
/// This turns the relay into an open UDP proxy for its clients. Use it for tests only.
#[derive(Debug, Clone, Copy, Default)]
pub struct ForwardAll;

impl TrafficPolicy for ForwardAll {
    fn allocation(&self, _identity: &ClientId) -> Box<dyn AllocationPolicy> {
        Box::new(ForwardAll)
    }
}

impl AllocationPolicy for ForwardAll {
    fn check(&mut self, _packet: &Packet<'_>) -> Verdict {
        Verdict::Forward
    }
}

/// The default time a client may send to a remote party after it last heard from it.
pub const DEFAULT_REPLY_WINDOW: Duration = Duration::from_secs(120);

/// The default number of remote parties tracked per allocation.
pub const DEFAULT_MAX_REMOTES: usize = 1024;

/// The default rate limit of an allocation, per direction: 2 MiB per second.
pub const DEFAULT_BYTES_PER_SECOND: u64 = 2 * 1024 * 1024;

/// The smallest QUIC packet that may carry a client's first Initial, see RFC 9000
/// section 14.1.
const MIN_INITIAL_SIZE: usize = 1200;

/// The smallest burst a rate limit allows, so that a packet of any forwarded size fits.
const MIN_BURST_BYTES: u64 = 64 * 1024;

/// How often the table of remote parties is searched for expired entries when it is full.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(1);

/// A limit on the bytes forwarded for one allocation in one direction.
///
/// This is a token bucket. Packets that exceed the limit are dropped, which the QUIC
/// endpoints see as loss and respond to by slowing down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    /// The sustained rate in bytes per second.
    pub bytes_per_second: NonZeroU64,
    /// How many bytes may be forwarded at once after a quiet period.
    ///
    /// Values below 64 KiB are raised to 64 KiB, so that a packet of any size the relay
    /// forwards fits.
    pub burst_bytes: u64,
}

impl RateLimit {
    /// Creates a limit of `bytes_per_second` with a burst of one second's worth.
    pub fn new(bytes_per_second: NonZeroU64) -> Self {
        Self {
            bytes_per_second,
            burst_bytes: bytes_per_second.get(),
        }
    }
}

/// Configuration of the [`DefaultPolicy`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DefaultPolicyConfig {
    /// How long after a remote party last sent to the allocation the client may send to
    /// it. Defaults to [`DEFAULT_REPLY_WINDOW`].
    ///
    /// A client can only send to remote parties that recently sent to its port. This
    /// keeps the client from using the relay as a general UDP proxy.
    pub reply_window: Duration,
    /// How many remote parties are tracked per allocation. Defaults to
    /// [`DEFAULT_MAX_REMOTES`].
    ///
    /// Packets of further remote parties are dropped until tracked ones expire.
    pub max_remotes: usize,
    /// Whether the first packet of a remote party must look like the start of a QUIC
    /// connection: a long header packet of at least 1200 bytes. Defaults to `true`.
    ///
    /// This makes it more expensive to flood the allocation from spoofed addresses. The
    /// price is that a dialer whose address changes mid-connection, for example because
    /// its NAT rebinds, can not continue the connection through the relay: the first
    /// packet from its new address is not an Initial. The connection then times out and
    /// the dialer has to connect again.
    pub require_initial: bool,
    /// The limit on bytes forwarded to the client. Defaults to
    /// [`DEFAULT_BYTES_PER_SECOND`]. `None` means unlimited.
    pub inbound: Option<RateLimit>,
    /// The limit on bytes forwarded from the client. Defaults to
    /// [`DEFAULT_BYTES_PER_SECOND`]. `None` means unlimited.
    pub outbound: Option<RateLimit>,
}

impl Default for DefaultPolicyConfig {
    fn default() -> Self {
        let limit = NonZeroU64::new(DEFAULT_BYTES_PER_SECOND).map(RateLimit::new);
        Self {
            reply_window: DEFAULT_REPLY_WINDOW,
            max_remotes: DEFAULT_MAX_REMOTES,
            require_initial: true,
            inbound: limit,
            outbound: limit,
        }
    }
}

/// The [`TrafficPolicy`] a relay should run with unless it has a reason not to.
///
/// - A client may only send to remote parties that recently sent to its port.
/// - The first packet of a remote party must look like the start of a QUIC connection.
/// - The bytes forwarded per allocation are limited in each direction.
///
/// See [`DefaultPolicyConfig`] for the details and how to tune them.
#[derive(Debug, Clone, Default)]
pub struct DefaultPolicy {
    config: DefaultPolicyConfig,
}

impl DefaultPolicy {
    /// Creates the policy.
    pub fn new(config: DefaultPolicyConfig) -> Self {
        Self { config }
    }
}

impl TrafficPolicy for DefaultPolicy {
    fn allocation(&self, _identity: &ClientId) -> Box<dyn AllocationPolicy> {
        Box::new(DefaultAllocationPolicy {
            remotes: HashMap::new(),
            last_cleanup: None,
            inbound: self.config.inbound.map(TokenBucket::new),
            outbound: self.config.outbound.map(TokenBucket::new),
            config: self.config.clone(),
        })
    }
}

#[derive(Debug)]
struct DefaultAllocationPolicy {
    config: DefaultPolicyConfig,
    /// The remote parties and when each last sent to the allocation.
    remotes: HashMap<RemoteAddr, Instant>,
    /// When expired remote parties were last removed because the table was full.
    last_cleanup: Option<Instant>,
    inbound: Option<TokenBucket>,
    outbound: Option<TokenBucket>,
}

impl DefaultAllocationPolicy {
    /// Returns whether `remote` sent to the allocation within the reply window.
    fn is_recent(&self, remote: &RemoteAddr, now: Instant) -> bool {
        self.remotes
            .get(remote)
            .is_some_and(|seen| now.saturating_duration_since(*seen) <= self.config.reply_window)
    }

    /// Makes room for a new remote party, returns whether there is room.
    fn make_room(&mut self, now: Instant) -> bool {
        if self.remotes.len() < self.config.max_remotes {
            return true;
        }
        // Searching the table costs time proportional to its size. Do not let a flood of
        // new remote parties trigger it for every packet.
        if self
            .last_cleanup
            .is_some_and(|last| now.saturating_duration_since(last) < CLEANUP_INTERVAL)
        {
            return false;
        }
        self.last_cleanup = Some(now);
        let window = self.config.reply_window;
        self.remotes
            .retain(|_, seen| now.saturating_duration_since(*seen) <= window);
        self.remotes.len() < self.config.max_remotes
    }

    fn check_inbound(&mut self, packet: &Packet<'_>) -> Verdict {
        let known = self.is_recent(&packet.remote, packet.now);
        if !known {
            if self.config.require_initial && !looks_like_initial(packet.payload) {
                return Verdict::Drop;
            }
            if !self.make_room(packet.now) {
                return Verdict::Drop;
            }
        }
        if let Some(bucket) = &mut self.inbound
            && !bucket.take(packet.payload.len(), packet.now)
        {
            return Verdict::Drop;
        }
        self.remotes.insert(packet.remote, packet.now);
        Verdict::Forward
    }

    fn check_outbound(&mut self, packet: &Packet<'_>) -> Verdict {
        if !self.is_recent(&packet.remote, packet.now) {
            return Verdict::Drop;
        }
        if let Some(bucket) = &mut self.outbound
            && !bucket.take(packet.payload.len(), packet.now)
        {
            return Verdict::Drop;
        }
        Verdict::Forward
    }
}

impl AllocationPolicy for DefaultAllocationPolicy {
    fn check(&mut self, packet: &Packet<'_>) -> Verdict {
        match packet.direction {
            Direction::Inbound => self.check_inbound(packet),
            Direction::Outbound => self.check_outbound(packet),
        }
    }
}

/// Returns whether `payload` could be the first packet of a QUIC connection.
///
/// That is an Initial packet in a datagram of at least 1200 bytes. The packet type is
/// only checked for the QUIC versions whose encoding is known here. A long header packet
/// of another version passes, the client then answers it with a Version Negotiation
/// packet.
fn looks_like_initial(payload: &[u8]) -> bool {
    const QUIC_V1: u32 = 0x0000_0001;
    const QUIC_V2: u32 = 0x6b33_43cf;

    if payload.len() < MIN_INITIAL_SIZE {
        return false;
    }
    let first = payload[0];
    // The header form bit: long header.
    if first & 0x80 == 0 {
        return false;
    }
    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    let packet_type = (first & 0x30) >> 4;
    match version {
        QUIC_V1 => packet_type == 0b00,
        // RFC 9369 section 3.2
        QUIC_V2 => packet_type == 0b01,
        _ => true,
    }
}

/// A token bucket that takes the time as an argument.
#[derive(Debug)]
struct TokenBucket {
    bytes_per_second: u64,
    burst: u64,
    tokens: u64,
    /// The time up to which tokens were added.
    refilled: Option<Instant>,
}

impl TokenBucket {
    fn new(limit: RateLimit) -> Self {
        let burst = limit.burst_bytes.max(MIN_BURST_BYTES);
        Self {
            bytes_per_second: limit.bytes_per_second.get(),
            burst,
            tokens: burst,
            refilled: None,
        }
    }

    /// Takes `bytes` tokens, returns whether there were enough.
    fn take(&mut self, bytes: usize, now: Instant) -> bool {
        if let Some(refilled) = self.refilled {
            let elapsed = now.saturating_duration_since(refilled);
            let added = (elapsed.as_nanos() * u128::from(self.bytes_per_second) / 1_000_000_000)
                .min(u128::from(self.burst)) as u64;
            if added > 0 {
                self.tokens = self.tokens.saturating_add(added).min(self.burst);
                // Only advance by the time the added tokens account for, so that the
                // remainder is not lost to rounding.
                let consumed = Duration::from_nanos(
                    (u128::from(added) * 1_000_000_000 / u128::from(self.bytes_per_second))
                        .min(u128::from(u64::MAX)) as u64,
                );
                self.refilled = Some(if self.tokens == self.burst {
                    now
                } else {
                    refilled + consumed
                });
            }
        } else {
            self.refilled = Some(now);
        }
        let bytes = bytes as u64;
        if self.tokens >= bytes {
            self.tokens -= bytes;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::*;

    fn remote(n: u16) -> RemoteAddr {
        RemoteAddr::udp(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), n))
    }

    fn initial() -> Vec<u8> {
        let mut packet = vec![0u8; MIN_INITIAL_SIZE];
        packet[0] = 0xc0;
        packet[4] = 1;
        packet
    }

    fn policy(config: DefaultPolicyConfig) -> Box<dyn AllocationPolicy> {
        DefaultPolicy::new(config).allocation(&ClientId::new("bob"))
    }

    fn check(
        policy: &mut Box<dyn AllocationPolicy>,
        direction: Direction,
        remote: RemoteAddr,
        payload: &[u8],
        now: Instant,
    ) -> Verdict {
        policy.check(&Packet {
            direction,
            remote,
            payload,
            now,
        })
    }

    fn unlimited() -> DefaultPolicyConfig {
        DefaultPolicyConfig {
            inbound: None,
            outbound: None,
            ..Default::default()
        }
    }

    #[test]
    fn recognises_initial_packets() {
        assert!(looks_like_initial(&initial()));

        let mut short = initial();
        short.truncate(MIN_INITIAL_SIZE - 1);
        assert!(!looks_like_initial(&short));
        assert!(!looks_like_initial(&[]));

        // A short header packet.
        let mut packet = initial();
        packet[0] = 0x40;
        assert!(!looks_like_initial(&packet));

        // A version 1 Handshake packet.
        let mut packet = initial();
        packet[0] = 0xe0;
        assert!(!looks_like_initial(&packet));

        // Version 2 encodes the Initial type differently.
        let mut packet = initial();
        packet[1..5].copy_from_slice(&0x6b33_43cfu32.to_be_bytes());
        assert!(!looks_like_initial(&packet));
        packet[0] = 0xd0;
        assert!(looks_like_initial(&packet));

        // An unknown version passes, so that the client can negotiate the version.
        let mut packet = initial();
        packet[1..5].copy_from_slice(&0x0a0a_0a0au32.to_be_bytes());
        packet[0] = 0xf0;
        assert!(looks_like_initial(&packet));
    }

    #[test]
    fn client_can_only_reply() {
        let now = Instant::now();
        let mut policy = policy(unlimited());
        let alice = remote(1);

        // Bob can not send to somebody who never sent to him.
        assert_eq!(
            check(&mut policy, Direction::Outbound, alice, b"hi", now),
            Verdict::Drop
        );
        assert_eq!(
            check(&mut policy, Direction::Inbound, alice, &initial(), now),
            Verdict::Forward
        );
        assert_eq!(
            check(&mut policy, Direction::Outbound, alice, b"hi", now),
            Verdict::Forward
        );
        // The same address through the tunnel is a different remote party.
        let tunnelled = RemoteAddr::tunnel(alice.addr);
        assert_eq!(
            check(&mut policy, Direction::Outbound, tunnelled, b"hi", now),
            Verdict::Drop
        );

        // The window is counted from the last packet of the remote party.
        let later = now + DEFAULT_REPLY_WINDOW;
        assert_eq!(
            check(&mut policy, Direction::Outbound, alice, b"hi", later),
            Verdict::Forward
        );
        let too_late = later + Duration::from_millis(1);
        assert_eq!(
            check(&mut policy, Direction::Outbound, alice, b"hi", too_late),
            Verdict::Drop
        );
        // Sending does not extend the window, hearing from the remote party does.
        assert_eq!(
            check(&mut policy, Direction::Inbound, alice, &initial(), too_late),
            Verdict::Forward
        );
        assert_eq!(
            check(&mut policy, Direction::Outbound, alice, b"hi", too_late),
            Verdict::Forward
        );
    }

    #[test]
    fn first_packet_must_be_an_initial() {
        let now = Instant::now();
        let mut policy = policy(unlimited());
        let alice = remote(1);

        assert_eq!(
            check(&mut policy, Direction::Inbound, alice, b"not quic", now),
            Verdict::Drop
        );
        // A dropped packet does not make the remote party known.
        assert_eq!(
            check(&mut policy, Direction::Outbound, alice, b"hi", now),
            Verdict::Drop
        );
        assert_eq!(
            check(&mut policy, Direction::Inbound, alice, &initial(), now),
            Verdict::Forward
        );
        // Later packets of a known remote party can be anything.
        assert_eq!(
            check(&mut policy, Direction::Inbound, alice, b"short", now),
            Verdict::Forward
        );
        // Once the remote party has expired it has to start over.
        let expired = now + DEFAULT_REPLY_WINDOW + Duration::from_secs(1);
        assert_eq!(
            check(&mut policy, Direction::Inbound, alice, b"short", expired),
            Verdict::Drop
        );

        let mut config = unlimited();
        config.require_initial = false;
        let mut policy = super::tests::policy(config);
        assert_eq!(
            check(&mut policy, Direction::Inbound, alice, b"not quic", now),
            Verdict::Forward
        );
    }

    #[test]
    fn bounds_the_number_of_remote_parties() {
        let now = Instant::now();
        let mut config = unlimited();
        config.max_remotes = 2;
        let mut policy = policy(config);

        for n in 1..=2 {
            assert_eq!(
                check(&mut policy, Direction::Inbound, remote(n), &initial(), now),
                Verdict::Forward
            );
        }
        assert_eq!(
            check(&mut policy, Direction::Inbound, remote(3), &initial(), now),
            Verdict::Drop
        );
        // Known remote parties are not affected.
        assert_eq!(
            check(&mut policy, Direction::Inbound, remote(1), b"more", now),
            Verdict::Forward
        );

        // Expired remote parties make room for new ones.
        let later = now + DEFAULT_REPLY_WINDOW + Duration::from_secs(2);
        assert_eq!(
            check(
                &mut policy,
                Direction::Inbound,
                remote(3),
                &initial(),
                later
            ),
            Verdict::Forward
        );
        assert_eq!(
            check(
                &mut policy,
                Direction::Inbound,
                remote(4),
                &initial(),
                later
            ),
            Verdict::Forward
        );
        // The table is full again and was searched just now.
        assert_eq!(
            check(
                &mut policy,
                Direction::Inbound,
                remote(5),
                &initial(),
                later
            ),
            Verdict::Drop
        );
    }

    #[test]
    fn limits_the_rate_in_each_direction() {
        let now = Instant::now();
        let limit = RateLimit {
            bytes_per_second: NonZeroU64::new(MIN_BURST_BYTES).unwrap(),
            burst_bytes: 0,
        };
        let mut config = unlimited();
        config.inbound = Some(limit);
        config.outbound = Some(limit);
        let mut policy = policy(config);
        let alice = remote(1);
        let packet = initial();
        let per_burst = MIN_BURST_BYTES as usize / packet.len();

        // The burst, which is raised to the minimum, passes. Then packets are dropped.
        for _ in 0..per_burst {
            assert_eq!(
                check(&mut policy, Direction::Inbound, alice, &packet, now),
                Verdict::Forward
            );
        }
        assert_eq!(
            check(&mut policy, Direction::Inbound, alice, &packet, now),
            Verdict::Drop
        );
        // The directions are limited independently.
        assert_eq!(
            check(&mut policy, Direction::Outbound, alice, &packet, now),
            Verdict::Forward
        );

        // Half a second later half of the burst is available again.
        let later = now + Duration::from_millis(500);
        let mut forwarded = 0;
        while check(&mut policy, Direction::Inbound, alice, &packet, later) == Verdict::Forward {
            forwarded += 1;
        }
        assert!((per_burst / 2 - 1..=per_burst / 2 + 1).contains(&forwarded));
    }

    #[test]
    fn token_bucket_keeps_the_sustained_rate() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(RateLimit {
            bytes_per_second: NonZeroU64::new(100_000).unwrap(),
            burst_bytes: MIN_BURST_BYTES,
        });
        // Offer a 1000 byte packet every millisecond for ten seconds: ten times the rate.
        let mut passed = 0u64;
        for ms in 0..10_000 {
            if bucket.take(1000, start + Duration::from_millis(ms)) {
                passed += 1000;
            }
        }
        let expected = MIN_BURST_BYTES + 10 * 100_000;
        assert!(
            passed.abs_diff(expected) <= 2000,
            "passed {passed} bytes, expected about {expected}"
        );
    }
}
