//! Policy deciding which packets the relay forwards.
//!
//! The relay carries traffic for strangers in both directions. Which of it to forward is
//! the relay operator's decision and sits behind the [`TrafficPolicy`] trait.

use std::{collections::HashMap, num::NonZeroU64, time::Duration};

use n0_error::{ensure, stack_error};
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
    ///
    /// Only packets from the remote party extend the window. A connection through the
    /// relay on which the remote party is silent for longer than this is cut off, so the
    /// endpoints need a keep-alive interval, or an idle timeout, shorter than the window.
    /// Must not be zero.
    pub reply_window: Duration,
    /// How many remote parties are tracked per allocation. Defaults to
    /// [`DEFAULT_MAX_REMOTES`].
    ///
    /// When the table is full a new remote party replaces the one that was silent the
    /// longest, preferring those the client never answered. A flood of packets from
    /// spoofed addresses can therefore not keep new dialers out, but it can push out
    /// remote parties that have been quiet for a moment. Must not be zero.
    pub max_remotes: usize,
    /// Whether the first packet of a remote party must look like the start of a QUIC
    /// connection: a long header packet of at least 1200 bytes. Defaults to `true`.
    ///
    /// This makes it more expensive to flood the allocation from spoofed addresses: every
    /// packet has to be large. It does not stop a flood, the relay can not tell a real
    /// Initial from a made up one. The price is that a dialer whose address changes mid-connection, for example because
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

/// The configuration of a [`DefaultPolicy`] is not usable.
#[stack_error(derive, add_meta)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum InvalidPolicyConfig {
    #[error("reply_window must not be zero")]
    ZeroReplyWindow,
    #[error("max_remotes must not be zero")]
    ZeroMaxRemotes,
}

impl DefaultPolicy {
    /// Creates the policy.
    pub fn new(config: DefaultPolicyConfig) -> Result<Self, InvalidPolicyConfig> {
        ensure!(
            !config.reply_window.is_zero(),
            InvalidPolicyConfig::ZeroReplyWindow
        );
        ensure!(config.max_remotes > 0, InvalidPolicyConfig::ZeroMaxRemotes);
        Ok(Self { config })
    }
}

impl TrafficPolicy for DefaultPolicy {
    fn allocation(&self, _identity: &ClientId) -> Box<dyn AllocationPolicy> {
        Box::new(DefaultAllocationPolicy {
            remotes: HashMap::new(),
            inbound: self.config.inbound.map(TokenBucket::new),
            outbound: self.config.outbound.map(TokenBucket::new),
            config: self.config.clone(),
        })
    }
}

/// What the policy remembers about a remote party.
#[derive(Debug, Clone, Copy)]
struct Remote {
    /// When the remote party last sent to the allocation.
    seen: Instant,
    /// Whether the client ever sent to the remote party.
    answered: bool,
}

#[derive(Debug)]
struct DefaultAllocationPolicy {
    config: DefaultPolicyConfig,
    remotes: HashMap<RemoteAddr, Remote>,
    inbound: Option<TokenBucket>,
    outbound: Option<TokenBucket>,
}

impl DefaultAllocationPolicy {
    /// Returns whether `remote` sent to the allocation within the reply window.
    fn is_recent(&self, remote: &RemoteAddr, now: Instant) -> bool {
        self.remotes.get(remote).is_some_and(|remote| {
            now.saturating_duration_since(remote.seen) <= self.config.reply_window
        })
    }

    /// Makes room for one more remote party if the table is full.
    ///
    /// Removes the remote party that was silent the longest, preferring those the client
    /// never answered: a remote party that only ever sent, such as a spoofed address in a
    /// flood, goes before one the client is talking to.
    fn make_room(&mut self) {
        if self.remotes.len() < self.config.max_remotes {
            return;
        }
        let victim = self
            .remotes
            .iter()
            .min_by_key(|(_, remote)| (remote.answered, remote.seen))
            .map(|(addr, _)| *addr);
        if let Some(victim) = victim {
            self.remotes.remove(&victim);
        }
    }

    fn check_inbound(&mut self, packet: &Packet<'_>) -> Verdict {
        let known = self.is_recent(&packet.remote, packet.now);
        if !known && self.config.require_initial && !looks_like_initial(packet.payload) {
            return Verdict::Drop;
        }
        // The rate limit comes before the table of remote parties is touched. It bounds
        // how often a flood of new remote parties can make the table search for room.
        if let Some(bucket) = &mut self.inbound
            && !bucket.take(packet.payload.len(), packet.now)
        {
            return Verdict::Drop;
        }
        match self.remotes.get_mut(&packet.remote) {
            // Also a remote party whose window has passed: it starts over, but what the
            // client did before still counts.
            Some(remote) => remote.seen = packet.now,
            None => {
                self.make_room();
                self.remotes.insert(
                    packet.remote,
                    Remote {
                        seen: packet.now,
                        answered: false,
                    },
                );
            }
        }
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
        if let Some(remote) = self.remotes.get_mut(&packet.remote) {
            remote.answered = true;
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
/// packet. Version 0 marks a Version Negotiation packet itself, which never starts a
/// connection.
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
        0 => false,
        _ => true,
    }
}

/// A token bucket that takes the time as an argument.
///
/// Tokens are counted in units of a billionth of a byte. Refilling is then exact for
/// every rate: a nanosecond adds `bytes_per_second` units.
#[derive(Debug)]
struct TokenBucket {
    bytes_per_second: u128,
    burst: u128,
    tokens: u128,
    /// The time up to which tokens were added.
    refilled: Option<Instant>,
}

/// How many token units a byte costs.
const UNITS_PER_BYTE: u128 = 1_000_000_000;

impl TokenBucket {
    fn new(limit: RateLimit) -> Self {
        let burst = u128::from(limit.burst_bytes.max(MIN_BURST_BYTES)) * UNITS_PER_BYTE;
        Self {
            bytes_per_second: u128::from(limit.bytes_per_second.get()),
            burst,
            tokens: burst,
            refilled: None,
        }
    }

    /// Takes `bytes` tokens, returns whether there were enough.
    fn take(&mut self, bytes: usize, now: Instant) -> bool {
        if let Some(refilled) = self.refilled {
            let elapsed = now.saturating_duration_since(refilled).as_nanos();
            self.tokens = self
                .tokens
                .saturating_add(elapsed.saturating_mul(self.bytes_per_second))
                .min(self.burst);
        }
        // Time never moves backwards here, `saturating_duration_since` saw to that.
        if self.refilled.is_none_or(|refilled| now > refilled) {
            self.refilled = Some(now);
        }
        let cost = bytes as u128 * UNITS_PER_BYTE;
        if self.tokens >= cost {
            self.tokens -= cost;
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
        DefaultPolicy::new(config)
            .unwrap()
            .allocation(&ClientId::new("bob"))
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

        // A Version Negotiation packet does not start a connection.
        let mut packet = initial();
        packet[1..5].copy_from_slice(&[0; 4]);
        assert!(!looks_like_initial(&packet));
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
    fn full_table_replaces_the_quietest_remote_party() {
        let now = Instant::now();
        let mut config = unlimited();
        config.max_remotes = 3;
        let mut policy = policy(config);
        let at = |secs| now + Duration::from_secs(secs);
        let inbound = |policy: &mut Box<dyn AllocationPolicy>, n, secs| {
            check(policy, Direction::Inbound, remote(n), &initial(), at(secs))
        };
        let outbound = |policy: &mut Box<dyn AllocationPolicy>, n, secs| {
            check(policy, Direction::Outbound, remote(n), b"hi", at(secs))
        };

        // Three remote parties. The client answers the first, which is also the oldest.
        for n in 1..=3 {
            assert_eq!(inbound(&mut policy, n, u64::from(n)), Verdict::Forward);
        }
        assert_eq!(outbound(&mut policy, 1, 3), Verdict::Forward);

        // A fourth one is not kept out. It replaces the quietest one that was never
        // answered, which is the second.
        assert_eq!(inbound(&mut policy, 4, 4), Verdict::Forward);
        assert_eq!(outbound(&mut policy, 2, 4), Verdict::Drop);
        assert_eq!(outbound(&mut policy, 1, 4), Verdict::Forward);
        assert_eq!(outbound(&mut policy, 3, 4), Verdict::Forward);
        assert_eq!(outbound(&mut policy, 4, 4), Verdict::Forward);

        // Now all were answered. The next one replaces the quietest of them.
        assert_eq!(inbound(&mut policy, 5, 5), Verdict::Forward);
        assert_eq!(outbound(&mut policy, 1, 5), Verdict::Drop);
        assert_eq!(outbound(&mut policy, 3, 5), Verdict::Forward);
    }

    #[test]
    fn flood_does_not_keep_dialers_out() {
        let now = Instant::now();
        let mut config = unlimited();
        config.max_remotes = 8;
        let mut policy = policy(config);

        // A flood from spoofed addresses fills the table many times over.
        for n in 0..1000u16 {
            assert_eq!(
                check(
                    &mut policy,
                    Direction::Inbound,
                    remote(1000 + n),
                    &initial(),
                    now
                ),
                Verdict::Forward
            );
            // A dialer that shows up in the middle of it gets in and stays in, since the
            // client answers it.
            if n == 500 {
                assert_eq!(
                    check(&mut policy, Direction::Inbound, remote(1), &initial(), now),
                    Verdict::Forward
                );
                assert_eq!(
                    check(&mut policy, Direction::Outbound, remote(1), b"hi", now),
                    Verdict::Forward
                );
            }
        }
        assert_eq!(
            check(&mut policy, Direction::Outbound, remote(1), b"hi", now),
            Verdict::Forward
        );
        assert_eq!(
            check(&mut policy, Direction::Inbound, remote(2), &initial(), now),
            Verdict::Forward
        );
    }

    #[test]
    fn rejects_unusable_config() {
        let config = DefaultPolicyConfig {
            max_remotes: 0,
            ..Default::default()
        };
        assert!(DefaultPolicy::new(config).is_err());
        let config = DefaultPolicyConfig {
            reply_window: Duration::ZERO,
            ..Default::default()
        };
        assert!(DefaultPolicy::new(config).is_err());
        assert!(DefaultPolicy::new(DefaultPolicyConfig::default()).is_ok());
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

    #[test]
    fn token_bucket_is_exact_for_very_high_rates() {
        let start = Instant::now();
        let rate = 1_500_000_000u64;
        let mut bucket = TokenBucket::new(RateLimit {
            bytes_per_second: NonZeroU64::new(rate).unwrap(),
            burst_bytes: MIN_BURST_BYTES,
        });
        // Empty the bucket, then ask for a byte every nanosecond. At this rate one and a
        // half bytes arrive per nanosecond, so every request is granted, and asking for
        // two bytes every nanosecond is granted three times out of four.
        assert!(bucket.take(MIN_BURST_BYTES as usize, start));
        let mut granted = 0;
        for ns in 1..=1000u64 {
            if bucket.take(2, start + Duration::from_nanos(ns)) {
                granted += 1;
            }
        }
        assert_eq!(granted, 750);
    }
}
