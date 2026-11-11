//! Bookkeeping of which client owns which public UDP port.
//!
//! Every client of the relay gets one port out of a configured range. The
//! [`PortAllocator`] only tracks ownership, it does not bind sockets. It is plain state
//! behind `&mut self`, and takes the current time as an argument, so that its behaviour
//! does not depend on a runtime.
//!
//! # Lifetime of a port
//!
//! - [`PortAllocator::acquire`] hands a port to a client identity. The port is then
//!   *active*.
//! - [`PortAllocator::release`] is called when the client's control channel closes. The
//!   port is then *held* for that identity for the release timeout. If the same identity
//!   acquires again within the timeout it gets the held port back.
//! - [`PortAllocator::expire`] frees the ports whose release timeout has passed.
//!
//! # Choosing a port
//!
//! The first candidate for an identity is derived from a hash of the identity, later
//! candidates follow in port order. A client that returns after its release timeout has
//! passed therefore usually gets its previous port back, as long as no other client has
//! taken it, without the relay remembering anything about the client.
//!
//! This is best effort. The hash is not keyed, so anyone who knows an identity can work
//! out its preferred port and take it while the client is away. What protects the client
//! is that dialers verify its identity end to end, not that it keeps its port.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    ops::RangeInclusive,
    time::Duration,
};

use bytes::Bytes;
use n0_error::{ensure, stack_error};
use n0_future::time::Instant;

/// The default time a port stays reserved for its client after the control channel closed.
pub const DEFAULT_RELEASE_TIMEOUT: Duration = Duration::from_secs(30);

/// The default range of ports handed out to clients.
pub const DEFAULT_PORT_RANGE: RangeInclusive<u16> = 1024..=65535;

/// How long a port that could not be bound is skipped.
const UNUSABLE_COOLDOWN: Duration = Duration::from_secs(60);

/// The longest a port is held. Longer release timeouts are clamped to this, which keeps
/// deadlines representable.
const MAX_RELEASE_TIMEOUT: Duration = Duration::from_secs(60 * 60 * 24 * 365);

/// The identity of a client, as established by the relay's authenticator.
///
/// The relay treats the identity as opaque bytes. It is used to recognise a returning
/// client and as the key for policies and logs.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ClientId(Bytes);

impl ClientId {
    /// Creates an identity from its bytes.
    pub fn new(bytes: impl Into<Bytes>) -> Self {
        Self(bytes.into())
    }

    /// Returns the bytes of the identity.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for ClientId {
    /// Formats the identity as lowercase hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.iter() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClientId({self})")
    }
}

/// No port is free for a new client.
#[stack_error(derive, add_meta)]
#[error("no port is available")]
pub struct NoPortAvailable {}

/// The port range of a [`PortAllocator`] is not usable.
#[stack_error(derive, add_meta)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum InvalidPortRange {
    #[error("port range {start}..={end} is empty")]
    Empty { start: u16, end: u16 },
    #[error("port 0 can not be handed out")]
    ContainsZero,
}

/// What [`PortAllocator::release`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Released {
    /// The port stays reserved for the identity until the deadline, at which
    /// [`PortAllocator::expire`] frees it. Keep the port's socket until then.
    Held(Instant),
    /// The port is free again, because the release timeout is zero. Close the port's
    /// socket.
    Freed,
    /// Nothing changed, because the generation is not the identity's current one. The
    /// port, if any, belongs to a newer acquisition. Leave its socket alone.
    Stale,
}

/// A port handed to a client by [`PortAllocator::acquire`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    /// The port the client owns.
    pub port: u16,
    /// Identifies this acquisition.
    ///
    /// When an identity acquires its port again the generation changes. A
    /// [`PortAllocator::release`] with an outdated generation is ignored, so that a
    /// connection that was taken over can not release the port of its successor.
    pub generation: u64,
    /// Whether the identity already owned the port, either actively or held.
    pub resumed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// A control channel is using the port.
    Active { generation: u64 },
    /// No control channel is using the port, it is reserved until `until`.
    Held { until: Instant },
}

#[derive(Debug)]
struct Entry {
    port: u16,
    state: State,
}

/// Tracks which client identity owns which port.
///
/// See the [module documentation](self) for details.
#[derive(Debug)]
pub struct PortAllocator {
    range: RangeInclusive<u16>,
    release_timeout: Duration,
    by_identity: HashMap<ClientId, Entry>,
    by_port: HashMap<u16, ClientId>,
    /// Ports that could not be bound, and until when they are skipped.
    unusable: HashMap<u16, Instant>,
    /// Ports that are never handed out.
    excluded: HashSet<u16>,
    /// The held ports ordered by the time their release timeout passes.
    held: BTreeMap<(Instant, u16), ClientId>,
    next_generation: u64,
}

impl PortAllocator {
    /// Creates an allocator handing out the ports in `range`.
    ///
    /// A released port stays reserved for its identity for `release_timeout`. With a zero
    /// timeout ports are freed as soon as they are released.
    pub fn new(
        range: RangeInclusive<u16>,
        release_timeout: Duration,
    ) -> Result<Self, InvalidPortRange> {
        ensure!(
            range.start() <= range.end(),
            InvalidPortRange::Empty {
                start: *range.start(),
                end: *range.end()
            }
        );
        ensure!(*range.start() != 0, InvalidPortRange::ContainsZero);
        Ok(Self {
            range,
            release_timeout: release_timeout.min(MAX_RELEASE_TIMEOUT),
            by_identity: HashMap::new(),
            by_port: HashMap::new(),
            unusable: HashMap::new(),
            excluded: HashSet::new(),
            held: BTreeMap::new(),
            next_generation: 0,
        })
    }

    /// Never hands out `port`.
    ///
    /// Use this for ports in the range that the relay itself listens on. Has no effect on
    /// a port that is already owned.
    pub fn exclude_port(&mut self, port: u16) {
        self.excluded.insert(port);
    }

    /// Returns the time a released port stays reserved for its identity.
    pub fn release_timeout(&self) -> Duration {
        self.release_timeout
    }

    /// Returns the number of ports that are active or held.
    pub fn len(&self) -> usize {
        self.by_identity.len()
    }

    /// Returns whether no port is active or held.
    pub fn is_empty(&self) -> bool {
        self.by_identity.is_empty()
    }

    /// Returns the port `identity` owns, either actively or held.
    pub fn port_of(&self, identity: &ClientId) -> Option<u16> {
        self.by_identity.get(identity).map(|entry| entry.port)
    }

    /// Returns the identity that owns `port`, either actively or held.
    pub fn owner_of(&self, port: u16) -> Option<&ClientId> {
        self.by_port.get(&port)
    }

    /// Hands a port to `identity`.
    ///
    /// If the identity already owns a port, because it is active or still held, that port
    /// is returned again with a new [`Lease::generation`]. Otherwise a free port is
    /// chosen.
    ///
    /// Call [`Self::expire`] with the same `now` first. A hold whose release timeout has
    /// passed but that was not expired yet is resumed like any other hold, while the
    /// caller may already have given up on it.
    pub fn acquire(&mut self, identity: &ClientId, now: Instant) -> Result<Lease, NoPortAvailable> {
        debug_assert!(
            self.next_expiry().is_none_or(|until| until > now),
            "expire must be called before acquire"
        );
        let generation = self.next_generation;
        self.next_generation += 1;

        if let Some(entry) = self.by_identity.get_mut(identity) {
            if let State::Held { until } = entry.state {
                self.held.remove(&(until, entry.port));
            }
            entry.state = State::Active { generation };
            return Ok(Lease {
                port: entry.port,
                generation,
                resumed: true,
            });
        }

        let port = self
            .find_free(identity, now)
            .ok_or_else(NoPortAvailable::new)?;
        self.by_port.insert(port, identity.clone());
        self.by_identity.insert(
            identity.clone(),
            Entry {
                port,
                state: State::Active { generation },
            },
        );
        Ok(Lease {
            port,
            generation,
            resumed: false,
        })
    }

    /// Releases the port of `identity` after its control channel closed.
    ///
    /// See [`Released`] for the possible outcomes and what to do with the port's socket.
    pub fn release(&mut self, identity: &ClientId, generation: u64, now: Instant) -> Released {
        let Some(entry) = self.by_identity.get_mut(identity) else {
            return Released::Stale;
        };
        if entry.state != (State::Active { generation }) {
            return Released::Stale;
        }
        if self.release_timeout.is_zero() {
            self.remove(identity);
            return Released::Freed;
        }
        let until = now + self.release_timeout;
        entry.state = State::Held { until };
        self.held.insert((until, entry.port), identity.clone());
        Released::Held(until)
    }

    /// Frees the port of `identity` because it could not be bound.
    ///
    /// The port is skipped for a while when choosing ports. Does nothing if `generation`
    /// is not the identity's current one.
    ///
    /// Only call this for a [`Lease`] that was not [resumed](Lease::resumed). A resumed
    /// port already has a socket, binding it again fails for that reason alone.
    pub fn mark_unusable(&mut self, identity: &ClientId, generation: u64, now: Instant) {
        let Some(entry) = self.by_identity.get(identity) else {
            return;
        };
        if entry.state != (State::Active { generation }) {
            return;
        }
        let port = entry.port;
        self.remove(identity);
        self.unusable.retain(|_, until| *until > now);
        self.unusable.insert(port, now + UNUSABLE_COOLDOWN);
    }

    /// Frees all ports whose release timeout has passed by `now`.
    ///
    /// Returns the identities and ports that were freed.
    pub fn expire(&mut self, now: Instant) -> Vec<(ClientId, u16)> {
        let mut expired = Vec::new();
        while let Some(entry) = self.held.first_entry() {
            let (until, port) = *entry.key();
            if until > now {
                break;
            }
            let identity = entry.get().clone();
            self.remove(&identity);
            expired.push((identity, port));
        }
        expired
    }

    /// Returns the earliest time at which [`Self::expire`] frees a port.
    pub fn next_expiry(&self) -> Option<Instant> {
        self.held.keys().next().map(|(until, _)| *until)
    }

    fn remove(&mut self, identity: &ClientId) {
        if let Some(entry) = self.by_identity.remove(identity) {
            self.by_port.remove(&entry.port);
            if let State::Held { until } = entry.state {
                self.held.remove(&(until, entry.port));
            }
        }
    }

    /// Finds a free port, starting at the preferred port of `identity`.
    fn find_free(&self, identity: &ClientId, now: Instant) -> Option<u16> {
        let start = u32::from(*self.range.start());
        let end = u32::from(*self.range.end());
        let count = end - start + 1;
        // Every port is owned, no need to look at each of them.
        if self.by_port.len() >= count as usize {
            return None;
        }
        let preferred = (stable_hash(identity.as_bytes()) % u64::from(count)) as u32;
        (0..count)
            .map(|offset| (start + (preferred + offset) % count) as u16)
            .find(|port| {
                !self.by_port.contains_key(port)
                    && !self.excluded.contains(port)
                    && self.unusable.get(port).is_none_or(|until| *until <= now)
            })
    }
}

/// FNV-1a, a hash that gives the same result in every process.
///
/// The preferred port of an identity must not change when the relay restarts, which rules
/// out the randomly keyed hashers of the standard library.
fn stable_hash(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(30);

    fn id(name: &str) -> ClientId {
        ClientId::new(name.as_bytes().to_vec())
    }

    #[test]
    fn preferred_port_is_stable() {
        let now = Instant::now();
        let mut a = PortAllocator::new(DEFAULT_PORT_RANGE, TIMEOUT).unwrap();
        let mut b = PortAllocator::new(DEFAULT_PORT_RANGE, TIMEOUT).unwrap();
        let port = a.acquire(&id("bob"), now).unwrap().port;
        assert_eq!(b.acquire(&id("bob"), now).unwrap().port, port);
        assert!(DEFAULT_PORT_RANGE.contains(&port));
        // A different identity prefers a different port.
        assert_ne!(a.acquire(&id("carol"), now).unwrap().port, port);
    }

    #[test]
    fn probes_forward_and_wraps() {
        let now = Instant::now();
        let mut alloc = PortAllocator::new(1000..=1003, TIMEOUT).unwrap();
        let mut ports = Vec::new();
        for i in 0..4 {
            let lease = alloc.acquire(&id(&format!("client-{i}")), now).unwrap();
            assert!(!lease.resumed);
            ports.push(lease.port);
        }
        ports.sort();
        assert_eq!(ports, vec![1000, 1001, 1002, 1003]);
        assert!(alloc.acquire(&id("one-too-many"), now).is_err());
        assert_eq!(alloc.len(), 4);
    }

    #[test]
    fn rejects_unusable_ranges() {
        #[allow(clippy::reversed_empty_ranges)]
        let res = PortAllocator::new(2000..=1000, TIMEOUT);
        assert!(matches!(res, Err(InvalidPortRange::Empty { .. })));
        let res = PortAllocator::new(0..=1000, TIMEOUT);
        assert!(matches!(res, Err(InvalidPortRange::ContainsZero { .. })));
    }

    #[test]
    fn excluded_ports_are_never_handed_out() {
        let now = Instant::now();
        let mut alloc = PortAllocator::new(1000..=1002, TIMEOUT).unwrap();
        alloc.exclude_port(1000);
        alloc.exclude_port(1002);
        assert_eq!(alloc.acquire(&id("bob"), now).unwrap().port, 1001);
        assert!(alloc.acquire(&id("carol"), now).is_err());
    }

    #[test]
    fn huge_release_timeout_does_not_overflow() {
        let now = Instant::now();
        let mut alloc = PortAllocator::new(1000..=1000, Duration::MAX).unwrap();
        let lease = alloc.acquire(&id("bob"), now).unwrap();
        assert!(matches!(
            alloc.release(&id("bob"), lease.generation, now),
            Released::Held(_)
        ));
        assert!(alloc.expire(now + Duration::from_secs(3600)).is_empty());
    }

    #[test]
    fn held_port_is_resumed_within_timeout() {
        let now = Instant::now();
        let mut alloc = PortAllocator::new(1000..=1001, TIMEOUT).unwrap();
        let lease = alloc.acquire(&id("bob"), now).unwrap();
        let until = now + TIMEOUT;
        assert_eq!(
            alloc.release(&id("bob"), lease.generation, now),
            Released::Held(until)
        );
        assert_eq!(alloc.next_expiry(), Some(until));

        // The held port still counts as taken.
        alloc.acquire(&id("carol"), now).unwrap();
        assert!(alloc.acquire(&id("dave"), now).is_err());
        assert!(alloc.expire(until - Duration::from_millis(1)).is_empty());

        let resumed = alloc
            .acquire(&id("bob"), until - Duration::from_millis(1))
            .unwrap();
        assert!(resumed.resumed);
        assert_eq!(resumed.port, lease.port);
        assert_ne!(resumed.generation, lease.generation);
        // Resuming cancels the release.
        assert_eq!(alloc.next_expiry(), None);
        assert!(alloc.expire(until + TIMEOUT).is_empty());
        assert_eq!(alloc.port_of(&id("bob")), Some(lease.port));
    }

    #[test]
    fn held_port_is_freed_after_timeout() {
        let now = Instant::now();
        let mut alloc = PortAllocator::new(1000..=1000, TIMEOUT).unwrap();
        let lease = alloc.acquire(&id("bob"), now).unwrap();
        let until = now + TIMEOUT;
        alloc.release(&id("bob"), lease.generation, now);

        assert_eq!(alloc.expire(until), vec![(id("bob"), 1000)]);
        assert!(alloc.is_empty());
        assert_eq!(alloc.owner_of(1000), None);

        // Somebody else can take the port now.
        let other = alloc.acquire(&id("carol"), until).unwrap();
        assert_eq!(other.port, 1000);
        assert!(!other.resumed);
        assert!(alloc.acquire(&id("bob"), until).is_err());
    }

    #[test]
    fn zero_timeout_frees_immediately() {
        let now = Instant::now();
        let mut alloc = PortAllocator::new(1000..=1000, Duration::ZERO).unwrap();
        let lease = alloc.acquire(&id("bob"), now).unwrap();
        assert_eq!(
            alloc.release(&id("bob"), lease.generation, now),
            Released::Freed
        );
        assert!(alloc.is_empty());
        assert!(alloc.acquire(&id("carol"), now).is_ok());
    }

    #[test]
    fn takeover_ignores_the_stale_release() {
        let now = Instant::now();
        let mut alloc = PortAllocator::new(1000..=1010, TIMEOUT).unwrap();
        let first = alloc.acquire(&id("bob"), now).unwrap();
        // A second control channel for the same identity takes over.
        let second = alloc.acquire(&id("bob"), now).unwrap();
        assert!(second.resumed);
        assert_eq!(second.port, first.port);

        // The first channel closing must not release the port.
        assert_eq!(
            alloc.release(&id("bob"), first.generation, now),
            Released::Stale
        );
        assert_eq!(alloc.next_expiry(), None);
        assert!(matches!(
            alloc.release(&id("bob"), second.generation, now),
            Released::Held(_)
        ));
        // Releasing twice is harmless.
        assert_eq!(
            alloc.release(&id("bob"), second.generation, now),
            Released::Stale
        );
    }

    #[test]
    fn unusable_port_is_skipped_for_a_while() {
        let now = Instant::now();
        let mut alloc = PortAllocator::new(1000..=1001, TIMEOUT).unwrap();
        let first = alloc.acquire(&id("bob"), now).unwrap();
        alloc.mark_unusable(&id("bob"), first.generation, now);
        assert!(alloc.is_empty());

        let second = alloc.acquire(&id("bob"), now).unwrap();
        assert_ne!(second.port, first.port);
        assert!(!second.resumed);
        // Both ports are taken or unusable.
        assert!(alloc.acquire(&id("carol"), now).is_err());

        let later = now + UNUSABLE_COOLDOWN;
        assert_eq!(alloc.acquire(&id("carol"), later).unwrap().port, first.port);
    }

    #[test]
    fn expires_in_deadline_order() {
        let now = Instant::now();
        let mut alloc = PortAllocator::new(1000..=1010, TIMEOUT).unwrap();
        let bob = alloc.acquire(&id("bob"), now).unwrap();
        let carol = alloc.acquire(&id("carol"), now).unwrap();
        let later = now + Duration::from_secs(10);
        alloc.release(&id("carol"), carol.generation, later);
        alloc.release(&id("bob"), bob.generation, now);

        assert_eq!(alloc.next_expiry(), Some(now + TIMEOUT));
        assert_eq!(alloc.expire(now + TIMEOUT), vec![(id("bob"), bob.port)]);
        assert_eq!(alloc.next_expiry(), Some(later + TIMEOUT));
        assert_eq!(
            alloc.expire(later + TIMEOUT),
            vec![(id("carol"), carol.port)]
        );
        assert!(alloc.is_empty());
    }

    #[test]
    fn client_id_formats_as_hex() {
        let id = ClientId::new(vec![0x00, 0xab, 0xff]);
        assert_eq!(id.to_string(), "00abff");
        assert_eq!(format!("{id:?}"), "ClientId(00abff)");
    }
}
