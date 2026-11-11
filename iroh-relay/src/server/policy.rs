//! Policy deciding which packets the relay forwards.
//!
//! The relay carries traffic for strangers in both directions. Which of it to forward is
//! the relay operator's decision and sits behind the [`TrafficPolicy`] trait.

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
