//! Racing a UDP dial against a dial through a TCP tunnel.

use std::{collections::HashMap, future::Future, hash::Hash, sync::Mutex, time::Duration};

use n0_error::stack_error;
use n0_future::time;

/// How long to give a UDP dial before also dialing through the tunnel.
pub const TUNNEL_RACE_DELAY: Duration = Duration::from_millis(250);

/// Which dial of a [`race_udp_and_tunnel`] completed first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Winner<U, T> {
    /// The dial over UDP.
    Udp(U),
    /// The dial through the tunnel.
    Tunnel(T),
}

/// Both dials of a [`race_udp_and_tunnel`] failed.
#[stack_error(derive, add_meta)]
#[error("the dial over UDP failed ({udp}), and so did the dial through the tunnel ({tunnel})")]
pub struct RaceError<UE, TE>
where
    UE: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
    TE: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
{
    /// Why the dial over UDP failed.
    pub udp: UE,
    /// Why the dial through the tunnel failed.
    pub tunnel: TE,
}

/// Dials a peer over UDP and, if that takes too long, through a TCP tunnel as well.
///
/// - `udp` is the dial over UDP. It starts right away.
/// - `tunnel` creates the dial through the tunnel. It is called, and its dial started,
///   once `delay` has passed without `udp` completing, or as soon as `udp` fails.
///   [`TUNNEL_RACE_DELAY`] is a good `delay`.
///
/// The first dial to succeed wins, and the other is dropped. Dropping a dial must cancel
/// it, which holds for the connection attempts of a QUIC stack. If both dials fail the
/// error carries both reasons.
///
/// On a network that is known to block UDP, skip the race and dial through the tunnel
/// only. [`FallbackMemory`] remembers which networks those are.
pub async fn race_udp_and_tunnel<U, UE, T, TE, UF, TF>(
    udp: UF,
    tunnel: impl FnOnce() -> TF,
    delay: Duration,
) -> Result<Winner<U, T>, RaceError<UE, TE>>
where
    UF: Future<Output = Result<U, UE>>,
    TF: Future<Output = Result<T, TE>>,
    UE: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
    TE: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
{
    tokio::pin!(udp);
    // The UDP dial runs alone at first.
    let mut udp_error = tokio::select! {
        biased;
        res = &mut udp => match res {
            Ok(conn) => return Ok(Winner::Udp(conn)),
            // No point in waiting out the delay.
            Err(err) => Some(err),
        },
        _ = time::sleep(delay) => None,
    };

    let tunnel = tunnel();
    tokio::pin!(tunnel);
    let mut tunnel_error = None;
    loop {
        tokio::select! {
            biased;
            res = &mut udp, if udp_error.is_none() => match res {
                Ok(conn) => return Ok(Winner::Udp(conn)),
                Err(err) => udp_error = Some(err),
            },
            res = &mut tunnel, if tunnel_error.is_none() => match res {
                Ok(conn) => return Ok(Winner::Tunnel(conn)),
                Err(err) => tunnel_error = Some(err),
            },
        }
        if udp_error.is_some() && tunnel_error.is_some() {
            break;
        }
    }
    match (udp_error, tunnel_error) {
        (Some(udp), Some(tunnel)) => Err(RaceError::new(udp, tunnel)),
        _ => unreachable!("the loop only ends when both dials failed"),
    }
}

/// Remembers on which networks dials only succeeded through the tunnel.
///
/// What identifies a network is up to the caller: `K` could be the address of the default
/// gateway, or the name of a wireless network. On a network that
/// [prefers the tunnel](Self::prefers_tunnel), skip the UDP dial.
///
/// An entry is forgotten after a while, so that UDP is tried again: a network can start
/// letting UDP through.
#[derive(Debug)]
pub struct FallbackMemory<K> {
    retry_udp_after: Duration,
    blocked: Mutex<HashMap<K, time::Instant>>,
}

impl<K: Hash + Eq> FallbackMemory<K> {
    /// Creates a memory that tries UDP again on a network `retry_udp_after` after a dial
    /// there last needed the tunnel.
    pub fn new(retry_udp_after: Duration) -> Self {
        Self {
            retry_udp_after,
            blocked: Mutex::new(HashMap::new()),
        }
    }

    /// Returns whether to dial through the tunnel right away on `network`.
    pub fn prefers_tunnel(&self, network: &K) -> bool {
        let mut blocked = self.blocked.lock().unwrap_or_else(|err| err.into_inner());
        match blocked.get(network) {
            Some(since) if since.elapsed() < self.retry_udp_after => true,
            Some(_) => {
                blocked.remove(network);
                false
            }
            None => false,
        }
    }

    /// Records which dial won a race on `network`.
    pub fn record<U, T>(&self, network: K, winner: &Winner<U, T>) {
        let mut blocked = self.blocked.lock().unwrap_or_else(|err| err.into_inner());
        match winner {
            Winner::Udp(_) => {
                blocked.remove(&network);
            }
            Winner::Tunnel(_) => {
                blocked.insert(network, time::Instant::now());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::pending;

    use super::*;

    const DELAY: Duration = Duration::from_millis(250);

    async fn after<T>(delay: Duration, value: T) -> T {
        time::sleep(delay).await;
        value
    }

    type Res = Result<&'static str, &'static str>;

    #[tokio::test(start_paused = true)]
    async fn udp_wins_before_the_tunnel_is_tried() {
        let start = time::Instant::now();
        let res = race_udp_and_tunnel(
            after(Duration::from_millis(100), Res::Ok("udp")),
            || -> std::future::Pending<Res> { panic!("the tunnel must not be dialed") },
            DELAY,
        )
        .await;
        assert_eq!(res.unwrap(), Winner::Udp("udp"));
        assert_eq!(start.elapsed(), Duration::from_millis(100));
    }

    #[tokio::test(start_paused = true)]
    async fn tunnel_wins_when_udp_is_blocked() {
        let start = time::Instant::now();
        let res = race_udp_and_tunnel(
            pending::<Res>(),
            || after(Duration::from_millis(50), Res::Ok("tunnel")),
            DELAY,
        )
        .await;
        assert_eq!(res.unwrap(), Winner::Tunnel("tunnel"));
        // The tunnel was only dialed after the delay.
        assert_eq!(start.elapsed(), DELAY + Duration::from_millis(50));
    }

    #[tokio::test(start_paused = true)]
    async fn slow_udp_still_wins_over_a_slower_tunnel() {
        let res = race_udp_and_tunnel(
            after(Duration::from_millis(300), Res::Ok("udp")),
            || after(Duration::from_millis(200), Res::Ok("tunnel")),
            DELAY,
        )
        .await;
        assert_eq!(res.unwrap(), Winner::Udp("udp"));
    }

    #[tokio::test(start_paused = true)]
    async fn tunnel_is_dialed_at_once_when_udp_fails() {
        let start = time::Instant::now();
        let res = race_udp_and_tunnel(
            after(Duration::from_millis(10), Res::Err("refused")),
            || after(Duration::from_millis(50), Res::Ok("tunnel")),
            DELAY,
        )
        .await;
        assert_eq!(res.unwrap(), Winner::Tunnel("tunnel"));
        assert_eq!(start.elapsed(), Duration::from_millis(60));
    }

    #[tokio::test(start_paused = true)]
    async fn udp_can_win_after_the_tunnel_failed() {
        let res = race_udp_and_tunnel(
            after(Duration::from_secs(2), Res::Ok("udp")),
            || after(Duration::from_millis(50), Res::Err("no tunnel")),
            DELAY,
        )
        .await;
        assert_eq!(res.unwrap(), Winner::Udp("udp"));
    }

    #[tokio::test(start_paused = true)]
    async fn reports_both_failures() {
        let res = race_udp_and_tunnel(
            after(Duration::from_secs(1), Res::Err("timed out")),
            || after(Duration::from_millis(50), Res::Err("no tunnel")),
            DELAY,
        )
        .await;
        let err = res.unwrap_err();
        assert_eq!(err.udp, "timed out");
        assert_eq!(err.tunnel, "no tunnel");
    }

    #[tokio::test(start_paused = true)]
    async fn memory_prefers_the_tunnel_for_a_while() {
        let memory = FallbackMemory::new(Duration::from_secs(60));
        assert!(!memory.prefers_tunnel(&"office"));

        memory.record("office", &Winner::<(), ()>::Tunnel(()));
        assert!(memory.prefers_tunnel(&"office"));
        assert!(!memory.prefers_tunnel(&"home"));

        // After a while UDP gets another chance.
        time::sleep(Duration::from_secs(61)).await;
        assert!(!memory.prefers_tunnel(&"office"));

        // A UDP win clears the entry at once.
        memory.record("office", &Winner::<(), ()>::Tunnel(()));
        memory.record("office", &Winner::<(), ()>::Udp(()));
        assert!(!memory.prefers_tunnel(&"office"));
    }
}
