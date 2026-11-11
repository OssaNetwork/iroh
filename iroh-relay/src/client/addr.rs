//! How the paths of a [`RelaySocket`](super::RelaySocket) appear as socket addresses.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::protos::relay::RemoteAddr;

/// The first six bytes of every synthetic address.
const PREFIX: [u8; 6] = [0xfd, 0x72, 0x65, 0x6c, 0x61, 0x79];

/// The byte after the prefix says what kind of path the address stands for.
const KIND_RELAYED_UDP: u8 = 1;
const KIND_RELAYED_TUNNEL: u8 = 2;
const KIND_TUNNEL: u8 = 3;

/// Returns whether `addr` lies in the range of the synthetic addresses.
pub(super) fn is_synthetic(addr: &SocketAddr) -> bool {
    match addr {
        SocketAddr::V4(_) => false,
        SocketAddr::V6(v6) => v6.ip().octets()[..6] == PREFIX,
    }
}

/// Identifies one of the relays a [`RelaySocket`](super::RelaySocket) is connected to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RelayIndex(pub(crate) u16);

/// A path to a peer, as seen by the QUIC stack on top of a
/// [`RelaySocket`](super::RelaySocket).
///
/// A QUIC stack addresses its peers by [`SocketAddr`]. A relay socket reaches a peer
/// either directly over UDP, or through a relay. To the QUIC stack the latter must be a
/// different address than the peer's own, since both paths can exist at the same time.
/// A relayed peer is therefore given a synthetic IPv6 address that encodes how to reach
/// it. This type converts between the two views.
///
/// The synthetic addresses lie in `fd72:656c:6179::/48`, a prefix from the range for
/// unique local addresses of RFC 4193, and are never sent on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PathAddr {
    /// The peer is reached directly over UDP at this address.
    ///
    /// The address is in canonical form: an IPv4 address is not IPv4-mapped.
    Direct(SocketAddr),
    /// The peer reached us through one of our relays.
    Relayed {
        /// The relay the peer sent to.
        relay: RelayIndex,
        /// The peer's address as the relay saw it.
        remote: RemoteAddr,
    },
    /// The peer is reached through a TCP tunnel to its relay, because UDP to the relay
    /// does not get through.
    Tunnel {
        /// The address the peer advertises: the IP of its relay and its port there.
        target: SocketAddrV4,
    },
}

impl PathAddr {
    /// Interprets an address the QUIC stack reported, for example as the remote address
    /// of a connection.
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        let SocketAddr::V6(v6) = addr else {
            return Self::Direct(addr);
        };
        let octets = v6.ip().octets();
        if octets[..6] != PREFIX {
            return Self::Direct(SocketAddr::new(v6.ip().to_canonical(), v6.port()));
        }
        let ip = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
        let tunnel = match octets[6] {
            KIND_RELAYED_UDP => false,
            KIND_RELAYED_TUNNEL => true,
            KIND_TUNNEL => {
                return Self::Tunnel {
                    target: SocketAddrV4::new(ip, v6.port()),
                };
            }
            // Not an address this version creates. Nothing can be sent to it.
            _ => return Self::Direct(addr),
        };
        let relay = RelayIndex(u16::from_be_bytes([octets[8], octets[9]]));
        Self::Relayed {
            relay,
            remote: RemoteAddr {
                addr: SocketAddrV4::new(ip, v6.port()),
                tunnel,
            },
        }
    }

    /// Returns the address the QUIC stack uses for this path.
    pub fn to_socket_addr(&self) -> SocketAddr {
        match self {
            Self::Direct(addr) => match addr {
                SocketAddr::V4(v4) => {
                    SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0).into()
                }
                SocketAddr::V6(_) => *addr,
            },
            Self::Relayed { relay, remote } => {
                let mut octets = [0u8; 16];
                octets[..6].copy_from_slice(&PREFIX);
                octets[6] = if remote.tunnel {
                    KIND_RELAYED_TUNNEL
                } else {
                    KIND_RELAYED_UDP
                };
                octets[8..10].copy_from_slice(&relay.0.to_be_bytes());
                octets[12..16].copy_from_slice(&remote.addr.ip().octets());
                SocketAddrV6::new(Ipv6Addr::from(octets), remote.addr.port(), 0, 0).into()
            }
            Self::Tunnel { target } => {
                let mut octets = [0u8; 16];
                octets[..6].copy_from_slice(&PREFIX);
                octets[6] = KIND_TUNNEL;
                octets[12..16].copy_from_slice(&target.ip().octets());
                SocketAddrV6::new(Ipv6Addr::from(octets), target.port(), 0, 0).into()
            }
        }
    }

    /// Returns whether the path goes through a relay, in either role: a peer that
    /// reached us through our relay, or a peer we reach through a tunnel to its relay.
    pub fn is_relayed(&self) -> bool {
        matches!(self, Self::Relayed { .. } | Self::Tunnel { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relayed_round_trip() {
        for tunnel in [false, true] {
            let path = PathAddr::Relayed {
                relay: RelayIndex(0x0102),
                remote: RemoteAddr {
                    addr: SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 4433),
                    tunnel,
                },
            };
            let addr = path.to_socket_addr();
            assert!(addr.is_ipv6());
            assert_eq!(addr.port(), 4433);
            assert_eq!(PathAddr::from_socket_addr(addr), path);
            assert!(path.is_relayed());
        }
        let path = PathAddr::Relayed {
            relay: RelayIndex(0x0102),
            remote: RemoteAddr::udp(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 4433)),
        };
        assert_eq!(
            path.to_socket_addr().to_string(),
            "[fd72:656c:6179:100:102:0:c633:6407]:4433"
        );
    }

    #[test]
    fn tunnel_round_trip() {
        let target = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 5), 41873);
        let path = PathAddr::Tunnel { target };
        let addr = path.to_socket_addr();
        assert_eq!(addr.to_string(), "[fd72:656c:6179:300::cb00:7105]:41873");
        assert_eq!(PathAddr::from_socket_addr(addr), path);
        assert!(path.is_relayed());
        // Not the same address as the target reached over UDP.
        assert_ne!(addr, PathAddr::Direct(target.into()).to_socket_addr());
    }

    #[test]
    fn direct_addresses_are_canonical() {
        let v4: SocketAddr = "198.51.100.7:4433".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:198.51.100.7]:4433".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:4433".parse().unwrap();

        assert_eq!(PathAddr::from_socket_addr(v4), PathAddr::Direct(v4));
        assert_eq!(PathAddr::from_socket_addr(mapped), PathAddr::Direct(v4));
        assert_eq!(PathAddr::from_socket_addr(v6), PathAddr::Direct(v6));

        assert_eq!(PathAddr::Direct(v4).to_socket_addr(), mapped);
        assert_eq!(PathAddr::Direct(v6).to_socket_addr(), v6);
        assert!(!PathAddr::Direct(v4).is_relayed());
    }

    #[test]
    fn unknown_kind_is_not_relayed() {
        let addr: SocketAddr = "[fd72:656c:6179:ff00::1]:1".parse().unwrap();
        assert_eq!(PathAddr::from_socket_addr(addr), PathAddr::Direct(addr));
    }
}
