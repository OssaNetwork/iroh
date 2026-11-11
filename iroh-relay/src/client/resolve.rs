//! Resolving the host of a relay.

use std::{net::IpAddr, pin::Pin, time::Duration};

#[cfg(feature = "dns")]
use iroh_dns::dns::DnsResolver;
use n0_error::{e, stack_error};
use n0_future::{Stream, StreamExt, stream, time};
use url::Url;

/// Errors when resolving a host.
#[stack_error(derive, add_meta, from_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum ResolveError {
    #[error("the URL has no host")]
    MissingHost,
    #[error("the host has no addresses")]
    NoAddresses,
    #[error("the lookup timed out")]
    Timeout,
    #[error("the lookup failed")]
    Lookup {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[cfg(feature = "dns")]
    #[error(transparent)]
    Dns { source: iroh_dns::dns::DnsError },
}

/// How many lookups with the resolver of the operating system run at a time.
///
/// Such a lookup can not be cancelled. It blocks a thread until the operating system
/// gives up, which can take much longer than the caller waits. Without a limit, a client
/// that keeps reconnecting while the resolver is stuck would start a thread per attempt.
const MAX_SYSTEM_LOOKUPS: usize = 4;

static SYSTEM_LOOKUPS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(MAX_SYSTEM_LOOKUPS);

/// How the client resolves the host name of a relay.
///
/// With the `dns` feature, which is on by default, this is a `DnsResolver` of the
/// `iroh-dns` crate unless another resolver is chosen. It resolves the address families
/// in parallel, so that one of them being slow does not hold up the other. Without the
/// feature it is the resolver of the operating system.
#[derive(Debug, Clone)]
pub struct HostResolver(Inner);

#[derive(Debug, Clone)]
enum Inner {
    System,
    #[cfg(feature = "dns")]
    Dns(DnsResolver),
}

impl Default for HostResolver {
    fn default() -> Self {
        #[cfg(feature = "dns")]
        {
            Self(Inner::Dns(DnsResolver::new()))
        }
        #[cfg(not(feature = "dns"))]
        {
            Self(Inner::System)
        }
    }
}

impl HostResolver {
    /// Resolves with the resolver of the operating system.
    ///
    /// It answers once it has the addresses of all families, and its lookups can not be
    /// cancelled. Prefer a `DnsResolver` where the `dns` feature can be used.
    pub fn system() -> Self {
        Self(Inner::System)
    }

    /// Resolves with `resolver`.
    #[cfg(feature = "dns")]
    pub fn dns(resolver: DnsResolver) -> Self {
        Self(Inner::Dns(resolver))
    }

    /// Resolves the host of `url`. The addresses arrive as the lookups complete.
    ///
    /// An IP address as the host is returned as is. The stream yields an error if no
    /// address could be found.
    pub(super) fn resolve_all<'a>(
        &'a self,
        url: &Url,
        timeout: Duration,
    ) -> Pin<Box<dyn Stream<Item = Result<IpAddr, ResolveError>> + Send + 'a>> {
        match &self.0 {
            Inner::System => {
                let host = url.host().map(|host| host.to_owned());
                let lookup = async move {
                    match host {
                        None => Err(e!(ResolveError::MissingHost)),
                        Some(url::Host::Ipv4(ip)) => Ok(vec![IpAddr::V4(ip)]),
                        Some(url::Host::Ipv6(ip)) => Ok(vec![IpAddr::V6(ip)]),
                        Some(url::Host::Domain(domain)) => {
                            time::timeout(timeout, system_lookup(domain))
                                .await
                                .map_err(|_| e!(ResolveError::Timeout))?
                        }
                    }
                };
                Box::pin(stream::once_future(lookup).flat_map(|res| {
                    let results: Vec<Result<IpAddr, ResolveError>> = match res {
                        Ok(addrs) => addrs.into_iter().map(Ok).collect(),
                        Err(err) => vec![Err(err)],
                    };
                    stream::iter(results)
                }))
            }
            #[cfg(feature = "dns")]
            Inner::Dns(resolver) => Box::pin(
                resolver
                    .resolve_host_all(url, timeout)
                    .map(|res| res.map_err(ResolveError::from)),
            ),
        }
    }
}

/// Resolves `domain` with the resolver of the operating system.
async fn system_lookup(domain: String) -> Result<Vec<IpAddr>, ResolveError> {
    // Waiting here is covered by the caller's timeout. The slot goes with the lookup,
    // which keeps it until the operating system answers, also when the caller has
    // stopped waiting.
    let slot = SYSTEM_LOOKUPS
        .acquire()
        .await
        .expect("the semaphore is never closed");
    let lookup = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        // The port does not matter for the lookup.
        std::net::ToSocketAddrs::to_socket_addrs(&(domain.as_str(), 0))
            .map(|addrs| addrs.map(|addr| addr.ip()).collect::<Vec<_>>())
    });
    let addrs = lookup
        .await
        .map_err(|err| e!(ResolveError::Lookup, std::io::Error::other(err)))?
        .map_err(|err| e!(ResolveError::Lookup, err))?;
    if addrs.is_empty() {
        return Err(e!(ResolveError::NoAddresses));
    }
    Ok(addrs)
}

#[cfg(feature = "dns")]
impl From<DnsResolver> for HostResolver {
    fn from(resolver: DnsResolver) -> Self {
        Self::dns(resolver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn resolve(resolver: &HostResolver, url: &str) -> Vec<Result<IpAddr, ResolveError>> {
        let url = Url::parse(url).unwrap();
        resolver
            .resolve_all(&url, Duration::from_secs(5))
            .collect()
            .await
    }

    #[tokio::test]
    async fn system_resolver() {
        let resolver = HostResolver::system();
        // An address is not looked up.
        let addrs = resolve(&resolver, "https://198.51.100.7:8443/").await;
        assert_eq!(addrs.len(), 1);
        assert_eq!(
            addrs[0].as_ref().unwrap(),
            &"198.51.100.7".parse::<IpAddr>().unwrap()
        );
        let addrs = resolve(&resolver, "https://[2001:db8::1]/").await;
        assert_eq!(
            addrs[0].as_ref().unwrap(),
            &"2001:db8::1".parse::<IpAddr>().unwrap()
        );

        let addrs = resolve(&resolver, "https://localhost/").await;
        assert!(!addrs.is_empty());
        for addr in addrs {
            assert!(addr.unwrap().is_loopback());
        }

        let url = Url::parse("data:text/plain,no-host").unwrap();
        let addrs: Vec<_> = resolver
            .resolve_all(&url, Duration::from_secs(5))
            .collect()
            .await;
        assert!(matches!(
            addrs.as_slice(),
            [Err(ResolveError::MissingHost { .. })]
        ));
    }

    #[cfg(feature = "dns")]
    #[tokio::test]
    async fn default_is_the_dns_resolver() {
        assert!(matches!(HostResolver::default().0, Inner::Dns(_)));
        assert!(matches!(HostResolver::system().0, Inner::System));
    }

    #[cfg(not(feature = "dns"))]
    #[test]
    fn default_is_the_system_resolver() {
        assert!(matches!(HostResolver::default().0, Inner::System));
    }
}
