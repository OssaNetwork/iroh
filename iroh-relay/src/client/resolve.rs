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

/// How the client resolves the host name of a relay.
///
/// By default this is the resolver of the operating system. With the `dns` feature a
/// `DnsResolver` of the `iroh-dns` crate can be used instead, which resolves the address
/// families in parallel and can be configured.
#[derive(Debug, Clone, Default)]
pub struct HostResolver(Inner);

#[derive(Debug, Clone, Default)]
enum Inner {
    #[default]
    System,
    #[cfg(feature = "dns")]
    Dns(DnsResolver),
}

impl HostResolver {
    /// Resolves with the resolver of the operating system.
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
        let domain = match url.host() {
            None => return Box::pin(stream::once(Err(e!(ResolveError::MissingHost)))),
            Some(url::Host::Ipv4(ip)) => return Box::pin(stream::once(Ok(IpAddr::V4(ip)))),
            Some(url::Host::Ipv6(ip)) => return Box::pin(stream::once(Ok(IpAddr::V6(ip)))),
            Some(url::Host::Domain(domain)) => domain.to_string(),
        };
        match &self.0 {
            Inner::System => {
                // The port does not matter for the lookup.
                let lookup = async move {
                    let addrs = time::timeout(timeout, tokio::net::lookup_host((domain, 0)))
                        .await
                        .map_err(|_| e!(ResolveError::Timeout))?
                        .map_err(|err| e!(ResolveError::Lookup, err))?;
                    let addrs: Vec<IpAddr> = addrs.map(|addr| addr.ip()).collect();
                    if addrs.is_empty() {
                        return Err(e!(ResolveError::NoAddresses));
                    }
                    Ok(addrs)
                };
                Box::pin(stream::once_future(lookup).flat_map(|res| match res {
                    Ok(addrs) => stream::iter(addrs.into_iter().map(Ok).collect::<Vec<_>>()),
                    Err(err) => stream::iter(vec![Err(err)]),
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

        // A name that does not exist, see RFC 6761.
        let addrs = resolve(&resolver, "https://does-not-exist.invalid/").await;
        assert_eq!(addrs.len(), 1);
        assert!(addrs[0].is_err());
    }
}
