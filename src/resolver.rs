use hickory_proto::rr::RecordType;
use hickory_resolver::Resolver;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::NetError;

use crate::config::{ResolverOpts as MyResolverOpts, Upstream};
use crate::resolver_runtime_provider::{ProxyConnectionProvider, ProxyRuntimeProvider};

#[derive(Debug)]
pub struct RecursiveResolver {
    pub resolver: Resolver<ProxyConnectionProvider>,
    pub options: MyResolverOpts,
}

impl RecursiveResolver {
    pub fn new(
        resolver_config: ResolverConfig,
        resolver_opts: Option<MyResolverOpts>,
        provider: ProxyConnectionProvider,
    ) -> Self {
        let mut opts = ResolverOpts::default();
        let options = resolver_opts.unwrap_or(MyResolverOpts {
            timeout: opts.timeout,
            ip_strategy: None,
            cache_size: usize::try_from(opts.cache_size).unwrap_or(8192),
        });
        opts.timeout = options.timeout;
        opts.ip_strategy = options.ip_strategy.unwrap_or_default();
        opts.cache_size = u64::try_from(options.cache_size).unwrap_or(8192);
        let mut builder = Resolver::builder_with_config(resolver_config, provider);
        *builder.options_mut() = opts;
        let resolver = builder.build().expect("failed to build resolver");
        RecursiveResolver { resolver, options }
    }

    pub async fn resolve(&self, domain: &str, record_type: RecordType) -> Result<Lookup, NetError> {
        match record_type {
            RecordType::A | RecordType::AAAA => match self.options.ip_strategy {
                Some(_) => match self.resolver.lookup_ip(domain).await {
                    Ok(res) => Ok(res.into()),
                    Err(e) => Err(e),
                },
                None => self.resolver.lookup(domain, record_type).await,
            },
            _ => self.resolver.lookup(domain, record_type).await,
        }
    }
}

impl From<(&Upstream, Option<MyResolverOpts>)> for RecursiveResolver {
    fn from((upstream, config): (&Upstream, Option<MyResolverOpts>)) -> Self {
        let (connection, address, proxy) = match upstream {
            Upstream::UdpUpstream { address, proxy } => (ConnectionConfig::udp(), address, proxy),
            Upstream::TcpUpstream { address, proxy } => (ConnectionConfig::tcp(), address, proxy),
            #[cfg(feature = "dns-over-tls")]
            Upstream::TlsUpstream {
                address,
                tls_host,
                proxy,
            } => (
                ConnectionConfig::tls(tls_host.as_str().into()),
                address,
                proxy,
            ),
            #[cfg(feature = "dns-over-https")]
            Upstream::HttpsUpstream {
                address,
                tls_host,
                proxy,
            } => (
                ConnectionConfig::https(tls_host.as_str().into(), None),
                address,
                proxy,
            ),
            #[cfg(feature = "dns-over-h3")]
            Upstream::H3Upstream {
                address,
                tls_host,
                proxy,
            } => (
                ConnectionConfig::h3(tls_host.as_str().into(), None),
                address,
                proxy,
            ),
            #[cfg(feature = "dns-over-quic")]
            Upstream::QuicUpstream {
                address,
                tls_host,
                proxy,
            } => (
                ConnectionConfig::quic(tls_host.as_str().into()),
                address,
                proxy,
            ),
        };
        let mut resolver_config = ResolverConfig::default();
        address.iter().for_each(|addr| {
            let mut name_server_config = NameServerConfig::udp(addr.ip());
            let mut server_connection = connection.clone();
            server_connection.port = addr.port();
            name_server_config.connections = vec![server_connection];
            resolver_config.add_name_server(name_server_config);
        });
        let runtime_provider =
            ProxyRuntimeProvider::new(proxy.as_ref().map(|p| p.parse().unwrap()));
        let provider = runtime_provider;
        RecursiveResolver::new(resolver_config, config, provider)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    #[tokio::test]
    async fn udp_resolver_test() {
        let dns_addr = "8.8.8.8:53".parse::<SocketAddr>().unwrap();
        let resolver: RecursiveResolver = (
            &Upstream::UdpUpstream {
                address: vec![dns_addr],
                proxy: None,
            },
            None,
        )
            .into();
        let response = resolver.resolve("dns.google", RecordType::A).await.unwrap();
        assert!(
            response
                .answers()
                .iter()
                .any(|r| r.data.to_string().eq("8.8.8.8"))
        );
    }

    #[tokio::test]
    async fn tcp_resolver_test() {
        let dns_addr = "8.8.8.8:53".parse::<SocketAddr>().unwrap();
        let resolver: RecursiveResolver = (
            &Upstream::TcpUpstream {
                address: vec![dns_addr],
                proxy: None,
            },
            None,
        )
            .into();
        let response = resolver.resolve("dns.google", RecordType::A).await.unwrap();
        assert!(
            response
                .answers()
                .iter()
                .any(|r| r.data.to_string().eq("8.8.8.8"))
        );
    }

    #[cfg(feature = "dns-over-tls")]
    #[tokio::test]
    async fn tls_resolver_test() {
        let dns_addr = "8.8.8.8:853".parse::<SocketAddr>().unwrap();
        let dns_host = String::from("dns.google");
        let resolver: RecursiveResolver = (
            &Upstream::TlsUpstream {
                address: vec![dns_addr],
                proxy: None,
                tls_host: dns_host,
            },
            None,
        )
            .into();
        let response = resolver.resolve("dns.google", RecordType::A).await.unwrap();
        assert!(
            response
                .answers()
                .iter()
                .any(|r| r.data.to_string().eq("8.8.8.8"))
        );
    }

    #[cfg(feature = "dns-over-https")]
    #[tokio::test]
    async fn https_resolver_test() {
        let dns_addr = "8.8.8.8:443".parse::<SocketAddr>().unwrap();
        let dns_host = String::from("dns.google");
        let resolver: RecursiveResolver = (
            &Upstream::HttpsUpstream {
                address: vec![dns_addr],
                proxy: None,
                tls_host: dns_host,
            },
            None,
        )
            .into();
        let response = resolver.resolve("dns.google", RecordType::A).await.unwrap();
        assert!(
            response
                .answers()
                .iter()
                .any(|r| r.data.to_string().eq("8.8.8.8"))
        );
    }

    #[cfg(feature = "dns-over-h3")]
    #[tokio::test]
    async fn h3_resolver_test() {
        let dns_addr = "8.8.8.8:443".parse::<SocketAddr>().unwrap();
        let dns_host = String::from("dns.google");
        let resolver: RecursiveResolver = (
            &Upstream::H3Upstream {
                address: vec![dns_addr],
                proxy: None,
                tls_host: dns_host,
            },
            None,
        )
            .into();
        let response = resolver.resolve("dns.google", RecordType::A).await.unwrap();
        assert!(
            response
                .answers()
                .iter()
                .any(|r| r.data.to_string().eq("8.8.8.8"))
        );
    }
}
