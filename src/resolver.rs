use std::net::SocketAddr;
use trust_dns_proto::rr::RecordType;
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::lookup::Lookup;
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Clone, Debug)]
pub struct RecursiveResolver {
    pub resolver: TokioAsyncResolver,
}

impl RecursiveResolver {
    pub fn new(resolver_config: ResolverConfig) -> Self {
        let resolver = TokioAsyncResolver::tokio(resolver_config, ResolverOpts::default());
        RecursiveResolver { resolver }
    }

    pub async fn resolve(
        &self,
        domain: String,
        record_type: RecordType,
    ) -> Result<Lookup, ResolveError> {
        self.resolver.lookup(domain, record_type).await
    }
}

pub fn udp_resolver(address: &SocketAddr) -> RecursiveResolver {
    let mut resolver_config = ResolverConfig::new();
    resolver_config.add_name_server(NameServerConfig::new(*address, Protocol::Udp));
    RecursiveResolver::new(resolver_config)
}

pub fn tcp_resolver(address: &SocketAddr) -> RecursiveResolver {
    let mut resolver_config = ResolverConfig::new();
    resolver_config.add_name_server(NameServerConfig::new(*address, Protocol::Tcp));
    RecursiveResolver::new(resolver_config)
}

pub fn tls_resolver(address: &SocketAddr, tls_host: &String) -> RecursiveResolver {
    let mut resolver_config = ResolverConfig::new();
    let mut name_server_config = NameServerConfig::new(*address, Protocol::Tls);
    name_server_config.tls_dns_name = Some(tls_host.to_owned());
    resolver_config.add_name_server(name_server_config);
    RecursiveResolver::new(resolver_config)
}

#[cfg(not(any(target_arch = "mips", target_arch = "mips64")))]
pub fn https_resolver(address: &SocketAddr, tls_host: &String) -> RecursiveResolver {
    let mut resolver_config = ResolverConfig::new();
    let mut name_server_config = NameServerConfig::new(*address, Protocol::Https);
    name_server_config.tls_dns_name = Some(tls_host.to_owned());
    resolver_config.add_name_server(name_server_config);
    RecursiveResolver::new(resolver_config)
}

#[cfg(any(target_arch = "mips", target_arch = "mips64"))]
pub fn https_resolver(address: &SocketAddr, tls_host: &String) -> RecursiveResolver {
    tls_resolver(address, tls_host)
}
