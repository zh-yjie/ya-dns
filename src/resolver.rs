use hickory_proto::rr::RecordType;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::error::ResolveError;
use hickory_resolver::lookup::Lookup;
use hickory_resolver::AsyncResolver;
use std::net::SocketAddr;

use crate::resolver_runtime_provider::{ProxyConnectionProvider, ProxyRuntimeProvider};

#[derive(Clone, Debug)]
pub struct RecursiveResolver {
    pub resolver: AsyncResolver<ProxyConnectionProvider>,
}

impl RecursiveResolver {
    pub fn new(
        resolver_config: ResolverConfig,
        options: ResolverOpts,
        provider: ProxyConnectionProvider,
    ) -> Self {
        let resolver = AsyncResolver::new(resolver_config, options, provider);
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

pub fn udp_resolver(address: &Vec<SocketAddr>) -> RecursiveResolver {
    let mut resolver_config = ResolverConfig::new();
    address.iter().for_each(|addr| {
        resolver_config.add_name_server(NameServerConfig::new(*addr, Protocol::Udp));
    });
    let runtime_provider = ProxyRuntimeProvider::new(None);
    let provider = ProxyConnectionProvider::new(runtime_provider);
    RecursiveResolver::new(resolver_config, ResolverOpts::default(), provider)
}

pub fn tcp_resolver(address: &Vec<SocketAddr>, proxy: &Option<String>) -> RecursiveResolver {
    let mut resolver_config = ResolverConfig::new();
    address.iter().for_each(|addr| {
        resolver_config.add_name_server(NameServerConfig::new(*addr, Protocol::Tcp));
    });
    let runtime_provider = ProxyRuntimeProvider::new(proxy.to_owned().map(|p| p.parse().unwrap()));
    let provider = ProxyConnectionProvider::new(runtime_provider);
    RecursiveResolver::new(resolver_config, ResolverOpts::default(), provider)
}

#[cfg(feature = "dns-over-tls")]
pub fn tls_resolver(
    address: &Vec<SocketAddr>,
    tls_host: &String,
    proxy: &Option<String>,
) -> RecursiveResolver {
    let mut resolver_config = ResolverConfig::new();
    address.iter().for_each(|addr| {
        let mut name_server_config = NameServerConfig::new(*addr, Protocol::Tls);
        name_server_config.tls_dns_name = Some(tls_host.to_owned());
        resolver_config.add_name_server(name_server_config);
    });
    let runtime_provider = ProxyRuntimeProvider::new(proxy.to_owned().map(|p| p.parse().unwrap()));
    let provider = ProxyConnectionProvider::new(runtime_provider);
    RecursiveResolver::new(resolver_config, ResolverOpts::default(), provider)
}

#[cfg(feature = "dns-over-https")]
pub fn https_resolver(
    address: &Vec<SocketAddr>,
    tls_host: &String,
    proxy: &Option<String>,
) -> RecursiveResolver {
    let mut resolver_config = ResolverConfig::new();
    address.iter().for_each(|addr| {
        let mut name_server_config = NameServerConfig::new(*addr, Protocol::Https);
        name_server_config.tls_dns_name = Some(tls_host.to_owned());
        resolver_config.add_name_server(name_server_config);
    });
    let runtime_provider = ProxyRuntimeProvider::new(proxy.to_owned().map(|p| p.parse().unwrap()));
    let provider = ProxyConnectionProvider::new(runtime_provider);
    RecursiveResolver::new(resolver_config, ResolverOpts::default(), provider)
}

#[cfg(test)]
mod tests {
    use tokio::runtime::Runtime;

    use super::*;

    #[test]
    fn udp_resolver_test() {
        let dns_addr = "8.8.8.8:53".parse::<SocketAddr>().unwrap();
        let io_loop = Runtime::new().unwrap();
        let resolver = udp_resolver(&vec![dns_addr]);
        let lookup_future = resolver.resolve(String::from("www.example.com"), RecordType::A);
        let response = io_loop.block_on(lookup_future).unwrap();
        let a = response
            .record_iter()
            .next()
            .expect("no addresses returned!")
            .data()
            .unwrap();
        assert_eq!("93.184.216.34", a.to_string());
    }

    #[test]
    fn tcp_resolver_test() {
        let dns_addr = "8.8.8.8:53".parse::<SocketAddr>().unwrap();
        let io_loop = Runtime::new().unwrap();
        let resolver = tcp_resolver(&vec![dns_addr], &None);
        let lookup_future = resolver.resolve(String::from("www.example.com"), RecordType::A);
        let response = io_loop.block_on(lookup_future).unwrap();
        let a = response
            .record_iter()
            .next()
            .expect("no addresses returned!")
            .data()
            .unwrap();
        assert_eq!("93.184.216.34", a.to_string());
    }

    #[cfg(feature = "dns-over-tls")]
    #[test]
    fn tls_resolver_test() {
        let dns_addr = "8.8.8.8:853".parse::<SocketAddr>().unwrap();
        let dns_host = String::from("dns.google");
        let io_loop = Runtime::new().unwrap();
        let resolver = tls_resolver(&vec![dns_addr], &dns_host, &None);
        let lookup_future = resolver.resolve(String::from("www.example.com"), RecordType::A);
        let response = io_loop.block_on(lookup_future).unwrap();
        let a = response
            .record_iter()
            .next()
            .expect("no addresses returned!")
            .data()
            .unwrap();
        assert_eq!("93.184.216.34", a.to_string());
    }

    #[cfg(feature = "dns-over-https")]
    #[test]
    fn https_resolver_test() {
        let dns_addr = "8.8.8.8:443".parse::<SocketAddr>().unwrap();
        let dns_host = String::from("dns.google");
        let io_loop = Runtime::new().unwrap();
        let resolver = https_resolver(&vec![dns_addr], &dns_host, &None);
        let lookup_future = resolver.resolve(String::from("www.example.com"), RecordType::A);
        let response = io_loop.block_on(lookup_future).unwrap();
        let a = response
            .record_iter()
            .next()
            .expect("no addresses returned!")
            .data()
            .unwrap();
        assert_eq!("93.184.216.34", a.to_string());
    }
}
