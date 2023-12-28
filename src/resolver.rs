use hickory_proto::rr::RecordType;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::error::ResolveError;
use hickory_resolver::lookup::Lookup;
use hickory_resolver::TokioAsyncResolver;
use std::net::SocketAddr;

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

#[cfg(feature = "dns-over-tls")]
pub fn tls_resolver(address: &SocketAddr, tls_host: &String) -> RecursiveResolver {
    let mut resolver_config = ResolverConfig::new();
    let mut name_server_config = NameServerConfig::new(*address, Protocol::Tls);
    name_server_config.tls_dns_name = Some(tls_host.to_owned());
    resolver_config.add_name_server(name_server_config);
    RecursiveResolver::new(resolver_config)
}

#[cfg(feature = "dns-over-https")]
pub fn https_resolver(address: &SocketAddr, tls_host: &String) -> RecursiveResolver {
    let mut resolver_config = ResolverConfig::new();
    let mut name_server_config = NameServerConfig::new(*address, Protocol::Https);
    name_server_config.tls_dns_name = Some(tls_host.to_owned());
    resolver_config.add_name_server(name_server_config);
    RecursiveResolver::new(resolver_config)
}

#[cfg(test)]
mod tests {
    use tokio::runtime::Runtime;

    use super::*;

    #[test]
    fn udp_resolver_test() {
        let dns_addr = "8.8.8.8:53".parse::<SocketAddr>().unwrap();
        let io_loop = Runtime::new().unwrap();
        let resolver = udp_resolver(&dns_addr);
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
        let resolver = tcp_resolver(&dns_addr);
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
    fn tls_resolver_test() {
        let dns_addr = "8.8.8.8:853".parse::<SocketAddr>().unwrap();
        let dns_host = String::from("dns.google");
        let io_loop = Runtime::new().unwrap();
        let resolver = tls_resolver(&dns_addr, &dns_host);
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
    fn https_resolver_test() {
        let dns_addr = "8.8.8.8:443".parse::<SocketAddr>().unwrap();
        let dns_host = String::from("dns.google");
        let io_loop = Runtime::new().unwrap();
        let resolver = https_resolver(&dns_addr, &dns_host);
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
