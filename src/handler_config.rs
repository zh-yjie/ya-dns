use crate::config::Upstream;
use crate::config::{Config, RequestRule, ResponseRule};
use crate::domain::DomainSuffix;
use crate::ip::IpRange;
use crate::resolver;
use crate::resolver::RecursiveResolver;
use hickory_resolver::config::ResolverOpts;
use regex::RegexSet;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct HandlerConfig {
    pub defaults: Arc<Vec<String>>,
    pub resolvers: Arc<HashMap<String, Arc<RecursiveResolver>>>,
    pub domains: Arc<HashMap<String, Domains>>,
    pub ranges: Arc<HashMap<String, IpRange>>,
    pub request_rules: Arc<Vec<RequestRule>>,
    pub response_rules: Arc<Vec<ResponseRule>>,
}

#[derive(Clone, Debug)]
pub struct Domains {
    pub regex_set: RegexSet,
    pub suffix: DomainSuffix,
}

impl From<Config> for HandlerConfig {
    fn from(config: Config) -> Self {
        // debug!(STDERR, "{:#?}", config);
        let mut opts = ResolverOpts::default();
        opts.timeout = config.resolver_opts.timeout;
        opts.ip_strategy = config.resolver_opts.ip_strategy.unwrap_or_default();
        opts.cache_size = config.resolver_opts.cache_size;
        let lookup_ip_only = config.resolver_opts.ip_strategy.is_some();
        let resolvers: HashMap<_, _> = config
            .upstreams
            .iter()
            .map(|(name, upstream)| {
                (
                    name.to_owned(),
                    match upstream {
                        Upstream::TcpUpstream { address, proxy } => Arc::new(
                            resolver::tcp_resolver(address, opts.to_owned(), lookup_ip_only, proxy),
                        ),
                        Upstream::UdpUpstream { address } => Arc::new(resolver::udp_resolver(
                            address,
                            opts.to_owned(),
                            lookup_ip_only,
                        )),
                        #[cfg(feature = "dns-over-tls")]
                        Upstream::TlsUpstream {
                            address,
                            tls_host,
                            proxy,
                        } => Arc::new(resolver::tls_resolver(
                            address,
                            tls_host,
                            opts.to_owned(),
                            lookup_ip_only,
                            proxy,
                        )),
                        #[cfg(feature = "dns-over-https")]
                        Upstream::HttpsUpstream {
                            address,
                            tls_host,
                            proxy,
                        } => Arc::new(resolver::https_resolver(
                            address,
                            tls_host,
                            opts.to_owned(),
                            lookup_ip_only,
                            proxy,
                        )),
                    },
                )
            })
            .collect();

        let domains: HashMap<_, _> = config
            .domains
            .iter()
            .map(|(name, domains)| {
                (
                    name.to_owned(),
                    Domains {
                        regex_set: RegexSet::new(&domains.regex_set).unwrap(),
                        suffix: domains.suffix_set.join("\n").parse().unwrap(),
                    },
                )
            })
            .collect();

        HandlerConfig {
            defaults: Arc::new(config.default_upstreams),
            resolvers: Arc::new(resolvers),
            domains: Arc::new(domains),
            ranges: Arc::new(config.ranges),
            request_rules: Arc::new(config.request_rules),
            response_rules: Arc::new(config.response_rules),
        }
    }
}
