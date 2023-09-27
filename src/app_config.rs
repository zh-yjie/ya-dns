use crate::config::Upstream;
use crate::config::{Config, RequestRule, ResponseRule};
use crate::domain::DomainSuffix;
use crate::ip::IpRange;
use crate::resolver;
use crate::resolver::RecursiveResolver;
use regex::RegexSet;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct AppConfig {
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

impl AppConfig {
    pub fn new(config: Config) -> Self {
        // debug!(STDERR, "{:#?}", config);
        let resolvers: HashMap<_, _> = config
            .upstreams
            .iter()
            .map(|(name, upstream)| {
                (
                    name.to_owned(),
                    match upstream {
                        Upstream::TcpUpstream { address } => {
                            Arc::new(resolver::tcp_resolver(address))
                        }
                        Upstream::UdpUpstream { address } => {
                            Arc::new(resolver::udp_resolver(address))
                        }
                        #[cfg(feature = "dns-over-tls")]
                        Upstream::TlsUpstream { address, tls_host } => {
                            Arc::new(resolver::tls_resolver(address, tls_host))
                        }
                        #[cfg(feature = "dns-over-https")]
                        Upstream::HttpsUpstream { address, tls_host } => {
                            Arc::new(resolver::https_resolver(address, tls_host))
                        }
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

        AppConfig {
            defaults: Arc::new(config.default_upstreams),
            resolvers: Arc::new(resolvers),
            domains: Arc::new(domains),
            ranges: Arc::new(config.ranges),
            request_rules: Arc::new(config.request_rules),
            response_rules: Arc::new(config.response_rules),
        }
    }
}
