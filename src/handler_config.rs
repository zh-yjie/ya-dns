use crate::config::{Config, RequestRule, ResponseRule};
use crate::domain::DomainSuffix;
use crate::ip::IpRange;
use crate::resolver::RecursiveResolver;
use regex::RegexSet;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug)]
pub struct HandlerConfig {
    pub defaults: Arc<Vec<String>>,
    pub resolvers: Arc<HashMap<String, Arc<RecursiveResolver>>>,
    pub domains: Arc<HashMap<String, Domains>>,
    pub ranges: Arc<HashMap<String, IpRange>>,
    pub request_rules: Arc<Vec<RequestRule>>,
    pub response_rules: Arc<Vec<ResponseRule>>,
}

#[derive(Debug)]
pub struct Domains {
    pub regex_set: RegexSet,
    pub suffix: DomainSuffix,
}

impl Default for Domains {
    fn default() -> Self {
        Self {
            regex_set: RegexSet::default(),
            suffix: DomainSuffix::default(),
        }
    }
}

impl From<Config> for HandlerConfig {
    fn from(config: Config) -> Self {
        // debug!(STDERR, "{:#?}", config);
        let resolvers: HashMap<_, _> = config
            .upstreams
            .iter()
            .map(|(name, upstream)| {
                (
                    name.clone(),
                    Arc::new((upstream, Some(config.resolver_opts)).into()),
                )
            })
            .collect();

        let domains: HashMap<_, _> = config
            .domains
            .into_iter()
            .map(|(name, domains)| match domains.build() {
                Ok(domains) => (
                    name,
                    Domains {
                        regex_set: RegexSet::new(&domains.regex_set).unwrap_or_default(),
                        suffix: domains.suffix_set.join("\n").parse().unwrap_or_default(),
                    },
                ),
                Err(_) => (name, Domains::default()),
            })
            .collect();

        let ranges: HashMap<_, _> = config
            .ranges
            .into_iter()
            .map(|(key, ip_range)| match ip_range.build() {
                Ok(ip_range) => (key, ip_range),
                Err(_) => (key, IpRange::default()),
            })
            .collect();

        HandlerConfig {
            defaults: Arc::new(config.default_upstreams),
            resolvers: Arc::new(resolvers),
            domains: Arc::new(domains),
            ranges: Arc::new(ranges),
            request_rules: Arc::new(config.request_rules),
            response_rules: Arc::new(config.response_rules),
        }
    }
}
