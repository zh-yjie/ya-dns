use crate::config::{Config, RequestRule, ResponseRule};
use crate::domain::DomainSuffix;
use crate::ip::IpRange;
use crate::resolver::RecursiveResolver;
use hickory_resolver::config::ResolverOpts;
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

impl From<Config> for HandlerConfig {
    fn from(config: Config) -> Self {
        // debug!(STDERR, "{:#?}", config);
        let mut opts = ResolverOpts::default();
        opts.timeout = config.resolver_opts.timeout;
        opts.ip_strategy = config.resolver_opts.ip_strategy.unwrap_or_default();
        opts.cache_size = config.resolver_opts.cache_size;
        let resolvers: HashMap<_, _> = config
            .upstreams
            .iter()
            .map(|(name, upstream)| (name.clone(), Arc::new((upstream, &opts).into())))
            .collect();

        let domains: HashMap<_, _> = config
            .domains
            .iter()
            .map(|(name, domains)| {
                (
                    name.clone(),
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
