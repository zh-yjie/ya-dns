use crate::config::Domains;
use crate::config::Upstream;
use crate::config::{Config, RequestRule, ResponseRule};
use crate::ip::IpRange;
use crate::resolver;
use crate::resolver::RecursiveResolver;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppConfig {
    pub defaults: Arc<Vec<String>>,
    pub resolvers: Arc<HashMap<String, Arc<RecursiveResolver>>>,
    pub domains: Arc<HashMap<String, Domains>>,
    pub ranges: Arc<HashMap<String, IpRange>>,
    pub request_rules: Arc<Vec<RequestRule>>,
    pub response_rules: Arc<Vec<ResponseRule>>,
}

impl AppConfig {
    pub fn new(config: Config) -> Self {
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
                        Upstream::TlsUpstream { address, tls_host } => {
                            Arc::new(resolver::tls_resolver(address, tls_host))
                        }
                        Upstream::HttpsUpstream { address, tls_host } => {
                            Arc::new(resolver::https_resolver(address, tls_host))
                        }
                    },
                )
            })
            .collect();

        AppConfig {
            defaults: Arc::new(config.default_upstreams),
            resolvers: Arc::new(resolvers),
            domains: Arc::new(config.domains),
            ranges: Arc::new(config.ranges),
            request_rules: Arc::new(config.request_rules),
            response_rules: Arc::new(config.response_rules),
        }
    }
}
