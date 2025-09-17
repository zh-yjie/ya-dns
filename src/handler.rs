use crate::{config::RuleAction, filter, handler_config::HandlerConfig};
use hickory_proto::{op::LowerQuery, rr::Record};
use hickory_resolver::ResolveError;
use hickory_server::{
    authority::MessageResponseBuilder,
    proto::op::{Header, MessageType, OpCode, ResponseCode},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};
use log::debug;
use std::time::Duration;
use tokio::runtime::{Builder, Runtime};

#[derive(Clone, Debug)]
struct RequestResult {
    answers: Option<Vec<Record>>,
    name_servers: Option<Vec<Record>>,
    soa: Option<Vec<Record>>,
    code: ResponseCode,
}

#[allow(dead_code)]
impl RequestResult {
    pub fn new_with_code(code: ResponseCode) -> Self {
        Self {
            answers: None,
            name_servers: None,
            soa: None,
            code,
        }
    }
    pub fn set_answers(&mut self, answers: Vec<Record>) {
        self.answers = Some(answers);
    }
    pub fn set_name_server(&mut self, name_servers: Vec<Record>) {
        self.name_servers = Some(name_servers);
    }
    pub fn set_soa(&mut self, soa: Vec<Record>) {
        self.soa = Some(soa);
    }
}

/// DNS Request Handler
#[derive(Debug)]
pub struct Handler {
    //pub counter: Arc<AtomicU64>,
    config: HandlerConfig,
    rt: Runtime,
}
impl Handler {
    /// Create handler from app config.
    pub fn new(cfg: HandlerConfig) -> Self {
        Handler {
            rt: Builder::new_multi_thread()
                .thread_name("handler-worker")
                .worker_threads(cfg.resolvers.len() * 2)
                .enable_all()
                .build()
                .unwrap(),
            config: cfg,
        }
    }

    /// Handle request, returning ResponseInfo if response was successfully sent, or an error.
    async fn do_handle_request(&self, request: &Request) -> Result<RequestResult, ResolveError> {
        let query = &request.queries()[0];
        debug!("DNS requests are forwarded to [{}].", query);
        // make sure the request is a query and the message type is a query
        if request.op_code() != OpCode::Query || request.message_type() != MessageType::Query {
            return Ok(RequestResult::new_with_code(ResponseCode::Refused));
        }
        self.lookup(query).await
    }

    /// Lookup for anything else (NXDOMAIN)
    async fn lookup(&self, query: &LowerQuery) -> Result<RequestResult, ResolveError> {
        //self.counter.fetch_add(1, Ordering::SeqCst);
        let config = &self.config;
        let resolvers = filter::resolvers(config, query);
        let mut join_set = tokio::task::JoinSet::new();
        resolvers.into_iter().for_each(|name| {
            if let Some(resolver) = config.resolvers.get(&name).cloned() {
                let domain = query.name().to_string();
                let query_type = query.query_type();
                join_set.spawn_on(
                    tokio::time::timeout(Duration::from_secs(5), async move {
                        let lookup = resolver.resolve(&domain, query_type).await;
                        (lookup, name, domain)
                    }),
                    self.rt.handle(),
                );
            }
        });
        let mut lookup_result = None;
        while let Some(res) = join_set.join_next().await {
            match res {
                Ok(lookup) => match lookup {
                    Ok((lookup, name, domain)) => {
                        match lookup {
                            Ok(lookup) => {
                                match filter::check_response(config, &domain, &name, &lookup) {
                                    RuleAction::Accept => {
                                        debug!("Use result from {}", name);
                                        let mut result =
                                            RequestResult::new_with_code(ResponseCode::NoError);
                                        result.set_answers(
                                            lookup.records().iter().cloned().collect(),
                                        );
                                        lookup_result = Some(result);
                                        break;
                                    }
                                    RuleAction::Drop => (),
                                }
                            }
                            Err(e) => match e.into_soa() {
                                Some(soa) => {
                                    let mut result =
                                        RequestResult::new_with_code(ResponseCode::NXDomain);
                                    result.set_soa(vec![soa.clone().into_record_of_rdata()]);
                                    lookup_result = Some(result);
                                }
                                None => (),
                            },
                        };
                    }
                    _ => {}
                },
                _ => {}
            };
        }
        join_set.abort_all();
        join_set.detach_all();
        match lookup_result {
            Some(lookup) => Ok(lookup),
            None => Ok(RequestResult::new_with_code(ResponseCode::NXDomain)),
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response: R,
    ) -> ResponseInfo {
        // try to handle request
        let result = if request.queries().len() > 0 {
            match self.do_handle_request(request).await {
                Ok(info) => info,
                Err(e) => {
                    debug!("Error in RequestHandler:{:#?}", e);
                    RequestResult::new_with_code(ResponseCode::ServFail)
                }
            }
        } else {
            RequestResult::new_with_code(ResponseCode::FormErr)
        };
        let answers = result.answers.unwrap_or_default();
        let name_servers: Vec<Record> = result.name_servers.unwrap_or_default();
        let soa: Vec<Record> = result.soa.unwrap_or_default();
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_response_code(result.code);
        header.set_recursion_available(true);
        let message = builder.build(header, answers.iter(), name_servers.iter(), soa.iter(), &[]);
        response.send_response(message).await.unwrap()
    }
}
