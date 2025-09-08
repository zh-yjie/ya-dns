use std::{sync::Arc, time::Duration};

use crate::{config::RuleAction, filter, handler_config::HandlerConfig};
use crossbeam_channel::bounded;
use hickory_proto::{
    op::{LowerQuery, Query},
    rr::{Record, RecordType},
    ProtoErrorKind,
};
use hickory_resolver::{lookup::Lookup, ResolveError, ResolveErrorKind};
use hickory_server::{
    authority::MessageResponseBuilder,
    proto::op::{Header, MessageType, OpCode, ResponseCode},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};
use log::debug;
use tokio::{runtime::Runtime, time::timeout};

#[derive(Clone, Debug)]
struct RequestResult {
    lookup: Option<Lookup>,
    code: ResponseCode,
}

/// DNS Request Handler
#[derive(Clone, Debug)]
pub struct Handler {
    //pub counter: Arc<AtomicU64>,
    config: HandlerConfig,
}
impl Handler {
    /// Create handler from app config.
    pub fn new(cfg: HandlerConfig) -> Self {
        Handler { config: cfg }
    }

    /// Handle request, returning ResponseInfo if response was successfully sent, or an error.
    async fn do_handle_request(&self, request: &Request) -> Result<RequestResult, ResolveError> {
        let query = &request.queries()[0];
        debug!("DNS requests are forwarded to [{}].", query);
        // make sure the request is a query and the message type is a query
        if request.op_code() != OpCode::Query || request.message_type() != MessageType::Query {
            return Ok(RequestResult {
                lookup: None,
                code: ResponseCode::Refused,
            });
        }
        self.lookup(query).await
    }

    /// Lookup for anything else (NXDOMAIN)
    async fn lookup(&self, query: &LowerQuery) -> Result<RequestResult, ResolveError> {
        //self.counter.fetch_add(1, Ordering::SeqCst);
        let config = &self.config;
        let resolvers = filter::resolvers(config, query);
        let resolvers_len = resolvers.len();
        let (tx, rx) = bounded(resolvers_len);
        let rt = Runtime::new().unwrap();
        resolvers
            .into_iter()
            .map(|name| {
                (
                    config.resolvers.get(&name).cloned().unwrap(),
                    name,
                    query.name().clone(),
                )
            })
            .for_each(|(rs, name, qname)| {
                let tx1 = tx.clone();
                let domain = query.name().to_string();
                let query_type = query.query_type();
                rt.spawn(async move {
                    let res =
                        timeout(Duration::from_secs(5), rs.resolve(&domain, query_type)).await;
                    let lookup = match res {
                        Ok(lookup) => lookup,
                        Err(_) => {
                            Err(ResolveErrorKind::Proto(ProtoErrorKind::Timeout.into()).into())
                        }
                    };
                    match lookup {
                        Ok(lookup) => {
                            let _ = tx1.try_send(Some((lookup, name, domain)));
                        }
                        Err(e) => {
                            match e.into_soa() {
                                Some(soa) => {
                                    let lookup = Lookup::new_with_max_ttl(
                                        Query::query(qname.into(), query_type),
                                        Arc::from([soa.clone().into_record_of_rdata()]),
                                    );
                                    let _ = tx1.try_send(Some((lookup, name, domain)));
                                }
                                None => {
                                    let _ = tx1.try_send(None);
                                }
                            };
                        }
                    }
                });
            });
        let mut lookup_result = None;
        for _ in 0..resolvers_len {
            let lookup = rx.recv().unwrap();
            match lookup {
                Some((lookup, name, domain)) => {
                    match filter::check_response(config, &domain, &name, &lookup) {
                        RuleAction::Accept => {
                            debug!("Use result from {}", name);
                            lookup_result = Some(lookup);
                            break;
                        }
                        RuleAction::Drop => (),
                    }
                }
                None => {}
            }
        }
        rt.shutdown_background();
        drop(tx);
        match lookup_result {
            Some(lookup) => Ok(RequestResult {
                lookup: Some(lookup),
                code: ResponseCode::NoError,
            }),
            None => Ok(RequestResult {
                lookup: None,
                code: ResponseCode::NXDomain,
            }),
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
        let (result, qtype) = if request.queries().len() > 0 {
            (
                match self.do_handle_request(request).await {
                    Ok(info) => info,
                    Err(e) => {
                        debug!("Error in RequestHandler:{:#?}", e);
                        RequestResult {
                            lookup: None,
                            code: ResponseCode::ServFail,
                        }
                    }
                },
                request.queries()[0].query_type(),
            )
        } else {
            (
                RequestResult {
                    lookup: None,
                    code: ResponseCode::FormErr,
                },
                RecordType::ZERO,
            )
        };
        let records = result
            .lookup
            .map(move |l| l.records().to_owned())
            .unwrap_or(vec![]);
        let answers: Vec<Record> = records
            .clone()
            .iter()
            .filter(|r| {
                qtype == r.record_type() || (!r.record_type().is_ns() && !r.record_type().is_soa())
            })
            .map(|r| r.clone())
            .collect();
        let name_servers: Vec<Record> = records
            .clone()
            .iter()
            .filter(|r| !qtype.is_ns() && r.record_type().is_ns())
            .map(|r| r.clone())
            .collect();
        let soa: Vec<Record> = records
            .clone()
            .iter()
            .filter(|r| !qtype.is_soa() && r.record_type().is_soa())
            .map(|r| r.clone())
            .collect();
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_response_code(result.code);
        header.set_recursion_available(true);
        header.set_answer_count(answers.len().try_into().unwrap_or(0));
        header.set_name_server_count(name_servers.len().try_into().unwrap_or(0) + soa.len().try_into().unwrap_or(0));
        let message = builder.build(header, answers.iter(), name_servers.iter(), soa.iter(), &[]);
        response.send_response(message).await.unwrap()
    }
}
