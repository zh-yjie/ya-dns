use crate::{config::RuleAction, filter, handler_config::HandlerConfig, logger::stderr};
use crossbeam_channel::bounded;
use hickory_resolver::error::ResolveError;
use hickory_server::{
    authority::MessageResponseBuilder,
    proto::op::{Header, MessageType, OpCode, ResponseCode},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};
use once_cell::sync::OnceCell;
use slog::debug;
use std::thread;
use tokio::runtime::Runtime;

static HANDLER_CONFIG: OnceCell<HandlerConfig> = OnceCell::new();

fn handler_config() -> &'static HandlerConfig {
    HANDLER_CONFIG
        .get()
        .expect("HandlerConfig is not initialized")
}

/// DNS Request Handler
#[derive(Clone, Debug)]
pub struct Handler {
    //pub counter: Arc<AtomicU64>,
}

impl Handler {
    /// Create handler from app config.
    pub fn new(cfg: HandlerConfig) -> Self {
        match HANDLER_CONFIG.set(cfg) {
            _ => Handler {
                // counter: Arc::new(AtomicU64::new(0)),
            },
        }
    }

    /// Handle requests for anything else (NXDOMAIN)
    async fn do_handle_request_default<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, ResolveError> {
        //self.counter.fetch_add(1, Ordering::SeqCst);
        let resolvers = filter::resolvers(handler_config(), request.query());
        let resolvers_len = resolvers.len();
        let (tx, rx) = bounded(resolvers_len);
        resolvers
            .iter()
            .map(|name| {
                (
                    name.to_owned(),
                    request.query().name().to_string(),
                    request.query().query_type(),
                )
            })
            .for_each(|(name, domain, query_type)| {
                let tx1 = tx.clone();
                thread::spawn(move || {
                    let io_loop = Runtime::new().unwrap();
                    let rs = handler_config().resolvers.get(name);
                    let lookup = io_loop.block_on(rs.unwrap().resolve(&domain, query_type));
                    match lookup {
                        Ok(lookup) => {
                            match filter::check_response(handler_config(), &domain, &name, &lookup)
                            {
                                RuleAction::Accept => {
                                    let _ = tx1.try_send(Some((lookup, name)));
                                }
                                RuleAction::Drop => {
                                    let _ = tx1.try_send(None);
                                }
                            }
                        }
                        Err(_) => {
                            let _ = tx1.try_send(None);
                        }
                    }
                });
            });

        let mut lookup_result = None;
        for _ in 0..resolvers_len {
            let lookup = rx.recv().unwrap();
            match lookup {
                Some((lookup, name)) => {
                    debug!(stderr(), "Use result from {}", name);
                    drop(tx);
                    let records = lookup.records();
                    let builder = MessageResponseBuilder::from_message_request(request);
                    let mut header = Header::response_from_request(request.header());
                    header.set_recursion_available(true);
                    let response = builder.build(header, records.iter(), &[], &[], &[]);
                    lookup_result = Some(responder.send_response(response).await?);
                    break;
                }
                None => {}
            }
        }
        match lookup_result {
            Some(lookup) => Ok(lookup),
            None => {
                let builder = MessageResponseBuilder::from_message_request(request);
                let response = builder.error_msg(request.header(), ResponseCode::NXDomain);
                Ok(responder.send_response(response).await?)
            }
        }
    }

    /// Handle request, returning ResponseInfo if response was successfully sent, or an error.
    async fn do_handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response: R,
    ) -> Result<ResponseInfo, ResolveError> {
        debug!(
            stderr(),
            "DNS requests are forwarded to [{}].",
            request.query()
        );
        // make sure the request is a query and the message type is a query
        if request.op_code() != OpCode::Query || request.message_type() != MessageType::Query {
            let builder = MessageResponseBuilder::from_message_request(request);
            let mut header = Header::response_from_request(request.header());
            header.set_response_code(ResponseCode::Refused);
            let res = builder.build_no_records(header);
            return Ok(response.send_response(res).await?);
        }

        self.do_handle_request_default(request, response).await
    }
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response: R,
    ) -> ResponseInfo {
        // try to handle request
        match self.do_handle_request(request, response).await {
            Ok(info) => info,
            Err(e) => {
                debug!(stderr(), "Error in RequestHandler:{:#?}", e);
                let mut header = Header::new();
                header.set_response_code(ResponseCode::ServFail);
                header.into()
            }
        }
    }
}
