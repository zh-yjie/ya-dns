use std::time::Duration;

use crate::{config::RuleAction, filter, handler_config::HandlerConfig, logger::stderr};
use crossbeam_channel::bounded;
use hickory_resolver::{
    error::{ResolveError, ResolveErrorKind},
    lookup::Lookup,
};
use hickory_server::{
    authority::MessageResponseBuilder,
    proto::op::{Header, MessageType, OpCode, ResponseCode},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};
use once_cell::sync::OnceCell;
use slog::debug;
use tokio::{runtime::Runtime, time::timeout};

static HANDLER_CONFIG: OnceCell<HandlerConfig> = OnceCell::new();

fn handler_config() -> &'static HandlerConfig {
    HANDLER_CONFIG
        .get()
        .expect("HandlerConfig is not initialized")
}

#[derive(Clone, Debug)]
struct RequestResult {
    lookup: Option<Lookup>,
    code: ResponseCode,
}

/// Handle request, returning ResponseInfo if response was successfully sent, or an error.
async fn do_handle_request(request: &Request) -> Result<RequestResult, ResolveError> {
    debug!(
        stderr(),
        "DNS requests are forwarded to [{}].",
        request.query()
    );
    // make sure the request is a query and the message type is a query
    if request.op_code() != OpCode::Query || request.message_type() != MessageType::Query {
        return Ok(RequestResult {
            lookup: None,
            code: ResponseCode::Refused,
        });
    }
    do_handle_request_default(request).await
}

/// Handle requests for anything else (NXDOMAIN)
async fn do_handle_request_default(request: &Request) -> Result<RequestResult, ResolveError> {
    //self.counter.fetch_add(1, Ordering::SeqCst);
    let resolvers = filter::resolvers(handler_config(), request.query());
    let resolvers_len = resolvers.len();
    let (tx, rx) = bounded(resolvers_len);
    let rt = Runtime::new().unwrap();
    resolvers
        .iter()
        .map(|name| {
            (
                handler_config().resolvers.get(*name).cloned().unwrap(),
                *name,
                request.query().name().to_string(),
                request.query().query_type(),
            )
        })
        .for_each(|(rs, name, domain, query_type)| {
            let tx1 = tx.clone();
            rt.spawn(async move {
                let res = timeout(Duration::from_secs(1), rs.resolve(&domain, query_type)).await;
                let lookup = match res {
                    Ok(lookup) => lookup,
                    Err(_) => Err(ResolveErrorKind::Timeout.into()),
                };
                match lookup {
                    Ok(lookup) => {
                        let _ = tx1.try_send(Some((lookup, name, domain)));
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
            Some((lookup, name, domain)) => {
                match filter::check_response(handler_config(), &domain, name, &lookup) {
                    RuleAction::Accept => {
                        debug!(stderr(), "Use result from {}", name);
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
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response: R,
    ) -> ResponseInfo {
        // try to handle request
        let result = match do_handle_request(request).await {
            Ok(info) => info,
            Err(e) => {
                debug!(stderr(), "Error in RequestHandler:{:#?}", e);
                RequestResult {
                    lookup: None,
                    code: ResponseCode::ServFail,
                }
            }
        };
        let records = result
            .lookup
            .map(move |l| l.records().to_owned())
            .unwrap_or(vec![]);
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_response_code(result.code);
        header.set_recursion_available(true);
        let message = builder.build(header, records.iter(), &[], &[], &[]);
        response.send_response(message).await.unwrap()
    }
}
