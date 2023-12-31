use crate::{config::RuleAction, filter, handler_config::HandlerConfig, logger::stderr};
use async_recursion::async_recursion;
use futures::{
    future::{self, MapErr, MapOk},
    Future, FutureExt, TryFutureExt,
};
use hickory_proto::op::Query;
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
use slog::{debug, error};
use std::pin::Pin;

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
        let tasks: Vec<_> = resolvers
            .into_iter()
            .map(|name| {
                let domain1 = request.query().name().to_string();
                let domain2 = request.query().name().to_string();
                let query_type = request.query().query_type();
                let name1 = name.to_string();
                let name2 = name.to_string();
                let rs = handler_config().resolvers.get(name);
                rs.unwrap()
                    .resolve(domain1, query_type)
                    .boxed()
                    .map_ok(move |resp| (domain2, name1, resp))
                    .map_err(move |e| (name2, e))
            })
            .collect();

        #[async_recursion]
        async fn process_all(
            handler: &Handler,
            error: Option<ResolveError>,
            tasks: Vec<
                MapErr<
                    MapOk<
                        Pin<
                            Box<dyn Future<Output = Result<Lookup, ResolveError>> + 'static + Send>,
                        >,
                        impl FnOnce(Lookup) -> (String, String, Lookup) + 'static + Send,
                    >,
                    impl FnOnce(ResolveError) -> (String, ResolveError) + 'static + Send,
                >,
            >,
        ) -> Result<Lookup, ResolveError> {
            // responses that are not received yet
            if tasks.is_empty() {
                Err(error.unwrap_or(
                    ResolveErrorKind::NoRecordsFound {
                        query: Box::new(Query::new()),
                        soa: *Box::new(None),
                        negative_ttl: None,
                        response_code: ResponseCode::NXDomain,
                        trusted: false,
                    }
                    .into(),
                ))
            } else {
                match future::select_all(tasks).await {
                    (Ok((domain, name, resp)), _index, remaining) => {
                        //debug!(STDERR, "DNS {} result {:?}", name, resp);
                        match filter::check_response(handler_config(), &domain, &name, &resp) {
                            RuleAction::Accept => {
                                // Ignore the remaining future
                                tokio::spawn(future::join_all(remaining).map(|_| ()));
                                debug!(stderr(), "Use result from {}", name);
                                Ok(resp)
                            }
                            RuleAction::Drop => process_all(handler, None, remaining).await,
                        }
                    }
                    (Err((name, e)), _index, remaining) => {
                        error!(stderr(), "{}: {}", name, e);
                        process_all(handler, Some(e), remaining).await
                    }
                }
            }
        }

        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_recursion_available(true);
        match process_all(self, None, tasks).await {
            Ok(lookup) => {
                let records = lookup.records();
                let response = builder.build(header, records.iter(), &[], &[], &[]);
                Ok(responder.send_response(response).await?)
            }
            Err(e) => {
                let (soa, response_code) = match e.kind() {
                    ResolveErrorKind::NoRecordsFound {
                        query: _,
                        ref soa,
                        negative_ttl: _,
                        response_code,
                        trusted: _,
                    } => (soa.clone(), *response_code),
                    _ => (*Box::new(None), ResponseCode::ServFail),
                };
                header.set_response_code(response_code);
                let soa = &match soa {
                    Some(soa) => vec![soa.as_ref().to_owned().into_record_of_rdata()],
                    None => vec![],
                }[..];
                let response = builder.build(header, &[], &[], soa, &[]);
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
