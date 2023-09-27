use crate::{config::RuleAction, filter, CONFIG, STDERR};
use async_recursion::async_recursion;
use futures::{
    future::{self, MapErr, MapOk},
    Future, FutureExt, TryFutureExt,
};
use slog::{debug, error};
use std::pin::Pin;
use trust_dns_proto::op::Query;
use trust_dns_resolver::{
    error::{ResolveError, ResolveErrorKind},
    lookup::Lookup,
};
use trust_dns_server::{
    authority::MessageResponseBuilder,
    proto::op::{Header, MessageType, OpCode, ResponseCode},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid OpCode {0:}")]
    InvalidOpCode(OpCode),
    #[error("Invalid MessageType {0:}")]
    InvalidMessageType(MessageType),
    #[error("IO error: {0:}")]
    Io(#[from] std::io::Error),
}

/// DNS Request Handler
#[derive(Clone)]
pub struct Handler {
    //pub counter: Arc<AtomicU64>,
}

impl Handler {
    /// Create new handler from command-line options.
    pub fn new() -> Self {
        Handler {
            // counter: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Handle requests for anything else (NXDOMAIN)
    async fn do_handle_request_default<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        //self.counter.fetch_add(1, Ordering::SeqCst);
        let resolvers = filter::resolvers(request.query());
        let tasks: Vec<_> = resolvers
            .into_iter()
            .map(|name| {
                let domain1 = request.query().name().to_string().to_owned();
                let domain2 = request.query().name().to_string().to_owned();
                let query_type = request.query().query_type().to_owned();
                let name1 = name.to_owned();
                let name2 = name.to_owned();
                let rs = CONFIG.app_config.resolvers.get(name);
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
                        match filter::check_response(&domain, &name, &resp) {
                            RuleAction::Accept => {
                                // Ignore the remaining future
                                tokio::spawn(future::join_all(remaining).map(|_| ()));
                                debug!(STDERR, "Use result from {}", name);
                                Ok(resp)
                            }
                            RuleAction::Drop => process_all(handler, None, remaining).await,
                        }
                    }
                    (Err((name, e)), _index, remaining) => {
                        error!(STDERR, "{}: {}", name, e);
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
        response: R,
    ) -> Result<ResponseInfo, Error> {
        debug!(
            STDERR,
            "DNS requests are forwarded to [{}].",
            request.query()
        );
        // make sure the request is a query
        if request.op_code() != OpCode::Query {
            return Err(Error::InvalidOpCode(request.op_code()));
        }

        // make sure the message type is a query
        if request.message_type() != MessageType::Query {
            return Err(Error::InvalidMessageType(request.message_type()));
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
                debug!(STDERR, "Error in RequestHandler:{:#?}", e);
                let mut header = Header::new();
                header.set_response_code(ResponseCode::ServFail);
                header.into()
            }
        }
    }
}
