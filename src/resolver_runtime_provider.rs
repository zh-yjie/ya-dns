use futures::Future;
#[cfg(any(feature = "dns-over-h3", feature = "dns-over-quic"))]
use hickory_proto::runtime::QuicSocketBinder;
use hickory_proto::runtime::{
    RuntimeProvider, TokioHandle, TokioTime, iocompat::AsyncIoTokioAsStd,
};
use hickory_resolver::name_server::GenericConnector;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

use crate::resolver_proxy;
use crate::resolver_proxy::{ProxyConfig, Socks5UdpSocket};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The Tokio Runtime for async execution
#[derive(Clone)]
pub struct ProxyRuntimeProvider {
    proxy: Option<Arc<ProxyConfig>>,
    handle: TokioHandle,
}

impl ProxyRuntimeProvider {
    pub fn new(proxy: Option<ProxyConfig>) -> Self {
        Self {
            proxy: proxy.map(Arc::new),
            handle: TokioHandle::default(),
        }
    }
}

impl RuntimeProvider for ProxyRuntimeProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = Socks5UdpSocket;
    type Tcp = AsyncIoTokioAsStd<resolver_proxy::TcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        wait_for: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        let proxy_config = self.proxy.clone();
        Box::pin(async move {
            let future = resolver_proxy::connect_tcp(server_addr, bind_addr, proxy_config.as_deref());
            let wait_for = wait_for.unwrap_or(CONNECT_TIMEOUT);
            match timeout(wait_for, future).await {
                Ok(Ok(socket)) => Ok(AsyncIoTokioAsStd(socket)),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connection to {server_addr:?} timed out after {wait_for:?}"),
                )),
            }
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        let proxy_config = self.proxy.clone();
        Box::pin(async move {
            let future = resolver_proxy::bind_udp(local_addr, server_addr, proxy_config.as_deref());
            let wait_for = CONNECT_TIMEOUT;
            match timeout(wait_for, future).await {
                Ok(Ok(socket)) => Ok(socket),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("bind {local_addr:?} timed out after {wait_for:?}"),
                )),
            }
        })
    }

    #[cfg(any(feature = "dns-over-h3", feature = "dns-over-quic"))]
    fn quic_binder(&self) -> Option<&dyn QuicSocketBinder> {
        Some(self)
    }
}

#[cfg(any(feature = "dns-over-h3", feature = "dns-over-quic"))]
impl QuicSocketBinder for ProxyRuntimeProvider {
    fn bind_quic(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Result<std::sync::Arc<dyn quinn::AsyncUdpSocket>, io::Error> {
        let socket = futures::executor::block_on(async {
            let future = resolver_proxy::quic_binder(local_addr, server_addr, self.proxy.as_deref());
            let wait_for = CONNECT_TIMEOUT;
            match timeout(wait_for, future).await {
                Ok(Ok(socket)) => Ok(socket),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("bind {local_addr:?} timed out after {wait_for:?}"),
                )),
            }
        })?;
        Ok(std::sync::Arc::new(socket))
    }
}

pub type ProxyConnectionProvider = GenericConnector<ProxyRuntimeProvider>;
