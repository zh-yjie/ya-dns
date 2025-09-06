use futures::Future;
#[cfg(feature = "dns-over-h3")]
use hickory_proto::runtime::QuicSocketBinder;
use hickory_proto::runtime::{
    iocompat::AsyncIoTokioAsStd, RuntimeProvider, TokioHandle, TokioTime,
};
use hickory_resolver::name_server::GenericConnector;
#[cfg(feature = "dns-over-h3")]
use quinn::Runtime;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
#[cfg(feature = "dns-over-h3")]
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpSocket;
use tokio::time::timeout;

use crate::resolver_proxy;
use crate::resolver_proxy::ProxyConfig;

/// The Tokio Runtime for async execution
#[derive(Clone)]
pub struct ProxyRuntimeProvider {
    proxy: Option<ProxyConfig>,
    handle: TokioHandle,
}

impl ProxyRuntimeProvider {
    pub fn new(proxy: Option<ProxyConfig>) -> Self {
        Self {
            proxy,
            handle: TokioHandle::default(),
        }
    }
}

impl RuntimeProvider for ProxyRuntimeProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = resolver_proxy::Socks5UdpSocket;
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
            let socket = match server_addr {
                SocketAddr::V4(_) => TcpSocket::new_v4(),
                SocketAddr::V6(_) => TcpSocket::new_v6(),
            }?;

            if let Some(bind_addr) = bind_addr {
                socket.bind(bind_addr)?;
            }
            socket.set_nodelay(true)?;
            let future = resolver_proxy::connect_tcp(server_addr, proxy_config.as_ref());
            let wait_for = wait_for.unwrap_or(Duration::from_secs(5));
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
            resolver_proxy::bind_udp(local_addr, server_addr, proxy_config.as_ref()).await
        })
    }

    #[cfg(feature = "dns-over-h3")]
    fn quic_binder(&self) -> Option<&dyn QuicSocketBinder> {
        Some(&TokioQuicSocketBinder)
    }
}

#[cfg(feature = "dns-over-h3")]
struct TokioQuicSocketBinder;

#[cfg(feature = "dns-over-h3")]
impl QuicSocketBinder for TokioQuicSocketBinder {
    fn bind_quic(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Result<Arc<dyn quinn::AsyncUdpSocket>, io::Error> {
        let socket = std::net::UdpSocket::bind(local_addr)?;
        quinn::TokioRuntime.wrap_udp_socket(socket)
    }
}

pub type ProxyConnectionProvider = GenericConnector<ProxyRuntimeProvider>;
