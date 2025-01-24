use futures::Future;
use hickory_proto::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::name_server::GenericConnector;
use std::io;
use std::pin::Pin;

use std::net::SocketAddr;

use hickory_proto::TokioTime;
use hickory_resolver::{name_server::RuntimeProvider, TokioHandle};

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
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        let proxy_config = self.proxy.clone();

        Box::pin(async move {
            resolver_proxy::connect_tcp(server_addr, proxy_config.as_ref())
                .await
                .map(AsyncIoTokioAsStd)
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
}

pub type ProxyConnectionProvider = GenericConnector<ProxyRuntimeProvider>;
