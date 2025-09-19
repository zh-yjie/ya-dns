use async_trait::async_trait;
use fast_socks5::AuthenticationMethod;
use fast_socks5::Socks5Command;
use fast_socks5::client::Socks5Stream;
use fast_socks5::new_udp_header;
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::util::target_addr::ToTargetAddr;
use futures::ready;
use hickory_proto::runtime::TokioTime;
use hickory_proto::udp::DnsUdpSocket;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::net::ToSocketAddrs;
use std::task::Context;
use std::task::Poll;
use std::{
    fmt::{Display, Write},
    io,
    net::{AddrParseError, SocketAddr},
    pin::Pin,
    str::FromStr,
};
use thiserror::Error;
use tokio::net::TcpSocket;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::net::UdpSocket;
use url::{ParseError, Url};

pub async fn connect_tcp(
    server_addr: SocketAddr,
    bind_addr: Option<SocketAddr>,
    proxy: Option<&ProxyConfig>,
) -> io::Result<TcpStream> {
    let target_addr = server_addr.ip().to_string();
    let target_port = server_addr.port();
    let socket = match server_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }?;
    if let Some(bind_addr) = bind_addr {
        socket.bind(bind_addr)?;
    }
    socket.set_nodelay(true)?;
    match proxy {
        Some(proxy) => match proxy.proto {
            ProxyProtocol::Socks5 => {
                let auth: Option<AuthenticationMethod> = Some(proxy.into());
                let socket = TokioTcpStream::connect(proxy.server).await?;
                let target_addr = (target_addr.as_str(), target_port).to_target_addr()?;
                let socks_stream =
                    connect_socks5_server(Socks5Command::TCPConnect, socket, target_addr, auth)
                        .await;
                socks_stream
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
                    .map(|(socks_stream, _)| TcpStream::Proxy(socks_stream))
            }
            ProxyProtocol::Http => {
                use async_http_proxy::{http_connect_tokio, http_connect_tokio_with_basic_auth};
                let mut tcp = socket.connect(server_addr).await?;
                if let Some(user) = proxy.username.as_deref() {
                    http_connect_tokio_with_basic_auth(
                        &mut tcp,
                        &target_addr,
                        target_port,
                        user,
                        proxy.password.as_deref().unwrap_or_default(),
                    )
                    .await
                } else {
                    http_connect_tokio(&mut tcp, &target_addr, target_port).await
                }
                .map_err(from_http_err)?;

                Ok(TcpStream::Tokio(tcp))
            }
        },
        None => Ok(TcpStream::Tokio(socket.connect(server_addr).await?)),
    }
}

pub async fn bind_udp(
    local_addr: SocketAddr,
    _server_addr: SocketAddr,
    proxy: Option<&ProxyConfig>,
) -> io::Result<Socks5UdpSocket> {
    match proxy {
        Some(proxy) => match proxy.proto {
            ProxyProtocol::Socks5 => {
                let auth: Option<AuthenticationMethod> = Some(proxy.into());
                let client_src = TargetAddr::Ip("[::]:0".parse().unwrap());
                let udp_socket = UdpSocket::bind(local_addr).await?;
                let socket = TokioTcpStream::connect(proxy.server).await?;
                socket.set_nodelay(true)?;
                let (proxy_stream, proxy_addr) =
                    connect_socks5_server(Socks5Command::UDPAssociate, socket, client_src, auth)
                        .await?;
                let proxy_addr_resolved = proxy_addr.to_socket_addrs()?.next().unwrap();
                udp_socket.connect(proxy_addr_resolved).await?;
                Ok(Socks5UdpSocket::Proxy(udp_socket, proxy_stream))
            }
            _ => Ok(Socks5UdpSocket::Tokio(UdpSocket::bind(local_addr).await?)),
        },
        None => Ok(Socks5UdpSocket::Tokio(UdpSocket::bind(local_addr).await?)),
    }
}

#[cfg(any(feature = "dns-over-h3", feature = "dns-over-quic"))]
pub async fn quic_binder(
    local_addr: SocketAddr,
    _server_addr: SocketAddr,
    proxy: Option<&ProxyConfig>,
) -> io::Result<Socks5QuicSocket> {
    use quinn::{Runtime, TokioRuntime};

    match proxy {
        Some(proxy) => match proxy.proto {
            ProxyProtocol::Socks5 => {
                let auth: Option<AuthenticationMethod> = Some(proxy.into());
                let client_src = TargetAddr::Ip("[::]:0".parse().unwrap());
                let udp_socket = UdpSocket::bind(local_addr).await?;
                let socket = TokioTcpStream::connect(proxy.server).await?;
                socket.set_nodelay(true)?;
                let (proxy_stream, proxy_addr) =
                    connect_socks5_server(Socks5Command::UDPAssociate, socket, client_src, auth)
                        .await?;
                let proxy_addr_resolved = proxy_addr.to_socket_addrs()?.next().unwrap();
                udp_socket.connect(proxy_addr_resolved).await?;
                Ok(Socks5QuicSocket::proxy(
                    TokioRuntime.wrap_udp_socket(udp_socket.into_std()?)?,
                    Some(proxy_stream),
                    Some(proxy_addr_resolved),
                ))
            }
            _ => Ok(Socks5QuicSocket::direct(
                TokioRuntime.wrap_udp_socket(std::net::UdpSocket::bind(local_addr)?)?,
            )),
        },
        None => Ok(Socks5QuicSocket::direct(
            TokioRuntime.wrap_udp_socket(std::net::UdpSocket::bind(local_addr)?)?,
        )),
    }
}

fn from_http_err(err: async_http_proxy::HttpError) -> io::Error {
    match err {
        async_http_proxy::HttpError::IoError(io) => io,
        err => io::Error::new(io::ErrorKind::ConnectionRefused, err),
    }
}

pub async fn connect_socks5_server(
    cmd: Socks5Command,
    socket: TokioTcpStream,
    target_addr: TargetAddr,
    auth: Option<AuthenticationMethod>,
) -> io::Result<(Socks5Stream<TokioTcpStream>, TargetAddr)> {
    let config = Default::default();
    let mut socks_stream = Socks5Stream::use_stream(socket, auth, config)
        .await
        .unwrap();
    let bind_addr = socks_stream.request(cmd, target_addr).await.unwrap();
    Ok((socks_stream, bind_addr))
}

impl From<&ProxyConfig> for AuthenticationMethod {
    fn from(value: &ProxyConfig) -> Self {
        value
            .username
            .as_deref()
            .map(|username| AuthenticationMethod::Password {
                username: username.to_string(),
                password: value.password.as_deref().unwrap_or_default().to_string(),
            })
            .unwrap_or(AuthenticationMethod::None)
    }
}

pub enum TcpStream {
    Tokio(TokioTcpStream),
    Proxy(Socks5Stream<TokioTcpStream>),
}

impl tokio::io::AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            TcpStream::Tokio(s) => Pin::new(s).poll_read(cx, buf),
            TcpStream::Proxy(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            TcpStream::Tokio(s) => Pin::new(s).poll_write(cx, buf),
            TcpStream::Proxy(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        match self.get_mut() {
            TcpStream::Tokio(s) => Pin::new(s).poll_flush(cx),
            TcpStream::Proxy(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        match self.get_mut() {
            TcpStream::Tokio(s) => Pin::new(s).poll_shutdown(cx),
            TcpStream::Proxy(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub proto: ProxyProtocol,
    pub server: SocketAddr,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Display for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.proto {
            ProxyProtocol::Socks5 => "socks5://",
            ProxyProtocol::Http => "http://",
        })?;

        if let Some(user) = self.username.as_deref() {
            f.write_str(user)?;

            if let Some(pwd) = self.password.as_deref() {
                f.write_char(':')?;
                f.write_str(pwd)?;
            }
            f.write_char('@')?;
        }

        write!(f, "{}", self.server)?;

        Ok(())
    }
}

impl FromStr for ProxyConfig {
    type Err = ProxyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::from_str(s)?;

        let proto = match url.scheme() {
            "socks5" => ProxyProtocol::Socks5,
            "http" => ProxyProtocol::Http,
            scheme => return Err(ProxyParseError::UnexpectedSchema(scheme.to_string())),
        };

        let server = match url
            .socket_addrs(|| match proto {
                ProxyProtocol::Socks5 => Some(1080),
                _ => None,
            })
            .into_iter()
            .flatten()
            .next()
        {
            Some(s) => s,
            None => return Err(ParseError::InvalidDomainCharacter.into()),
        };

        let mut username = Some(url.username());
        if matches!(username, Some("")) {
            username = None;
        }

        let password = url.password();

        Ok(Self {
            proto,
            server,
            username: username.map(|s| s.to_string()),
            password: password.map(|s| s.to_string()),
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ProxyProtocol {
    Socks5,
    Http,
}

#[derive(Error, Debug)]
pub enum ProxyParseError {
    #[error("UnexpectedSchema {0:?}")]
    UnexpectedSchema(String),
    #[error(" address parse error {0:?}")]
    Addr(#[from] AddrParseError),
    #[error("{0:?}")]
    Parse(#[from] ParseError),
}

#[allow(dead_code)]
pub enum Socks5UdpSocket {
    Tokio(UdpSocket),
    Proxy(UdpSocket, Socks5Stream<TokioTcpStream>),
}

#[async_trait]
impl DnsUdpSocket for Socks5UdpSocket {
    type Time = TokioTime;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        match self {
            Socks5UdpSocket::Tokio(udp_socket) => {
                let mut buf = tokio::io::ReadBuf::new(buf);
                let addr = ready!(udp_socket.poll_recv_from(cx, &mut buf))?;
                let len = buf.filled().len();
                Poll::Ready(Ok((len, addr)))
            }
            Socks5UdpSocket::Proxy(udp_socket, _) => {
                let mut t_buf = [0u8; 0x10000];
                let mut r_buf = tokio::io::ReadBuf::new(&mut t_buf);
                ready!(udp_socket.poll_recv_from(cx, &mut r_buf))?;
                let size = r_buf.filled().len();
                let (addr, data, len) = parse_socks5_udp(&mut t_buf[..size]);
                buf[..len].copy_from_slice(data);
                Poll::Ready(Ok((len, addr)))
            }
        }
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        match self {
            Socks5UdpSocket::Tokio(udp_socket) => udp_socket.poll_send_to(cx, buf, target),
            Socks5UdpSocket::Proxy(udp_socket, _) => {
                let mut _buf = new_udp_header(target).unwrap();
                let _buf_len = _buf.len();
                _buf.extend_from_slice(buf);
                let len = ready!(udp_socket.poll_send(cx, &_buf))?;
                Poll::Ready(Ok(len - _buf_len))
            }
        }
    }
}

fn parse_socks5_udp<'a>(req: &'a [u8]) -> (SocketAddr, &'a [u8], usize) {
    let size = req.len();
    let mut position = 4;
    let atyp = read::<1>(&req[3..size])[0];
    let addr = match atyp {
        fast_socks5::consts::SOCKS5_ADDR_TYPE_IPV4 => {
            let [a, b, c, d] = read::<4>(&req[4..size]);
            let port = read::<2>(&req[8..size]);
            let port = (port[0] as u16) << 8 | port[1] as u16;
            position += 6;
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(a, b, c, d),
                port.into(),
            )))
        }
        fast_socks5::consts::SOCKS5_ADDR_TYPE_IPV6 => {
            let x = read::<16>(&req[4..size]);
            let port = read::<2>(&req[20..size]);
            let port = (port[0] as u16) << 8 | port[1] as u16;
            position += 18;
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(x),
                port.into(),
                0,
                0,
            )))
        }
        fast_socks5::consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
            let len = usize::from(read::<1>(&req[4..size])[0]);
            let mut domain = vec![];
            domain.copy_from_slice(&req[5..len]);
            let domain = String::from_utf8(domain).unwrap();
            let port = read::<2>(&req[(5 + len)..size]);
            let port = (port[0] as u16) << 8 | port[1] as u16;
            let target_addr = TargetAddr::Domain(domain, port);
            position += 3 + len;
            Some(target_addr.to_socket_addrs().unwrap().next().unwrap())
        }
        _ => Some(SocketAddr::from(([0, 0, 0, 0], 0))),
    };
    let len = size - position;
    let data = &req[position..size];
    (addr.unwrap(), data, len)
}

fn read<const N: usize>(buf: &[u8]) -> [u8; N] {
    let mut result = [0u8; N];
    result.copy_from_slice(&buf[..N]);
    result
}

#[cfg(any(feature = "dns-over-h3", feature = "dns-over-quic"))]
#[derive(Debug)]
pub struct Socks5QuicSocket {
    quic_socket: std::sync::Arc<dyn quinn::AsyncUdpSocket>,
    socks5_stream: Option<Socks5Stream<TokioTcpStream>>,
    proxy_addr: Option<SocketAddr>,
}

#[cfg(any(feature = "dns-over-h3", feature = "dns-over-quic"))]
impl Socks5QuicSocket {
    pub fn direct(quic_socket: std::sync::Arc<dyn quinn::AsyncUdpSocket>) -> Self {
        Self::proxy(quic_socket, None, None)
    }
    pub fn proxy(
        quic_socket: std::sync::Arc<dyn quinn::AsyncUdpSocket>,
        socks5_stream: Option<Socks5Stream<TokioTcpStream>>,
        proxy_addr: Option<SocketAddr>,
    ) -> Self {
        Socks5QuicSocket {
            quic_socket,
            socks5_stream,
            proxy_addr,
        }
    }
}

#[cfg(any(feature = "dns-over-h3", feature = "dns-over-quic"))]
impl quinn::AsyncUdpSocket for Socks5QuicSocket {
    fn create_io_poller(self: std::sync::Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.quic_socket.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        let mut destination = transmit.destination;
        let mut contents = Vec::new();
        if self.socks5_stream.is_some() {
            contents = new_udp_header(destination).unwrap();
            destination = self.proxy_addr.unwrap();
        }
        contents.extend_from_slice(transmit.contents);
        let new_transmit = quinn::udp::Transmit {
            destination: destination,
            ecn: transmit.ecn,
            contents: &contents,
            segment_size: transmit.segment_size,
            src_ip: transmit.src_ip,
        };
        self.quic_socket.try_send(&new_transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let size = ready!(self.quic_socket.poll_recv(cx, bufs, meta))?;
        if self.socks5_stream.is_some() {
            for i in 0..size {
                let buf: &[u8] = bufs[i].as_ref();
                let (_addr, data, _len) = parse_socks5_udp(&buf);
                let buffer = data.to_vec();
                bufs[i] = io::IoSliceMut::new(Box::leak(buffer.into_boxed_slice()));
            }
        }
        Poll::Ready(Ok(size))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.quic_socket.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.quic_socket.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.quic_socket.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.quic_socket.may_fragment()
    }
}
