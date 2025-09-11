use async_trait::async_trait;
use fast_socks5::client::Config;
use fast_socks5::client::Socks5Stream;
use fast_socks5::new_udp_header;
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::AuthenticationMethod;
use fast_socks5::Socks5Command;
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
use std::time::Duration;
use std::{
    fmt::{Display, Write},
    io,
    net::{AddrParseError, SocketAddr},
    pin::Pin,
    str::FromStr,
};
use tokio::net::TcpSocket;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use thiserror::Error;
use url::{ParseError, Url};

pub async fn connect_tcp(
    server_addr: SocketAddr,
    bind_addr: Option<SocketAddr>,
    proxy: Option<&ProxyConfig>,
) -> io::Result<TcpStream> {
    let target_addr = server_addr.ip().to_string();
    let target_port = server_addr.port();

    match proxy {
        Some(proxy) => match proxy.proto {
            ProxyProtocol::Socks5 => {
                let socks5stream = if proxy.username.is_some() {
                    Socks5Stream::connect_with_password(
                        proxy.server,
                        target_addr,
                        target_port,
                        proxy
                            .username
                            .as_deref()
                            .map(|s| s.to_owned())
                            .unwrap_or_default(),
                        proxy
                            .password
                            .as_deref()
                            .map(|s| s.to_owned())
                            .unwrap_or_default(),
                        Default::default(),
                    )
                    .await
                } else {
                    Socks5Stream::connect(
                        proxy.server,
                        target_addr,
                        target_port,
                        Default::default(),
                    )
                    .await
                };

                socks5stream
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
                    .map(TcpStream::Proxy)
            }
            ProxyProtocol::Http => {
                use async_http_proxy::{http_connect_tokio, http_connect_tokio_with_basic_auth};

                let mut tcp = TokioTcpStream::connect(proxy.server).await?;

                if let Some(user) = proxy.username.as_deref() {
                    http_connect_tokio_with_basic_auth(
                        &mut tcp,
                        &target_addr,
                        target_port,
                        user,
                        proxy.password.as_deref().unwrap_or(""),
                    )
                    .await
                } else {
                    http_connect_tokio(&mut tcp, &target_addr, target_port).await
                }
                .map_err(from_http_err)?;

                Ok(TcpStream::Tokio(tcp))
            }
        },
        None => {
            let socket = match server_addr {
                SocketAddr::V4(_) => TcpSocket::new_v4(),
                SocketAddr::V6(_) => TcpSocket::new_v6(),
            }?;
            if let Some(bind_addr) = bind_addr {
                socket.bind(bind_addr)?;
            }
            socket.set_nodelay(true)?;
            Ok(TcpStream::Tokio(socket.connect(server_addr).await?))
        }
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
                let auth = if proxy.username.is_some() {
                    Some(AuthenticationMethod::Password {
                        username: proxy
                            .username
                            .as_deref()
                            .map(|s| s.to_owned())
                            .unwrap_or_default(),
                        password: proxy
                            .password
                            .as_deref()
                            .map(|s| s.to_owned())
                            .unwrap_or_default(),
                    })
                } else {
                    None
                };
                let future = TokioTcpStream::connect(proxy.server.clone());
                let wait_for = Duration::from_secs(5);
                match timeout(wait_for, future).await {
                    Ok(socket) => match socket {
                        Ok(backing_socket) => {
                            let client_src = TargetAddr::Ip("[::]:0".parse().unwrap());
                            let udp_socket = UdpSocket::bind(local_addr).await?;
                            let mut proxy_stream =
                                Socks5Stream::use_stream(backing_socket, auth, Config::default())
                                    .await
                                    .unwrap();
                            let proxy_addr = proxy_stream
                                .request(Socks5Command::UDPAssociate, client_src)
                                .await
                                .unwrap();
                            let proxy_addr_resolved = proxy_addr.to_socket_addrs()?.next().unwrap();
                            udp_socket.connect(proxy_addr_resolved).await?;
                            Ok(Socks5UdpSocket::Proxy(udp_socket, proxy_stream))
                        }
                        Err(e) => Err(e),
                    },
                    Err(_) => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "connection to proxy {0:?} timed out after {wait_for:?}",
                            proxy.server.clone()
                        ),
                    )),
                }
            }
            _ => Ok(Socks5UdpSocket::Tokio(UdpSocket::bind(local_addr).await?)),
        },
        None => Ok(Socks5UdpSocket::Tokio(UdpSocket::bind(local_addr).await?)),
    }
}

fn from_http_err(err: async_http_proxy::HttpError) -> io::Error {
    match err {
        async_http_proxy::HttpError::IoError(io) => io,
        err => io::Error::new(io::ErrorKind::ConnectionRefused, err),
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
            username: username.map(|s| s.to_owned()),
            password: password.map(|s| s.to_owned()),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocol {
    Socks5,
    Http,
}

#[derive(Error, Debug, PartialEq, Eq)]
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
