use crate::config::{Config, ConfigBuilder};
use crate::handler::Handler;
use clap::Parser;
use config::ConfigError;
use hickory_server::ServerFuture;
use log::{error, info};
use option::Args;
use std::fs::File;
use std::process::exit;
use std::time::Duration;
use std::{io, io::prelude::*};
use tokio;
use tokio::net::{TcpListener, UdpSocket};

mod config;
mod domain;
mod filter;
mod handler;
mod handler_config;
mod ip;
mod option;
mod resolver;
mod resolver_proxy;
mod resolver_runtime_provider;

#[cfg(not(target_os = "windows"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> io::Result<()> {
    #[cfg(feature = "debug")]
    console_subscriber::ConsoleLayer::builder()
        .retention(Duration::from_secs(60))
        .server_addr(([0, 0, 0, 0], 5555))
        .init();

    let config = config().unwrap_or_log();

    #[cfg(feature = "logging")]
    init_logger(config.log_level);

    let bind_socket = config.bind;
    let mut server = ServerFuture::new(Handler::new(config.into()));

    let bind = UdpSocket::bind(bind_socket).await?;
    info!("Listening on UDP: {}", bind_socket);
    server.register_socket(bind);

    let bind = TcpListener::bind(bind_socket).await?;
    info!("Listening on TCP: {}", bind_socket);
    server.register_listener(bind, Duration::from_secs(10));

    Ok(server.block_until_done().await?)
}

#[cfg(feature = "logging")]
fn init_logger(log_level: log::LevelFilter) {
    let mut builder = env_logger::Builder::new();
    builder.filter_level(log_level);
    builder.parse_default_env();
    builder.init();
}

fn config() -> Result<Config, ConfigError> {
    let args = Args::parse();
    let config_path = args.config;
    let mut file = File::open(config_path).unwrap();
    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();

    let builder: ConfigBuilder = toml::from_str(&content).unwrap();
    builder.build()
}

trait ShouldSuccess {
    type Item;

    fn unwrap_or_log(self) -> Self::Item;
}

impl<T, F> ShouldSuccess for Result<T, F>
where
    F: Into<ConfigError>,
{
    type Item = T;

    fn unwrap_or_log(self) -> T {
        self.unwrap_or_else(|e| {
            let e: ConfigError = e.into();
            error!("{}", e);
            exit(1);
        })
    }
}
