use crate::config::{Config, ConfigBuilder, ConfigError};
use crate::handler::Handler;
use crate::option::Args;
use clap::Parser;
use hickory_server::ServerFuture;
use log::info;
use std::io;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::Duration;
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

#[tokio::main]
async fn main() -> io::Result<()> {
    #[cfg(feature = "debug")]
    console_subscriber::ConsoleLayer::builder()
        .retention(Duration::from_secs(60))
        .server_addr(([0, 0, 0, 0], 5555))
        .init();

    let config = match config() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Error loading configuration: {}", e);
            exit(1);
        }
    };

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
    let config_path = match args.config {
        Some(path) => PathBuf::from(path),
        None => {
            let default_files = ["config.toml", "config.yaml", "config.yml"];
            let mut found_path = None;
            for file in &default_files {
                let path = Path::new(file);
                if path.exists() {
                    found_path = Some(path.to_path_buf());
                    break;
                }
            }
            found_path.ok_or(ConfigError::FileNotFound)?
        }
    };

    let builder = ConfigBuilder::from_file(&config_path)?;
    builder.build()
}
