use crate::app_config::AppConfig;
use crate::config::{Config, ConfigBuilder};
use crate::handler::Handler;
use anyhow::Result;
use clap::Parser;
use failure::Error;
use lazy_static::lazy_static;
use option::Args;
use slog::{crit, debug, info};
use slog::{o, Drain, Logger};
use std::fmt::Display;
use std::fs::File;
use std::io::prelude::*;
use std::net::SocketAddr;
use std::process::exit;
use std::time::Duration;
use tokio;
use tokio::net::{TcpListener, UdpSocket};
use trust_dns_server::ServerFuture;

mod app_config;
mod config;
mod domain;
mod filter;
mod handler;
mod ip;
mod option;
mod resolver;

struct MainConfig {
    pub bind: SocketAddr,
    pub app_config: AppConfig,
}

lazy_static! {
    static ref STDOUT: Logger = stdout_logger();
    static ref STDERR: Logger = stderr_logger();
    static ref CONFIG: MainConfig = {
        let config = config().unwrap_or_log();
        MainConfig {
            bind: config.bind,
            app_config: AppConfig::new(config),
        }
    };
}

#[tokio::main]
async fn main() -> Result<()> {
    let bind_socket = CONFIG.bind;
    let mut server = ServerFuture::new(Handler::default());

    let bind = UdpSocket::bind(bind_socket);
    info!(STDOUT, "Listening on UDP: {}", bind_socket);
    server.register_socket(bind.await?);

    let bind = TcpListener::bind(bind_socket);
    info!(STDOUT, "Listening on TCP: {}", bind_socket);
    server.register_listener(bind.await?, Duration::from_secs(10));

    server.block_until_done().await?;

    Ok(())
}

fn config() -> Result<Config, Error> {
    let args = Args::parse();
    let config_path = args.config;
    let mut file = File::open(config_path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    let builder: ConfigBuilder = toml::from_str(&content)?;
    builder.build()
}

fn stdout_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    Logger::root(drain, o!())
}

fn stderr_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build();
    let drain = std::sync::Mutex::new(drain).fuse();

    Logger::root(drain, o!())
}

trait ShouldSuccess {
    type Item;

    fn unwrap_or_log(self) -> Self::Item;

    fn unwrap_or_log_with<D: Display>(self, description: D) -> Self::Item;
}

impl<T, F> ShouldSuccess for Result<T, F>
where
    F: Into<Error>,
{
    type Item = T;

    fn unwrap_or_log(self) -> T {
        self.unwrap_or_else(|e| {
            let e: Error = e.into();
            crit!(STDERR, "{}", e);
            debug!(STDERR, "{:?}", e.backtrace());
            exit(1);
        })
    }

    fn unwrap_or_log_with<D: Display>(self, description: D) -> T {
        self.unwrap_or_else(|e| {
            let e: Error = e.into();
            crit!(STDERR, "{}: {}", description, e);
            debug!(STDERR, "{:?}", e.backtrace());
            exit(1);
        })
    }
}

trait Transpose {
    type Output;
    fn transpose(self) -> Self::Output;
}

impl<T, E> Transpose for Option<Result<T, E>> {
    type Output = Result<Option<T>, E>;

    fn transpose(self) -> Self::Output {
        match self {
            Some(Ok(x)) => Ok(Some(x)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }
}
