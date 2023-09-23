use crate::app_config::AppConfig;
use crate::config::{Config, ConfigBuilder};
use crate::handler::Handler;
use anyhow::Result;
use clap::Parser;
use failure::Error;
use lazy_static::lazy_static;
use slog::{crit, debug, info};
use slog::{o, Drain, Logger};
use std::fmt::Display;
use std::fs::File;
use std::io::prelude::*;
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
mod resolver;

lazy_static! {
    static ref STDOUT: Logger = stdout_logger();
    static ref STDERR: Logger = stderr_logger();
    static ref APPCONFIG: AppConfig = AppConfig::new(config().unwrap_or_log());
}

const TCP_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<()> {
    let conf = config().unwrap_or_log();
    //debug!(STDERR, "{:#?}", conf);

    let bind_socket = conf.bind;
    let request_handler = Handler::new();
    let mut server = ServerFuture::new(request_handler);

    let bind = UdpSocket::bind(bind_socket);
    info!(STDOUT, "Listening on UDP: {}", bind_socket);
    server.register_socket(bind.await?);

    let bind = TcpListener::bind(bind_socket);
    info!(STDOUT, "Listening on TCP: {}", bind_socket);
    server.register_listener(bind.await?, TCP_TIMEOUT);

    server.block_until_done().await?;

    Ok(())
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(
        short,
        long,
        default_value = "config.toml",
        value_name = "CONFIG_FILE",
        help = "Specify the config file"
    )]
    config: String,
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

// Wait for #47338 to be stable
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
