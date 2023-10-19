use crate::config::{Config, ConfigBuilder};
use crate::handler::Handler;
use crate::logger::{STDERR, STDOUT};
use anyhow::Result;
use clap::Parser;
use failure::Error;
use hickory_server::ServerFuture;
use option::Args;
use slog::{crit, debug, info};
use std::fmt::Display;
use std::fs::File;
use std::io::prelude::*;
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
mod logger;
mod option;
mod resolver;

#[tokio::main]
async fn main() -> Result<()> {
    let config = config().unwrap_or_log();
    let bind_socket = config.bind;
    let mut server = ServerFuture::new(Handler::new(config.into()));

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
