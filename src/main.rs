//! Static file IP authorizer service.
//!
//! This binary runs an Axum HTTP service intended to be used behind a reverse
//! proxy (for example Caddy/Nginx) to authorize access to static paths based on
//! directory rules and IP/CIDR whitelists.
#![deny(missing_docs)]

/// HTTP application state, routing, and authorization logic.
mod app;
/// Command line argument parsing.
mod cli;
/// Shared data and error types.
mod types;

#[cfg(test)]
mod tests;

use clap::Parser;
use toasty_driver_sqlite::Sqlite;
use tracing_subscriber::{EnvFilter, fmt};

use crate::{
    app::{build_router, init_state_with_driver},
    cli::Cli,
};

/// Initializes tracing with a user-supplied filter expression.
pub(crate) fn init_tracing(filter: &str) {
    let filter =
        EnvFilter::try_new(filter).expect("invalid --log-filter, expected tracing filter syntax");
    fmt().with_env_filter(filter).with_target(false).init();
}

/// Starts the authorizer HTTP server.
#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_tracing(&cli.log_filter);

    let state = init_state_with_driver(Sqlite::open(&cli.database_path))
        .await
        .expect("database initialization failed");
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(cli.bind_addr)
        .await
        .expect("failed to bind listener");
    axum::serve(listener, app).await.expect("server error");
}
