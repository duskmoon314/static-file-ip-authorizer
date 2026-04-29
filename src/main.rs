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

use anyhow::Context;
use clap::Parser;
use std::{
    fs::{self, OpenOptions},
    io,
    path::Path,
};
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

/// Ensures the configured SQLite database path exists before opening it.
///
/// Returns `true` when this call created the database file.
pub(crate) fn prepare_database_file(path: &Path) -> io::Result<bool> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
            tracing::info!(
                database_directory = %parent.display(),
                "created database directory"
            );
        }
    }

    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(_) => {
            tracing::info!(database_path = %path.display(), "created database file");
            Ok(true)
        }
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            if path.is_file() {
                Ok(false)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("database path exists but is not a file: {}", path.display()),
                ))
            }
        }
        Err(err) => Err(err),
    }
}

/// Starts the authorizer HTTP server.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log_filter);

    let database_path = cli.database_path();
    prepare_database_file(&database_path).with_context(|| {
        format!(
            "unable to prepare database file `{}`",
            database_path.display()
        )
    })?;
    tracing::info!(database_path = %database_path.display(), "using database file");

    let state = init_state_with_driver(Sqlite::open(&database_path))
        .await
        .with_context(|| {
            format!(
                "database initialization failed for `{}`",
                database_path.display()
            )
        })?;
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(cli.bind_addr)
        .await
        .with_context(|| format!("failed to bind listener `{}`", cli.bind_addr))?;
    axum::serve(listener, app).await.context("server error")?;
    Ok(())
}
