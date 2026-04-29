//! Command line arguments for the authorizer service.

use clap::Parser;
use directories::BaseDirs;
use std::{net::SocketAddr, path::PathBuf};

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const DATABASE_FILE_NAME: &str = concat!(env!("CARGO_PKG_NAME"), ".db");

/// Process-level CLI configuration.
#[derive(Debug, Clone, Parser)]
#[command(name = "static-file-ip-authorizer")]
pub(crate) struct Cli {
    /// Socket address the HTTP server binds to.
    #[arg(long, default_value = "0.0.0.0:3000")]
    pub(crate) bind_addr: SocketAddr,
    /// SQLite database file path used for persisted rules. Defaults to the OS
    /// user data path, or a local file if no user data directory is available.
    #[arg(long, value_name = "PATH")]
    pub(crate) database_path: Option<PathBuf>,
    /// `tracing_subscriber` filter expression controlling log verbosity.
    #[arg(long, default_value = "static_file_ip_authorizer=info,tower_http=info")]
    pub(crate) log_filter: String,
}

impl Cli {
    /// Returns the explicit database path or the user-writable default path.
    pub(crate) fn database_path(&self) -> PathBuf {
        self.database_path
            .clone()
            .unwrap_or_else(default_database_path)
    }
}

/// Returns the default SQLite database path.
pub(crate) fn default_database_path() -> PathBuf {
    BaseDirs::new()
        .map(|dirs| dirs.data_dir().join(APP_NAME).join(DATABASE_FILE_NAME))
        .unwrap_or_else(|| PathBuf::from(DATABASE_FILE_NAME))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies CLI defaults are applied when no flags are passed.
    #[test]
    fn parse_uses_defaults() {
        let cli = Cli::parse_from(["static-file-ip-authorizer"]);
        assert_eq!(cli.bind_addr, "0.0.0.0:3000".parse().unwrap());
        assert!(cli.database_path.is_none());
        assert_eq!(cli.database_path(), default_database_path());
        assert_eq!(
            cli.log_filter,
            "static_file_ip_authorizer=info,tower_http=info"
        );
    }

    /// Verifies CLI flags override default values.
    #[test]
    fn parse_overrides_defaults() {
        let cli = Cli::parse_from([
            "static-file-ip-authorizer",
            "--bind-addr",
            "127.0.0.1:8080",
            "--database-path",
            "/tmp/custom.db",
            "--log-filter",
            "debug",
        ]);
        assert_eq!(cli.bind_addr, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(cli.database_path(), PathBuf::from("/tmp/custom.db"));
        assert_eq!(cli.log_filter, "debug");
    }
}
