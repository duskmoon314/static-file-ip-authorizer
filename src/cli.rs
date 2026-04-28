//! Command line arguments for the authorizer service.

use clap::Parser;
use std::{net::SocketAddr, path::PathBuf};

/// Process-level CLI configuration.
#[derive(Debug, Clone, Parser)]
#[command(name = "static-file-ip-authorizer")]
pub(crate) struct Cli {
    /// Socket address the HTTP server binds to.
    #[arg(long, default_value = "0.0.0.0:3000")]
    pub(crate) bind_addr: SocketAddr,
    /// SQLite database file path used for persisted rules.
    #[arg(long, default_value = "/var/lib/static-file-ip-authorizer/static-file-ip-authorizer.db")]
    pub(crate) database_path: PathBuf,
    /// `tracing_subscriber` filter expression controlling log verbosity.
    #[arg(long, default_value = "static_file_ip_authorizer=info,tower_http=info")]
    pub(crate) log_filter: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies CLI defaults are applied when no flags are passed.
    #[test]
    fn parse_uses_defaults() {
        let cli = Cli::parse_from(["static-file-ip-authorizer"]);
        assert_eq!(cli.bind_addr, "0.0.0.0:3000".parse().unwrap());
        assert_eq!(
            cli.database_path,
            PathBuf::from("/var/lib/static-file-ip-authorizer/static-file-ip-authorizer.db")
        );
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
        assert_eq!(cli.database_path, PathBuf::from("/tmp/custom.db"));
        assert_eq!(cli.log_filter, "debug");
    }
}
