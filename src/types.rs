//! Shared error, database model, and request/response types.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Application-level error type surfaced by handlers and setup routines.
#[derive(Debug, Error)]
pub(crate) enum AppError {
    /// Client-provided input is invalid.
    #[error("{0}")]
    BadRequest(String),
    /// Database or ORM operation failed.
    #[error(transparent)]
    Db(#[from] toasty::Error),
    /// Internal invariant or unexpected state failure.
    #[error("{0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    /// Converts application errors into JSON HTTP responses.
    fn into_response(self) -> Response {
        let status = match self {
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Db(_) | AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let error = self.to_string();
        (status, Json(ErrorPayload { error })).into_response()
    }
}

/// Serialized error response payload.
#[derive(Debug, Serialize)]
struct ErrorPayload {
    /// Human-readable error message.
    error: String,
}

/// Directory authorization rule persisted in the database.
#[derive(Debug, Clone, toasty::Model)]
pub(crate) struct DirectoryRule {
    /// Stable rule identifier.
    #[key]
    #[auto]
    pub(crate) id: uuid::Uuid,
    /// Normalized directory prefix, for example `/datasets/private`.
    #[unique]
    pub(crate) path_prefix: String,
    /// Whether this directory prefix is publicly accessible.
    pub(crate) is_public: bool,
}

/// Whitelist entry associated with a directory rule.
#[derive(Debug, Clone, toasty::Model)]
pub(crate) struct WhitelistEntry {
    /// Stable whitelist row identifier.
    #[key]
    #[auto]
    pub(crate) id: uuid::Uuid,
    /// Parent [`DirectoryRule`] identifier.
    #[index]
    pub(crate) directory_rule_id: uuid::Uuid,
    /// Single IP or CIDR string in canonical form.
    pub(crate) cidr_or_ip: String,
}

/// Normalized response shape for one directory rule.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RulePayload {
    /// Directory prefix.
    pub(crate) dir: String,
    /// Public-access flag.
    pub(crate) public: bool,
    /// Canonical whitelist entries.
    pub(crate) whitelist: Vec<String>,
}

/// Collection response for rule listing.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RulesPayload {
    /// All persisted rules.
    pub(crate) rules: Vec<RulePayload>,
}

/// Request body for toggling a directory's public visibility.
#[derive(Debug, Deserialize)]
pub(crate) struct SetPublicRequest {
    /// Directory prefix to update or create.
    pub(crate) dir: String,
    /// New public-access value.
    pub(crate) public: bool,
}

/// Request body for appending whitelist entries to a directory rule.
#[derive(Debug, Deserialize)]
pub(crate) struct AddWhitelistRequest {
    /// Directory prefix to update or create.
    pub(crate) dir: String,
    /// Entries to validate and append.
    pub(crate) entries: Vec<String>,
}
