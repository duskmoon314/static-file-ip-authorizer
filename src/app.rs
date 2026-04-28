//! Core application runtime: state initialization, routes, and handler logic.

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post, put},
};
use ipnet::IpNet;
use std::{collections::BTreeSet, net::IpAddr};
use toasty::Db;
use toasty_driver_sqlite::Sqlite;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{Level, debug};

use crate::types::{
    AddWhitelistRequest, AppError, DirectoryRule, RulePayload, RulesPayload, SetPublicRequest,
    WhitelistEntry,
};

/// Shared application state injected into request handlers.
#[derive(Clone)]
pub(crate) struct AppState {
    /// Toasty database handle.
    pub(crate) db: Db,
}

/// Builds app state from a configured database driver and ensures schema exists.
pub(crate) async fn init_state_with_driver(driver: Sqlite) -> Result<AppState, AppError> {
    let mut builder = Db::builder();
    builder.models(toasty::models!(DirectoryRule, WhitelistEntry));

    let db = builder.build(driver).await?;
    if let Err(err) = db.push_schema().await {
        if is_schema_already_initialized_error(&err) {
            tracing::info!(error = %err, "database schema already initialized, skipping create");
        } else {
            return Err(err.into());
        }
    }
    Ok(AppState { db })
}

/// Builds app state backed by an in-memory SQLite database for tests.
#[cfg(test)]
pub(crate) async fn test_state_in_memory() -> AppState {
    init_state_with_driver(Sqlite::in_memory())
        .await
        .expect("in-memory state init should work")
}

/// Constructs the Axum router with all HTTP endpoints and middleware.
pub(crate) fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/auth", get(auth_handler))
        .route("/rules", get(list_rules_handler))
        .route("/rules/public", put(set_public_handler))
        .route("/rules/whitelist", post(add_whitelist_handler))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state)
}

/// Authorizes a proxied static-file request from forwarded headers.
async fn auth_handler(State(state): State<AppState>, headers: HeaderMap) -> StatusCode {
    let authorized: Result<bool, AppError> = async {
        let Some(client_ip) = parse_client_ip(&headers) else {
            return Ok(false);
        };
        let Some(uri) = parse_request_uri(&headers) else {
            return Ok(false);
        };

        debug!("auth request for uri `{uri}` from client IP {client_ip}");

        let mut db = state.db.clone();
        let mut rules = DirectoryRule::all().exec(&mut db).await?;
        rules.sort_by(|a, b| b.path_prefix.len().cmp(&a.path_prefix.len()));

        let Some(rule) = rules
            .into_iter()
            .find(|rule| directory_rule_matches_uri(&rule.path_prefix, &uri))
        else {
            return Ok(false);
        };

        if rule.is_public {
            return Ok(true);
        }

        let entries = WhitelistEntry::filter_by_directory_rule_id(rule.id)
            .exec(&mut db)
            .await?;

        Ok(entries
            .iter()
            .any(|entry| whitelist_entry_matches_ip(&entry.cidr_or_ip, client_ip)))
    }
    .await;

    match authorized {
        Ok(true) => StatusCode::OK,
        Ok(false) => StatusCode::FORBIDDEN,
        Err(_) => StatusCode::FORBIDDEN,
    }
}

/// Returns all rules in an export-friendly normalized JSON shape.
async fn list_rules_handler(State(state): State<AppState>) -> Result<Json<RulesPayload>, AppError> {
    let mut db = state.db.clone();
    let mut rules = DirectoryRule::all().exec(&mut db).await?;
    rules.sort_by(|a, b| a.path_prefix.cmp(&b.path_prefix));

    let mut payload = Vec::with_capacity(rules.len());
    for rule in rules {
        payload.push(export_rule(&mut db, rule).await?);
    }

    Ok(Json(RulesPayload { rules: payload }))
}

/// Upserts a directory rule and sets its public flag.
async fn set_public_handler(
    State(state): State<AppState>,
    Json(payload): Json<SetPublicRequest>,
) -> Result<Json<RulePayload>, AppError> {
    let normalized_dir = normalize_dir_prefix(&payload.dir)?;

    let mut db = state.db.clone();
    let existing = DirectoryRule::filter_by_path_prefix(&normalized_dir)
        .exec(&mut db)
        .await?;

    if let Some(mut rule) = existing.into_iter().next() {
        rule.update()
            .is_public(payload.public)
            .exec(&mut db)
            .await?;
    } else {
        toasty::create!(DirectoryRule {
            path_prefix: normalized_dir.clone(),
            is_public: payload.public
        })
        .exec(&mut db)
        .await?;
    }

    let rule = export_rule_by_dir(&mut db, &normalized_dir).await?;
    Ok(Json(rule))
}

/// Validates and appends whitelist entries for a directory rule.
async fn add_whitelist_handler(
    State(state): State<AppState>,
    Json(payload): Json<AddWhitelistRequest>,
) -> Result<Json<RulePayload>, AppError> {
    let normalized_dir = normalize_dir_prefix(&payload.dir)?;
    if payload.entries.is_empty() {
        return Err(AppError::BadRequest(
            "`entries` must contain at least one IP or CIDR".into(),
        ));
    }

    let mut normalized_entries = BTreeSet::new();
    for entry in payload.entries {
        normalized_entries.insert(normalize_whitelist_entry(&entry)?);
    }

    let mut db = state.db.clone();
    let rule = ensure_rule_exists(&mut db, &normalized_dir).await?;

    let existing = WhitelistEntry::filter_by_directory_rule_id(rule.id)
        .exec(&mut db)
        .await?;
    let mut existing_entries: BTreeSet<String> =
        existing.into_iter().map(|entry| entry.cidr_or_ip).collect();

    for entry in normalized_entries {
        if existing_entries.insert(entry.clone()) {
            toasty::create!(WhitelistEntry {
                directory_rule_id: rule.id,
                cidr_or_ip: entry
            })
            .exec(&mut db)
            .await?;
        }
    }

    let rule = export_rule_by_dir(&mut db, &normalized_dir).await?;
    Ok(Json(rule))
}

/// Normalizes a directory prefix into canonical matching form.
fn normalize_dir_prefix(input: &str) -> Result<String, AppError> {
    normalize_uri_for_matching(input).ok_or_else(|| {
        AppError::BadRequest("`dir` must be a non-empty path like /datasets/private".into())
    })
}

/// Loads and exports one rule by normalized directory key.
async fn export_rule_by_dir(db: &mut Db, dir: &str) -> Result<RulePayload, AppError> {
    let rule = DirectoryRule::filter_by_path_prefix(dir)
        .exec(db)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| AppError::Internal("rule missing after upsert".into()))?;
    export_rule(db, rule).await
}

/// Converts one persisted rule row into API payload format.
async fn export_rule(db: &mut Db, rule: DirectoryRule) -> Result<RulePayload, AppError> {
    let mut whitelist: Vec<String> = WhitelistEntry::filter_by_directory_rule_id(rule.id)
        .exec(db)
        .await?
        .into_iter()
        .map(|entry| entry.cidr_or_ip)
        .collect();
    whitelist.sort();

    Ok(RulePayload {
        dir: rule.path_prefix,
        public: rule.is_public,
        whitelist,
    })
}

/// Finds an existing rule by directory or creates a default private one.
async fn ensure_rule_exists(db: &mut Db, dir: &str) -> Result<DirectoryRule, AppError> {
    if let Some(rule) = DirectoryRule::filter_by_path_prefix(dir)
        .exec(db)
        .await?
        .into_iter()
        .next()
    {
        return Ok(rule);
    }

    Ok(toasty::create!(DirectoryRule {
        path_prefix: dir.to_string(),
        is_public: false
    })
    .exec(db)
    .await?)
}

/// Parses the client IP from the first value in `X-Forwarded-For`.
fn parse_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    let raw = headers.get("X-Forwarded-For")?.to_str().ok()?;
    let first = raw.split(',').next()?.trim();
    if first.is_empty() {
        return None;
    }
    first.parse::<IpAddr>().ok()
}

/// Parses and normalizes the requested URI from `X-Forwarded-Uri`.
fn parse_request_uri(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get("X-Forwarded-Uri")?.to_str().ok()?;
    normalize_uri_for_matching(raw)
}

/// Normalizes URI/path inputs for prefix-based authorization matching.
fn normalize_uri_for_matching(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    let path = trimmed.split('?').next()?.trim();
    if path.is_empty() {
        return None;
    }

    let mut normalized = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    while normalized.contains("//") {
        normalized = normalized.replace("//", "/");
    }
    while normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }
    Some(normalized)
}

/// Tests whether a directory prefix matches a target URI recursively.
fn directory_rule_matches_uri(prefix: &str, uri: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    if uri == prefix {
        return true;
    }
    uri.strip_prefix(prefix)
        .map(|rest| rest.starts_with('/'))
        .unwrap_or(false)
}

/// Validates and canonicalizes one whitelist entry as IP or CIDR.
fn normalize_whitelist_entry(input: &str) -> Result<String, AppError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(AppError::BadRequest(
            "whitelist entry must be a non-empty IP or CIDR".into(),
        ));
    }
    if let Ok(net) = trimmed.parse::<IpNet>() {
        return Ok(net.to_string());
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    Err(AppError::BadRequest(format!(
        "invalid whitelist entry `{trimmed}`; expected IPv4/IPv6 or CIDR"
    )))
}

/// Checks whether an IP matches one whitelist entry.
fn whitelist_entry_matches_ip(entry: &str, ip: IpAddr) -> bool {
    if let Ok(net) = entry.parse::<IpNet>() {
        return net.contains(&ip);
    }
    if let Ok(single_ip) = entry.parse::<IpAddr>() {
        return single_ip == ip;
    }
    false
}

/// Returns true when schema DDL failed only because objects already exist.
fn is_schema_already_initialized_error(err: &toasty::Error) -> bool {
    if !err.is_driver_operation_failed() {
        return false;
    }

    let message = err.to_string();
    let already_exists = message.contains("already exists");
    let is_create_stmt = message.contains("CREATE TABLE")
        || message.contains("CREATE INDEX")
        || message.contains("CREATE UNIQUE INDEX");

    already_exists && is_create_stmt
}
