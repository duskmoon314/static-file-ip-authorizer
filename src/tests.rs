use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};
use toasty_driver_sqlite::Sqlite;
use tower::ServiceExt;

use crate::app::{build_router, test_state_in_memory};

/// Sends a `PUT /rules/public` request and returns the status code.
async fn put_public_rule(app: &Router, dir: &str, public: bool) -> StatusCode {
    let req = Request::builder()
        .method("PUT")
        .uri("/rules/public")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "dir": dir,
                "public": public
            })
            .to_string(),
        ))
        .unwrap();
    app.clone().oneshot(req).await.unwrap().status()
}

/// Sends a `POST /rules/whitelist` request and returns the status code.
async fn post_whitelist(app: &Router, dir: &str, entries: Vec<String>) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri("/rules/whitelist")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "dir": dir,
                "entries": entries
            })
            .to_string(),
        ))
        .unwrap();
    app.clone().oneshot(req).await.unwrap().status()
}

/// Missing forwarded headers should fail closed.
#[tokio::test]
async fn auth_denies_when_headers_missing() {
    let state = test_state_in_memory().await;
    let app = build_router(state);

    let req = Request::builder().uri("/auth").body(Body::empty()).unwrap();
    let res = app.oneshot(req).await.unwrap();

    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

/// Public directory rules should allow access regardless of client IP.
#[tokio::test]
async fn auth_allows_public_directory() {
    let state = test_state_in_memory().await;
    let app = build_router(state.clone());

    assert_eq!(
        put_public_rule(&app, "/datasets/share", true).await,
        StatusCode::OK
    );

    let req = Request::builder()
        .uri("/auth")
        .header("X-Forwarded-For", "203.0.113.10")
        .header("X-Forwarded-URI", "/datasets/share/file.txt")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

/// Non-public rules should allow only matching whitelisted ranges.
#[tokio::test]
async fn auth_allows_whitelisted_cidr() {
    let state = test_state_in_memory().await;
    let app = build_router(state.clone());

    assert_eq!(
        put_public_rule(&app, "/datasets/private", false).await,
        StatusCode::OK
    );
    assert_eq!(
        post_whitelist(&app, "/datasets/private", vec!["10.10.0.0/16".to_string()]).await,
        StatusCode::OK
    );

    let req = Request::builder()
        .uri("/auth")
        .header("X-Forwarded-For", "10.10.5.99")
        .header("X-Forwarded-URI", "/datasets/private/a.bin")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

/// Listing rules should return the complete normalized export shape.
#[tokio::test]
async fn list_rules_returns_full_export_shape() {
    let state = test_state_in_memory().await;
    let app = build_router(state.clone());

    assert_eq!(
        put_public_rule(&app, "/datasets/private", false).await,
        StatusCode::OK
    );
    assert_eq!(
        post_whitelist(
            &app,
            "/datasets/private",
            vec!["192.168.0.0/24".to_string(), "2001:db8::/32".to_string()],
        )
        .await,
        StatusCode::OK
    );

    let req = Request::builder()
        .uri("/rules")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let payload: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(payload["rules"].as_array().unwrap().len(), 1);
    assert_eq!(payload["rules"][0]["dir"], "/datasets/private");
    assert_eq!(payload["rules"][0]["public"], false);
    assert_eq!(
        payload["rules"][0]["whitelist"],
        json!(["192.168.0.0/24", "2001:db8::/32"])
    );
}

/// `PUT /rules/public` should upsert and normalize directory paths.
#[tokio::test]
async fn put_rules_public_endpoint_upserts() {
    let state = test_state_in_memory().await;
    let app = build_router(state);

    let req = Request::builder()
        .method("PUT")
        .uri("/rules/public")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "dir": "/datasets/new/",
                "public": true
            })
            .to_string(),
        ))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["dir"], "/datasets/new");
    assert_eq!(payload["public"], true);
    assert_eq!(payload["whitelist"], json!([]));
}

/// Invalid whitelist entries should be rejected as bad requests.
#[tokio::test]
async fn post_whitelist_rejects_invalid_entry() {
    let state = test_state_in_memory().await;
    let app = build_router(state);

    assert_eq!(
        post_whitelist(&app, "/datasets/private", vec!["not-an-ip".to_string()]).await,
        StatusCode::BAD_REQUEST
    );
}

/// Reinitializing on the same file-backed database should not fail.
#[tokio::test]
async fn init_state_handles_existing_file_db() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "static-file-ip-authorizer-{nanos}-{}.db",
        std::process::id()
    ));

    let _ = std::fs::remove_file(&path);

    let first = crate::app::init_state_with_driver(Sqlite::open(&path)).await;
    assert!(first.is_ok());
    let second = crate::app::init_state_with_driver(Sqlite::open(&path)).await;
    assert!(second.is_ok());

    drop(first);
    drop(second);
    let _ = std::fs::remove_file(&path);
}

/// Startup database preparation should create missing parent directories and files.
#[test]
fn prepare_database_file_creates_missing_parent_directory_and_file() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "static-file-ip-authorizer-prepare-{nanos}-{}",
        std::process::id()
    ));
    let path = root.join("state").join("rules.db");

    let created = crate::prepare_database_file(&path).unwrap();

    assert!(created);
    assert!(path.is_file());

    let _ = std::fs::remove_dir_all(root);
}

/// Startup database preparation should not truncate an existing SQLite file.
#[test]
fn prepare_database_file_preserves_existing_file() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "static-file-ip-authorizer-prepare-existing-{nanos}-{}",
        std::process::id()
    ));
    let path = root.join("rules.db");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(&path, b"existing").unwrap();

    let created = crate::prepare_database_file(&path).unwrap();

    assert!(!created);
    assert_eq!(std::fs::read(&path).unwrap(), b"existing");

    let _ = std::fs::remove_dir_all(root);
}
