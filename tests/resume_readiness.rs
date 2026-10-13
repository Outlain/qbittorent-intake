//! A rejected Resume must preserve the durable pause and explain every failed
//! readiness check in the shape consumed by the existing settings interface.
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use serde_json::{json, Value};
use torrent_intake::{
    config::Config,
    http::{router, App},
    persistence::{state, Database},
};
use tower::ServiceExt;

#[test]
fn failed_resume_reports_checks_and_preserves_pause() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let mut config = Config::defaults();
    config.values["data_dir"] = json!(root);
    config.values["database_url"] = json!(format!("sqlite:///{}", root.join("db").display()));
    config.values["event_dir"] = json!(root);
    config.values["local_staging_root"] = json!(root);
    config.values["clamd_socket_path"] = json!(root.join("unavailable.sock"));
    // This placeholder deliberately skips even the read-only qBittorrent probe.
    config.values["qbt_password"] = json!("REPLACE_WITH_TEST_SECRET");
    config.values["infected_action"] = json!("delete");
    let app = App::new(
        config.clone(),
        Database::open(config.database_path().unwrap()).unwrap(),
        true,
    )
    .unwrap();
    let pause_path = root.join("controller-paused.json");
    let before = std::fs::read(&pause_path).unwrap();
    let token = state::admin_token(&root).unwrap();
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let response = router(app.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/resume")
                    .header("X-TI-Admin-Token", &token)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"confirm_external_state":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(body["detail"]["message"]
            .as_str()
            .unwrap()
            .contains("remains paused"));
        let checks = body["detail"]["checks"].as_array().unwrap();
        for name in ["qBittorrent connection", "ClamD and definitions"] {
            let check = checks.iter().find(|check| check["name"] == name).unwrap();
            assert_eq!(check["ok"], false);
            assert_ne!(check["required"], false);
            assert!(!check["message"].as_str().unwrap().is_empty());
        }
        assert!(!String::from_utf8_lossy(&bytes).contains("REPLACE_WITH_TEST_SECRET"));
        assert!(!String::from_utf8_lossy(&bytes).contains(&token));
    });
    assert_eq!(std::fs::read(&pause_path).unwrap(), before);
    assert_eq!(app.status()["paused"], true);
    assert_eq!(app.status()["drained"], true);
    assert_eq!(app.status()["infected_action"], "delete");
    drop(app);
    let restarted = App::new(
        config.clone(),
        Database::open(config.database_path().unwrap()).unwrap(),
        false,
    )
    .unwrap();
    assert_eq!(restarted.status()["paused"], true);
}
