//! Transport-level regression tests use an isolated data directory and no live
//! qBittorrent or ClamD. They exercise the same router the binary serves.
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
fn first_run_and_admin_boundaries() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let mut config = Config::defaults();
    config.values["data_dir"] = json!(root);
    config.values["database_url"] =
        json!(format!("sqlite:///{}", root.join("intake.db").display()));
    config.values["event_dir"] = json!(root);
    config.persist().unwrap();
    let db = Database::open(config.database_path().unwrap()).unwrap();
    let app = App::new(config, db, true).unwrap();
    let token = state::admin_token(&root).unwrap();
    let service = router(app.clone());
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let request = || {
            Request::builder()
                .method("POST")
                .uri("/jobs")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap()
        };
        assert_eq!(
            service.clone().oneshot(request()).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let response = service
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/controller/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let value: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
        assert_eq!(value["paused"], true);
        assert_eq!(value["drained"], true);
        assert_eq!(value["infected_action"], "hold");
        let no_token = service
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(no_token.status(), StatusCode::FORBIDDEN);
        assert_eq!(no_token.headers()["cache-control"], "no-store");
        let cross_origin = service
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/status")
                    .header("host", "localhost:8000")
                    .header("origin", "https://attacker.example")
                    .header("X-TI-Admin-Token", &token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross_origin.status(), StatusCode::FORBIDDEN);
        let same_origin = service
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/status")
                    .header("host", "localhost:8000")
                    .header("origin", "http://localhost:8000")
                    .header("X-TI-Admin-Token", &token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(same_origin.status(), StatusCode::OK);
        let html = service
            .clone()
            .oneshot(Request::builder().uri("/ui").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(html.status(), StatusCode::OK);
        let html = String::from_utf8(
            to_bytes(html.into_body(), 1024 * 1024)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(html.contains("New Intake"));
        assert!(!html.contains(&token));
        let redirect = service
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(redirect.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(redirect.headers()["location"], "/ui");
        for path in ["/docs", "/redoc", "/openapi.json"] {
            let response = service
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
            if path == "/openapi.json" {
                let schema: Value = serde_json::from_slice(&body).unwrap();
                assert!(schema["paths"]["/jobs"]["post"].is_object());
            }
        }
        let invalid = service
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/settings/review")
                    .header("X-TI-Admin-Token", &token)
                    .header("content-type", "application/json")
                    .body(Body::from("[]"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let too_large = service
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/settings/review")
                    .header("X-TI-Admin-Token", &token)
                    .body(Body::from(vec![b' '; 65537]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(too_large.status(), StatusCode::PAYLOAD_TOO_LARGE);
    });
    assert_eq!(app.status()["drained"], true);
}

#[test]
fn settings_drafts_are_side_effect_free_and_secret_safe() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let mut config = Config::defaults();
    config.values["data_dir"] = json!(root);
    config.values["database_url"] = json!(format!("sqlite:///{}", root.join("db").display()));
    config.values["qbt_password"] = json!("KEEP-THIS-SECRET");
    config.persist().unwrap();
    let before = std::fs::read(root.join("settings.json")).unwrap();
    let app = App::new(
        config.clone(),
        Database::open(config.database_path().unwrap()).unwrap(),
        true,
    )
    .unwrap();
    let token = state::admin_token(&root).unwrap();
    let service = router(app);
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let payload = json!({
            "revision": config.revision().unwrap(),
            "settings": {"qbt_password": "replacement-secret"}
        });
        let response = service
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/settings/review")
                    .header("X-TI-Admin-Token", token)
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8(
            to_bytes(response.into_body(), 65536)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(!body.contains("KEEP-THIS-SECRET"));
        assert!(!body.contains("replacement-secret"));
    });
    assert_eq!(std::fs::read(root.join("settings.json")).unwrap(), before);
}

#[test]
fn invalid_settings_drafts_report_exact_fields_without_saving_or_echoing_secrets() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let mut config = Config::defaults();
    config.values["data_dir"] = json!(root);
    config.values["database_url"] = json!(format!("sqlite:///{}", root.join("db").display()));
    config.values["qbt_password"] = json!("saved-secret-for-draft-regression");
    config.overrides.insert("debug".into());
    config.persist().unwrap();
    let before = std::fs::read(root.join("settings.json")).unwrap();
    let app = App::new(
        config.clone(),
        Database::open(config.database_path().unwrap()).unwrap(),
        true,
    )
    .unwrap();
    let token = state::admin_token(&root).unwrap();
    let service = router(app);
    let cases = [
        (
            json!({"post_promotion_copy_rules":[{"source":"/downloads/Media","destination":"/app/data","enabled":true}]}),
            vec!["post_promotion_copy_rules"],
        ),
        (
            json!({"qbt_host":"bad address","qbt_password":"replacement-secret-for-draft-regression"}),
            vec!["qbt_host"],
        ),
        (
            json!({"qbt_host":"http://reader:inline-secret-for-draft-regression@bad host"}),
            vec!["qbt_host"],
        ),
        (json!({"qbt_host":42}), vec!["qbt_host"]),
        (
            json!({"scanner_max_file_mib":2001}),
            vec!["scanner_max_file_mib"],
        ),
        (
            json!({"max_concurrent_scans":5}),
            vec!["max_concurrent_scans", "max_scan_slots"],
        ),
        (
            json!({"nas_staging_locations":[{"id":"bad","label":"Bad storage","path":"/app/data"}]}),
            vec!["nas_staging_locations"],
        ),
        (
            json!({"archive_scratch_dir":"/scratch","archive_scratch_mount_marker":"/elsewhere/marker"}),
            vec!["archive_scratch_mount_marker"],
        ),
        (json!({"debug":true}), vec!["debug"]),
        (json!({"infected_action":"delete"}), vec!["infected_action"]),
        (json!({}), vec!["_form"]),
    ];
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        for (settings, expected_fields) in cases {
            for endpoint in ["/admin/settings/review", "/admin/settings"] {
                let response = service.clone().oneshot(Request::builder()
                    .method("POST").uri(endpoint)
                    .header("X-TI-Admin-Token", &token)
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"settings":settings,"revision":config.revision().unwrap(),"confirm_advanced":true}).to_string())).unwrap()).await.unwrap();
                assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY, "{endpoint} {expected_fields:?}");
                let bytes = to_bytes(response.into_body(),65536).await.unwrap();
                let body = std::str::from_utf8(&bytes).unwrap();
                for secret in ["saved-secret-for-draft-regression", "replacement-secret-for-draft-regression", "inline-secret-for-draft-regression"] {
                    assert!(!body.contains(secret), "validation reflected a credential");
                }
                let value: Value = serde_json::from_slice(&bytes).unwrap();
                let fields = value["detail"]["fields"].as_object().unwrap();
                assert_eq!(fields.len(), expected_fields.len(), "{value}");
                for name in &expected_fields {
                    assert!(fields[*name].as_str().is_some_and(|message| !message.is_empty()), "{value}");
                }
            }
        }
        // The connection-test endpoint shares the same draft validation before
        // making any network request, so malformed addresses highlight there too.
        let response = service.oneshot(Request::builder().method("POST").uri("/admin/test-connection")
            .header("X-TI-Admin-Token", &token).header("content-type", "application/json")
            .body(Body::from(json!({"settings":{"qbt_host":"bad address"}}).to_string())).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let value: Value = serde_json::from_slice(&to_bytes(response.into_body(),65536).await.unwrap()).unwrap();
        assert!(value["detail"]["fields"]["qbt_host"].is_string());
    });
    assert_eq!(std::fs::read(root.join("settings.json")).unwrap(), before);
    assert!(!root.join("restart-required").exists());
}

#[test]
fn browser_number_strings_and_structured_drafts_review_and_save_as_typed_settings() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let mut config = Config::defaults();
    config.values["data_dir"] = json!(root);
    config.values["database_url"] = json!(format!("sqlite:///{}", root.join("db").display()));
    config.values["qbt_web_url"] = json!("https://qbittorrent.example.invalid");
    config.persist().unwrap();
    let before = std::fs::read(root.join("settings.json")).unwrap();
    let app = App::new(
        config.clone(),
        Database::open(config.database_path().unwrap()).unwrap(),
        true,
    )
    .unwrap();
    let token = state::admin_token(&root).unwrap();
    let service = router(app);
    // templates/settings.js intentionally submits number input.value strings,
    // while boolean, nullable and structured editors submit real JSON values.
    let payload = json!({"revision":config.revision().unwrap(),"confirm_advanced":true,"settings":{
        "large_media_chunk_mib":"256", "qbt_request_timeout_seconds":"20",
        "post_promotion_delay_seconds":"0", "qbt_web_url":null,
        "post_promotion_copy_enabled":true,
        "post_promotion_copy_rules":[
            {"source":"/downloads/Media","destination":"/copy-target/Media","enabled":true},
            {"source":"/downloads/Files","destination":"/copy-target/Files","enabled":false}
        ],
        "nas_staging_locations":[
            {"id":"primary","label":"Primary storage","path":"/downloads/torrent-intake/staging","mount_marker":null},
            {"id":"extra","label":"Extra storage","path":"/nas-extra/intake","mount_marker":"/nas-extra/.mounted"}
        ],
        "default_nas_staging_id":"extra"
    }});
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        for endpoint in ["/admin/settings/review", "/admin/settings"] {
            let response = service
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(endpoint)
                        .header("X-TI-Admin-Token", &token)
                        .header("content-type", "application/json")
                        .body(Body::from(payload.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let value: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap())
                    .unwrap();
            assert_eq!(status, StatusCode::OK, "{value}");
            if endpoint.ends_with("review") {
                let changes = value["changes"].as_array().unwrap();
                assert!(changes
                    .iter()
                    .any(|change| change["name"] == "large_media_chunk_mib"));
                assert!(!changes
                    .iter()
                    .any(|change| change["name"] == "qbt_request_timeout_seconds"));
                assert_eq!(std::fs::read(root.join("settings.json")).unwrap(), before);
                assert!(!root.join("restart-required").exists());
            }
        }
    });
    let saved: Value =
        serde_json::from_slice(&std::fs::read(root.join("settings.json")).unwrap()).unwrap();
    assert_eq!(saved["settings"]["large_media_chunk_mib"], json!(256));
    assert_eq!(saved["settings"]["post_promotion_delay_seconds"], json!(0));
    assert_eq!(saved["settings"]["post_promotion_copy_enabled"], true);
    assert_eq!(saved["settings"]["qbt_web_url"], Value::Null);
    assert_eq!(
        saved["settings"]["post_promotion_copy_rules"],
        payload["settings"]["post_promotion_copy_rules"]
    );
    assert_eq!(
        saved["settings"]["nas_staging_locations"],
        payload["settings"]["nas_staging_locations"]
    );
    assert!(root.join("restart-required").exists());
}

#[test]
fn unexpected_path_segments_cannot_invoke_job_actions() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let mut config = Config::defaults();
    config.values["data_dir"] = json!(root);
    config.values["database_url"] = json!(format!("sqlite:///{}", root.join("db").display()));
    config.persist().unwrap();
    let db = Database::open(config.database_path().unwrap()).unwrap();
    db.insert_job(&json!({
        "id": "history", "magnet_uri": "magnet:?xt=urn:btih:0000000000000000000000000000000000000000",
        "final_parent": "/media", "staging_preference": "local",
        "staging_root_initial": "/staging-local", "managed_tag": "intake",
        "unique_tag": "ti_job_history", "state": "done", "is_terminal": true
    })).unwrap();
    // Construct an unpaused controller without starting its worker. A malformed
    // route must be rejected before any external service or job action is used.
    let app = App::new(config, db.clone(), false).unwrap();
    let service = router(app);
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        for uri in [
            "/jobs/history/retry/extra",
            "/jobs/history/final-destination/extra",
        ] {
            let response = service
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(uri)
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        }
    });
    assert_eq!(db.get_job("history").unwrap().unwrap()["state"], "done");
}

#[test]
fn pause_waits_for_a_slow_upload_and_disconnect_releases_its_guard() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let mut config = Config::defaults();
    config.values["data_dir"] = json!(root);
    config.values["database_url"] = json!(format!("sqlite:///{}", root.join("db").display()));
    config.persist().unwrap();
    let db = Database::open(config.database_path().unwrap()).unwrap();
    let app = App::new(config, db.clone(), false).unwrap();
    let token = state::admin_token(&root).unwrap();
    let service = router(app.clone());
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let reading_body = std::sync::Arc::new(tokio::sync::Notify::new());
        let signal = reading_body.clone();
        let stream = futures_util::stream::once(async move {
            signal.notify_one();
            std::future::pending::<Result<axum::body::Bytes, std::io::Error>>().await
        });
        let request = Request::builder()
            .method("POST")
            .uri("/jobs")
            .header("content-type", "application/json")
            .body(Body::from_stream(stream))
            .unwrap();
        let upload = tokio::spawn(service.clone().oneshot(request));
        tokio::time::timeout(std::time::Duration::from_secs(5), reading_body.notified())
            .await
            .unwrap();
        let pause = service
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/pause")
                    .header("X-TI-Admin-Token", token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pause.status(), StatusCode::OK);
        assert_eq!(app.status()["paused"], true);
        assert_eq!(app.status()["drained"], false);
        upload.abort();
        assert!(upload.await.unwrap_err().is_cancelled());
        assert_eq!(app.status()["drained"], true);
    });
    assert!(db.list_jobs().unwrap().is_empty());
}

#[test]
fn legacy_completion_callbacks_accept_multipart_and_urlencoded_forms() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let mut config = Config::defaults();
    config.values["data_dir"] = json!(root);
    config.values["database_url"] = json!(format!("sqlite:///{}", root.join("db").display()));
    config.values["completion_event_token"] = json!("synthetic-callback-token");
    let app = App::new(
        config.clone(),
        Database::open(config.database_path().unwrap()).unwrap(),
        false,
    )
    .unwrap();
    let service = router(app);
    // An unknown torrent exercises authentication and parsing without contacting
    // qBittorrent. The legacy API returns 404 for an authenticated unknown hash.
    // Both forms are used by existing completion-command examples.
    let multipart = |token: &str| {
        format!(
        "--compat\r\nContent-Disposition: form-data; name=\"token\"\r\n\r\n{token}\r\n\
         --compat\r\nContent-Disposition: form-data; name=\"qbt_hash\"\r\n\r\n0000000000000000000000000000000000000000\r\n--compat--\r\n"
    )
    };
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        for (content_type, body, expected) in [
            (
                "application/x-www-form-urlencoded",
                "token=synthetic-callback-token&qbt_hash=0000000000000000000000000000000000000000"
                    .to_owned(),
                StatusCode::NOT_FOUND,
            ),
            (
                "multipart/form-data; boundary=compat",
                multipart("synthetic-callback-token"),
                StatusCode::NOT_FOUND,
            ),
            (
                "multipart/form-data; boundary=compat",
                multipart("incorrect-token"),
                StatusCode::FORBIDDEN,
            ),
            (
                "application/x-www-form-urlencoded",
                "token=incorrect-token&qbt_hash=0000000000000000000000000000000000000000"
                    .to_owned(),
                StatusCode::FORBIDDEN,
            ),
        ] {
            let response = service
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/events/qbt-complete-form")
                        .header("content-type", content_type)
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{content_type}");
        }
    });
}
