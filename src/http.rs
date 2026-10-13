//! HTTP is an adapter, not the owner of business rules. It validates transport
//! limits and authentication, then runs synchronous disk/network work on Tokio's
//! blocking pool. A request guard lives *inside* that work so a disconnected
//! browser cannot make a still-running mutation disappear from the drain count.
use crate::{
    config::Config,
    persistence::{self, Database},
    workflow::Workflow,
};
use anyhow::{ensure, Context, Result};
use axum::{
    body::{Body, Bytes},
    extract::{FromRequest, Multipart, Request, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    Router,
};
use base64::Engine;
use futures_util::StreamExt;
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct RuntimeState {
    paused: bool,
    reason: String,
    active_mutations: usize,
    worker_active: bool,
}
pub struct App {
    pub config: Config,
    pub db: Database,
    pub workflow: Workflow,
    token: String,
    runtime: Mutex<RuntimeState>,
    admin_operation: Arc<tokio::sync::Mutex<()>>,
    uploads: Arc<tokio::sync::Semaphore>,
    pub shutdown: AtomicBool,
}
impl App {
    pub fn new(config: Config, db: Database, fresh: bool) -> Result<Arc<Self>> {
        let root = config.path("data_dir");
        let token = persistence::state::admin_token(&root)?;
        let pause = root.join("controller-paused.json");
        let paused = fresh || pause.exists();
        let reason = if pause.exists() {
            serde_json::from_slice::<Value>(&persistence::state::read_private(&pause, 65536)?)?
                ["reason"]
                .as_str()
                .unwrap_or("Controller paused by operator")
                .to_owned()
        } else {
            "New installation: configure or restore before resuming".into()
        };
        if paused {
            persistence::state::write_json(&pause, &json!({"reason":reason}))?;
        }
        let workflow = Workflow::new(config.clone(), db.clone())?;
        workflow.set_paused(paused);
        Ok(Arc::new(Self {
            config,
            db,
            workflow,
            token,
            runtime: Mutex::new(RuntimeState {
                paused,
                reason,
                active_mutations: 0,
                worker_active: false,
            }),
            admin_operation: Arc::new(tokio::sync::Mutex::new(())),
            uploads: Arc::new(tokio::sync::Semaphore::new(2)),
            shutdown: AtomicBool::new(false),
        }))
    }
    pub fn status(&self) -> Value {
        let state = self.runtime.lock().unwrap();
        let root = self.config.path("data_dir");
        json!({
            "paused":state.paused,
            "reason":if state.paused{Some(state.reason.clone())}else{None},
            "drained":state.paused&&!state.worker_active&&state.active_mutations==0&&self.workflow.active_tasks()==0,
            "restart_required":root.join("restart-required").exists()||root.join(".restore-pending").exists(),
            "restore_pending":root.join(".restore-pending").exists(),
            // Report the active policy, not an unsaved browser draft. A restored
            // delete policy must be visible before the operator resumes work.
            "infected_action":self.config.string("infected_action")
        })
    }
    fn require_drained(&self) -> Result<()> {
        let status = self.status();
        ensure!(
            status["drained"] == true,
            "Pause Intake and wait until drained first"
        );
        ensure!(
            status["restart_required"] != true,
            "Restart to apply the pending settings or restore first"
        );
        Ok(())
    }
    fn pause(&self) -> Result<Value> {
        let reason = "Operator requested a portable backup or configuration change";
        persistence::state::write_json(
            &self.config.path("data_dir").join("controller-paused.json"),
            &json!({"reason":reason}),
        )?;
        let mut state = self.runtime.lock().unwrap();
        state.paused = true;
        state.reason = reason.into();
        self.workflow.set_paused(true);
        drop(state);
        Ok(self.status())
    }
    fn resume(&self) -> std::result::Result<Value, ApiError> {
        self.require_drained()?;
        let checks = self.readiness();
        if checks
            .iter()
            .any(|check| check["required"] != false && check["ok"] != true)
        {
            // Keep the same check results for the browser and the decision.
            // No pause marker or worker state changes until all required checks pass.
            return Err(ApiError(
                StatusCode::CONFLICT,
                json!({"message":"Resume checks failed; the controller remains paused.","checks":checks}),
            ));
        }
        std::fs::remove_file(self.config.path("data_dir").join("controller-paused.json"))
            .context("Remove controller pause marker")?;
        persistence::state::sync_directory(&self.config.path("data_dir"))?;
        let mut state = self.runtime.lock().unwrap();
        self.workflow.set_paused(false);
        state.paused = false;
        state.reason.clear();
        drop(state);
        Ok(self.status())
    }
    fn connection(config: &Config) -> Value {
        let configured = !config.string("qbt_password").is_empty()
            && !config
                .string("qbt_password")
                .to_uppercase()
                .starts_with("REPLACE_");
        let ok = configured
            && crate::workflow::qbt::Qbt::new(config.clone())
                .and_then(|q| q.json("app/preferences", &[]))
                .is_ok();
        json!({
            "name":"qBittorrent connection",
            "ok":ok,
            "message":if ok{"Authentication and read-only API check succeeded."}else{"Cannot reach or authenticate to qBittorrent. Check address, credentials and network."}
        })
    }
    fn readiness(&self) -> Vec<Value> {
        let health = self.workflow.scanner.health();
        let mut checks = vec![
            Self::connection(&self.config),
            json!({"name":"ClamD and definitions","ok":health.can_scan,"message":health.message}),
        ];
        checks.extend(Self::storage_checks(&self.config));
        checks
    }
    /// Mount diagnostics are independent of qBittorrent and ClamD. Optional
    /// destinations appear here even though their absence need not stop intake.
    fn storage_checks(config: &Config) -> Vec<Value> {
        let mut checks = Vec::new();
        let mut required_paths = vec![
            config.string("data_dir"),
            config.string("event_dir"),
            config.string("local_staging_root"),
        ];
        if config.string("infected_action") == "quarantine" {
            required_paths.push(config.string("quarantine_root"));
        }
        let mut paths = required_paths.clone();
        paths.extend(config.allowed_final_parent_prefixes());
        let mut seen = std::collections::HashSet::new();
        for path in paths.into_iter().filter(|path| seen.insert(path.clone())) {
            let ok = persistence::paths::require_storage(&path, None).is_ok();
            checks.push(json!({
                "name":format!("Storage: {path}"),
                "ok":ok,
                "required":required_paths.contains(&path),
                "message":if ok{"Directory is accessible. Verify the intended host mount."}else{"Directory is missing or inaccessible. Check mounts and UID/GID."}
            }));
        }
        for location in config.effective_nas_locations() {
            let path = location["path"].as_str().unwrap_or("");
            checks.push(json!({
                "name":format!("NAS: {} ({path})",location["label"].as_str().unwrap_or("")),
                "required":false,
                "ok":persistence::paths::require_storage(path,location["mount_marker"].as_str()).is_ok(),
                "message":"Jobs needing this location wait while it is unavailable."
            }));
        }
        if config.bool("post_promotion_copy_enabled") {
            let destinations: std::collections::BTreeSet<_> = config
                .get("post_promotion_copy_rules")
                .as_array()
                .into_iter()
                .flatten()
                .filter(|rule| rule["enabled"] != false)
                .filter_map(|rule| rule["destination"].as_str())
                .collect();
            if destinations.is_empty() {
                checks.push(json!({
                    "name": "Copy rules",
                    "ok": false,
                    "required": false,
                    "message": "No enabled copy rules. Configure source-to-destination rules before expecting promoted content to be copied."
                }));
            }
            for destination in destinations {
                let result = crate::workflow::copy_destination(std::path::Path::new(destination));
                let message = match &result {
                    Ok(_) => "Copy destination and its mount marker are accessible.".to_owned(),
                    Err(error) => error.to_string(),
                };
                checks.push(json!({
                    "name": format!("Copy destination: {destination}"),
                    "ok": result.is_ok(),
                    "required": false,
                    "message": format!("{message} Copies wait if unavailable; normal Intake work can continue.")
                }));
            }
        }
        checks
    }
    /// One dispatcher decides when polling is allowed. Scan tasks are tracked by
    /// Workflow as well, so `drained` includes work outliving a single tick.
    pub fn start_worker(self: &Arc<Self>) -> std::thread::JoinHandle<()> {
        let app = self.clone();
        std::thread::spawn(move || {
            while !app.shutdown.load(Ordering::SeqCst) {
                let run = {
                    let mut state = app.runtime.lock().unwrap();
                    if state.paused {
                        false
                    } else {
                        state.worker_active = true;
                        true
                    }
                };
                if run {
                    if let Err(error) = app.workflow.tick() {
                        tracing::warn!("Worker tick: {error:#}");
                    }
                    app.runtime.lock().unwrap().worker_active = false;
                }
                for _ in 0..app.config.u64("scan_scheduler_interval_seconds").max(1) * 10 {
                    if app.shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
            app.workflow.shutdown();
            // The dispatcher launches owned scan/hook tasks. Keep the process
            // lock alive until they have observed cancellation and saved their
            // interruption state, rather than letting process exit kill them.
            while app.workflow.active_tasks() != 0 {
                std::thread::sleep(Duration::from_millis(100));
            }
        })
    }
}
struct MutationGuard(Arc<App>);
impl Drop for MutationGuard {
    fn drop(&mut self) {
        self.0.runtime.lock().unwrap().active_mutations -= 1;
    }
}
#[derive(Debug)]
struct ApiError(StatusCode, Value);
impl ApiError {
    fn message(code: StatusCode, message: impl ToString) -> Self {
        Self(code, json!(message.to_string()))
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, axum::Json(json!({"detail":self.1}))).into_response()
    }
}
impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        Self::message(StatusCode::CONFLICT, error)
    }
}

enum Output {
    Redirect,
    Json(Value),
    Html(String),
    Empty,
    Download(PathBuf, tempfile::TempDir),
}
struct Input {
    path: String,
    method: Method,
    query: String,
    headers: HeaderMap,
    json: Value,
    torrent: Option<(String, Vec<u8>)>,
    restore: Option<(PathBuf, tempfile::TempDir)>,
}
pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .fallback(dispatch)
        .layer(axum::extract::DefaultBodyLimit::disable())
        .with_state(app)
}
async fn dispatch(State(app): State<Arc<App>>, request: Request) -> Response {
    let admin = request.uri().path().starts_with("/admin/");
    let result = handle(app, request).await;
    let mut response = match result {
        Ok(output) => output,
        Err(error) => error.into_response(),
    };
    if admin {
        response
            .headers_mut()
            .insert("Cache-Control", "no-store".parse().unwrap());
    }
    response
}
async fn handle(app: Arc<App>, request: Request) -> std::result::Result<Response, ApiError> {
    let path = request.uri().path().to_owned();
    let method = request.method().clone();
    let headers = request.headers().clone();
    let query = request.uri().query().unwrap_or("").to_owned();
    let admin = path.starts_with("/admin/");
    if admin {
        let supplied = headers
            .get("X-TI-Admin-Token")
            .and_then(|x| x.to_str().ok())
            .unwrap_or("");
        if !persistence::state::authorized(supplied, &app.token) {
            return Err(ApiError::message(
                StatusCode::FORBIDDEN,
                "A valid local administrator token is required",
            ));
        }
        if let Some(origin) = headers.get("origin").and_then(|h| h.to_str().ok()) {
            let parsed = url::Url::parse(origin)
                .map_err(|_| ApiError::message(StatusCode::FORBIDDEN, "Invalid Origin"))?;
            let authority = &parsed[url::Position::BeforeHost..url::Position::AfterPort];
            if Some(authority) != headers.get("host").and_then(|h| h.to_str().ok()) {
                return Err(ApiError::message(
                    StatusCode::FORBIDDEN,
                    "Cross-origin administration is not allowed",
                ));
            }
        }
    }
    let mutation = {
        let mut state = app.runtime.lock().unwrap();
        if state.paused && path.starts_with("/qbt/") {
            return Err(ApiError::message(
                StatusCode::SERVICE_UNAVAILABLE,
                "Live qBittorrent lookups are paused with the controller",
            ));
        }
        if !admin && !matches!(method, Method::GET | Method::HEAD | Method::OPTIONS) {
            if state.paused {
                return Err(ApiError::message(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Controller is paused for backup, restore, or configuration",
                ));
            }
            state.active_mutations += 1;
            Some(MutationGuard(app.clone()))
        } else {
            None
        }
    };
    let operation = if admin {
        Some(app.admin_operation.clone().lock_owned().await)
    } else {
        None
    };
    let upload_slot = if path == "/jobs/torrent" {
        Some(
            app.uploads
                .clone()
                .acquire_owned()
                .await
                .map_err(|e| ApiError::message(StatusCode::SERVICE_UNAVAILABLE, e))?,
        )
    } else {
        None
    };
    let mut input = Input {
        path: path.clone(),
        method,
        query,
        headers,
        json: json!({}),
        torrent: None,
        restore: None,
    };
    if path == "/events/qbt-complete-form"
        && input.method == Method::POST
        && input
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("multipart/form-data"))
    {
        let mut multipart = Multipart::from_request(
            limit_body(
                request,
                if path == "/jobs/torrent" {
                    32 * 1024 * 1024 + 128 * 1024
                } else {
                    128 * 1024
                },
            ),
            &app,
        )
        .await
        .map_err(|e| ApiError::message(StatusCode::UNPROCESSABLE_ENTITY, e))?;
        let mut total = 0usize;
        let mut fields = serde_json::Map::new();
        while let Some(mut field) = multipart
            .next_field()
            .await
            .map_err(|e| ApiError::message(StatusCode::UNPROCESSABLE_ENTITY, e))?
        {
            let name = field.name().unwrap_or("").to_owned();
            if name.is_empty()
                || fields.contains_key(&name)
                || field.file_name().is_some()
                || fields.len() >= 32
            {
                return Err(ApiError::message(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Expected unique completion text fields",
                ));
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = field
                .chunk()
                .await
                .map_err(|e| ApiError::message(StatusCode::UNPROCESSABLE_ENTITY, e))?
            {
                total += chunk.len();
                if total > 65536 || fields.len() > 32 {
                    return Err(ApiError::message(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "Completion event is too large",
                    ));
                }
                bytes.extend(chunk);
            }
            let text = String::from_utf8(bytes).map_err(|_| {
                ApiError::message(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Completion fields must be UTF-8",
                )
            })?;
            fields.insert(name, json!(text));
        }
        input.json = Value::Object(fields);
    } else if path == "/jobs/torrent" && input.method == Method::POST {
        let mut multipart = Multipart::from_request(
            limit_body(
                request,
                if path == "/jobs/torrent" {
                    32 * 1024 * 1024 + 128 * 1024
                } else {
                    128 * 1024
                },
            ),
            &app,
        )
        .await
        .map_err(|e| ApiError::message(StatusCode::UNPROCESSABLE_ENTITY, e))?;
        let mut settings_seen = false;
        while let Some(mut field) = multipart
            .next_field()
            .await
            .map_err(|e| ApiError::message(StatusCode::UNPROCESSABLE_ENTITY, e))?
        {
            let name = field.name().unwrap_or("").to_owned();
            if name == "file" && input.torrent.is_none() {
                let filename = field.file_name().unwrap_or("").to_owned();
                if !filename.to_lowercase().ends_with(".torrent")
                    || filename.chars().any(char::is_control)
                    || filename.contains(['/', '\\'])
                {
                    return Err(ApiError::message(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "Upload one .torrent metadata file",
                    ));
                }
                let mut bytes = Vec::new();
                while let Some(chunk) = field
                    .chunk()
                    .await
                    .map_err(|e| ApiError::message(StatusCode::UNPROCESSABLE_ENTITY, e))?
                {
                    if bytes.len() + chunk.len() > 32 * 1024 * 1024 {
                        return Err(ApiError::message(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "Torrent metadata exceeds 32 MiB",
                        ));
                    }
                    bytes.extend(chunk);
                }
                input.torrent = Some((filename, bytes));
            } else if name == "settings" && !settings_seen {
                let mut bytes = Vec::new();
                while let Some(chunk) = field
                    .chunk()
                    .await
                    .map_err(|e| ApiError::message(StatusCode::UNPROCESSABLE_ENTITY, e))?
                {
                    if bytes.len() + chunk.len() > 65536 {
                        return Err(ApiError::message(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "Settings are too large",
                        ));
                    }
                    bytes.extend(chunk);
                }
                input.json = serde_json::from_slice(&bytes)
                    .map_err(|e| ApiError::message(StatusCode::UNPROCESSABLE_ENTITY, e))?;
                settings_seen = true;
            } else {
                return Err(ApiError::message(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Expected exactly one file and one settings field",
                ));
            }
        }
        if input.torrent.is_none() || !settings_seen {
            return Err(ApiError::message(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Both file and settings are required",
            ));
        }
    } else if path == "/admin/restore" && input.method == Method::POST {
        app.require_drained()?;
        if input
            .headers
            .get("X-TI-Confirm-Restore")
            .and_then(|h| h.to_str().ok())
            != Some("replace-after-restart")
        {
            return Err(ApiError::message(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Explicit restore confirmation is required",
            ));
        }
        let directory = tempfile::Builder::new()
            .prefix(".restore-upload-")
            .tempdir_in(app.config.path("data_dir"))
            .map_err(anyhow::Error::from)?;
        let path = directory.path().join("upload.tibak");
        let file = persistence::state::create_private(&path)?;
        let mut file = tokio::fs::File::from_std(file);
        let mut size = 0usize;
        let mut stream = request.into_body().into_data_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| ApiError::message(StatusCode::BAD_REQUEST, e))?;
            size += chunk.len();
            if size > persistence::backup::MAX_BACKUP_BYTES as usize + 64 {
                return Err(ApiError::message(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Backup exceeds upload size limit",
                ));
            }
            file.write_all(&chunk).await.map_err(anyhow::Error::from)?;
        }
        file.sync_all().await.map_err(anyhow::Error::from)?;
        drop(file);
        input.restore = Some((path, directory));
    } else if !matches!(input.method, Method::GET | Method::HEAD | Method::OPTIONS) {
        let bytes = axum::body::to_bytes(
            request.into_body(),
            if admin { 65536 } else { 2 * 1024 * 1024 },
        )
        .await
        .map_err(|e| ApiError::message(StatusCode::PAYLOAD_TOO_LARGE, e))?;
        if !bytes.is_empty() {
            input.json = if path == "/events/qbt-complete-form" {
                if input
                    .headers
                    .get("content-type")
                    .and_then(|h| h.to_str().ok())
                    .is_some_and(|v| v.starts_with("multipart/form-data"))
                {
                    return Err(ApiError::message(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "Use URL-encoded completion callbacks with this endpoint",
                    ));
                }
                let map: serde_json::Map<String, Value> = url::form_urlencoded::parse(&bytes)
                    .map(|(k, v)| (k.into_owned(), json!(v.into_owned())))
                    .collect();
                Value::Object(map)
            } else {
                serde_json::from_slice(&bytes)
                    .map_err(|e| ApiError::message(StatusCode::UNPROCESSABLE_ENTITY, e))?
            };
        }
        if !input.json.is_object() {
            return Err(ApiError::message(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Expected a JSON object",
            ));
        }
    }
    let output = tokio::task::spawn_blocking(move || {
        let _lifetime = (mutation, operation, upload_slot);
        execute(&app, input)
    })
    .await
    .map_err(|_| ApiError::message(StatusCode::INTERNAL_SERVER_ERROR, "Request worker failed"))??;
    Ok(match output {
        Output::Redirect => axum::response::Redirect::temporary("/ui").into_response(),
        Output::Json(value) => axum::Json(value).into_response(),
        Output::Html(html) => axum::response::Html(html).into_response(),
        Output::Empty => StatusCode::NO_CONTENT.into_response(),
        Output::Download(path, directory) => {
            let file = tokio::fs::File::open(path)
                .await
                .map_err(anyhow::Error::from)?;
            let stream = futures_util::stream::try_unfold(
                (file, directory),
                |(mut file, directory)| async move {
                    let mut bytes = vec![0u8; 65536];
                    let n = file.read(&mut bytes).await?;
                    if n == 0 {
                        Ok::<_, std::io::Error>(None)
                    } else {
                        bytes.truncate(n);
                        Ok(Some((Bytes::from(bytes), (file, directory))))
                    }
                },
            );
            Response::builder()
                .header("Content-Type", "application/octet-stream")
                .header(
                    "Content-Disposition",
                    "attachment; filename=\"torrent-intake.tibak\"",
                )
                .body(Body::from_stream(stream))
                .unwrap()
        }
    })
}
fn execute(app: &App, input: Input) -> std::result::Result<Output, ApiError> {
    let path = input.path.as_str();
    let method = input.method.as_str();
    let payload = &input.json;
    let value = match (method, path) {
        ("GET", "/openapi.json") => serde_json::from_str(include_str!("../resources/openapi.json"))
            .expect("compiled API schema"),
        ("GET", "/docs") | ("GET", "/redoc") => {
            return Ok(Output::Html(
                include_str!("../resources/api-docs.html").into(),
            ))
        }
        ("GET", "/") => return Ok(Output::Redirect),
        ("GET", "/ui") => {
            return Ok(Output::Html(render_ui(
                &app.config,
                &app.workflow.list_jobs()?,
            )?))
        }
        ("GET", "/health") => {
            let health = app.workflow.scanner.health();
            if !health.can_scan {
                return Err(ApiError::message(
                    StatusCode::SERVICE_UNAVAILABLE,
                    health.message,
                ));
            }
            for key in ["data_dir", "event_dir"] {
                persistence::paths::require_storage(&app.config.string(key), None)
                    .map_err(|e| ApiError::message(StatusCode::SERVICE_UNAVAILABLE, e))?;
            }
            json!({"status":"ok"})
        }
        ("GET", "/controller/status") => app.status(),
        // The rows are already JSON values. Taking ownership avoids cloning
        // every history record just to wrap the list in another JSON value.
        ("GET", "/jobs") => Value::Array(app.workflow.list_jobs()?),
        ("POST", "/jobs") | ("POST", "/jobs/torrent") => {
            app.workflow.submit(payload.clone(), input.torrent)?
        }
        ("POST", "/jobs/bulk") => {
            let jobs = payload["jobs"]
                .as_array()
                .filter(|j| !j.is_empty() && j.len() <= 50)
                .ok_or_else(|| {
                    ApiError::message(StatusCode::UNPROCESSABLE_ENTITY, "Submit 1 through 50 jobs")
                })?;
            let mut created = vec![];
            let mut errors = serde_json::Map::new();
            for (index, job) in jobs.iter().enumerate() {
                match app.workflow.submit(job.clone(), None) {
                    Ok(job) => created.push(job),
                    Err(error) => {
                        errors.insert((index + 1).to_string(), json!(error.to_string()));
                    }
                }
            }
            json!({"requested":jobs.len(),"created":created.len(),"failed":errors.len(),"jobs":created,"errors":errors})
        }
        ("GET", "/scanner/status") => app.workflow.scanner_status()?,
        ("POST", "/scanner/slots") | ("POST", "/scanner/maintenance") => {
            app.workflow.scanner_control(payload.clone())?
        }
        ("GET", "/qbt/categories") => {
            let v = app.workflow.qbt.json("torrents/categories", &[])?;
            json!({"categories":v.as_object().map(|m|m.keys().cloned().collect::<Vec<_>>()).unwrap_or_default()})
        }
        ("GET", "/qbt/tags") => {
            let tags = app.workflow.selectable_tags()?;
            json!({"tags":tags})
        }
        ("GET", "/qbt/transfer") => app.workflow.qbt.json("transfer/info", &[])?,
        ("GET", "/qbt/final-path-suggestions") => app.workflow.suggestions()?,
        ("GET", "/fs/final-path-suggestions") => {
            let prefix = url::form_urlencoded::parse(input.query.as_bytes())
                .find(|(k, _)| k == "prefix")
                .map(|(_, v)| v.into_owned())
                .unwrap_or_else(|| app.config.string("final_parent_prefix"));
            json!({"paths":filesystem_suggestions(&app.config,&prefix)?})
        }
        ("POST", "/events/qbt-complete") | ("POST", "/events/qbt-complete-form") => {
            let expected = app.config.string("completion_event_token");
            if expected.is_empty() {
                return Err(ApiError::message(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Completion event authentication is not configured",
                ));
            }
            if !persistence::state::authorized(payload["token"].as_str().unwrap_or(""), &expected) {
                return Err(ApiError::message(
                    StatusCode::FORBIDDEN,
                    "Invalid completion event token",
                ));
            }
            let job = app
                .workflow
                .completion(payload.clone())?
                .ok_or_else(|| ApiError::message(StatusCode::NOT_FOUND, "No matching job found"))?;
            json!({"status":"accepted","job_id":job["id"],"state":job["state"]})
        }
        ("GET", "/admin/status") => {
            let mut status = app.status();
            status["revision"] = json!(app.config.revision()?);
            status["settings"] = app.config.catalog();
            let bytes = persistence::backup::database_size_bytes(&app.config.values).ok();
            status["backup"] = json!({"database_bytes":bytes,"database_limit_bytes":persistence::backup::MAX_DATABASE_BYTES});
            status
        }
        ("POST", "/admin/pause") => app.pause()?,
        ("POST", "/admin/checks") => json!({"checks":app.readiness()}),
        ("POST", "/admin/resume") => {
            if payload["confirm_external_state"] != true {
                return Err(ApiError::message(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Confirm mounts, qBittorrent state and that the old controller is stopped",
                ));
            }
            app.resume()?
        }
        ("POST", "/admin/test-connection") => {
            let updates = &payload["settings"];
            let candidate = if updates.as_object().is_some_and(|o| !o.is_empty()) {
                if !updates.as_object().unwrap().keys().all(|k| {
                    [
                        "qbt_host",
                        "qbt_username",
                        "qbt_password",
                        "qbt_web_url",
                        "qbt_request_timeout_seconds",
                    ]
                    .contains(&k.as_str())
                }) {
                    return Err(ApiError::message(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "Only connection fields can be tested",
                    ));
                }
                draft(app, payload)?.0
            } else {
                app.config.clone()
            };
            App::connection(&candidate)
        }
        ("POST", "/admin/settings/review") => {
            ensure_api(
                app.status()["restart_required"] != true,
                "Restart before editing settings again",
            )?;
            let (_, changes) = draft(app, payload)?;
            json!({"changes":changes,"revision":app.config.revision()?})
        }
        ("POST", "/admin/settings") => {
            app.require_drained()?;
            let (candidate, changes) = draft(app, payload)?;
            ensure_api(!changes.is_empty(), "No settings changed")?;
            ensure_api(
                !changes.iter().any(|c| c["advanced"] == true)
                    || payload["confirm_advanced"] == true,
                "Advanced scanner, storage or script changes require explicit confirmation",
            )?;
            persistence::state::write_private(
                &app.config.path("data_dir").join("restart-required"),
                b"settings changed\n",
            )?;
            candidate.persist()?;
            json!({"restart_required":true,"message":"Settings saved locally. Restart the container to apply them."})
        }
        ("POST", "/admin/deployment-notes") => {
            let notes = payload["notes"].as_str().context("Expected text notes")?;
            persistence::state::write_private(
                &app.config.path("data_dir").join("deployment-notes.txt"),
                notes.as_bytes(),
            )?;
            json!({"saved":true})
        }
        ("POST", "/admin/backup") => {
            app.require_drained()?;
            let directory = tempfile::Builder::new()
                .prefix(".backup-")
                .tempdir_in(app.config.path("data_dir"))
                .map_err(anyhow::Error::from)?;
            let file = persistence::backup::create_backup(
                &app.config.values,
                directory.path(),
                payload["passphrase"].as_str().unwrap_or(""),
            )?;
            return Ok(Output::Download(file, directory));
        }
        ("POST", "/admin/restore") => {
            app.require_drained()?;
            let encoded = input
                .headers
                .get("X-TI-Backup-Passphrase")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| {
                    ApiError::message(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "Invalid passphrase encoding",
                    )
                })?;
            ensure_api(bytes.len() <= 1024, "Passphrase too long")?;
            let phrase = String::from_utf8(bytes).map_err(|_| {
                ApiError::message(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Invalid passphrase encoding",
                )
            })?;
            let (file, directory) = input.restore.context("Missing restore upload")?;
            persistence::restore::stage_restore(
                &file,
                directory.path(),
                &app.config.values,
                &phrase,
            )
            .map_err(|_| {
                ApiError::message(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Restore rejected. Check passphrase, backup validity and disk space; existing data was not replaced.",
                )
            })?
        }
        ("POST", p) if p.starts_with("/jobs/bulk-") => {
            let action = match p {
                "/jobs/bulk-retry" => "retry",
                "/jobs/bulk-delete" => "delete",
                "/jobs/bulk-scan-next" => "prioritize",
                "/jobs/bulk-scan-pause" => "pause",
                "/jobs/bulk-scan-resume" => "resume",
                "/jobs/bulk-move-to-nas" => "move-to-nas",
                _ => return Err(ApiError::message(StatusCode::NOT_FOUND, "Unknown route")),
            };
            let ids = payload["job_ids"]
                .as_array()
                .context("job_ids must be an array")?
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .context("job IDs must be strings")
                })
                .collect::<Result<Vec<_>>>()?;
            app.workflow.bulk(action, ids, payload.clone())?
        }
        ("POST", "/jobs/clear-completed") | ("POST", "/jobs/clear-failed") => {
            let ids = app
                .workflow
                .list_jobs()?
                .into_iter()
                .filter(|j| {
                    if path.ends_with("failed") {
                        j["state"] == "error"
                    } else {
                        [
                            "done",
                            "infected_held",
                            "infected_quarantined",
                            "infected_deleted",
                        ]
                        .iter()
                        .any(|s| j["state"] == *s)
                    }
                })
                .filter_map(|j| j["id"].as_str().map(str::to_owned))
                .collect();
            app.workflow.bulk("delete", ids, json!({}))?
        }
        _ => {
            let parts: Vec<_> = path.trim_matches('/').split('/').collect();
            if (parts.len() == 2 || parts.len() == 3) && parts[0] == "jobs" {
                let id = parts[1];
                if app.db.get_job(id)?.is_none() {
                    return Err(ApiError::message(StatusCode::NOT_FOUND, "Job not found"));
                }
                match (method, parts.get(2).copied()) {
                    ("GET", None) => app.workflow.get_job(id)?,
                    ("DELETE", None) => {
                        app.workflow.action(id, "delete", json!({}))?;
                        return Ok(Output::Empty);
                    }
                    ("POST", Some("retry")) => app.workflow.action(id, "retry", payload.clone())?,
                    ("PATCH", Some("final-destination")) => {
                        app.workflow
                            .action(id, "final-destination", payload.clone())?
                    }
                    _ => return Err(ApiError::message(StatusCode::NOT_FOUND, "Unknown route")),
                }
            } else if parts.len() == 4
                && parts[0] == "admin"
                && parts[1] == "jobs"
                && method == "POST"
                && ["retry-hook", "cancel-copy"].contains(&parts[3])
            {
                app.require_drained()?;
                app.workflow.action(parts[2], parts[3], payload.clone())?
            } else {
                return Err(ApiError::message(StatusCode::NOT_FOUND, "Unknown route"));
            }
        }
    };
    Ok(Output::Json(value))
}
fn limit_body(request: Request, limit: usize) -> Request {
    let (parts, body) = request.into_parts();
    Request::from_parts(parts, Body::new(http_body_util::Limited::new(body, limit)))
}
fn ensure_api(condition: bool, message: &str) -> std::result::Result<(), ApiError> {
    if condition {
        Ok(())
    } else {
        Err(ApiError::message(StatusCode::CONFLICT, message))
    }
}
fn draft(app: &App, payload: &Value) -> std::result::Result<(Config, Vec<Value>), ApiError> {
    if let Some(revision) = payload["revision"].as_str() {
        ensure_api(
            revision == app.config.revision()?,
            "Settings changed in another session; reload and review again",
        )?;
    }
    let result = app.config.draft(&payload["settings"]).map_err(|e| {
        let message = e.to_string();
        let names = e
            .downcast_ref::<crate::config::SettingsValidationError>()
            .map(|error| error.fields.clone())
            .unwrap_or_else(|| vec!["_form".into()]);
        let fields: serde_json::Map<String, Value> = names
            .into_iter()
            .map(|name| (name, json!(message)))
            .collect();
        ApiError(
            StatusCode::UNPROCESSABLE_ENTITY,
            json!({"message":"Check the highlighted settings; nothing was saved.","fields":fields}),
        )
    })?;
    persistence::storage::validate_location_changes(&app.db, &app.config, &result.0)?;
    Ok(result)
}
fn filesystem_suggestions(config: &Config, prefix: &str) -> Result<Vec<String>> {
    let candidate = persistence::paths::canonical_final_parent(
        prefix,
        &config.allowed_final_parent_prefixes(),
        &config.blocked_roots(),
    )?;
    let path = std::path::Path::new(&candidate);
    let (directory, filter) = if path.is_dir() {
        (path, "")
    } else {
        (
            path.parent().context("Invalid prefix")?,
            path.file_name().and_then(|p| p.to_str()).unwrap_or(""),
        )
    };
    let mut result = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() && entry.file_name().to_string_lossy().starts_with(filter) {
            if let Ok(value) = persistence::paths::canonical_final_parent(
                &entry.path().to_string_lossy(),
                &config.allowed_final_parent_prefixes(),
                &config.blocked_roots(),
            ) {
                result.push(value);
            }
        }
        if result.len() >= 100 {
            break;
        }
    }
    result.sort();
    Ok(result)
}
pub fn render_ui(config: &Config, jobs: &[Value]) -> Result<String> {
    let mut env = minijinja::Environment::new();
    env.add_filter("forceescape", |value: String| -> minijinja::Value {
        minijinja::Value::from_safe_string(
            value
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&#34;")
                .replace('\'', "&#39;"),
        )
    });
    env.add_template_owned(
        "index.html",
        include_str!("../templates/index.html")
            .replace("job.hook_destination.rstrip('/')", "job.hook_destination"),
    )?;
    env.add_template("settings.html", include_str!("../templates/settings.html"))?;
    env.add_template("settings.css", include_str!("../templates/settings.css"))?;
    env.add_template("settings.js", include_str!("../templates/settings.js"))?;
    // Build MiniJinja's context directly: an intermediate serde_json object
    // would duplicate the entire job history before the template conversion.
    Ok(env
        .get_template("index.html")?
        .render(minijinja::context! {
            title => config.string("ui_title"),
            jobs => jobs,
            settings => config.template_values(),
            settings_catalog => config.catalog(),
            max_custom_tags => 20,
            max_custom_tag_length => 64,
            private_job_tag_prefix => "ti_job_"
        })?)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn optional_copy_and_extra_media_mounts_are_reported() {
        let temporary = tempfile::tempdir().unwrap();
        let missing = temporary.path().join("missing-media");
        let mut config = Config::defaults();
        config.values["final_parent_prefixes"] = json!(missing);
        config.values["post_promotion_copy_enabled"] = json!(true);
        let checks = App::storage_checks(&config);
        assert!(checks.iter().any(|check| {
            check["name"] == format!("Storage: {}", missing.display())
                && check["ok"] == false
                && check["required"] == false
        }));
        assert!(checks
            .iter()
            .any(|check| check["name"] == "Copy rules" && check["ok"] == false));
        config.values["post_promotion_copy_rules"] = json!([{
            "source": "/media",
            "destination": missing,
            "enabled": true
        }]);
        assert!(App::storage_checks(&config).iter().any(|check| {
            check["name"] == format!("Copy destination: {}", missing.display())
                && check["ok"] == false
                && check["required"] == false
        }));
    }
    #[test]
    fn original_ui_renders_with_redacted_config() {
        let mut c = Config::defaults();
        c.values["qbt_password"] = json!("hidden-secret-test");
        let html = render_ui(&c, &[]).unwrap();
        assert!(html.contains("New Intake"));
        assert!(!html.contains("hidden-secret-test"));
        assert!(!html.contains("{%"));
    }
    #[test]
    fn untrusted_torrent_names_and_errors_remain_escaped() {
        let attack = "\"><img src=x onerror=alert(1)>";
        let jobs = [json!({
            "id": "test-job",
            "torrent_name": attack,
            "last_error": attack,
            "final_parent": "/downloads/Media",
            "state": "error",
            "is_terminal": true,
            "can_edit_final_destination": true,
            "scan": null,
            "hook_status": null
        })];
        let html = render_ui(&Config::defaults(), &jobs).unwrap();
        assert!(!html.contains(attack));
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
    }
}
