//! Protocol-level tests use a loopback qBittorrent double, never a user's daemon.
use super::*;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::Duration as Wait,
};

struct FakeQbt {
    url: String,
    torrent: Arc<Mutex<Option<Value>>>,
    calls: Arc<Mutex<Vec<String>>>,
    tags: Arc<Mutex<Vec<String>>>,
    fail_info_requests: Arc<AtomicUsize>,
    info_response: Arc<Mutex<Option<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl FakeQbt {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let torrent = Arc::new(Mutex::new(None::<Value>));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let tags = Arc::new(Mutex::new(Vec::<String>::new()));
        let fail_info_requests = Arc::new(AtomicUsize::new(0));
        let info_response = Arc::new(Mutex::new(None::<String>));
        let stop = Arc::new(AtomicBool::new(false));
        let state = torrent.clone();
        let seen = calls.clone();
        let available_tags = tags.clone();
        let failures = fail_info_requests.clone();
        let overridden_info = info_response.clone();
        let stopped = stop.clone();
        let handle = thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                let (mut connection, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Wait::from_millis(2));
                        continue;
                    }
                    Err(_) => break,
                };
                connection.set_nonblocking(false).unwrap();
                connection
                    .set_read_timeout(Some(Wait::from_secs(2)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0; 8192];
                let mut expected = None;
                loop {
                    let count = connection.read(&mut buffer).unwrap_or(0);
                    if count == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                    if expected.is_none() {
                        if let Some(end) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                            let headers = String::from_utf8_lossy(&bytes[..end]);
                            let length = headers
                                .lines()
                                .find_map(|line| {
                                    line.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .and_then(|value| value.trim().parse::<usize>().ok())
                                })
                                .unwrap_or(0);
                            expected = Some(end + 4 + length);
                        }
                    }
                    if expected.is_some_and(|length| bytes.len() >= length) {
                        break;
                    }
                }
                let request = String::from_utf8_lossy(&bytes);
                let path = request
                    .lines()
                    .next()
                    .unwrap_or("")
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("");
                seen.lock().unwrap().push(path.to_owned());
                let mut torrent = state.lock().unwrap();
                let body = request
                    .split_once("\r\n\r\n")
                    .map(|(_, body)| body)
                    .unwrap_or("");
                let fields: std::collections::HashMap<String, String> =
                    url::form_urlencoded::parse(body.as_bytes())
                        .into_owned()
                        .collect();
                let unavailable = path.starts_with("/api/v2/torrents/info")
                    && failures.load(Ordering::SeqCst) > 0;
                if unavailable {
                    failures.fetch_sub(1, Ordering::SeqCst);
                }
                let (response, headers) = if unavailable {
                    ("temporary qBittorrent failure".to_owned(), "")
                } else if path == "/api/v2/auth/login" {
                    ("Ok.".to_owned(), "Set-Cookie: SID=fake; Path=/\r\n")
                } else if path.starts_with("/api/v2/torrents/info") {
                    let hashes = path.split_once('?').and_then(|(_, query)| {
                        url::form_urlencoded::parse(query.as_bytes())
                            .find(|(key, _)| key == "hashes")
                            .map(|(_, value)| value.into_owned())
                    });
                    let found = torrent.as_ref().filter(|torrent| {
                        hashes.as_ref().is_none_or(|hashes| {
                            hashes
                                .split('|')
                                .any(|hash| hash == string(torrent, "hash"))
                        })
                    });
                    (
                        overridden_info.lock().unwrap().clone().unwrap_or_else(|| {
                            serde_json::to_string(&found.into_iter().collect::<Vec<_>>()).unwrap()
                        }),
                        "",
                    )
                } else if path == "/api/v2/torrents/add" {
                    let tags = multipart(body, "tags");
                    let save = multipart(body, "savepath");
                    *torrent = Some(json!({
                        "hash": "a".repeat(40),
                        "name": "Example",
                        "save_path": save,
                        "content_path": format!("{save}/payload"),
                        "tags": tags,
                        "state": "downloading",
                        "progress": 0.25,
                        "amount_left": 75,
                        "total_size": 100,
                        "eta": 30,
                        "dlspeed": 3,
                        "upspeed": 0,
                    }));
                    ("Ok.".into(), "")
                } else if path == "/api/v2/torrents/stop" {
                    if let Some(torrent) = torrent.as_mut() {
                        torrent["state"] = json!("stoppedUP");
                    }
                    (String::new(), "")
                } else if path == "/api/v2/torrents/start" {
                    if let Some(torrent) = torrent.as_mut() {
                        torrent["state"] = json!("uploading");
                    }
                    (String::new(), "")
                } else if path == "/api/v2/torrents/setLocation" {
                    if let Some(torrent) = torrent.as_mut() {
                        torrent["save_path"] = json!(fields["location"]);
                        torrent["content_path"] = json!(format!("{}/payload", fields["location"]));
                    }
                    (String::new(), "")
                } else if path == "/api/v2/torrents/delete" {
                    *torrent = None;
                    (String::new(), "")
                } else if path == "/api/v2/torrents/categories" {
                    ("{}".into(), "")
                } else if path == "/api/v2/torrents/tags" {
                    (
                        serde_json::to_string(&*available_tags.lock().unwrap()).unwrap(),
                        "",
                    )
                } else {
                    (String::new(), "")
                };
                let _ = write!(
                    connection,
                    concat!(
                        "HTTP/1.1 {}\r\nContent-Type: application/json\r\n",
                        "Content-Length: {}\r\nConnection: close\r\n{}\r\n{}",
                    ),
                    if unavailable {
                        "503 Service Unavailable"
                    } else {
                        "200 OK"
                    },
                    response.len(),
                    headers,
                    response,
                );
            }
        });
        Self {
            url: format!("http://{address}"),
            torrent,
            calls,
            tags,
            fail_info_requests,
            info_response,
            stop,
            thread: Some(handle),
        }
    }
}
impl Drop for FakeQbt {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.url.trim_start_matches("http://"));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
fn multipart<'a>(body: &'a str, name: &str) -> &'a str {
    body.split(&format!("name=\"{name}\"\r\n\r\n"))
        .nth(1)
        .and_then(|part| part.split("\r\n").next())
        .unwrap_or("")
}
fn fixture() -> (tempfile::TempDir, FakeQbt, Workflow) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let qbt = FakeQbt::new();
    let mut config = Config::defaults();
    for (key, name) in [
        ("data_dir", "data"),
        ("local_staging_root", "staging"),
        ("nas_staging_root", "nas"),
        ("final_parent_prefix", "media"),
        ("event_dir", "events"),
        ("quarantine_root", "quarantine"),
    ] {
        let path = root.join(name);
        std::fs::create_dir(&path).unwrap();
        config.values[key] = json!(path);
    }
    config.values["qbt_host"] = json!(qbt.url);
    config.values["local_free_space_buffer_gib"] = json!(0);
    let db = Database::open(root.join("data/db.sqlite")).unwrap();
    let workflow = Workflow::new(config, db).unwrap();
    (temp, qbt, workflow)
}
fn submit(workflow: &Workflow) -> Value {
    workflow
        .submit(
            json!({
                "magnet_uri": format!("magnet:?xt=urn:btih:{}", "a".repeat(40)),
                "final_parent": workflow.config.path("final_parent_prefix").join("Media"),
                "custom_tags": ["Media"],
            }),
            None,
        )
        .unwrap()
}

#[test]
fn qbt_owned_responses_preserve_empty_first_row_and_invalid_response_behavior() {
    let (_temp, qbt, workflow) = fixture();
    assert!(workflow.qbt.list().unwrap().is_empty());
    assert!(workflow.qbt.torrent("missing").unwrap().is_none());

    let torrents = json!([
        {"hash": "first", "name": "First torrent", "tags": "Media"},
        {"hash": "second", "name": "Second torrent", "tags": "Files"},
    ]);
    *qbt.info_response.lock().unwrap() = Some(torrents.to_string());
    assert_eq!(
        workflow.qbt.list().unwrap(),
        torrents.as_array().unwrap().clone()
    );
    assert_eq!(
        workflow.qbt.torrent("first|second").unwrap(),
        Some(torrents[0].clone())
    );

    *qbt.info_response.lock().unwrap() = Some("{}".to_owned());
    assert!(workflow
        .qbt
        .list()
        .unwrap_err()
        .to_string()
        .contains("not an array"));
    assert!(workflow.qbt.torrent("first").unwrap().is_none());

    *qbt.info_response.lock().unwrap() = Some("invalid JSON".to_owned());
    assert!(workflow.qbt.list().is_err());
    assert!(workflow.qbt.torrent("first").is_err());
    let requests = qbt.calls.lock().unwrap().len();
    assert!(workflow.qbt.torrent("").unwrap().is_none());
    assert_eq!(qbt.calls.lock().unwrap().len(), requests);
}

#[test]
fn unchanged_polls_and_idle_recovery_do_not_rewrite_job_history() {
    let (_temp, _qbt, workflow) = fixture();
    let job = submit(&workflow);
    let id = string(&job, "id");
    let connection = workflow.db.connect().unwrap();
    connection
        .execute_batch(
            "CREATE TABLE measured_updates(table_name TEXT);
         CREATE TRIGGER measured_jobs AFTER UPDATE ON jobs BEGIN
             INSERT INTO measured_updates VALUES ('jobs'); END;
         CREATE TRIGGER measured_runs AFTER UPDATE ON scan_runs BEGIN
             INSERT INTO measured_updates VALUES ('scan_runs'); END;",
        )
        .unwrap();
    for _ in 0..10 {
        workflow.process_job(&workflow.job(id).unwrap()).unwrap();
    }
    let download_writes: u64 = connection
        .query_row("SELECT COUNT(*) FROM measured_updates", [], |row| {
            row.get(0)
        })
        .unwrap();
    workflow
        .update(id, json!({"state": "scan_paused"}))
        .unwrap();
    workflow
        .db
        .save_scan_run(id, &json!({"pause_requested": true}))
        .unwrap();
    connection
        .execute("DELETE FROM measured_updates", [])
        .unwrap();
    for _ in 0..10 {
        workflow.recover_scans().unwrap();
    }
    let recovery_writes: u64 = connection
        .query_row("SELECT COUNT(*) FROM measured_updates", [], |row| {
            row.get(0)
        })
        .unwrap();
    eprintln!("ten unchanged download polls: {download_writes} UPDATEs; ten idle recovery passes: {recovery_writes} UPDATEs");
    assert_eq!(download_writes, 0);
    assert_eq!(recovery_writes, 0);
}

#[test]
fn terminal_history_is_filtered_before_worker_rows_are_materialized() {
    let (_temp, _qbt, workflow) = fixture();
    let job = submit(&workflow);
    let connection = workflow.db.connect().unwrap();
    connection.execute(
        "WITH RECURSIVE sequence(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM sequence WHERE n<1000)
         INSERT INTO jobs(id,magnet_uri,final_parent,staging_preference,staging_root_initial,
            managed_tag,unique_tag,state,is_terminal)
         SELECT 'history-'||n,magnet_uri,final_parent,staging_preference,staging_root_initial,
            managed_tag,'historical-tag-'||n,'done',1 FROM sequence,jobs WHERE jobs.id=?1",
        [string(&job, "id")],
    ).unwrap();
    let previous_rows = workflow.db.list_jobs().unwrap().len();
    let active = workflow.jobs_query("WHERE is_terminal=0", []).unwrap();
    let scan_candidates = workflow
        .jobs_query("WHERE state IN ('scanning','scan_pending')", [])
        .unwrap();
    let hook_candidates = workflow
        .jobs_query("WHERE hook_status='pending'", [])
        .unwrap();
    eprintln!(
        "history selection: {previous_rows} previous rows; {} active, {} scan, {} hook rows",
        active.len(),
        scan_candidates.len(),
        hook_candidates.len()
    );
    assert_eq!(previous_rows, 1001);
    assert_eq!(active.len(), 1);
    assert!(scan_candidates.is_empty());
    assert!(hook_candidates.is_empty());
    assert!(!active[0]
        .as_object()
        .unwrap()
        .contains_key("torrent_file_data"));
    workflow.set_paused(true);
    assert_eq!(workflow.list_jobs().unwrap().len(), 1001);
}

#[test]
fn temporary_hash_lookup_failure_stays_queued_and_recovers_on_fast_tick() {
    let (_temp, qbt, workflow) = fixture();
    let job = submit(&workflow);
    let id = string(&job, "id");
    workflow.mark(id, "waiting_for_qbt_hash", None).unwrap();
    *workflow.last_poll.lock().unwrap() = std::time::Instant::now();
    qbt.fail_info_requests.store(1, Ordering::SeqCst);
    workflow.tick().unwrap();
    let queued = workflow.job(id).unwrap();
    assert_eq!(queued["state"], "waiting_for_qbt_hash");
    assert_eq!(queued["is_terminal"], false);
    assert!(string(&queued, "last_error").contains("will retry"));
    workflow.tick().unwrap();
    assert_eq!(workflow.job(id).unwrap()["state"], "downloading");
}

#[test]
fn offline_copy_target_defers_before_walking_changed_source() {
    let (_temp, _qbt, mut workflow) = fixture();
    let job = submit(&workflow);
    let id = string(&job, "id");
    let parent = std::path::PathBuf::from(string(&job, "final_parent"));
    std::fs::create_dir_all(&parent).unwrap();
    let source = parent.join("payload");
    std::fs::create_dir(&source).unwrap();
    // A source walk would fail on this symlink. Missing destination storage
    // must defer the action before that potentially expensive walk begins.
    std::os::unix::fs::symlink(parent.join("missing"), source.join("link")).unwrap();
    workflow.config.values["post_promotion_copy_enabled"] = json!(true);
    workflow.update(id, json!({
        "state": "done", "is_terminal": true, "scan_completed_at": now(), "promoted_at": now(),
        "content_path": source, "hook_kind": "copy", "hook_status": "pending", "hook_due_at": after(-1),
        "hook_destination": format!("/copy-target/absent-{}", uuid::Uuid::new_v4()),
    })).unwrap();
    workflow.schedule_hook().unwrap();
    let pending = workflow.job(id).unwrap();
    assert_eq!(pending["hook_status"], "pending");
    assert_eq!(pending["hook_attempts"], 0);
    assert!(!string(&pending, "hook_error").contains("symlink"));
    assert!(string(&pending, "hook_due_at") > now().as_str());
}

#[test]
fn submission_deduplicates_and_ui_has_live_stats() {
    let (_temp, qbt, workflow) = fixture();
    let job = submit(&workflow);
    assert_eq!(job["state"], "downloading");
    assert_eq!(job["progress"], 0.25);
    assert_eq!(job["download_speed_bytes_per_s"], 3);
    assert!(
        string(qbt.torrent.lock().unwrap().as_ref().unwrap(), "tags")
            .contains(string(&job, "unique_tag"))
    );
    let duplicate = workflow.submit(
        json!({"magnet_uri":job["magnet_uri"],"final_parent":job["final_parent"]}),
        None,
    );
    assert!(duplicate.is_err());
    assert_eq!(workflow.db.list_jobs().unwrap().len(), 1);
    assert_eq!(
        qbt.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|path| path.as_str() == "/api/v2/auth/login")
            .count(),
        1
    );
}

#[test]
fn historical_ownership_tags_are_reserved_in_suggestions_and_submissions() {
    let (_temp, qbt, workflow) = fixture();
    let job = submit(&workflow);
    workflow
        .update(
            string(&job, "id"),
            json!({
                "managed_tag": "HistoricalManager",
                "unique_tag": "LegacyOwner",
            }),
        )
        .unwrap();
    *qbt.tags.lock().unwrap() = vec![
        "Media",
        "media",
        "HistoricalManager",
        "HISTORICALMANAGER",
        "LegacyOwner",
        "TI_JOB_example",
        "bad,tag",
        "  Archive  ",
        "Media",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    qbt.tags
        .lock()
        .unwrap()
        .push(workflow.config.string("managed_tag"));
    assert_eq!(
        workflow.selectable_tags().unwrap(),
        vec!["Archive", "Media", "media"]
    );

    let calls_before = qbt.calls.lock().unwrap().len();
    for reserved in ["historicalmanager", "LEGACYOWNER"] {
        let result = workflow.submit(
            json!({
                "magnet_uri": format!("magnet:?xt=urn:btih:{}", "b".repeat(40)),
                "final_parent": job["final_parent"],
                "custom_tags": [reserved],
            }),
            None,
        );
        assert!(result.unwrap_err().to_string().contains("historical"));
    }
    assert_eq!(workflow.db.list_jobs().unwrap().len(), 1);
    assert_eq!(qbt.calls.lock().unwrap().len(), calls_before);
}

#[test]
fn post_promotion_admin_actions_enforce_state_and_feature_gates() {
    let (_temp, _qbt, mut workflow) = fixture();
    let job = submit(&workflow);
    let id = string(&job, "id");
    workflow
        .update(
            id,
            json!({
                "state": "done",
                "is_terminal": true,
                "scan_completed_at": now(),
                "promoted_at": now(),
                "hook_kind": "copy",
                "hook_status": "succeeded",
                "hook_destination": "/copy-target/original-route",
                "hook_copy_source_root": "/media",
                "hook_copy_relative_path": "Media/payload",
            }),
        )
        .unwrap();
    assert!(workflow.action(id, "retry-hook", json!({})).is_err());
    assert!(workflow.action(id, "cancel-copy", json!({})).is_err());

    workflow
        .update(id, json!({"hook_status": "failed"}))
        .unwrap();
    assert!(workflow.action(id, "retry-hook", json!({})).is_err());
    workflow.config.values["post_promotion_copy_enabled"] = json!(true);
    let retry = workflow.action(id, "retry-hook", json!({})).unwrap();
    assert_eq!(retry["queued"], true);
    let queued = workflow.job(id).unwrap();
    assert_eq!(queued["hook_status"], "pending");
    assert_eq!(queued["hook_destination"], "/copy-target/original-route");
    assert_eq!(queued["hook_copy_relative_path"], "Media/payload");

    let cancelled = workflow.action(id, "cancel-copy", json!({})).unwrap();
    assert_eq!(cancelled["hook_status"], "cancelled");
    assert!(workflow.action(id, "retry-copy", json!({})).is_err());
    assert!(workflow.action(id, "cancel-copy", json!({})).is_err());

    workflow.config.values["post_promotion_copy_enabled"] = json!(false);
    workflow
        .update(
            id,
            json!({
                "hook_kind": "script",
                "hook_status": "interrupted",
                "hook_script": "/hooks/old-script",
            }),
        )
        .unwrap();
    assert!(workflow.action(id, "retry-hook", json!({})).is_err());
    workflow.config.values["post_promotion_enabled"] = json!(true);
    workflow.config.values["post_promotion_script"] = json!("/hooks/new-script");
    assert_eq!(
        workflow.action(id, "retry-hook", json!({})).unwrap()["queued"],
        true
    );
    let queued = workflow.job(id).unwrap();
    assert_eq!(queued["hook_script"], "/hooks/new-script");
    assert!(queued["hook_destination"].is_null());
    assert!(workflow.action(id, "cancel-copy", json!({})).is_err());
}

#[test]
fn offline_archive_workspace_does_not_prevent_controller_startup() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let scratch = root.join("offline-mount");
    let mut config = Config::defaults();
    config.values["data_dir"] = json!(root.join("data"));
    config.values["archive_scratch_dir"] = json!(scratch);
    config.values["archive_enabled"] = json!(true);
    std::fs::create_dir(config.path("data_dir")).unwrap();
    let db = Database::open(root.join("data/db.sqlite")).unwrap();
    assert!(Workflow::new(config.clone(), db.clone()).is_ok());
    assert!(
        !scratch.exists(),
        "startup must not create a missing mountpoint"
    );
    config.values["archive_enabled"] = json!(false);
    assert!(Workflow::new(config, db).is_ok());
    assert!(!scratch.exists());
}

#[test]
fn completion_callback_never_replaces_verified_path_and_wrong_tag_is_ignored() {
    let (_temp, _qbt, workflow) = fixture();
    let job = submit(&workflow);
    let id = string(&job, "id");
    let result = workflow
        .completion(
            json!({"qbt_hash":job["qbt_hash"],"unique_tag":"ti_job_old","content_path":"/etc"}),
        )
        .unwrap();
    assert!(result.is_none());
    let result=workflow.completion(json!({"qbt_hash":job["qbt_hash"],"unique_tag":job["unique_tag"],"content_path":"/etc"})).unwrap().unwrap();
    assert_ne!(result["content_path"], "/etc");
    workflow.mark(id, "done", None).unwrap();
    let before = workflow.job(id).unwrap();
    workflow
        .completion(json!({"unique_tag":job["unique_tag"],"content_path":"/etc"}))
        .unwrap();
    assert_eq!(workflow.job(id).unwrap(), before);
}
#[test]
fn historical_callback_routing_retains_terminal_row_and_rejects_conflicting_owner() {
    let (_temp, _qbt, workflow) = fixture();
    let current = submit(&workflow);
    let current_id = string(&current, "id");
    let mut old = workflow.job(current_id).unwrap();
    old["id"] = json!("historical-job");
    old["unique_tag"] = json!("ti_job_historical");
    old["state"] = json!("done");
    old["is_terminal"] = json!(true);
    workflow.db.insert_job(&old).unwrap();
    let result = workflow
        .completion(json!({
            "qbt_hash": current["qbt_hash"], "unique_tag": old["unique_tag"],
        }))
        .unwrap()
        .unwrap();
    assert_eq!(result["id"], old["id"]);
    assert_eq!(workflow.job(current_id).unwrap()["state"], "downloading");
    assert_eq!(workflow.job("historical-job").unwrap(), old);

    let mut conflicting = old.clone();
    conflicting["id"] = json!("other-active-job");
    conflicting["unique_tag"] = json!("ti_job_other");
    conflicting["qbt_hash"] = json!("b".repeat(40));
    conflicting["state"] = json!("downloading");
    conflicting["is_terminal"] = json!(false);
    workflow.db.insert_job(&conflicting).unwrap();
    let rejected = workflow
        .completion(json!({
            "qbt_hash": current["qbt_hash"], "unique_tag": conflicting["unique_tag"],
        }))
        .unwrap();
    assert!(rejected.is_none());
    assert_eq!(workflow.job("other-active-job").unwrap(), conflicting);
    let result = workflow
        .completion(json!({"qbt_hash": string(&current, "qbt_hash").to_uppercase()}))
        .unwrap()
        .unwrap();
    assert_eq!(result["id"], current["id"]);
}

#[test]
fn copy_queue_requires_clean_promotion_and_never_pins_traversal() {
    let (_temp, _qbt, mut workflow) = fixture();
    let current = submit(&workflow);
    let root = workflow.config.path("final_parent_prefix");
    workflow.config.values["post_promotion_copy_enabled"] = json!(true);
    workflow.config.values["post_promotion_copy_rules"] = json!([
        {"source": root, "destination": "/copy-target/media", "enabled": true},
    ]);
    let mut job = workflow.job(string(&current, "id")).unwrap();
    assert!(workflow
        .hook_patch(&job)
        .unwrap()
        .as_object()
        .unwrap()
        .is_empty());
    job["state"] = json!("done");
    job["is_terminal"] = json!(true);
    job["scan_completed_at"] = json!(now());
    job["promoted_at"] = json!(now());
    for invalid in [
        root.clone(),
        root.join("../outside"),
        std::path::PathBuf::from("relative"),
    ] {
        job["content_path"] = json!(invalid);
        assert!(workflow
            .hook_patch(&job)
            .unwrap()
            .as_object()
            .unwrap()
            .is_empty());
    }
    job["content_path"] = json!(root.join("Media/payload"));
    assert_eq!(
        workflow.hook_patch(&job).unwrap()["hook_copy_relative_path"],
        "Media/payload"
    );
}

#[test]
fn removing_tracking_does_not_delete_pause_or_mutate_torrent() {
    let (_temp, qbt, workflow) = fixture();
    let job = submit(&workflow);
    qbt.calls.lock().unwrap().clear();
    assert_eq!(
        workflow
            .action(string(&job, "id"), "delete", json!({}))
            .unwrap()["deleted"],
        true
    );
    assert!(qbt.torrent.lock().unwrap().is_some());
    assert!(qbt.calls.lock().unwrap().is_empty());
}
#[test]
fn missing_owner_tag_blocks_staging_change() {
    let (_temp, qbt, workflow) = fixture();
    let job = submit(&workflow);
    let id = string(&job, "id");
    workflow.mark(id, "waiting_for_local_space", None).unwrap();
    qbt.torrent.lock().unwrap().as_mut().unwrap()["tags"] = json!("unmanaged");
    qbt.calls.lock().unwrap().clear();
    assert!(workflow.action(id, "move-to-nas", json!({})).is_err());
    assert!(!qbt
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|path| path.contains("setLocation") || path.ends_with("/stop")));
}
#[test]
fn promotion_waits_for_verified_destination_and_atomically_queues_hook() {
    let (_temp, qbt, mut workflow) = fixture();
    workflow.config.values["post_promotion_enabled"] = json!(true);
    workflow.config.values["post_promotion_script"] = json!("/hooks/example");
    let job = submit(&workflow);
    let id = string(&job, "id");
    let staged = workflow.config.path("local_staging_root").join("payload");
    std::fs::write(&staged, b"scanned").unwrap();
    workflow
        .update(id, json!({"state":"scan_clean","scan_completed_at":now()}))
        .unwrap();
    {
        let mut state = qbt.torrent.lock().unwrap();
        let torrent = state.as_mut().unwrap();
        torrent["progress"] = json!(1.0);
        torrent["amount_left"] = json!(0);
        torrent["state"] = json!("stoppedUP");
    }
    workflow.reconcile(&workflow.job(id).unwrap()).unwrap();
    assert_eq!(workflow.job(id).unwrap()["state"], "promoting");
    // A successful setLocation request does not establish completion until the
    // filesystem path and next authenticated qB snapshot both confirm it.
    assert!(workflow.reconcile(&workflow.job(id).unwrap()).is_err());
    let parent = std::path::Path::new(string(&job, "final_parent"));
    std::fs::create_dir_all(parent).unwrap();
    std::fs::rename(staged, parent.join("payload")).unwrap();
    workflow.reconcile(&workflow.job(id).unwrap()).unwrap();
    assert_eq!(workflow.job(id).unwrap()["state"], "done");
    assert_eq!(workflow.job(id).unwrap()["hook_status"], "pending");
    assert_eq!(
        qbt.torrent.lock().unwrap().as_ref().unwrap()["state"],
        "uploading"
    );
}
#[test]
fn expired_scan_lease_requeues_but_live_lease_is_preserved() {
    let (_temp, _qbt, workflow) = fixture();
    let job = submit(&workflow);
    let id = string(&job, "id");
    workflow
        .db
        .save_scan_run(
            id,
            &json!({"worker_id":"old","lease_expires_at":after(600)}),
        )
        .unwrap();
    workflow.mark(id, "scanning", None).unwrap();
    workflow
        .db
        .save_scan_file(
            id,
            &json!({
                "relative_path": "active.mkv", "size_bytes": 10, "mtime_ns": 1,
                "status": "scanning", "scan_started_at": now(),
            }),
        )
        .unwrap();
    workflow
        .db
        .save_scan_file(
            id,
            &json!({
                "relative_path": "clean.mkv", "size_bytes": 20, "mtime_ns": 2,
                "status": "clean", "scan_started_at": "2026-01-01 00:00:00",
            }),
        )
        .unwrap();
    workflow.recover_scans().unwrap();
    assert_eq!(workflow.job(id).unwrap()["state"], "scanning");
    workflow
        .db
        .save_scan_run(
            id,
            &json!({"lease_expires_at":after(-600),"pause_requested":true}),
        )
        .unwrap();
    workflow.recover_scans().unwrap();
    assert_eq!(workflow.job(id).unwrap()["state"], "scan_paused");
    assert!(workflow.db.get_scan_run(id).unwrap().unwrap()["worker_id"].is_null());
    let files = workflow.db.list_scan_files(id).unwrap();
    assert_eq!(files[0]["status"], "pending");
    assert!(files[0]["scan_started_at"].is_null());
    assert_eq!(files[1]["status"], "clean");
    assert_eq!(files[1]["scan_started_at"], "2026-01-01 00:00:00");
}

#[test]
fn scan_checkpoints_are_invalidated_by_changed_file_or_engine() {
    let (_temp, _qbt, workflow) = fixture();
    let job = submit(&workflow);
    let id = string(&job, "id");
    let root = workflow.config.path("local_staging_root").join("payload");
    std::fs::create_dir(&root).unwrap();
    let file = root.join("file.bin");
    std::fs::write(&file, b"original").unwrap();
    workflow
        .db
        .save_scan_run(
            id,
            &json!({"worker_id":"test","lease_expires_at":after(600)}),
        )
        .unwrap();
    let mut identity = crate::scanning::ScannerIdentity {
        backend: "test".into(),
        engine_version: Some("1".into()),
        database_version: Some("1".into()),
        database_updated_at: Some(Utc::now()),
        policy_version: "policy".into(),
        raw_version: "test".into(),
    };
    assert_eq!(
        workflow
            .prepare_manifest(id, "test", &root, &identity)
            .unwrap()[0]["status"],
        "pending"
    );
    workflow
        .db
        .save_scan_file(id, &json!({"relative_path":"file.bin","status":"clean"}))
        .unwrap();
    assert_eq!(
        workflow
            .prepare_manifest(id, "test", &root, &identity)
            .unwrap()[0]["status"],
        "clean"
    );
    std::fs::write(&file, b"replaced").unwrap();
    assert_eq!(
        workflow
            .prepare_manifest(id, "test", &root, &identity)
            .unwrap()[0]["status"],
        "pending"
    );
    workflow
        .db
        .save_scan_file(id, &json!({"relative_path":"file.bin","status":"clean"}))
        .unwrap();
    identity.engine_version = Some("2".into());
    assert_eq!(
        workflow
            .prepare_manifest(id, "test", &root, &identity)
            .unwrap()[0]["status"],
        "pending"
    );
    workflow.set_paused(true);
    assert!(workflow
        .prepare_manifest(id, "test", &root, &identity)
        .is_err());
}

#[test]
fn eta_preserves_sample_threshold_confidence_history_bound_and_elapsed_guard() {
    let (_temp, _qbt, workflow) = fixture();
    let job = submit(&workflow);
    let id = string(&job, "id");
    let mib = 1024 * 1024;
    workflow
        .db
        .save_scan_file(
            id,
            &json!({
                "relative_path": "remaining.mkv", "size_bytes": 20 * mib,
                "mtime_ns": 0, "status": "pending",
            }),
        )
        .unwrap();
    for index in 0..2 {
        workflow
            .db
            .save_scan_file(
                id,
                &json!({
                    "relative_path": format!("done-{index}"), "size_bytes": 10 * mib,
                    "mtime_ns": index, "status": "clean", "scan_duration_seconds": 10 + index,
                    "scanned_at": now(),
                }),
            )
            .unwrap();
    }
    assert_eq!(workflow.estimate_eta(id).unwrap(), (None, None));
    workflow
        .db
        .save_scan_file(
            id,
            &json!({
                "relative_path": "done-2", "size_bytes": 10 * mib, "mtime_ns": 2,
                "status": "clean", "scan_duration_seconds": 12, "scanned_at": now(),
            }),
        )
        .unwrap();
    assert_eq!(workflow.estimate_eta(id).unwrap(), (Some(11), Some("low")));
    let connection = workflow.db.connect().unwrap();
    connection.execute(
        "WITH RECURSIVE sequence(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM sequence WHERE n<100)
         INSERT INTO scan_files(job_id,relative_path,size_bytes,mtime_ns,status,scan_duration_seconds,scanned_at)
         SELECT ?1,'recent-'||n,?2,n,'clean',20,?3 FROM sequence",
        rusqlite::params![id, 10 * mib, now()],
    ).unwrap();
    connection.execute(
        "WITH RECURSIVE sequence(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM sequence WHERE n<200)
         INSERT INTO scan_files(job_id,relative_path,size_bytes,mtime_ns,status,scan_duration_seconds,scanned_at)
         SELECT ?1,'old-'||n,?2,n,'clean',999,'2000-01-01 00:00:00' FROM sequence",
        rusqlite::params![id, 10 * mib],
    ).unwrap();
    assert_eq!(
        workflow.estimate_eta(id).unwrap(),
        (Some(20), Some("high")),
        "only the latest 100 samples inform the estimate"
    );
    workflow.db.save_scan_file(id, &json!({
        "relative_path": "remaining.mkv", "status": "scanning", "scan_started_at": after(-120),
    })).unwrap();
    assert_eq!(workflow.estimate_eta(id).unwrap(), (None, Some("low")));
    workflow
        .db
        .save_scan_file(
            id,
            &json!({
                "relative_path": "remaining.mkv", "status": "clean",
            }),
        )
        .unwrap();
    assert_eq!(workflow.estimate_eta(id).unwrap(), (Some(0), Some("high")));
}

struct FakeClamd {
    path: std::path::PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl FakeClamd {
    fn new(path: std::path::PathBuf, infected: bool) -> Self {
        use std::os::unix::net::UnixListener;
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let handle = thread::spawn(move || {
            while !stopping.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Wait::from_millis(2));
                        continue;
                    }
                    Err(_) => break,
                };
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(Wait::from_secs(2))).unwrap();
                let mut command = Vec::new();
                let mut byte = [0];
                while stream.read_exact(&mut byte).is_ok() {
                    if byte[0] == 0 {
                        break;
                    }
                    command.push(byte[0]);
                }
                if command == b"zVERSION" {
                    let version = format!(
                        "ClamAV 1.4.3/12345/{}\0",
                        Utc::now().format("%a %b %d %H:%M:%S %Y")
                    );
                    let _ = stream.write_all(version.as_bytes());
                } else if command == b"zINSTREAM" {
                    loop {
                        let mut length = [0; 4];
                        if stream.read_exact(&mut length).is_err() {
                            break;
                        }
                        let size = u32::from_be_bytes(length);
                        if size == 0 {
                            break;
                        }
                        let mut payload = vec![0; size as usize];
                        if stream.read_exact(&mut payload).is_err() {
                            break;
                        }
                    }
                    let _ = stream.write_all(if infected {
                        b"stream: Eicar-Test-Signature FOUND\0"
                    } else {
                        b"stream: OK\0"
                    });
                }
            }
        });
        Self {
            path,
            stop,
            thread: Some(handle),
        }
    }
}
impl Drop for FakeClamd {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = std::os::unix::net::UnixStream::connect(&self.path);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
#[test]
fn scan_worker_reaches_clean_or_infected_only_after_checkpointing_actual_file() {
    for infected in [false, true] {
        let (_temp, qbt, mut workflow) = fixture();
        let job = submit(&workflow);
        let id = string(&job, "id");
        let payload = workflow.config.path("local_staging_root").join("payload");
        std::fs::write(&payload, b"bytes inspected by the fake daemon").unwrap();
        let daemon = FakeClamd::new(
            workflow.config.path("data_dir").join("clamd.sock"),
            infected,
        );
        let scanner = Arc::get_mut(&mut workflow.scanner).unwrap();
        scanner.settings.socket_path = daemon.path.clone();
        scanner.settings.ffprobe_binary = "/usr/bin/true".into();
        scanner.settings.ffmpeg_binary = "/usr/bin/true".into();
        {
            let mut state = qbt.torrent.lock().unwrap();
            let torrent = state.as_mut().unwrap();
            torrent["progress"] = json!(1.0);
            torrent["amount_left"] = json!(0);
            torrent["state"] = json!("uploading");
        }
        workflow.tick().unwrap();
        let deadline = std::time::Instant::now() + Wait::from_secs(10);
        while workflow.active_tasks() > 0 && std::time::Instant::now() < deadline {
            thread::sleep(Wait::from_millis(10));
        }
        assert_eq!(workflow.active_tasks(), 0);
        let updated = workflow.job(id).unwrap();
        assert_eq!(
            updated["state"],
            if infected {
                "scan_infected"
            } else {
                "scan_clean"
            },
            "{updated}"
        );
        let files = workflow.db.list_scan_files(id).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(
            files[0]["status"],
            if infected { "infected" } else { "clean" }
        );
        let run = workflow.db.get_scan_run(id).unwrap().unwrap();
        assert!(run["worker_id"].is_null());
        assert_eq!(run["completed_files"], 1);
        if infected {
            workflow.tick().unwrap();
            assert_eq!(workflow.job(id).unwrap()["state"], "infected_held");
        }
    }
}
