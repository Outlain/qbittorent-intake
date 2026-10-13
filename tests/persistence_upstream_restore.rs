//! Real upstream-produced archives, native restoration, and actual server startup.
#[path = "support/persistence_fixture.rs"]
mod fixture;

use anyhow::Result;
use base64::Engine;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use torrent_intake::persistence::{db::query_values, restore, state, Database};

#[test]
fn current_python_backup_preserves_every_saved_field_and_original_torrent_bytes() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let config = fixture::receiver(directory.path())?;
    let expected = fixture::expected();
    assert_eq!(
        hex::encode(Sha256::digest(fixture::BACKUP)),
        expected["sha256"]
    );
    let _lock = state::ControllerLock::acquire(&config.path("data_dir"))?;
    // Replacing an existing installation preserves a rollback snapshot and its token.
    let prior = Database::open(config.database_path()?)?;
    prior.insert_job(&json!({"id":"before-restore","magnet_uri":"magnet:?xt=urn:btih:0123456789012345678901234567890123456789","final_parent":"/media","staging_preference":"local","staging_root_initial":"/downloads/staging","managed_tag":"intake","unique_tag":"before-restore"}))?;
    drop(prior);
    let token = state::admin_token(&config.path("data_dir"))?;
    fixture::stage(&config)?;
    restore::apply_pending_restore(&config.values)?;
    let restored = fixture::restored_config(&config)?;
    for (key, value) in expected["settings"].as_object().unwrap() {
        let wanted = if ["data_dir", "database_url"].contains(&key.as_str()) {
            &config.values[key]
        } else {
            value
        };
        assert_eq!(&restored.values[key], wanted, "changed saved setting {key}");
    }
    assert_eq!(restored.values["infected_action"], "delete");
    assert_eq!(restored.values["post_promotion_enabled"], true);
    let database = Database::open(restored.database_path()?)?;
    let connection = database.connect()?;
    for (table, order) in [
        ("jobs", "id"),
        ("scan_runs", "job_id"),
        ("scan_files", "id"),
        ("scanner_control", "id"),
    ] {
        let rows = query_values(
            &connection,
            &format!("SELECT * FROM {table} ORDER BY {order}"),
            [],
        )?;
        assert_eq!(
            json!(rows),
            expected["tables"][table],
            "changed saved {table} fields"
        );
    }
    for (id, encoded) in expected["torrent_data"].as_object().unwrap() {
        let bytes = database.torrent_data(id)?.unwrap();
        assert_eq!(
            bytes,
            base64::engine::general_purpose::STANDARD.decode(encoded.as_str().unwrap())?
        );
        let parsed = torrent_intake::persistence::parse_torrent(&bytes)?;
        let job = database.get_job(id)?.unwrap();
        assert_eq!(parsed.magnet_uri, job["magnet_uri"]);
        assert!(
            torrent_intake::workflow::qbt::magnet_hashes(&parsed.magnet_uri)?
                .iter()
                .any(|hash| Some(hash.as_str()) == job["qbt_hash"].as_str())
        );
    }
    assert_eq!(
        fs::read_to_string(config.path("data_dir").join("deployment-notes.txt"))?,
        expected["notes"].as_str().unwrap()
    );
    assert_eq!(state::admin_token(&config.path("data_dir"))?, token);
    assert!(config
        .path("data_dir")
        .join("controller-paused.json")
        .exists());
    let receipt: serde_json::Value = serde_json::from_slice(&fs::read(
        config.path("data_dir").join("last-restore.json"),
    )?)?;
    let rollback = Database::open(
        std::path::Path::new(receipt["rollback_directory"].as_str().unwrap())
            .join("torrent_intake.db"),
    )?;
    assert!(rollback.get_job("before-restore")?.is_some());
    Ok(())
}

struct RecordingQbt {
    calls: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
    host: String,
}
impl RecordingQbt {
    fn start() -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let host = format!("http://{}", listener.local_addr()?);
        let calls = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (recorded, stopping) = (calls.clone(), stop.clone());
        let worker = thread::spawn(move || {
            while !stopping.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        recorded.fetch_add(1, Ordering::SeqCst);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                        let mut buffer = [0; 4096];
                        let _ = stream.read(&mut buffer);
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]",
                        );
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            calls,
            stop,
            worker: Some(worker),
            host,
        })
    }
}
impl Drop for RecordingQbt {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

#[test]
fn startup_applies_upstream_backup_without_contacting_qbt_or_running_queued_actions() -> Result<()>
{
    let directory = tempfile::tempdir()?;
    let config = fixture::receiver(directory.path())?;
    let recorder = RecordingQbt::start()?;
    fixture::stage(&config)?;
    let controller = fixture::Controller::start(&config, &recorder.host)?;
    let restored = fixture::restored_config(&config)?;
    assert_eq!(restored.values["infected_action"], "delete");
    assert_eq!(restored.values["post_promotion_enabled"], true);
    // Several scheduler cycles plus repeated job reads must remain non-mutating.
    for _ in 0..4 {
        assert_eq!(controller.get("/controller/status")?["paused"], true);
        controller.get("/jobs")?;
        thread::sleep(Duration::from_millis(550));
    }
    let database = Database::open(restored.database_path()?)?;
    for job in fixture::expected()["tables"]["jobs"].as_array().unwrap() {
        let saved = database.get_job(job["id"].as_str().unwrap())?.unwrap();
        assert_eq!(saved["state"], job["state"]);
        assert_eq!(saved["hook_status"], job["hook_status"]);
        assert_eq!(saved["hook_attempts"], job["hook_attempts"]);
    }
    assert_eq!(
        recorder.calls.load(Ordering::SeqCst),
        0,
        "paused restoration or polling contacted qBittorrent"
    );
    assert!(config.path("data_dir").join("admin-token").exists());
    Ok(())
}
