//! Crash recovery with a live idle SQLite connection. The child deliberately
//! skips all Rust destructors, leaving committed WAL pages and an unfinished
//! transaction for SQLite to recover on the parent's next open.
use anyhow::Result;
use serde_json::json;
use std::{fs, process::Command};
use torrent_intake::persistence::Database;

const CHILD_DATABASE: &str = "TI_PERSISTENCE_RECOVERY_CHILD_DATABASE";

#[test]
fn committed_wal_survives_abrupt_exit_and_uncommitted_changes_roll_back() -> Result<()> {
    if let Some(path) = std::env::var_os(CHILD_DATABASE) {
        let database = Database::open(path)?;
        database.insert_job(&json!({
            "id":"crash-job","magnet_uri":"magnet:?xt=urn:btih:123","final_parent":"/media",
            "staging_preference":"local","staging_root_initial":"/staging",
            "managed_tag":"intake","unique_tag":"crash-job","state":"scanning"
        }))?;
        database.set_torrent_data("crash-job", b"original private torrent metadata")?;
        database.save_scan_run(
            "crash-job",
            &json!({"root_path":"/staging/payload","completed_files":1}),
        )?;
        database.save_scan_file(
            "crash-job",
            &json!({
                "relative_path":"payload.bin","size_bytes":42,"mtime_ns":123,"status":"clean"
            }),
        )?;
        let writer = database.connect()?;
        writer.execute_batch(
            "BEGIN IMMEDIATE; UPDATE jobs SET state='uncommitted' WHERE id='crash-job';",
        )?;
        // process::exit closes OS handles without running Database/Connection
        // destructors, so SQLite cannot perform its normal final checkpoint.
        std::process::exit(77);
    }

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("crash.sqlite");
    let output = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "committed_wal_survives_abrupt_exit_and_uncommitted_changes_roll_back",
            "--nocapture",
        ])
        .env(CHILD_DATABASE, &path)
        .output()?;
    assert_eq!(
        output.status.code(),
        Some(77),
        "child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        fs::metadata(directory.path().join("crash.sqlite-wal"))?.len() > 0,
        "the child must leave committed WAL pages for recovery"
    );
    let recovered = Database::open(&path)?;
    assert_eq!(
        recovered.get_job("crash-job")?.unwrap()["state"],
        "scanning"
    );
    assert_eq!(
        recovered.torrent_data("crash-job")?.unwrap(),
        b"original private torrent metadata"
    );
    assert_eq!(
        recovered.get_scan_run("crash-job")?.unwrap()["completed_files"],
        1
    );
    assert_eq!(
        recovered.list_scan_files("crash-job")?[0]["status"],
        "clean"
    );
    let connection = recovered.connect()?;
    assert_eq!(
        connection.query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))?,
        "ok"
    );
    assert!(!connection.prepare("PRAGMA foreign_key_check")?.exists([])?);
    Ok(())
}
