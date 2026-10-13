//! Reproducible persistence microbenchmark. No network or permanent files.
//! `cargo run --release --example persistence_probe -- 1000 [history_jobs]`
//! Allocation counters include Rust allocations, not SQLite's C allocator.
//! Linux additionally reports /proc/self/io write-call and storage counters.
use anyhow::Result;
use serde_json::json;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicU64, Ordering::Relaxed},
    time::Instant,
};
use torrent_intake::persistence::{backup, db::Database, state};

struct CountingAllocator;
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static ALLOCATED: AtomicU64 = AtomicU64::new(0);
static LIVE: AtomicU64 = AtomicU64::new(0);
static PEAK: AtomicU64 = AtomicU64::new(0);
fn allocated(size: usize) {
    ALLOCATIONS.fetch_add(1, Relaxed);
    ALLOCATED.fetch_add(size as u64, Relaxed);
    let current = LIVE.fetch_add(size as u64, Relaxed) + size as u64;
    PEAK.fetch_max(current, Relaxed);
}
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as u64, Relaxed);
        unsafe { System.dealloc(pointer, layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let replacement = unsafe { System.realloc(pointer, layout, size) };
        if !replacement.is_null() {
            LIVE.fetch_sub(layout.size() as u64, Relaxed);
            allocated(size);
        }
        replacement
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn process_io() -> (u64, u64, u64) {
    let text = std::fs::read_to_string("/proc/self/io").unwrap_or_default();
    let get = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(0)
    };
    (
        get("syscw:"),
        get("write_bytes:"),
        get("cancelled_write_bytes:"),
    )
}
fn resident_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
        * 1024
}
fn measure(name: &str, operations: usize, mut operation: impl FnMut() -> Result<()>) -> Result<()> {
    let io_before = process_io();
    let live_before = LIVE.load(Relaxed);
    PEAK.store(live_before, Relaxed);
    let allocations_before = ALLOCATIONS.load(Relaxed);
    let bytes_before = ALLOCATED.load(Relaxed);
    let started = Instant::now();
    for _ in 0..operations {
        operation()?;
    }
    let elapsed = started.elapsed();
    let peak = PEAK.load(Relaxed).saturating_sub(live_before);
    let allocations = ALLOCATIONS.load(Relaxed) - allocations_before;
    let allocated_bytes = ALLOCATED.load(Relaxed) - bytes_before;
    let io_after = process_io();
    println!(
        "{}",
        json!({
            "phase":name,"operations":operations,"elapsed_us":elapsed.as_micros(),
            "rust_allocations":allocations,"rust_allocated_bytes":allocated_bytes,
            "rust_peak_additional_bytes":peak,
            "write_syscalls":io_after.0-io_before.0,
            "storage_write_bytes":io_after.1-io_before.1,
            "cancelled_storage_write_bytes":io_after.2-io_before.2
        })
    );
    Ok(())
}
fn main() -> Result<()> {
    let count = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "1000".into())
        .parse()?;
    let directory = tempfile::tempdir()?;
    let rss_before = resident_bytes();
    let rust_before = LIVE.load(Relaxed);
    let sqlite_before = unsafe { rusqlite::ffi::sqlite3_memory_used() };
    let db = Database::open(directory.path().join("database.sqlite"))?;
    let rust_extra = LIVE.load(Relaxed).saturating_sub(rust_before);
    let sqlite_extra = unsafe { rusqlite::ffi::sqlite3_memory_used() } - sqlite_before;
    let rss_extra = resident_bytes().saturating_sub(rss_before);
    println!(
        "{}",
        json!({"phase":"connection_mode","production_idle_connection":true,
        "sqlite_version":rusqlite::version(),"retained_database_rust_bytes":rust_extra,
        "retained_database_sqlite_bytes":sqlite_extra,"rss_delta_bytes":rss_extra})
    );
    db.insert_job(&json!({
        "id":"probe","magnet_uri":"magnet:?xt=urn:btih:123","final_parent":"/media",
        "staging_preference":"local","staging_root_initial":"/staging",
        "managed_tag":"intake","unique_tag":"probe"
    }))?;
    db.save_scan_file(
        "probe",
        &json!({"relative_path":"file","size_bytes":42,"mtime_ns":123}),
    )?;
    let history_jobs: usize = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "0".into())
        .parse()?;
    if history_jobs > 0 {
        db.connect()?.execute("WITH RECURSIVE history(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM history WHERE i<?1)
            INSERT INTO jobs(id,magnet_uri,final_parent,staging_preference,staging_root_initial,managed_tag,unique_tag,is_terminal,torrent_file_data)
            SELECT 'history-'||i,'magnet:?xt=urn:btih:123','/media','local','/staging','intake','history-'||i,1,zeroblob(4096) FROM history", [history_jobs])?;
    }
    let file = directory.path().join("private.json");
    state::write_private(&file, &[b'x'; 4096])?;
    println!(
        "{}",
        json!({"phase":"database", "history_jobs":history_jobs,
        "bytes":std::fs::metadata(&db.path)?.len(),
        "synchronous":db.connect()?.pragma_query_value(None,"synchronous",|row|row.get::<_,i64>(0))?,
        "cache_size":db.connect()?.pragma_query_value(None,"cache_size",|row|row.get::<_,i64>(0))?})
    );
    measure("already_private_file", count, || state::make_private(&file))?;
    measure("already_private_directory", count, || {
        state::private_directory(directory.path())
    })?;
    measure("read_private_4k", count, || {
        state::read_private(&file, 8192)?;
        Ok(())
    })?;
    measure("read_job", count, || {
        db.get_job("probe")?;
        Ok(())
    })?;
    let patch = json!({"last_error":null,"is_terminal":false,"state":"submitted"});
    measure("unchanged_job", count, || db.update_job("probe", &patch))?;
    let patch = json!({"relative_path":"file","status":"pending"});
    measure("unchanged_checkpoint", count, || {
        db.save_scan_file("probe", &patch)
    })?;
    let mut value = 0;
    measure("changed_job", count, || {
        value += 1;
        db.update_job("probe", &json!({"size_bytes":value}))
    })?;
    measure("digest_4k", count, || {
        backup::file_digest(&file)?;
        Ok(())
    })?;
    // Truncate through a short-lived worker connection. The production idle
    // connection remains alive; the probe does not add a second idle handle.
    db.connect()?
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    let patch = json!({"last_error":null,"is_terminal":false,"state":"submitted"});
    measure("unchanged_job_after_checkpoint", count, || {
        db.update_job("probe", &patch)
    })?;
    let wal = std::fs::metadata(directory.path().join("database.sqlite-wal"))
        .map(|m| m.len())
        .unwrap_or(0);
    println!("{}", json!({"phase":"unchanged_job_wal","wal_bytes":wal}));
    Ok(())
}
