//! Reproducible UI allocation probe; run with `cargo run --release --example
//! http_profile -- 1000`. Counts requested heap bytes, not process RSS or disk I/O.
//! Use the same fixture/count/build mode when comparing two source revisions.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering::Relaxed},
    time::Instant,
};
use torrent_intake::{config::Config, http::render_ui};

struct CountingAllocator;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);

fn allocated(size: usize) {
    let live = LIVE.fetch_add(size, Relaxed) + size;
    PEAK.fetch_max(live, Relaxed);
    ALLOCATED.fetch_add(size, Relaxed);
    CALLS.fetch_add(1, Relaxed);
}
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = System.alloc(layout);
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = System.alloc_zeroed(layout);
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Relaxed);
        System.dealloc(pointer, layout);
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let result = System.realloc(pointer, layout, new_size);
        if !result.is_null() {
            LIVE.fetch_sub(layout.size(), Relaxed);
            allocated(new_size);
        }
        result
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn measure(name: &str, action: impl FnOnce() -> String) {
    let initial_live = LIVE.load(Relaxed);
    let initial_allocated = ALLOCATED.load(Relaxed);
    let initial_calls = CALLS.load(Relaxed);
    PEAK.store(initial_live, Relaxed);
    let started = Instant::now();
    let output = action();
    let elapsed = started.elapsed();
    let peak = PEAK.load(Relaxed).saturating_sub(initial_live);
    let allocated = ALLOCATED.load(Relaxed) - initial_allocated;
    let calls = CALLS.load(Relaxed) - initial_calls;
    println!(
        "{}",
        json!({
            "case": name,
            "elapsed_ms": elapsed.as_secs_f64() * 1000.0,
            "peak_extra_heap_bytes": peak,
            "allocated_bytes": allocated,
            "allocation_calls": calls,
            "output_bytes": output.len(),
            "sha256": hex::encode(Sha256::digest(output.as_bytes()))
        })
    );
}

fn main() {
    let count: usize = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "1000".into())
        .parse()
        .unwrap();
    let config = Config::defaults();
    let jobs: Vec<Value> = (0..count)
        .map(|index| json!({
            "id": format!("job-{index:06}"),
            "torrent_name": format!("Example media batch {:02} file {:02} 2160p", index / 24, index % 24),
            "magnet_uri": format!("magnet:?xt=urn:btih:{index:040x}"),
            "state": "done", "is_terminal": true,
            "staging_preference": "local", "staging_root_initial": "/staging-local",
            "final_parent": "/downloads/Media", "final_category": "Files",
            "content_path": format!("/downloads/Media/sample-{index:06}.mkv"),
            "size_bytes": 12_000_000_000_u64, "custom_tags": ["Files", "4K"],
            "managed_tag": "intake", "unique_tag": format!("ti_job_{index:06}"),
            "qbt_hash": format!("{index:040x}"), "last_error": null,
            "created_at": "2026-10-12 10:00:00", "updated_at": "2026-10-12 10:00:00",
            "hook_status": null, "scan": null
        }))
        .collect();
    for _ in 0..3 {
        measure("render_ui", || render_ui(&config, &jobs).unwrap());
    }
    // Show the isolated cost of the old and new JSON wrapping expressions.
    let old_rows = jobs.clone();
    measure("json_macro_wrapper", || json!(old_rows).to_string());
    let new_rows = jobs.clone();
    measure("owned_array_wrapper", || Value::Array(new_rows).to_string());
}
