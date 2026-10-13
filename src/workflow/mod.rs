//! Application use cases. HTTP handlers call these methods; the worker calls
//! `tick`. Neither needs to know how qBittorrent or SQLite encodes its protocol.
mod actions;
mod hooks;
pub(crate) use hooks::copy_destination;
pub use hooks::{run_copy_hook, CopyHookRequest};
pub mod qbt;
mod safety;
mod scan;
#[cfg(test)]
mod tests;

use crate::{
    config::Config,
    persistence::{
        db::{job_columns, query_values},
        parse_torrent, Database,
    },
    scanning::{ScanSettings, Scanner},
};
use anyhow::{bail, Context, Result};
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

#[derive(Clone)]
pub struct Workflow {
    pub config: Config,
    pub db: Database,
    pub qbt: qbt::Qbt,
    pub scanner: Arc<Scanner>,
    management: Arc<Mutex<()>>,
    stopping: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    active_scans: Arc<AtomicUsize>,
    active_hooks: Arc<AtomicUsize>,
    last_poll: Arc<Mutex<std::time::Instant>>,
}

pub(super) fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or("")
}
pub(super) fn number(value: &Value, key: &str) -> u64 {
    value[key]
        .as_u64()
        .or_else(|| value[key].as_i64().map(|v| v.max(0) as u64))
        .unwrap_or(0)
}
pub(super) fn boolean(value: &Value, key: &str) -> bool {
    value[key]
        .as_bool()
        .unwrap_or_else(|| value[key].as_i64().unwrap_or(0) != 0)
}
pub(super) fn now() -> String {
    Utc::now().format("%Y-%m-%d %H:%M:%S%.6f").to_string()
}
pub(super) fn after(seconds: i64) -> String {
    (Utc::now() + Duration::seconds(seconds))
        .format("%Y-%m-%d %H:%M:%S%.6f")
        .to_string()
}
pub(super) fn terminal(state: &str) -> bool {
    matches!(
        state,
        "done" | "infected_held" | "infected_quarantined" | "infected_deleted" | "error"
    )
}
pub(super) fn scan_state(state: &str) -> bool {
    matches!(state, "scan_pending" | "scanning" | "scan_paused")
}
pub(super) fn action_state(state: &str) -> bool {
    matches!(
        state,
        "scan_clean"
            | "promoting"
            | "scan_infected"
            | "quarantining_infected"
            | "deleting_infected"
    )
}

impl Workflow {
    pub fn new(config: Config, db: Database) -> Result<Self> {
        crate::persistence::storage::pin_existing_jobs(&db, &config)?;
        let scanner = Scanner::new(ScanSettings::from_values(&config.values)?);
        if config.bool("archive_enabled") {
            if let Err(error) = scanner.cleanup_archive_workspaces() {
                // An offline extraction mount must not prevent configuration,
                // native scans, or media scans. Archive inspection will still
                // enforce its own storage checks before extracting anything.
                tracing::warn!("Archive workspace cleanup deferred: {error}");
            }
        }
        let workflow = Self {
            qbt: qbt::Qbt::new(config.clone())?,
            config,
            db,
            scanner: Arc::new(scanner),
            management: Arc::new(Mutex::new(())),
            stopping: Arc::new(AtomicBool::new(false)),
            paused: Arc::new(AtomicBool::new(false)),
            active_scans: Arc::new(AtomicUsize::new(0)),
            active_hooks: Arc::new(AtomicUsize::new(0)),
            last_poll: Arc::new(Mutex::new(
                std::time::Instant::now() - std::time::Duration::from_secs(86400),
            )),
        };
        workflow.db.connect()?.execute(
            "INSERT OR IGNORE INTO scanner_control
                (id, requested_slots, boost_until_queue_empty, maintenance_mode, updated_at)
             VALUES (1, ?1, 0, 0, ?2)",
            rusqlite::params![workflow.config.u64("max_concurrent_scans").max(1), now()],
        )?;
        // Scripts may have performed external side effects before a crash. Only
        // an explicit user retry may repeat a previously claimed action.
        workflow.db.connect()?.execute(
            "UPDATE jobs SET hook_status='interrupted',
                hook_error='Process restarted while action was running; inspect destination before retry',
                hook_finished_at=?1
             WHERE hook_status='running'",
            [now()],
        )?;
        // Startup occurs under the exclusive controller lock: no worker from
        // the prior process is alive, even when its lease has time remaining.
        workflow.db.connect()?.execute(
            "UPDATE scan_runs SET lease_expires_at=NULL
             WHERE job_id IN (SELECT id FROM jobs WHERE state='scanning')",
            [],
        )?;
        workflow.recover_scans()?;
        Ok(workflow)
    }
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
    }
    pub fn shutdown(&self) {
        self.stop();
    }
    pub fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::SeqCst);
    }
    pub fn active_tasks(&self) -> usize {
        self.active_workers()
    }
    pub fn active_workers(&self) -> usize {
        self.active_scans.load(Ordering::SeqCst) + self.active_hooks.load(Ordering::SeqCst)
    }
    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst) || self.paused.load(Ordering::SeqCst)
    }
    pub(super) fn job(&self, id: &str) -> Result<Value> {
        self.db.get_job(id)?.context("Job not found")
    }
    pub(super) fn update(&self, id: &str, patch: Value) -> Result<()> {
        self.db.update_job(id, &patch)
    }
    /// Filter in SQLite before decoding rows. Callers pass fixed SQL clauses;
    /// external values are always bound parameters, never part of this string.
    pub(super) fn jobs_query<P: rusqlite::Params>(
        &self,
        clause: &str,
        params: P,
    ) -> Result<Vec<Value>> {
        query_values(
            &self.db.connect()?,
            &format!("SELECT {} FROM jobs {clause}", job_columns()),
            params,
        )
    }
    fn update_observation(&self, job: &Value, mut patch: Value) -> Result<()> {
        let fields = patch
            .as_object_mut()
            .context("observation must be an object")?;
        fields.retain(|key, value| key != "updated_at" && job[key] != *value);
        if fields.is_empty() {
            return Ok(());
        }
        fields.insert("updated_at".into(), json!(now()));
        self.update(string(job, "id"), patch)
    }
    pub(super) fn mark(&self, id: &str, state: &str, error: Option<String>) -> Result<()> {
        self.update_observation(
            &self.job(id)?,
            json!({
                "state": state,
                "is_terminal": terminal(state),
                "updated_at": now(),
                "last_error": error,
            }),
        )
    }
    pub(super) fn sync_torrent(&self, job: &Value, torrent: &Value) -> Result<()> {
        self.update_observation(
            job,
            json!({
                "qbt_hash": torrent["hash"],
                "torrent_name": torrent["name"],
                "size_bytes": torrent["total_size"]
                    .as_u64()
                    .or_else(|| torrent["size"].as_u64()),
                "content_path": torrent["content_path"],
                "last_seen_qbt_state": torrent["state"],
                "updated_at": now(),
            }),
        )
    }
    pub(super) fn find_torrent(&self, job: &Value) -> Result<Option<Value>> {
        if let Some(torrent) = self.qbt.torrent(string(job, "qbt_hash"))? {
            // A hash can be re-used by a different intake submission. The
            // private tag is the identity of *this* submission.
            if qbt::tags(&torrent).contains(string(job, "unique_tag")) {
                return Ok(Some(torrent));
            }
        }
        self.qbt.by_tag(string(job, "unique_tag"))
    }
    pub fn get_job(&self, id: &str) -> Result<Value> {
        let mut job = self.enrich(self.job(id)?)?;
        if let Ok(Some(torrent)) = if self.is_stopping() {
            Ok(None)
        } else {
            self.find_torrent(&job)
        } {
            live_stats(&mut job, &torrent);
        }
        Ok(job)
    }
    pub fn list_jobs(&self) -> Result<Vec<Value>> {
        let mut runs: HashMap<String, Value> =
            query_values(&self.db.connect()?, "SELECT * FROM scan_runs", [])?
                .into_iter()
                .map(|run| (string(&run, "job_id").to_owned(), run))
                .collect();
        let mut queue = Vec::new();
        let mut jobs = Vec::new();
        for job in self.db.list_jobs()? {
            let run = runs.remove(string(&job, "id"));
            if string(&job, "state") == "scan_pending" {
                queue.push((
                    string(&job, "id").to_owned(),
                    self.queue_key(&job, run.as_ref().unwrap_or(&Value::Null)),
                ));
            }
            jobs.push(self.enrich_with_run(job, run)?);
        }
        if let Ok(torrents) = if self.is_stopping() {
            Ok(Vec::new())
        } else {
            self.qbt.list()
        } {
            let by_hash: HashMap<_, _> = torrents
                .iter()
                .map(|torrent| {
                    (
                        string(torrent, "hash").to_ascii_lowercase(),
                        (torrent, qbt::tags(torrent)),
                    )
                })
                .collect();
            for job in &mut jobs {
                if let Some((torrent, tags)) =
                    by_hash.get(&string(job, "qbt_hash").to_ascii_lowercase())
                {
                    if tags.contains(string(job, "unique_tag")) {
                        live_stats(job, torrent);
                    }
                }
            }
        }
        queue.sort_by(|a, b| a.1.cmp(&b.1));
        let positions: HashMap<_, _> = queue
            .into_iter()
            .enumerate()
            .map(|(index, (id, _))| (id, index + 1))
            .collect();
        for job in &mut jobs {
            job["scan_queue_position"] = positions
                .get(string(job, "id"))
                .map(|position| json!(position))
                .unwrap_or(Value::Null);
        }
        Ok(jobs)
    }
    fn enrich(&self, job: Value) -> Result<Value> {
        let run = self.db.get_scan_run(string(&job, "id"))?;
        self.enrich_with_run(job, run)
    }
    fn enrich_with_run(&self, mut job: Value, run: Option<Value>) -> Result<Value> {
        job["custom_tags"] =
            serde_json::from_str(string(&job, "custom_tags_json")).unwrap_or_else(|_| json!([]));
        for key in [
            "progress",
            "eta_seconds",
            "download_speed_bytes_per_s",
            "upload_speed_bytes_per_s",
            "activity_summary",
            "scan_current_file",
            "scan_current_file_started_at",
            "scan_queue_position",
            "scan_last_error",
            "scan_progress_percent",
            "scan_eta_seconds",
            "scan_eta_confidence",
            "scan_engine_version",
            "scan_database_version",
            "scan_database_updated_at",
            "scan_policy_version",
        ] {
            job[key] = Value::Null;
        }
        for key in [
            "scan_priority",
            "scan_total_files",
            "scan_completed_files",
            "scan_total_bytes",
            "scan_completed_bytes",
            "scan_attempts",
        ] {
            job[key] = json!(0);
        }
        job["scan_pause_requested"] = json!(false);
        job["scan_is_large"] = json!(
            number(&job, "size_bytes") >= self.config.u64("large_scan_gib") * 1024 * 1024 * 1024
        );
        job["can_edit_final_destination"] = json!(editable(&job, run.as_ref()));
        if let Some(run) = run {
            for key in [
                "priority",
                "pause_requested",
                "total_files",
                "completed_files",
                "total_bytes",
                "completed_bytes",
                "current_file",
                "current_file_started_at",
                "attempts",
                "last_error",
                "engine_version",
                "database_version",
                "database_updated_at",
                "policy_version",
            ] {
                job[format!("scan_{key}")] = run[key].clone();
            }
            let total = number(&run, "total_bytes");
            job["scan_progress_percent"] = if total > 0 {
                json!((number(&run, "completed_bytes") as f64 / total as f64 * 100.0).min(100.0))
            } else {
                Value::Null
            };
            job["scan_is_large"] = json!(
                total.max(number(&job, "size_bytes"))
                    >= self.config.u64("large_scan_gib") * 1024 * 1024 * 1024
            );
            if string(&job, "state") == "scanning" {
                let (seconds, confidence) = self.estimate_eta(string(&job, "id"))?;
                job["scan_eta_seconds"] = json!(seconds);
                job["scan_eta_confidence"] = json!(confidence);
            }
            if scan_state(string(&job, "state")) || action_state(string(&job, "state")) {
                job["activity_summary"] = json!(format!(
                    "{} | {}/{} files | {}/{} bytes{}{}",
                    string(&job, "state").replace('_', " "),
                    number(&run, "completed_files"),
                    number(&run, "total_files"),
                    number(&run, "completed_bytes"),
                    number(&run, "total_bytes"),
                    if string(&run, "current_file").is_empty() {
                        String::new()
                    } else {
                        format!(" | {}", string(&run, "current_file"))
                    },
                    if boolean(&run, "pause_requested") && string(&job, "state") == "scanning" {
                        " | pause requested after current file"
                    } else {
                        ""
                    }
                ));
            }
        }
        Ok(job)
    }
    pub fn submit(&self, options: Value, torrent_file: Option<(String, Vec<u8>)>) -> Result<Value> {
        let _lock = self
            .management
            .lock()
            .map_err(|_| anyhow::anyhow!("management lock poisoned"))?;
        let final_parent = self.final_parent(string(&options, "final_parent"))?;
        let tags =
            safety::normalize_tags(&options["custom_tags"], &self.config.string("managed_tag"))?;
        let reserved = self.reserved_tags()?;
        if tags
            .iter()
            .any(|tag| reserved.contains(&tag.to_lowercase()))
        {
            bail!("custom tags cannot reuse current or historical Intake ownership tags");
        }
        let magnet = match &torrent_file {
            Some((_, data)) => {
                if !string(&options, "magnet_uri").is_empty() {
                    bail!("submit a magnet or a torrent file, not both");
                }
                parse_torrent(data)?.magnet_uri
            }
            None => string(&options, "magnet_uri").trim().to_owned(),
        };
        qbt::magnet_hashes(&magnet)?;
        if self.qbt.existing(&magnet)?.is_some() {
            bail!("torrent already exists in qBittorrent");
        }
        let preference = if string(&options, "staging_preference").is_empty() {
            "local"
        } else {
            string(&options, "staging_preference")
        };
        if !matches!(preference, "local" | "nas") {
            bail!("staging preference must be local or nas");
        }
        let location = self.nas_location(string(&options, "nas_staging_id"))?;
        let root = if preference == "local" {
            self.config.string("local_staging_root")
        } else {
            string(&location, "path").to_owned()
        };
        let id = uuid::Uuid::new_v4().to_string();
        let tag = format!("ti_job_{}", uuid::Uuid::new_v4().simple());
        let filename = torrent_file.as_ref().map(|(name, _)| {
            name.replace('\\', "/")
                .rsplit('/')
                .next()
                .unwrap_or("upload.torrent")
                .chars()
                .take(255)
                .collect::<String>()
        });
        self.db.insert_job(&json!({
            "id": id,
            "created_at": now(),
            "updated_at": now(),
            "magnet_uri": magnet,
            "torrent_file_name": filename,
            "final_parent": final_parent,
            "final_category": options["final_category"],
            "staging_preference": preference,
            "staging_actual": preference,
            "staging_root_initial": root,
            "staging_root_actual": root,
            "staging_overridden": false,
            "nas_staging_id": location["id"],
            "nas_staging_label": location["label"],
            "nas_staging_path": location["path"],
            "nas_mount_marker": location["mount_marker"],
            "managed_tag": self.config.string("managed_tag"),
            "unique_tag": tag,
            "custom_tags_json": serde_json::to_string(&tags)?,
            "state": "adding_to_qbt",
            "is_terminal": false,
        }))?;
        let torrent_data = torrent_file.map(|(_, data)| data);
        if let Some(data) = &torrent_data {
            self.db.set_torrent_data(&id, data)?;
        }
        let job = self.job(&id)?;
        if preference == "nas" {
            if let Err(error) = safety::storage(&root, string(&location, "mount_marker")) {
                self.mark(&id, "waiting_for_nas", Some(error.to_string()))?;
                return self.get_job(&id);
            }
        }
        if let Err(error) = self.add_job_with_data(&job, torrent_data) {
            self.mark(
                &id,
                "error",
                Some(format!("qBittorrent submission failed: {error:#}")),
            )?;
            return Err(error);
        }
        self.mark(&id, "waiting_for_qbt_hash", None)?;
        if let Err(error) = self.process_job(&self.job(&id)?) {
            if error.downcast_ref::<reqwest::Error>().is_some() {
                self.update(
                    &id,
                    json!({"last_error": format!("qBittorrent hash lookup will retry: {error:#}")}),
                )?;
            } else {
                self.mark(&id, "error", Some(error.to_string()))?;
            }
        }
        self.get_job(&id)
    }
    fn add_job(&self, job: &Value) -> Result<()> {
        let data = self.db.torrent_data(string(job, "id"))?;
        self.add_job_with_data(job, data)
    }
    fn add_job_with_data(&self, job: &Value, data: Option<Vec<u8>>) -> Result<()> {
        if !job["torrent_file_name"].is_null() {
            let bytes = data.as_ref().context("saved torrent metadata is missing")?;
            if parse_torrent(bytes)?.magnet_uri != string(job, "magnet_uri") {
                bail!("saved torrent metadata does not match job");
            }
        }
        let mut tags = vec![
            string(job, "managed_tag").to_owned(),
            string(job, "unique_tag").to_owned(),
        ];
        let custom: Vec<String> = serde_json::from_str(string(job, "custom_tags_json"))?;
        tags.extend(custom);
        self.qbt.add(
            string(job, "magnet_uri"),
            data,
            string(job, "torrent_file_name"),
            string(job, "staging_root_actual"),
            &tags,
            &self.config.string("intake_category"),
        )
    }
    fn nas_location(&self, id: &str) -> Result<Value> {
        if id.is_empty() {
            return self.config.default_nas_location();
        }
        self.config
            .effective_nas_locations()
            .into_iter()
            .find(|item| string(item, "id") == id)
            .context("unknown NAS staging location")
    }
    pub fn completion(&self, event: Value) -> Result<Option<Value>> {
        let _lock = self
            .management
            .lock()
            .map_err(|_| anyhow::anyhow!("management lock poisoned"))?;
        let mut tags: HashSet<String> = string(&event, "tags")
            .split(',')
            .map(str::trim)
            .filter(|tag| tag.starts_with("ti_job_"))
            .map(str::to_owned)
            .collect();
        if !string(&event, "unique_tag").is_empty() {
            tags.insert(string(&event, "unique_tag").trim().to_owned());
        }
        if tags.len() > 1 {
            return Ok(None);
        }
        let hash = string(&event, "qbt_hash").trim();
        let candidate = if let Some(tag) = tags.iter().next() {
            self.jobs_query("WHERE unique_tag=?1 LIMIT 1", [tag])?
                .into_iter()
                .next()
        } else {
            if hash.is_empty() {
                return Ok(None);
            }
            let mut active = self.jobs_query(
                "WHERE is_terminal=0 AND qbt_hash=?1 COLLATE NOCASE LIMIT 2",
                [hash],
            )?;
            if active.len() > 1 {
                return Ok(None);
            }
            match active.pop() {
                Some(job) => Some(job),
                None => self
                    .jobs_query(
                        "WHERE qbt_hash=?1 COLLATE NOCASE ORDER BY created_at DESC,id LIMIT 1",
                        [hash],
                    )?
                    .into_iter()
                    .next(),
            }
        };
        let Some(job) = candidate else {
            return Ok(None);
        };
        if !hash.is_empty() && !string(&job, "qbt_hash").eq_ignore_ascii_case(hash) {
            let conflict: bool = self.db.connect()?.query_row(
                "SELECT EXISTS(SELECT 1 FROM jobs WHERE id!=?1 AND is_terminal=0
                 AND qbt_hash=?2 COLLATE NOCASE)",
                rusqlite::params![string(&job, "id"), hash],
                |row| row.get(0),
            )?;
            if conflict {
                return Ok(None);
            }
        }
        if !boolean(&job, "is_terminal")
            && !scan_state(string(&job, "state"))
            && !action_state(string(&job, "state"))
        {
            // Callback paths/names are intentionally ignored. Only authenticated
            // qBittorrent state may tell the worker what to scan or move.
            self.update(string(&job,"id"),json!({
                "completion_event_received_at": after(-(self.config.u64("completion_grace_seconds") as i64)),
                "state": "completion_event_received",
                "updated_at": now(),
            }))?;
            if let Err(error) = self.process_job(&self.job(string(&job, "id"))?) {
                self.update(
                    string(&job, "id"),
                    json!({"last_error":format!("Completion verification will retry: {error:#}")}),
                )?;
            }
        }
        Ok(Some(self.get_job(string(&job, "id"))?))
    }
    pub fn action(&self, id: &str, action: &str, options: Value) -> Result<Value> {
        let _lock = self
            .management
            .lock()
            .map_err(|_| anyhow::anyhow!("management lock poisoned"))?;
        let job = self.job(id)?;
        match action {
            "delete" => {
                if matches!(string(&job, "hook_status"), "pending" | "running") {
                    bail!(
                        "cannot remove a job while a post-promotion action is pending or running"
                    );
                }
                self.db
                    .connect()?
                    .execute("DELETE FROM jobs WHERE id=?1", [id])?;
                return Ok(json!({"deleted":true,"id":id}));
            }
            "retry" => {
                if string(&job, "state") != "error" {
                    bail!("only jobs in error can be retried");
                }
                if self.db.get_scan_run(id)?.is_some() {
                    self.db.save_scan_run(
                        id,
                        &json!({
                            "pause_requested": false,
                            "failure_count": 0,
                            "next_attempt_at": null,
                            "worker_id": null,
                            "lease_expires_at": null,
                            "heartbeat_at": null,
                            "current_file": null,
                            "current_file_started_at": null,
                            "verdict": null,
                            "last_error": null,
                        }),
                    )?;
                }
                self.update(
                    id,
                    json!({
                        "state": "waiting_for_qbt_hash",
                        "is_terminal": false,
                        "last_error": null,
                        "scan_completed_at": null,
                        "threat_name": null,
                    }),
                )?;
                if self.find_torrent(&job)?.is_none() {
                    self.add_job(&job)?;
                }
                self.process_job(&self.job(id)?)?;
            }
            "pause" | "pause-scan" => {
                if !scan_state(string(&job, "state")) {
                    bail!("job is not queued or scanning");
                }
                self.db
                    .save_scan_run(id, &json!({"pause_requested":true,"updated_at":now()}))?;
                if string(&job, "state") != "scanning" {
                    self.mark(id, "scan_paused", None)?;
                }
            }
            "resume" | "resume-scan" => {
                if !scan_state(string(&job, "state")) {
                    bail!("job is not queued or paused");
                }
                self.db
                    .save_scan_run(id, &json!({"pause_requested":false,"updated_at":now()}))?;
                if string(&job, "state") == "scan_paused" {
                    self.mark(id, "scan_pending", None)?;
                }
            }
            "prioritize" => {
                if !scan_state(string(&job, "state")) {
                    bail!("job is not in the scan queue");
                }
                let max: i64 = self.db.connect()?.query_row(
                    "SELECT COALESCE(MAX(priority),0) FROM scan_runs",
                    [],
                    |r| r.get(0),
                )?;
                self.db
                    .save_scan_run(id, &json!({"priority":max+1,"updated_at":now()}))?;
            }
            "final-destination" => {
                let destination = self.final_parent(string(&options, "final_parent"))?;
                let mut connection = self.db.connect()?;
                let transaction = connection
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let run = self.db.get_scan_run(id)?;
                if !editable(&job, run.as_ref()) {
                    bail!("destination editing is locked; wait for a safely paused scan");
                }
                let changed = transaction.execute(
                    "UPDATE jobs SET final_parent=?1, updated_at=?2
                     WHERE id=?3 AND final_parent=?4 AND state=?5",
                    rusqlite::params![
                        destination,
                        now(),
                        id,
                        string(&options, "expected_final_parent"),
                        string(&job, "state"),
                    ],
                )?;
                if changed != 1 {
                    bail!("destination changed concurrently; refresh this job");
                }
                transaction.commit()?;
            }
            "move-to-nas" => {
                if !matches!(
                    string(&job, "state"),
                    "waiting_for_local_space" | "waiting_for_nas"
                ) {
                    bail!("job is not waiting for storage");
                }
                if !string(&options, "nas_staging_id").is_empty() {
                    let location = self.nas_location(string(&options, "nas_staging_id"))?;
                    self.update(
                        id,
                        json!({
                            "nas_staging_id": location["id"],
                            "nas_staging_label": location["label"],
                            "nas_staging_path": location["path"],
                            "nas_mount_marker": location["mount_marker"],
                        }),
                    )?;
                }
                self.move_to_nas(&self.job(id)?, "manual_move_to_nas")?;
            }
            "retry-copy" | "retry-hook" => {
                if !matches!(string(&job, "hook_status"), "failed" | "interrupted") {
                    bail!("Only a failed or interrupted copy/script can be retried");
                }
                let enabled = if string(&job, "hook_kind") == "copy" {
                    self.config.bool("post_promotion_copy_enabled")
                } else {
                    self.config.bool("post_promotion_enabled")
                };
                if !enabled {
                    bail!(
                        "Enable the corresponding copy/script feature and restart before retrying"
                    );
                }
                if string(&job, "state") != "done"
                    || !boolean(&job, "is_terminal")
                    || job["scan_completed_at"].is_null()
                    || job["promoted_at"].is_null()
                {
                    bail!("This job has not completed clean promotion");
                }
                let mut retry = job.clone();
                retry["hook_status"] = Value::Null;
                let patch = self.hook_patch(&retry)?;
                if patch["hook_status"] != "pending" {
                    bail!("The saved post-promotion action cannot be queued");
                }
                self.update(id, patch)?;
                return Ok(json!({
                    "queued": true,
                    "message": "Action queued. Verify and resume Intake to run it; the torrent will not be scanned or moved again.",
                }));
            }
            "cancel-copy" => {
                if string(&job, "hook_kind") != "copy"
                    || !matches!(
                        string(&job, "hook_status"),
                        "pending" | "failed" | "interrupted"
                    )
                {
                    bail!("Only a pending, failed or interrupted built-in copy can be cancelled; refresh the job status");
                }
                self.update(
                    id,
                    json!({
                        "hook_status": "cancelled",
                        "hook_finished_at": now(),
                        "hook_error": "Copy cancelled by administrator. No files were removed; any existing or partial copy remains. This request cannot be retried.",
                    }),
                )?;
                return Ok(json!({
                    "hook_status": "cancelled",
                    "message": "Copy cancelled. No files were removed, including partial copies. This old request cannot be retried; its Intake history can now be cleared after resuming.",
                }));
            }
            "process" => self.process_job(&job)?,
            _ => bail!("unknown job action: {action}"),
        }
        self.get_job(id)
    }
    pub fn bulk(&self, action: &str, ids: Vec<String>, options: Value) -> Result<Value> {
        let mut processed = Vec::new();
        let mut failed = Vec::new();
        let mut errors = serde_json::Map::new();
        let unique: HashSet<_> = ids.into_iter().collect();
        let requested = unique.len();
        for id in unique {
            match self.action(&id, action, options.clone()) {
                Ok(_) => processed.push(id),
                Err(error) => {
                    errors.insert(id.clone(), json!(error.to_string()));
                    failed.push(id);
                }
            }
        }
        Ok(json!({
            "requested": requested,
            "processed": processed.len(),
            "skipped": 0,
            "failed": failed.len(),
            "processed_ids": processed,
            "skipped_ids": [],
            "failed_ids": failed,
            "errors": errors,
        }))
    }
    /// Historical ownership tags remain reserved after the configuration changes.
    /// Otherwise a custom tag could make an unrelated torrent look Intake-owned.
    fn reserved_tags(&self) -> Result<HashSet<String>> {
        let mut reserved = HashSet::from([self.config.string("managed_tag").to_lowercase()]);
        let connection = self.db.connect()?;
        let mut statement =
            connection.prepare("SELECT DISTINCT managed_tag, unique_tag FROM jobs")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?,
            ))
        })?;
        for row in rows {
            let (managed, unique) = row?;
            for tag in [managed, unique].into_iter().flatten() {
                reserved.insert(tag.to_lowercase());
            }
        }
        Ok(reserved)
    }

    pub fn selectable_tags(&self) -> Result<Vec<String>> {
        let reserved = self.reserved_tags()?;
        let raw = self.qbt.json("torrents/tags", &[])?;
        let mut tags = Vec::new();
        for tag in raw.as_array().into_iter().flatten() {
            let Ok(normalized) =
                safety::normalize_tags(&json!([tag]), &self.config.string("managed_tag"))
            else {
                continue;
            };
            for tag in normalized {
                if !reserved.contains(&tag.to_lowercase()) {
                    tags.push(tag);
                }
            }
        }
        tags.sort_by_key(|tag| (tag.to_lowercase(), tag.clone()));
        tags.dedup();
        Ok(tags)
    }

    pub fn suggestions(&self) -> Result<Value> {
        let torrents = self.qbt.list()?;
        let mut paths = self.config.allowed_final_parent_prefixes();
        for torrent in torrents {
            let path = string(&torrent, "save_path");
            if self.final_parent(path).is_ok() {
                paths.push(path.to_owned());
            }
        }
        paths.sort();
        paths.dedup();
        let categories = self.qbt.json("torrents/categories", &[])?;
        let tags = self.selectable_tags()?;
        Ok(json!({
            "paths": paths,
            "categories": categories
                .as_object()
                .map(|map| map.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default(),
            "tags": tags,
            "nas_staging_locations": self.config.effective_nas_locations(),
        }))
    }
    pub fn tick(&self) -> Result<()> {
        if self.is_stopping() {
            return Ok(());
        }
        let _lock = self
            .management
            .lock()
            .map_err(|_| anyhow::anyhow!("management lock poisoned"))?;
        self.recover_scans()?;
        let poll_due = {
            let mut last = self
                .last_poll
                .lock()
                .map_err(|_| anyhow::anyhow!("poll timer poisoned"))?;
            let due = last.elapsed()
                >= std::time::Duration::from_secs(
                    self.config.u64("polling_interval_seconds").max(1),
                );
            if due {
                *last = std::time::Instant::now();
            }
            due
        };
        let jobs = self.jobs_query(
            "WHERE is_terminal=0 AND state NOT IN ('scan_pending','scanning','scan_paused')
             AND (?1 OR state IN ('scan_clean','promoting','scan_infected',
                 'quarantining_infected','deleting_infected','waiting_for_qbt_hash',
                 'adding_to_qbt','completion_event_received'))
             ORDER BY created_at ASC,id DESC",
            [poll_due],
        )?;
        for job in jobs {
            let result = if action_state(string(&job, "state")) {
                self.reconcile(&job)
            } else {
                self.process_job(&job)
            };
            if let Err(error) = result {
                if action_state(string(&job, "state")) {
                    self.update_observation(
                        &job,
                        json!({
                            "last_error": format!("Post-scan action will retry: {error:#}"),
                        }),
                    )?;
                } else if string(&job, "state") == "waiting_for_qbt_hash"
                    && error.downcast_ref::<reqwest::Error>().is_some()
                {
                    self.update_observation(
                        &job,
                        json!({
                            "last_error": format!("qBittorrent hash lookup will retry: {error:#}"),
                        }),
                    )?;
                } else {
                    self.mark(string(&job, "id"), "error", Some(format!("{error:#}")))?;
                }
            }
        }
        self.schedule_scans()?;
        self.schedule_hook()?;
        Ok(())
    }
}

fn editable(job: &Value, run: Option<&Value>) -> bool {
    if boolean(job, "is_terminal") {
        return false;
    }
    if [
        "scan_completed_at",
        "promoted_at",
        "deleted_at",
        "threat_name",
        "quarantine_path",
        "hook_status",
    ]
    .iter()
    .any(|key| !job[key].is_null())
    {
        return false;
    }
    if matches!(
        string(job, "state"),
        "downloading" | "waiting_for_local_space" | "waiting_for_nas" | "waiting_for_qbt_hash"
    ) {
        return run.is_none()
            && job["completion_event_received_at"].is_null()
            && job["download_complete_at"].is_null();
    }
    string(job, "state") == "scan_paused"
        && run.is_some_and(|run| {
            boolean(run, "pause_requested")
                && [
                    "worker_id",
                    "lease_expires_at",
                    "heartbeat_at",
                    "current_file",
                    "current_file_started_at",
                    "verdict",
                ]
                .iter()
                .all(|key| run[key].is_null())
        })
}

fn live_stats(job: &mut Value, torrent: &Value) {
    job["last_seen_qbt_state"] = torrent["state"].clone();
    job["progress"] = torrent["progress"].clone();
    job["eta_seconds"] = torrent["eta"].clone();
    job["download_speed_bytes_per_s"] = torrent["dlspeed"].clone();
    job["upload_speed_bytes_per_s"] = torrent["upspeed"].clone();
    if !scan_state(string(job, "state")) && !action_state(string(job, "state")) {
        job["activity_summary"] = json!(format!(
            "qB {} | {:.2}% | down {} B/s | up {} B/s",
            string(torrent, "state"),
            torrent["progress"].as_f64().unwrap_or(0.0) * 100.0,
            number(torrent, "dlspeed"),
            number(torrent, "upspeed")
        ));
    }
}
