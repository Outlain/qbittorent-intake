//! Resumable scan scheduling. A run owns a lease; each completed file owns a
//! fingerprint. Losing either invalidates permission to publish a verdict.
use super::*;
use crate::{
    persistence::db::query_one,
    scanning::{FileIdentity, ScanError, ScannerIdentity},
};
use std::{
    collections::HashMap,
    path::Path,
    thread,
    time::{Duration as Wait, Instant},
};

impl Workflow {
    pub(super) fn maintenance(&self) -> Result<bool> {
        Ok(self.db.connect()?.query_row(
            "SELECT maintenance_mode FROM scanner_control WHERE id=1",
            [],
            |row| row.get::<_, bool>(0),
        )?)
    }
    pub fn scanner_status(&self) -> Result<Value> {
        let control = query_one(
            &self.db.connect()?,
            "SELECT * FROM scanner_control WHERE id=1",
            [],
        )?
        .context("scanner control missing")?;
        let (active, active_large, queued, paused): (u64, u64, u64, u64) =
            self.db.connect()?.query_row(
                "SELECT
                    COALESCE(SUM(j.state='scanning' AND r.lease_expires_at>?1),0),
                    COALESCE(SUM(j.state='scanning' AND r.lease_expires_at>?1
                        AND MAX(COALESCE(j.size_bytes,0),COALESCE(r.total_bytes,0))>=?2),0),
                    COALESCE(SUM(j.state='scan_pending'),0),
                    COALESCE(SUM(j.state='scan_paused'),0)
                 FROM jobs j LEFT JOIN scan_runs r ON r.job_id=j.id
                 WHERE j.state IN ('scanning','scan_pending','scan_paused')",
                rusqlite::params![
                    now(),
                    self.config.u64("large_scan_gib") * 1024 * 1024 * 1024
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )?;
        let mut health = serde_json::to_value(self.scanner.health())?;
        let identity = health["identity"].as_object().cloned().unwrap_or_default();
        for key in [
            "backend",
            "engine_version",
            "database_version",
            "database_updated_at",
            "policy_version",
            "raw_version",
        ] {
            health[key] = identity.get(key).cloned().unwrap_or(Value::Null);
        }
        Ok(json!({
            "default_slots": self.config.u64("max_concurrent_scans"),
            "requested_slots": number(&control, "requested_slots"),
            "hard_max_slots": self.config.u64("max_scan_slots"),
            "max_large_scans": self.config.u64("max_concurrent_large_scans"),
            "large_scan_gib": self.config.u64("large_scan_gib"),
            "per_job_scan_workers": self.config.u64("per_job_scan_workers"),
            "clamd_max_inflight_requests": self.config.u64("clamd_max_inflight_requests"),
            "active": active,
            "active_large": active_large,
            "queued": queued,
            "paused": paused,
            "boost_until_queue_empty": boolean(&control, "boost_until_queue_empty"),
            "maintenance_mode": boolean(&control, "maintenance_mode"),
            "maintenance_reason": control["maintenance_reason"],
            "maintenance_started_at": control["maintenance_started_at"],
            "maintenance_drained": boolean(&control, "maintenance_mode") && active == 0,
            "health": health,
        }))
    }
    /// Match the original estimator: a fixed per-file cost plus a size-dependent
    /// cost fitted to the latest 100 clean files. The bound keeps UI refreshes
    /// independent of the number of files in a large torrent's history.
    pub(super) fn estimate_eta(&self, id: &str) -> Result<(Option<u64>, Option<&'static str>)> {
        let connection = self.db.connect()?;
        let mut statement = connection.prepare(
            "SELECT size_bytes,scan_duration_seconds FROM scan_files
             WHERE job_id=?1 AND status='clean' AND scan_duration_seconds>0
             ORDER BY scanned_at DESC LIMIT 100",
        )?;
        let samples = statement
            .query_map([id], |row| {
                Ok((
                    row.get::<_, u64>(0)? as f64 / (1024.0 * 1024.0),
                    row.get::<_, f64>(1)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if samples.len() < 3 {
            return Ok((None, None));
        }
        let (remaining_count, remaining_bytes): (u64, u64) = connection.query_row(
            "SELECT COUNT(*),COALESCE(SUM(size_bytes),0) FROM scan_files
             WHERE job_id=?1 AND status IN ('pending','scanning')",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if remaining_count == 0 {
            return Ok((Some(0), Some("high")));
        }
        let count = samples.len() as f64;
        let mean_size = samples.iter().map(|(size, _)| size).sum::<f64>() / count;
        let mean_duration = samples.iter().map(|(_, duration)| duration).sum::<f64>() / count;
        let variance = samples
            .iter()
            .map(|(size, _)| (size - mean_size).powi(2))
            .sum::<f64>();
        let slope = if variance > 1e-9 {
            (samples
                .iter()
                .map(|(size, duration)| (size - mean_size) * (duration - mean_duration))
                .sum::<f64>()
                / variance)
                .max(0.0)
        } else {
            0.0
        };
        let intercept = (mean_duration - slope * mean_size).max(0.05);
        let predict = |size_mib: f64| intercept + slope * size_mib;
        let mut estimate = intercept * remaining_count as f64
            + slope * (remaining_bytes as f64 / (1024.0 * 1024.0));
        let relative_error = samples
            .iter()
            .map(|(size, duration)| (predict(*size) - duration).abs() / duration.max(0.1))
            .sum::<f64>()
            / count;
        if let Some(current) = query_one(&connection,
            "SELECT size_bytes,scan_started_at FROM scan_files WHERE job_id=?1 AND status='scanning' LIMIT 1",
            [id],
        )? {
            if let Ok(started) = chrono::NaiveDateTime::parse_from_str(
                string(&current, "scan_started_at"), "%Y-%m-%d %H:%M:%S%.f",
            ) {
                let elapsed = (Utc::now().naive_utc() - started).num_milliseconds().max(0) as f64 / 1000.0;
                let predicted = predict(number(&current, "size_bytes") as f64 / (1024.0 * 1024.0));
                if elapsed > (predicted * 2.0).max(60.0) {
                    return Ok((None, Some("low")));
                }
                estimate -= elapsed.min(predicted);
            }
        }
        let confidence = if samples.len() >= 30 && relative_error <= 0.35 {
            "high"
        } else if samples.len() >= 10 && relative_error <= 0.75 {
            "medium"
        } else {
            "low"
        };
        Ok((Some((estimate + 0.5).max(0.0) as u64), Some(confidence)))
    }
    pub fn scanner_control(&self, options: Value) -> Result<Value> {
        let _lock = self
            .management
            .lock()
            .map_err(|_| anyhow::anyhow!("management lock poisoned"))?;
        if let Some(slots) = options["slots"].as_u64() {
            if slots < 1 || slots > self.config.u64("max_scan_slots").max(1) {
                bail!("scanner slots outside configured limits");
            }
            self.db.connect()?.execute(
                "UPDATE scanner_control SET requested_slots=?1,
                    boost_until_queue_empty=?2, updated_at=?3 WHERE id=1",
                rusqlite::params![
                    slots,
                    options["boost_until_queue_empty"]
                        .as_bool()
                        .unwrap_or(slots > self.config.u64("max_concurrent_scans")),
                    now(),
                ],
            )?;
        }
        if let Some(enabled) = options["enabled"]
            .as_bool()
            .or_else(|| options["maintenance_mode"].as_bool())
        {
            self.db.connect()?.execute(
                "UPDATE scanner_control SET maintenance_mode=?1, maintenance_reason=?2,
                    maintenance_started_at=?3, updated_at=?4 WHERE id=1",
                rusqlite::params![
                    enabled,
                    options["reason"].as_str(),
                    if enabled { Some(now()) } else { None },
                    now(),
                ],
            )?;
        }
        self.scanner_status()
    }
    pub(super) fn recover_scans(&self) -> Result<()> {
        // A live worker renews its lease while clamd is busy. Only expired
        // leases are recovered; another process may still own a healthy run.
        let mut connection = self.db.connect()?;
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        transaction.execute(
            "UPDATE jobs SET state=CASE
                WHEN (SELECT pause_requested FROM scan_runs WHERE job_id=jobs.id)=1
                THEN 'scan_paused' ELSE 'scan_pending' END, updated_at=?1
             WHERE state='scanning' AND id IN
                (SELECT job_id FROM scan_runs WHERE lease_expires_at IS NULL OR lease_expires_at < ?1)",
            [now()],
        )?;
        transaction.execute(
            "UPDATE scan_files SET status='pending', scan_started_at=NULL WHERE status='scanning'
             AND job_id IN (SELECT id FROM jobs WHERE state IN ('scan_pending','scan_paused'))",
            [],
        )?;
        transaction.execute(
            "UPDATE scan_runs SET worker_id=NULL, heartbeat_at=NULL, lease_expires_at=NULL,
                current_file=NULL, current_file_started_at=NULL
             WHERE job_id IN (SELECT id FROM jobs WHERE state IN ('scan_pending','scan_paused'))
             AND (worker_id IS NOT NULL OR heartbeat_at IS NOT NULL OR lease_expires_at IS NOT NULL
                  OR current_file IS NOT NULL OR current_file_started_at IS NOT NULL)",
            [],
        )?;
        transaction.commit()?;
        Ok(())
    }
    pub(super) fn schedule_scans(&self) -> Result<()> {
        if self.is_stopping() || self.maintenance()? {
            return Ok(());
        }
        let control = query_one(
            &self.db.connect()?,
            "SELECT * FROM scanner_control WHERE id=1",
            [],
        )?
        .context("scanner control missing")?;
        let jobs = self.jobs_query("WHERE state IN ('scanning','scan_pending')", [])?;
        let queued = jobs
            .iter()
            .any(|job| string(job, "state") == "scan_pending");
        let mut candidates = Vec::new();
        let mut active = 0;
        let mut large_active = 0;
        for job in jobs {
            let run = self
                .db
                .get_scan_run(string(&job, "id"))?
                .unwrap_or(Value::Null);
            if string(&job, "state") == "scanning" {
                active += 1;
                if self.large(&job, &run) {
                    large_active += 1;
                }
            }
            if string(&job, "state") == "scan_pending"
                && !boolean(&run, "pause_requested")
                && (string(&run, "next_attempt_at").is_empty()
                    || string(&run, "next_attempt_at") <= now().as_str())
            {
                candidates.push((job, run));
            }
        }
        if !queued && boolean(&control, "boost_until_queue_empty") {
            self.db.connect()?.execute(
                "UPDATE scanner_control SET requested_slots=?1, boost_until_queue_empty=0 WHERE id=1",
                [self.config.u64("max_concurrent_scans").max(1)],
            )?;
        }
        // Priority wins, then aged jobs, then smaller work. Age prevents an
        // endless stream of small torrents starving an older large one.
        candidates.sort_by_key(|(job, run)| self.queue_key(job, run));
        let available = number(&control, "requested_slots")
            .min(self.config.u64("max_scan_slots").max(1))
            .saturating_sub(active);
        if available == 0 || candidates.is_empty() {
            return Ok(());
        }
        // Avoid turning a daemon outage into one job failure per scheduler tick.
        if !self.scanner.health().can_scan {
            return Ok(());
        }
        let mut claimed = 0;
        for (job, run) in candidates {
            if claimed >= available {
                break;
            }
            let large = self.large(&job, &run);
            if large && large_active >= self.config.u64("max_concurrent_large_scans").max(1) {
                continue;
            }
            let id = string(&job, "id").to_owned();
            let worker = uuid::Uuid::new_v4().to_string();
            let mut connection = self.db.connect()?;
            let transaction =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let changed = transaction.execute(
                "UPDATE jobs SET state='scanning', updated_at=?1, last_error=NULL
                 WHERE id=?2 AND state='scan_pending'
                 AND EXISTS(SELECT 1 FROM scan_runs WHERE job_id=?2 AND pause_requested=0)",
                rusqlite::params![now(), id],
            )?;
            if changed != 1 {
                continue;
            }
            transaction.execute(
                "UPDATE scan_runs SET worker_id=?1, started_at=?2, heartbeat_at=?2,
                    lease_expires_at=?3, next_attempt_at=NULL, attempts=attempts+1, updated_at=?2
                 WHERE job_id=?4",
                rusqlite::params![
                    worker,
                    now(),
                    after(self.config.u64("scan_lease_seconds").max(30) as i64),
                    id,
                ],
            )?;
            transaction.commit()?;
            self.active_scans.fetch_add(1, Ordering::SeqCst);
            let workflow = self.clone();
            thread::spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    workflow.scan_claim(&id, &worker)
                }));
                let error = match outcome {
                    Ok(Err(error)) => Some(error),
                    Err(_) => Some(anyhow::anyhow!("scan worker panicked")),
                    Ok(Ok(())) => None,
                };
                if let Some(error) = error {
                    if let Err(report) = workflow.scan_failed(&id, &worker, error) {
                        eprintln!("scan error could not be recorded: {report:#}");
                    }
                }
                workflow.active_scans.fetch_sub(1, Ordering::SeqCst);
            });
            claimed += 1;
            if large {
                large_active += 1;
            }
        }
        Ok(())
    }
    pub(super) fn queue_key(
        &self,
        job: &Value,
        run: &Value,
    ) -> (std::cmp::Reverse<u64>, bool, u64, String) {
        let queued = ["queued_at", "updated_at", "created_at"]
            .iter()
            .find_map(|key| {
                if *key == "queued_at" {
                    run[*key].as_str()
                } else {
                    job[*key].as_str()
                }
            })
            .unwrap_or("");
        let age = chrono::NaiveDateTime::parse_from_str(queued, "%Y-%m-%d %H:%M:%S%.f")
            .ok()
            .map(|time| (Utc::now().naive_utc() - time).num_hours().clamp(0, 50) as u64)
            .unwrap_or(0);
        let size = if number(run, "total_bytes") > 0 {
            number(run, "total_bytes")
        } else {
            number(job, "size_bytes")
        };
        (
            std::cmp::Reverse(number(run, "priority").saturating_add(age)),
            self.large(job, run),
            size,
            queued.to_owned(),
        )
    }
    fn large(&self, job: &Value, run: &Value) -> bool {
        number(job, "size_bytes").max(number(run, "total_bytes"))
            >= self.config.u64("large_scan_gib") * 1024 * 1024 * 1024
    }
    fn owns(&self, id: &str, worker: &str) -> Result<bool> {
        Ok(self
            .db
            .get_scan_run(id)?
            .is_some_and(|run| string(&run, "worker_id") == worker))
    }
    fn heartbeat(&self, id: &str, worker: &str) -> Result<bool> {
        let changed = self.db.connect()?.execute(
            "UPDATE scan_runs SET heartbeat_at=?1, lease_expires_at=?2, updated_at=?1
             WHERE job_id=?3 AND worker_id=?4",
            rusqlite::params![
                now(),
                after(self.config.u64("scan_lease_seconds").max(30) as i64),
                id,
                worker,
            ],
        )?;
        Ok(changed == 1)
    }
    fn release(&self, id: &str, worker: &str, state: &str) -> Result<()> {
        let mut connection = self.db.connect()?;
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE scan_runs SET worker_id=NULL, lease_expires_at=NULL, heartbeat_at=NULL,
                current_file=NULL, current_file_started_at=NULL, updated_at=?1
             WHERE job_id=?2 AND worker_id=?3",
            rusqlite::params![now(), id, worker],
        )?;
        if changed == 1 {
            transaction.execute(
                "UPDATE jobs SET state=?1,is_terminal=?2,updated_at=?3 WHERE id=?4",
                rusqlite::params![state, terminal(state), now(), id],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }
    fn scan_claim(&self, id: &str, worker: &str) -> Result<()> {
        let initial_guard = self
            .management
            .lock()
            .map_err(|_| anyhow::anyhow!("management lock poisoned"))?;
        if !self.owns(id, worker)? {
            return Err(ScanError::Cancelled.into());
        }
        let job = self.job(id)?;
        let torrent = self
            .find_torrent(&job)?
            .context("torrent temporarily unavailable")?;
        let hash = self.guard(&job, &torrent, false, true)?;
        self.qbt.pause(&hash)?;
        drop(initial_guard);
        let deadline = Instant::now()
            + Wait::from_secs(self.config.u64("pause_confirmation_timeout_seconds").max(1));
        let root = loop {
            if self.is_stopping() || !self.heartbeat(id, worker)? {
                return Err(ScanError::Cancelled.into());
            }
            let torrent = self
                .find_torrent(&job)?
                .context("torrent unavailable while confirming pause")?;
            if safety::paused(&torrent) {
                break self.guard_staging(&job, &torrent)?;
            }
            if Instant::now() >= deadline {
                bail!("qBittorrent did not confirm pause before scan");
            }
            thread::sleep(Wait::from_millis(250));
        };
        self.update(id, json!({"content_path":root}))?;
        let mut files_this_claim = 0;
        let mut prepared = false;
        loop {
            if self.is_stopping() || !self.owns(id, worker)? {
                return Err(ScanError::Cancelled.into());
            }
            let run = self.db.get_scan_run(id)?.context("scan run removed")?;
            if boolean(&run, "pause_requested") {
                self.release(id, worker, "scan_paused")?;
                return Ok(());
            }
            if self.maintenance()? {
                self.release(id, worker, "scan_pending")?;
                return Ok(());
            }
            let health = self.scanner.health();
            if !health.can_scan {
                return Err(ScanError::Unavailable(health.message).into());
            }
            let identity = health.identity.context("scanner identity unavailable")?;
            let version = identity_patch(&identity);
            if !prepared
                || run["engine_version"] != version["engine_version"]
                || run["policy_version"] != version["policy_version"]
            {
                self.prepare_manifest(id, worker, &root, &identity)?;
                prepared = true;
            }
            let mut pending = query_one(
                &self.db.connect()?,
                "SELECT * FROM scan_files WHERE job_id=?1 AND status='pending'
                 ORDER BY size_bytes,id LIMIT 1",
                [id],
            )?;
            if pending.is_none() {
                self.prepare_manifest(id, worker, &root, &identity)?;
                pending = query_one(
                    &self.db.connect()?,
                    "SELECT * FROM scan_files WHERE job_id=?1 AND status='pending'
                     ORDER BY size_bytes,id LIMIT 1",
                    [id],
                )?;
            }
            let Some(file) = pending.as_ref() else {
                // Re-enumeration above includes files created/changed after an
                // earlier checkpoint. Ownership and location are checked again.
                let torrent = self
                    .find_torrent(&self.job(id)?)?
                    .context("torrent disappeared before final scan verification")?;
                if self.guard_staging(&self.job(id)?, &torrent)? != root {
                    bail!("torrent path changed during scanning");
                }
                let _lock = self
                    .management
                    .lock()
                    .map_err(|_| anyhow::anyhow!("management lock poisoned"))?;
                let run = self.db.get_scan_run(id)?.context("scan run removed")?;
                if boolean(&run, "pause_requested") {
                    self.release(id, worker, "scan_paused")?;
                    return Ok(());
                }
                if !self.owns(id, worker)? {
                    return Err(ScanError::Cancelled.into());
                }
                self.db.save_scan_run(id, &json!({"verdict":"clean"}))?;
                self.update(id, json!({"scan_completed_at":now()}))?;
                self.release(id, worker, "scan_clean")?;
                return Ok(());
            };
            let relative = string(file, "relative_path");
            let absolute = if relative == "." {
                root.clone()
            } else {
                root.join(relative)
            };
            let before = safety::fingerprint(&absolute)?;
            if !safety::same_fingerprint(file, &before) {
                prepared = false;
                continue;
            }
            let begin_file = self
                .management
                .lock()
                .map_err(|_| anyhow::anyhow!("management lock poisoned"))?;
            if !self.owns(id, worker)? {
                return Err(ScanError::Cancelled.into());
            }
            self.db.save_scan_file(
                id,
                &json!({
                    "relative_path": relative,
                    "status": "scanning",
                    "attempts": number(file, "attempts") + 1,
                    "scan_started_at": now(),
                    "last_error": null,
                }),
            )?;
            self.db.save_scan_run(
                id,
                &json!({"current_file":relative,"current_file_started_at":now()}),
            )?;
            drop(begin_file);
            let heartbeat_time = Mutex::new(Instant::now() - Wait::from_secs(60));
            let cancelled = || {
                if self.is_stopping() {
                    return true;
                }
                let Ok(mut last) = heartbeat_time.lock() else {
                    return true;
                };
                if last.elapsed()
                    >= Wait::from_secs(self.config.u64("scan_heartbeat_seconds").clamp(1, 10))
                {
                    *last = Instant::now();
                    if !self.heartbeat(id, worker).unwrap_or(false) {
                        return true;
                    }
                }
                false
            };
            let result = self.scanner.scan_path(
                &absolute,
                Some(FileIdentity::read(&absolute)?),
                &cancelled,
            )?;
            // Reading ownership and publishing a result are one critical
            // section with respect to recovery, deletion, and a new claim.
            let publication = self
                .management
                .lock()
                .map_err(|_| anyhow::anyhow!("management lock poisoned"))?;
            if !self.owns(id, worker)? {
                return Err(ScanError::Cancelled.into());
            }
            if !safety::same_fingerprint(&before, &safety::fingerprint(&absolute)?) {
                bail!("file changed during scan");
            }
            let version = identity_patch(&result.identity);
            let mut patch = json!({
                "relative_path": relative,
                "status": if result.infected { "infected" } else { "clean" },
                "threat_name": result.threat_name,
                "scan_method": result.scan_method,
                "scan_started_at": result.scan_started_at,
                "scan_duration_seconds": result.duration_seconds,
                "scanned_at": now(),
                "last_error": null,
            });
            patch
                .as_object_mut()
                .unwrap()
                .extend(version.as_object().unwrap().clone());
            self.db.save_scan_file(id, &patch)?;
            self.db.connect()?.execute(
                "UPDATE scan_runs SET completed_files=completed_files+1,
                    completed_bytes=completed_bytes+?1 WHERE job_id=?2 AND worker_id=?3",
                rusqlite::params![number(file, "size_bytes"), id, worker],
            )?;
            self.db.save_scan_run(
                id,
                &json!({
                    "failure_count": 0,
                    "last_error": null,
                    "current_file": null,
                    "current_file_started_at": null,
                }),
            )?;
            if result.infected {
                self.db.save_scan_run(id, &json!({"verdict":"infected"}))?;
                self.update(
                    id,
                    json!({
                        "threat_name": result.threat_name.unwrap_or_else(|| "unknown".into()),
                        "scan_completed_at": now(),
                    }),
                )?;
                self.release(id, worker, "scan_infected")?;
                self.event(
                    id,
                    "threat_detected",
                    "critical",
                    "Malware detected in torrent intake",
                    json!({"source_path":absolute,"action_success":false}),
                )?;
                return Ok(());
            }
            drop(publication);
            files_this_claim += 1;
            if files_this_claim >= self.config.u64("scan_yield_after_files").max(1) {
                let priority = number(&run, "priority");
                let yield_now: bool = self.db.connect()?.query_row(
                    "SELECT EXISTS(SELECT 1 FROM jobs j LEFT JOIN scan_runs r ON r.job_id=j.id
                     WHERE j.state='scan_pending' AND
                       (COALESCE(r.priority,0)>?1 OR (?2 AND
                        MAX(COALESCE(j.size_bytes,0),COALESCE(r.total_bytes,0))<?3)))",
                    rusqlite::params![
                        priority,
                        self.large(&job, &run),
                        self.config.u64("large_scan_gib") * 1024 * 1024 * 1024
                    ],
                    |row| row.get(0),
                )?;
                if yield_now {
                    self.release(id, worker, "scan_pending")?;
                    return Ok(());
                }
            }
        }
    }
    pub(super) fn prepare_manifest(
        &self,
        id: &str,
        worker: &str,
        root: &Path,
        identity: &ScannerIdentity,
    ) -> Result<Vec<Value>> {
        let last_heartbeat = Mutex::new(Instant::now() - Wait::from_secs(60));
        let current = safety::manifest_with(root, &|| {
            if self.is_stopping() {
                return Err(ScanError::Cancelled.into());
            }
            let mut last = last_heartbeat
                .lock()
                .map_err(|_| anyhow::anyhow!("manifest heartbeat lock poisoned"))?;
            if last.elapsed() >= Wait::from_secs(1) {
                *last = Instant::now();
                if !self.heartbeat(id, worker)? {
                    return Err(ScanError::Cancelled.into());
                }
            }
            Ok(())
        })?;
        let _publication = self
            .management
            .lock()
            .map_err(|_| anyhow::anyhow!("management lock poisoned"))?;
        if !self.heartbeat(id, worker)? {
            return Err(ScanError::Cancelled.into());
        }
        let run = self.db.get_scan_run(id)?.unwrap_or(Value::Null);
        let versions = identity_patch(identity);
        let reset = string(&run, "root_path") != root.to_string_lossy()
            || run["engine_version"] != versions["engine_version"]
            || run["policy_version"] != versions["policy_version"];
        let old: HashMap<String, Value> = self
            .db
            .list_scan_files(id)?
            .into_iter()
            .map(|file| (string(&file, "relative_path").to_owned(), file))
            .collect();
        let paths: HashSet<_> = current
            .iter()
            .map(|file| string(file, "relative_path"))
            .collect();
        let connection = self.db.connect()?;
        for name in old.keys() {
            if !paths.contains(name.as_str()) {
                connection.execute(
                    "DELETE FROM scan_files WHERE job_id=?1 AND relative_path=?2",
                    rusqlite::params![id, name],
                )?;
            }
        }
        for mut file in current {
            let relative = string(&file, "relative_path").to_owned();
            let reusable = old.get(&relative).is_some_and(|old| {
                !reset && string(old, "status") == "clean" && safety::same_fingerprint(old, &file)
            });
            if reusable {
                continue;
            }
            file["status"] = json!("pending");
            file["threat_name"] = Value::Null;
            file["scanned_at"] = Value::Null;
            file["last_error"] = Value::Null;
            for key in [
                "scanner_version",
                "engine_version",
                "database_version",
                "database_updated_at",
                "policy_version",
                "scan_method",
                "scan_started_at",
                "scan_duration_seconds",
            ] {
                file[key] = Value::Null;
            }
            self.db.save_scan_file(id, &file)?;
        }
        let mut files = self.db.list_scan_files(id)?;
        files.sort_by_key(|file| number(file, "size_bytes"));
        let mut patch = versions;
        patch["root_path"] = json!(root);
        patch["total_files"] = json!(files.len());
        patch["completed_files"] = json!(files
            .iter()
            .filter(|file| string(file, "status") == "clean")
            .count());
        patch["total_bytes"] = json!(files
            .iter()
            .map(|file| number(file, "size_bytes"))
            .sum::<u64>());
        patch["completed_bytes"] = json!(files
            .iter()
            .filter(|file| string(file, "status") == "clean")
            .map(|file| number(file, "size_bytes"))
            .sum::<u64>());
        patch["updated_at"] = json!(now());
        self.db.save_scan_run(id, &patch)?;
        Ok(files)
    }
    fn scan_failed(&self, id: &str, worker: &str, error: anyhow::Error) -> Result<()> {
        let _publication = self
            .management
            .lock()
            .map_err(|_| anyhow::anyhow!("management lock poisoned"))?;
        if !self.owns(id, worker)? {
            return Ok(());
        }
        let run = self.db.get_scan_run(id)?.context("scan run removed")?;
        let message = format!("{error:#}");
        let interrupted = matches!(
            error.downcast_ref::<ScanError>(),
            Some(ScanError::Cancelled)
        );
        let unavailable = matches!(
            error.downcast_ref::<ScanError>(),
            Some(ScanError::Unavailable(_))
        );
        let policy = matches!(
            error.downcast_ref::<ScanError>(),
            Some(ScanError::Policy(_) | ScanError::Limit { .. })
        );
        let failures = number(&run, "failure_count") + u64::from(!interrupted && !unavailable);
        let state = if policy || failures >= self.config.u64("scan_max_failures").max(1) {
            "error"
        } else if boolean(&run, "pause_requested") {
            "scan_paused"
        } else {
            "scan_pending"
        };
        self.db.connect()?.execute(
            "UPDATE scan_files SET status='pending', last_error=?1
             WHERE job_id=?2 AND status='scanning'",
            rusqlite::params![message, id],
        )?;
        self.db.save_scan_run(
            id,
            &json!({
                "failure_count": failures,
                "last_error": message,
                "next_attempt_at": if interrupted {
                    Value::Null
                } else {
                    json!(after(
                        (self.config.u64("scan_retry_base_seconds").max(1)
                            * 2u64.saturating_pow(failures.saturating_sub(1).min(8) as u32)) as i64
                    ))
                },
            }),
        )?;
        self.update(id, json!({"last_error":message}))?;
        self.release(id, worker, state)?;
        self.event(
            id,
            "scan_failed",
            "warning",
            "Scanning stopped before a clean verdict",
            json!({"error":message,"retry":state!="error"}),
        )?;
        Ok(())
    }
}
fn identity_patch(identity: &ScannerIdentity) -> Value {
    json!({
        "scanner_version": identity.raw_version,
        "engine_version": identity.engine_version,
        "database_version": identity.database_version,
        "database_updated_at": identity.database_updated_at,
        "policy_version": identity.policy_version,
    })
}
