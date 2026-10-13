//! Download reconciliation and post-scan effects. Every effect is followed by
//! later observation: accepting a move/delete request is not proof it finished.
use super::*;
use safety::{complete, paused, storage};
use std::{fs, path::Path};

impl Workflow {
    pub(super) fn process_job(&self, job: &Value) -> Result<()> {
        let id = string(job, "id");
        if boolean(job, "is_terminal")
            || scan_state(string(job, "state"))
            || action_state(string(job, "state"))
        {
            return Ok(());
        }
        if string(job, "state") == "waiting_for_nas" && string(job, "qbt_hash").is_empty() {
            if let Err(error) = storage(
                string(job, "nas_staging_path"),
                string(job, "nas_mount_marker"),
            ) {
                self.update(id, json!({"last_error":error.to_string()}))?;
                return Ok(());
            }
            // An add response can be lost after qBittorrent accepted it. Always
            // look for our private tag before attempting another submission.
            if self.find_torrent(job)?.is_none() {
                self.add_job(job)?;
            }
        }
        let Some(torrent) = self.find_torrent(job)? else {
            if string(job, "state") == "adding_to_qbt" {
                self.add_job(job)?;
                self.mark(id, "waiting_for_qbt_hash", None)?;
                return Ok(());
            }
            if string(job, "qbt_hash").is_empty() {
                self.mark(id, "waiting_for_qbt_hash", None)?;
                return Ok(());
            }
            bail!("torrent disappeared from qBittorrent");
        };
        let mut current = job.clone();
        current["qbt_hash"] = torrent["hash"].clone();
        self.guard(&current, &torrent, false, false)?;
        self.sync_torrent(job, &torrent)?;
        if string(job, "staging_actual") == "nas" {
            if let Err(error) = storage(
                string(job, "nas_staging_path"),
                string(job, "nas_mount_marker"),
            ) {
                if !paused(&torrent) {
                    self.qbt.pause(string(&torrent, "hash"))?;
                }
                self.mark(id, "waiting_for_nas", Some(error.to_string()))?;
                return Ok(());
            }
            if string(job, "state") == "waiting_for_nas" {
                self.qbt.resume(string(&torrent, "hash"))?;
                self.mark(id, "downloading", None)?;
                return Ok(());
            }
        }
        if matches!(string(&torrent, "state"), "error" | "missingFiles") {
            bail!("qBittorrent reports {}", string(&torrent, "state"));
        }
        if string(job, "staging_actual") == "local" && self.local_capacity(&current, &torrent)? {
            return Ok(());
        }
        if complete(&torrent) {
            if let Some(received) = job["completion_event_received_at"]
                .as_str()
                .and_then(|value| {
                    chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f").ok()
                })
            {
                if Utc::now().naive_utc()
                    < received
                        + Duration::seconds(self.config.u64("completion_grace_seconds") as i64)
                {
                    self.update_observation(
                        job,
                        json!({
                            "download_complete_at": job["download_complete_at"].as_str()
                                .map(str::to_owned).unwrap_or_else(now),
                            "state": "download_complete",
                        }),
                    )?;
                    return Ok(());
                }
            }
            self.update(
                id,
                json!({
                    "download_complete_at": job["download_complete_at"]
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(now),
                    "state": "scan_pending",
                    "last_error": null,
                }),
            )?;
            self.db.save_scan_run(
                id,
                &json!({"queued_at":now(),"updated_at":now(),"pause_requested":false}),
            )?;
        } else {
            self.update_observation(
                job,
                json!({
                    "state": "downloading",
                    "is_terminal": false,
                    "last_error": null,
                }),
            )?;
        }
        Ok(())
    }
    /// Reserve remaining bytes for older intake jobs and unmanaged local
    /// torrents. Already downloaded data is accounted for by filesystem free space.
    fn local_capacity(&self, job: &Value, torrent: &Value) -> Result<bool> {
        let id = string(job, "id");
        let hash = string(torrent, "hash");
        if string(job, "state") == "waiting_for_nas" {
            self.move_to_nas(job, "waiting_for_nas")?;
            return Ok(true);
        }
        if number(torrent, "total_size").max(number(torrent, "size"))
            > self.config.u64("local_max_gib") * 1024 * 1024 * 1024
        {
            self.move_to_nas(job, "size_exceeds_threshold")?;
            return Ok(true);
        }
        let current_remaining = remaining(torrent);
        if current_remaining == 0 {
            return Ok(false);
        }
        let root = self.config.path("local_staging_root");
        storage(root.to_str().context("invalid local root")?, "")?;
        let free = fs2::available_space(&root)?
            .saturating_sub(self.config.u64("local_free_space_buffer_gib") * 1024 * 1024 * 1024);
        let jobs = self.jobs_query(
            "WHERE is_terminal=0 AND staging_actual='local' ORDER BY created_at ASC,id DESC",
            [],
        )?;
        let torrents = self.qbt.list()?;
        let local = jobs.iter();
        let by_hash: std::collections::HashMap<_, _> = torrents
            .iter()
            .map(|torrent| (string(torrent, "hash"), torrent))
            .collect();
        let tracked: HashSet<_> = local.clone().map(|job| string(job, "qbt_hash")).collect();
        let mut reserved = 0u64;
        for torrent in &torrents {
            if !tracked.contains(string(torrent, "hash"))
                && Path::new(string(torrent, "save_path")).starts_with(&root)
            {
                reserved = reserved.saturating_add(remaining(torrent));
            }
        }
        for other in local {
            if string(other, "id") == id {
                break;
            }
            if let Some(t) = by_hash.get(string(other, "qbt_hash")) {
                if string(other, "state") == "waiting_for_nas" && paused(t) {
                    continue;
                }
                reserved = reserved.saturating_add(remaining(t));
            } else {
                reserved = reserved.saturating_add(number(other, "size_bytes"));
            }
        }
        if reserved.saturating_add(current_remaining) <= free {
            if string(job, "state") == "waiting_for_local_space" {
                self.qbt.resume(hash)?;
            }
            return Ok(false);
        }
        if self.config.string("local_overflow_policy") == "nas" {
            self.move_to_nas(job, "insufficient_local_space")?;
        } else {
            if !paused(torrent) {
                self.qbt.pause(hash)?;
            }
            self.mark(id, "waiting_for_local_space", None)?;
        }
        Ok(true)
    }
    pub(super) fn move_to_nas(&self, job: &Value, reason: &str) -> Result<()> {
        let id = string(job, "id");
        let hash = string(job, "qbt_hash");
        let torrent = self
            .find_torrent(job)?
            .context("torrent unavailable while switching storage")?;
        self.guard(job, &torrent, false, false)?;
        self.qbt.pause(hash)?;
        if let Err(error) = storage(
            string(job, "nas_staging_path"),
            string(job, "nas_mount_marker"),
        ) {
            self.update(id, json!({"override_reason":reason}))?;
            self.mark(id, "waiting_for_nas", Some(error.to_string()))?;
            return Ok(());
        }
        // qBittorrent performs the move, maintaining its own torrent file map.
        // Do not rename data behind its back or infer success from local paths.
        self.qbt.location(hash, string(job, "nas_staging_path"))?;
        self.update(
            id,
            json!({
                "staging_actual": "nas",
                "staging_root_actual": job["nas_staging_path"],
                "staging_overridden": true,
                "override_reason": reason,
            }),
        )?;
        self.qbt.resume(hash)?;
        self.mark(id, "downloading", None)
    }
    pub(super) fn reconcile(&self, job: &Value) -> Result<()> {
        if matches!(string(job, "state"), "scan_clean" | "promoting") {
            self.promote(job)
        } else {
            self.infected(job)
        }
    }
    fn promote(&self, job: &Value) -> Result<()> {
        let id = string(job, "id");
        let destination = self.final_parent(string(job, "final_parent"))?;
        if string(job, "state") == "scan_clean" {
            self.mark(id, "promoting", None)?;
        }
        let torrent = self
            .find_torrent(job)?
            .context("torrent unavailable during promotion")?;
        if string(&torrent, "state") == "moving" {
            return Ok(());
        }
        let hash = self.guard(job, &torrent, false, true)?;
        if !paused(&torrent) {
            self.qbt.pause(&hash)?;
            return Ok(());
        }
        let at_destination = Path::new(string(&torrent, "save_path")).canonicalize().ok()
            == Path::new(&destination).canonicalize().ok()
            && Path::new(&destination).exists();
        if !at_destination {
            self.guard_staging(job, &torrent)?;
            self.require_final_storage(Path::new(&destination))?;
            self.qbt.location(&hash, &destination)?;
            return Ok(());
        }
        let content = self.guard_destination(job, &torrent, Path::new(&destination), true)?;
        if !string(job, "final_category").is_empty() {
            let category = self.qbt.category(&hash, string(job, "final_category"))?;
            self.update(id, json!({"final_category":category}))?;
        }
        self.qbt.resume(&hash)?;
        let mut completed = job.clone();
        let mut patch = json!({
            "content_path": content,
            "promoted_at": job["promoted_at"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(now),
            "state": "done",
            "is_terminal": true,
            "updated_at": now(),
            "last_error": null,
        });
        completed
            .as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        patch
            .as_object_mut()
            .unwrap()
            .extend(self.hook_patch(&completed)?.as_object().unwrap().clone());
        // One durable write publishes completion and creates its optional hook.
        // A crash cannot leave a done job whose post-promotion work was lost.
        self.event(
            id,
            "promotion_completed",
            "info",
            "Clean torrent promotion verified",
            json!({"destination_path":destination,"action_success":true}),
        )?;
        self.update(id, patch)?;
        Ok(())
    }
    fn infected(&self, job: &Value) -> Result<()> {
        let id = string(job, "id");
        let torrent = self.find_torrent(job)?;
        match self.config.string("infected_action").as_str() {
            "hold" => {
                let torrent =
                    torrent.context("infected torrent unavailable; cannot verify hold")?;
                self.guard_staging(job, &torrent)?;
                self.event(
                    id,
                    "infected_content_held",
                    "critical",
                    "Infected torrent remains paused in staging",
                    json!({"action_success":true}),
                )?;
                self.mark(id, "infected_held", None)?;
            }
            "delete" => {
                if string(job, "state") == "scan_infected" {
                    self.mark(id, "deleting_infected", None)?;
                }
                if let Some(torrent) = torrent {
                    self.guard_staging(job, &torrent)?;
                    self.qbt.delete_with_files(string(&torrent, "hash"))?;
                    return Ok(());
                }
                let run = self.db.get_scan_run(id)?.unwrap_or(Value::Null);
                let path = if string(&run, "root_path").is_empty() {
                    string(job, "content_path")
                } else {
                    string(&run, "root_path")
                };
                if path_has_content(Path::new(path))? {
                    bail!("infected content still exists; deletion is not verified");
                }
                self.update(id, json!({"deleted_at":now()}))?;
                self.event(
                    id,
                    "infected_content_deleted",
                    "critical",
                    "Infected torrent and content deletion verified",
                    json!({"action_success":true}),
                )?;
                self.mark(id, "infected_deleted", None)?;
            }
            "quarantine" => {
                let torrent = torrent.context("infected torrent unavailable during quarantine")?;
                if string(&torrent, "state") == "moving" {
                    return Ok(());
                }
                let hash = self.guard(job, &torrent, false, true)?;
                if !paused(&torrent) {
                    self.qbt.pause(&hash)?;
                    return Ok(());
                }
                let root = safety::checked(&self.config.path("quarantine_root"))?;
                let destination = if string(job, "quarantine_path").is_empty() {
                    self.guard_staging(job, &torrent)?;
                    let path = root.join(format!("{id}-{}", uuid::Uuid::new_v4().simple()));
                    fs::create_dir(&path)?;
                    self.update(id,json!({"quarantine_path":path,"state":"quarantining_infected","updated_at":now()}))?;
                    path
                } else {
                    safety::within(Path::new(string(job, "quarantine_path")), &root)?
                };
                if destination == root {
                    bail!("quarantine path cannot equal quarantine root");
                }
                if Path::new(string(&torrent, "save_path")).canonicalize().ok()
                    != Some(destination.clone())
                {
                    self.guard_staging(job, &torrent)?;
                    self.qbt.location(
                        &hash,
                        destination.to_str().context("invalid quarantine path")?,
                    )?;
                    return Ok(());
                }
                let content = self.guard_destination(job, &torrent, &destination, true)?;
                self.update(id, json!({"content_path":content}))?;
                self.event(
                    id,
                    "infected_content_quarantined",
                    "critical",
                    "Infected torrent quarantine verified",
                    json!({"destination_path":destination,"action_success":true}),
                )?;
                self.mark(id, "infected_quarantined", None)?;
            }
            _ => bail!("invalid infected action"),
        }
        Ok(())
    }
    pub(super) fn event(
        &self,
        id: &str,
        kind: &str,
        severity: &str,
        message: &str,
        details: Value,
    ) -> Result<()> {
        let root = self.config.path("event_dir");
        safety::checked(&root)?;
        if !root.is_dir() {
            bail!("event sink is not an available directory");
        }
        let identifier = if details["action_success"] == true {
            format!("{id}-{kind}")
        } else if details["hook_attempt"].is_number() {
            format!("{id}-{kind}-{}", details["hook_attempt"])
        } else {
            uuid::Uuid::new_v4().to_string()
        };
        if identifier.len() > 200
            || !identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            bail!("event identifier contains unsupported characters");
        }
        let mut payload = json!({
            "schema_version": 1,
            "service": "torrent-intake",
            "event_id": identifier,
            "event_type": kind,
            "severity": severity,
            "message": message.chars().take(2000).collect::<String>(),
            "timestamp": Utc::now().to_rfc3339(),
            "job_id": id,
        });
        if let Some(job) = self.db.get_job(id)? {
            for (field, column) in [
                ("torrent_hash", "qbt_hash"),
                ("threat_name", "threat_name"),
                ("source_path", "content_path"),
            ] {
                if !job[column].is_null() {
                    payload[field] = job[column].clone();
                }
            }
        }
        if let Some(fields) = details.as_object() {
            payload.as_object_mut().unwrap().extend(fields.clone());
        }
        let target = root.join(format!("{identifier}.json"));
        let temporary = root.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .open(&temporary)?;
        use std::io::Write;
        file.write_all(&serde_json::to_vec_pretty(&payload)?)?;
        file.sync_all()?;
        fs::rename(temporary, target)?;
        crate::persistence::state::sync_directory(&root)?;
        Ok(())
    }
}
fn remaining(torrent: &Value) -> u64 {
    torrent["amount_left"].as_u64().unwrap_or_else(|| {
        let total = number(torrent, "total_size").max(number(torrent, "size"));
        ((1.0 - torrent["progress"].as_f64().unwrap_or(0.0).clamp(0.0, 1.0)) * total as f64).ceil()
            as u64
    })
}

fn path_has_content(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
        Ok(info) if info.is_dir() && !info.file_type().is_symlink() => {
            Ok(fs::read_dir(path)?.next().transpose()?.is_some())
        }
        Ok(_) => Ok(true),
    }
}
