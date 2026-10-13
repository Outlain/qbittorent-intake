//! Configuration is deliberately data driven. `defaults.json` contains the same
//! names and defaults as the Python application, and the catalog contains its
//! human explanations. Loading, validation and persistence are separate steps:
//! reviewing a draft never changes the running controller.
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct Config {
    pub values: Value,
    /// Names explicitly supplied by the process or .env file. The editor locks
    /// these fields because they would override a saved edit on the next start.
    pub overrides: HashSet<String>,
}
pub type Settings = Config;

/// Structured validation location for the settings editor. Keep the field names
/// separate from prose so HTTP/UI code never guesses them from an error string.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct SettingsValidationError {
    pub fields: Vec<String>,
    message: String,
}

fn with_fields<T>(fields: &[&str], result: Result<T>) -> Result<T> {
    result.map_err(|error| {
        if error.downcast_ref::<SettingsValidationError>().is_some() {
            return error;
        }
        let context = SettingsValidationError {
            fields: fields.iter().map(|name| (*name).to_owned()).collect(),
            message: error.to_string(),
        };
        error.context(context)
    })
}

fn require_fields(fields: &[&str], condition: bool, message: impl Into<String>) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(SettingsValidationError {
            fields: fields.iter().map(|name| (*name).to_owned()).collect(),
            message: message.into(),
        }
        .into())
    }
}

/// Number inputs in the retained browser editor submit strings. Match the
/// original draft's scalar coercion before validation, but never round a decimal
/// string through floating point: "256.0001" must not silently become 256.
fn draft_integer(value: &Value) -> Option<u64> {
    if let Some(number) = value.as_u64() {
        return Some(number);
    }
    if let Some(boolean) = value.as_bool() {
        return Some(u64::from(boolean));
    }
    if let Some(number) = value.as_f64() {
        return (number.is_finite()
            && number >= 0.0
            && number < u64::MAX as f64
            && number.fract() == 0.0)
            .then_some(number as u64);
    }
    let text = value.as_str()?.trim();
    let negative = text.starts_with('-');
    let unsigned = text.strip_prefix(['+', '-']).unwrap_or(text);
    let whole = match unsigned.split_once('.') {
        Some((whole, fraction))
            if !fraction.is_empty() && fraction.bytes().all(|byte| byte == b'0') =>
        {
            whole
        }
        Some(_) => return None,
        None => unsigned,
    };
    let bytes = whole.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_digit() || !bytes[bytes.len() - 1].is_ascii_digit() {
        return None;
    }
    for (index, byte) in bytes.iter().enumerate() {
        if !(byte.is_ascii_digit()
            || (*byte == b'_'
                && index > 0
                && index + 1 < bytes.len()
                && bytes[index - 1].is_ascii_digit()
                && bytes[index + 1].is_ascii_digit()))
        {
            return None;
        }
    }
    let number = whole.replace('_', "").parse::<u64>().ok()?;
    (!negative || number == 0).then_some(number)
}

fn draft_value(current: &Value, value: &Value) -> Result<Value> {
    if current.is_number() {
        return draft_integer(value)
            .map(|number| json!(number))
            .context("Use a nonnegative whole number");
    }
    if current.is_boolean() {
        let boolean = if let Some(boolean) = value.as_bool() {
            Some(boolean)
        } else if let Some(text) = value.as_str() {
            match text.to_ascii_lowercase().as_str() {
                "1" | "true" | "t" | "yes" | "y" | "on" => Some(true),
                "0" | "false" | "f" | "no" | "n" | "off" => Some(false),
                _ => None,
            }
        } else {
            match value.as_f64() {
                Some(1.0) => Some(true),
                Some(0.0) => Some(false),
                _ => None,
            }
        };
        return boolean
            .map(|boolean| json!(boolean))
            .context("Use a boolean value");
    }
    // Nullable strings and structured editors already send null/arrays/objects.
    // Their exact shape is checked by the ordinary configuration validator.
    Ok(value.clone())
}

impl Config {
    pub fn defaults() -> Self {
        Self {
            values: serde_json::from_str(include_str!("../resources/defaults.json"))
                .expect("compiled defaults"),
            overrides: HashSet::new(),
        }
    }
    pub fn load() -> Result<Self> {
        let root = std::env::var("TI_DATA_DIR").unwrap_or_else(|_| "/app/data".into());
        absolute(&root)?;
        let mut result = Self::defaults();
        result.values["data_dir"] = json!(root);
        result.values["database_url"] = json!(format!("sqlite:///{root}/torrent_intake.db"));
        let saved = Path::new(&root).join("settings.json");
        crate::persistence::state::reject_symlink(&saved)?;
        if saved.exists() {
            let bytes = crate::persistence::state::read_private(&saved, 1024 * 1024)?;
            let payload: Value =
                serde_json::from_slice(&bytes).context("settings.json is not valid JSON")?;
            ensure!(
                payload["schema_version"] == 1 && payload["settings"].is_object(),
                "settings.json must contain schema_version=1 and a settings object"
            );
            for (name, value) in payload["settings"].as_object().unwrap() {
                ensure!(
                    result.values.get(name).is_some(),
                    "settings.json contains unknown setting: {name}"
                );
                if name != "data_dir" {
                    result.values[name] = value.clone();
                }
            }
        }
        let mut environment = std::collections::BTreeMap::new();
        if Path::new(".env").exists() {
            for item in dotenvy::from_path_iter(".env")? {
                let (key, value) = item?;
                environment.insert(key, value);
            }
        }
        environment.extend(std::env::vars());
        let defaults = Self::defaults();
        for (key, raw) in environment {
            let name = key.to_ascii_lowercase();
            let Some(name) = name.strip_prefix("ti_") else {
                continue;
            };
            if defaults.values.get(name).is_none() {
                continue;
            }
            if name == "data_dir" {
                ensure!(
                    raw == root,
                    "TI_DATA_DIR must be set in the process environment, not only in .env"
                );
                continue;
            }
            let default = &defaults.values[name];
            let parsed = if default.is_boolean() {
                match raw.to_ascii_lowercase().as_str() {
                    "true" | "1" | "yes" | "on" => json!(true),
                    "false" | "0" | "no" | "off" => json!(false),
                    _ => bail!("{key} must be a boolean"),
                }
            } else if default.is_number() {
                json!(raw
                    .parse::<u64>()
                    .with_context(|| format!("{key} must be a nonnegative whole number"))?)
            } else if default.is_array() {
                serde_json::from_str(&raw).with_context(|| format!("{key} must be a JSON array"))?
            } else {
                json!(raw)
            };
            result.values[name] = parsed;
            result.overrides.insert(name.to_string());
        }
        result.validate()?;
        Ok(result)
    }
    pub fn get(&self, name: &str) -> &Value {
        &self.values[name]
    }
    pub fn string(&self, name: &str) -> String {
        self.get(name).as_str().unwrap_or("").to_string()
    }
    pub fn bool(&self, name: &str) -> bool {
        self.get(name).as_bool().unwrap_or(false)
    }
    pub fn u64(&self, name: &str) -> u64 {
        self.get(name).as_u64().unwrap_or(0)
    }
    pub fn path(&self, name: &str) -> PathBuf {
        PathBuf::from(self.string(name))
    }
    pub fn effective_nas_locations(&self) -> Vec<Value> {
        let locations = self
            .get("nas_staging_locations")
            .as_array()
            .cloned()
            .unwrap_or_default();
        if locations.is_empty() {
            vec![
                json!({"id":"primary","label":"Main NAS","path":self.string("nas_staging_root"),"mount_marker":null}),
            ]
        } else {
            locations
        }
    }
    pub fn default_nas_location(&self) -> Result<Value> {
        self.nas_location(self.get("default_nas_staging_id").as_str())
    }
    pub fn nas_location(&self, id: Option<&str>) -> Result<Value> {
        let locations = self.effective_nas_locations();
        match id.filter(|x| !x.is_empty()) {
            Some(id) => locations
                .into_iter()
                .find(|x| x["id"] == id)
                .with_context(|| format!("Unknown NAS staging location: {id}")),
            None => Ok(locations[0].clone()),
        }
    }
    pub fn allowed_final_parent_prefixes(&self) -> Vec<String> {
        let mut values = vec![self.string("final_parent_prefix")];
        values.extend(
            self.string("final_parent_prefixes")
                .split(',')
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(str::to_owned),
        );
        values.sort();
        values.dedup();
        values
    }
    pub fn blocked_roots(&self) -> Vec<String> {
        let mut roots = [
            "local_staging_root",
            "nas_staging_root",
            "data_dir",
            "event_dir",
            "quarantine_root",
        ]
        .map(|k| self.string(k))
        .to_vec();
        roots.extend(
            self.effective_nas_locations()
                .iter()
                .filter_map(|v| v["path"].as_str().map(str::to_owned)),
        );
        let scratch = if self.string("archive_scratch_dir").is_empty() {
            self.path("data_dir")
        } else {
            self.path("archive_scratch_dir")
        };
        roots.push(scratch.join("archive-scan").to_string_lossy().into_owned());
        roots
    }
    pub fn persist(&self) -> Result<()> {
        crate::persistence::state::write_json(
            &self.path("data_dir").join("settings.json"),
            &json!({"schema_version":1,"settings":self.values}),
        )
    }
    pub fn revision(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(
            crate::persistence::state::read_private(
                &self.path("data_dir").join("settings.json"),
                1024 * 1024,
            )?,
        )))
    }
    pub fn database_path(&self) -> Result<PathBuf> {
        let path = crate::persistence::backup::sqlite_path(&self.string("database_url"))?;
        absolute(&path.to_string_lossy())
    }
    pub fn validate(&self) -> Result<()> {
        let defaults = Self::defaults();
        for (name, value) in self
            .values
            .as_object()
            .context("settings must be an object")?
        {
            let default = defaults
                .values
                .get(name)
                .with_context(|| format!("Unknown setting: {name}"))?;
            let matches = if default.is_null() {
                value.is_null() || value.is_string()
            } else if default.is_boolean() {
                value.is_boolean()
            } else if default.is_number() {
                value.is_u64()
            } else if default.is_array() {
                value.is_array()
            } else {
                value.is_string()
            };
            require_fields(&[name], matches, format!("Wrong value type for {name}"))?;
            if value.is_number() {
                let (min, max) = number_limits(name);
                let n = value.as_u64().unwrap();
                require_fields(
                    &[name],
                    n >= min && max.is_none_or(|max| n <= max),
                    format!("{name} is outside its permitted range ({min} through {max:?})"),
                )?;
            }
        }
        with_fields(&["database_url"], self.database_path())?;
        for name in ["qbt_host", "qbt_web_url"] {
            if self.get(name).is_null() {
                continue;
            }
            let text = self.string(name);
            let url = with_fields(
                &[name],
                url::Url::parse(&text)
                    .with_context(|| format!("{name} needs a complete HTTP(S) URL")),
            )?;
            require_fields(
                &[name],
                matches!(url.scheme(), "http" | "https")
                    && url.host_str().is_some()
                    && url.port() != Some(0)
                    && !text.chars().any(char::is_whitespace),
                format!("Invalid {name}"),
            )?;
        }
        for name in ["qbt_username", "ui_title", "intake_category"] {
            require_fields(
                &[name],
                !self.string(name).trim().is_empty(),
                format!("{name} must not be empty"),
            )?;
        }
        let tag = self.string("managed_tag");
        require_fields(
            &["managed_tag"],
            !tag.trim().is_empty()
                && tag == tag.trim()
                && tag.chars().count() <= 64
                && !tag.chars().any(|c| c.is_control() || c == ',')
                && !tag.to_lowercase().starts_with("ti_job_"),
            "Invalid managed_tag",
        )?;
        for (name, options) in [
            ("infected_action", &["hold", "quarantine", "delete"][..]),
            ("local_overflow_policy", &["queue", "nas"][..]),
            ("scanner_backend", &["clamd"][..]),
        ] {
            require_fields(
                &[name],
                options.contains(&self.string(name).as_str()),
                format!("Invalid {name}"),
            )?;
        }
        for (low, high) in [
            (
                "scanner_definitions_warn_hours",
                "scanner_definitions_stale_hours",
            ),
            ("max_concurrent_scans", "max_scan_slots"),
            ("max_concurrent_large_scans", "max_scan_slots"),
            ("media_attachment_max_mib", "media_attachment_total_mib"),
            ("large_media_min_chunk_mib", "large_media_chunk_mib"),
            ("large_media_chunk_mib", "scanner_max_file_mib"),
            ("per_job_scan_workers", "clamd_max_inflight_requests"),
        ] {
            require_fields(
                &[low, high],
                self.u64(low) <= self.u64(high),
                format!("{low} cannot exceed {high}"),
            )?;
        }
        require_fields(
            &["scan_heartbeat_seconds", "scan_lease_seconds"],
            self.u64("scan_heartbeat_seconds") < self.u64("scan_lease_seconds"),
            "Heartbeat must be shorter than scan lease",
        )?;
        require_fields(
            &[
                "large_media_chunk_mib",
                "large_media_min_chunk_mib",
                "large_media_overlap_kib",
            ],
            self.u64("large_media_chunk_mib") <= 2000
                && self.u64("large_media_min_chunk_mib") > 0
                && self.u64("large_media_overlap_kib")
                    < self.u64("large_media_min_chunk_mib") * 1024,
            "Invalid media window/overlap limits",
        )?;
        for name in [
            "data_dir",
            "local_staging_root",
            "nas_staging_root",
            "final_parent_prefix",
            "event_dir",
            "quarantine_root",
            "clamd_socket_path",
            "ffprobe_binary",
            "ffmpeg_binary",
        ] {
            with_fields(&[name], absolute(&self.string(name)))?;
        }
        for prefix in self.allowed_final_parent_prefixes() {
            with_fields(&["final_parent_prefixes"], absolute(&prefix))?;
        }
        self.validate_storage()?;
        require_fields(
            &["post_promotion_enabled", "post_promotion_copy_enabled"],
            !(self.bool("post_promotion_enabled") && self.bool("post_promotion_copy_enabled")),
            "Choose either built-in copying or a custom script",
        )?;
        if self.bool("post_promotion_enabled") {
            require_fields(
                &["post_promotion_enabled", "post_promotion_script"],
                !self.string("post_promotion_script").is_empty(),
                "Configure post_promotion_script before enabling it",
            )?;
        }
        if !self.string("post_promotion_script").is_empty() {
            let p = with_fields(
                &["post_promotion_script"],
                absolute(&self.string("post_promotion_script")),
            )?;
            require_fields(
                &["post_promotion_script"],
                p.starts_with("/hooks") && p != Path::new("/hooks"),
                "Trusted hook must be under /hooks",
            )?;
        }
        if !self.string("post_promotion_copy_destination").is_empty() {
            with_fields(
                &["post_promotion_copy_destination"],
                copy_destination(&self.string("post_promotion_copy_destination")),
            )?;
        }
        with_fields(&["post_promotion_copy_rules"], self.validate_copy_rules())?;
        Ok(())
    }

    fn validate_copy_rules(&self) -> Result<()> {
        let rules = self
            .get("post_promotion_copy_rules")
            .as_array()
            .context("copy rules must be an array")?;
        ensure!(rules.len() <= 32, "At most 32 copy rules");
        let mut sources = HashSet::new();
        for rule in rules {
            ensure!(
                rule.is_object()
                    && rule.as_object().unwrap().keys().all(|k| [
                        "source",
                        "destination",
                        "enabled"
                    ]
                    .contains(&k.as_str())),
                "Unknown copy rule field"
            );
            ensure!(
                rule.get("enabled").is_none_or(Value::is_boolean),
                "Copy enabled must be a boolean"
            );
            let source = rule["source"].as_str().context("Copy source is required")?;
            absolute(source)?;
            let source = crate::persistence::paths::canonical_final_parent(
                source,
                &self.allowed_final_parent_prefixes(),
                &self.blocked_roots(),
            )?;
            let destination = copy_destination(
                rule["destination"]
                    .as_str()
                    .context("Copy destination is required")?,
            )?;
            ensure!(sources.insert(source.clone()), "Duplicate copy source");
            ensure!(
                !Path::new(&source).starts_with(&destination) && !destination.starts_with(&source),
                "Copy paths overlap"
            );
        }
        Ok(())
    }
    fn validate_storage(&self) -> Result<()> {
        let locations = self.effective_nas_locations();
        let location_field = if self
            .get("nas_staging_locations")
            .as_array()
            .unwrap()
            .is_empty()
        {
            "nas_staging_root"
        } else {
            "nas_staging_locations"
        };
        require_fields(
            &[location_field],
            locations.len() <= 32,
            "At most 32 NAS locations",
        )?;
        let mut ids = HashSet::new();
        let mut roots = vec![with_fields(
            &["local_staging_root"],
            resolved(&self.string("local_staging_root")),
        )?];
        let mut operational = [
            "/app",
            "/state",
            "/events",
            "/hooks",
            "/copy-target",
            "/var/lib/clamav",
            "/quarantine",
            "/downloads/docker",
        ]
        .into_iter()
        .map(resolved)
        .collect::<Result<Vec<_>>>()?;
        for key in ["data_dir", "event_dir", "quarantine_root"] {
            operational.push(with_fields(&[key], resolved(&self.string(key)))?);
        }
        for item in &locations {
            with_fields(
                &[location_field],
                (|| {
                    let id = item["id"].as_str().context("NAS id must be text")?;
                    ensure!(
                        !id.is_empty()
                            && id.len() <= 64
                            && id
                                .bytes()
                                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
                            && ids.insert(id.to_owned()),
                        "Invalid or duplicate NAS id"
                    );
                    let label = item["label"].as_str().context("NAS label must be text")?;
                    ensure!(
                        !label.trim().is_empty()
                            && label.chars().count() <= 100
                            && !label.chars().any(char::is_control),
                        "Invalid NAS label"
                    );
                    let path = resolved(item["path"].as_str().context("NAS path is required")?)?;
                    if let Some(marker) = item["mount_marker"].as_str() {
                        resolved(marker)?;
                    }
                    if !self
                        .get("nas_staging_locations")
                        .as_array()
                        .unwrap()
                        .is_empty()
                    {
                        ensure!(
                            !operational.iter().any(|p| overlaps(&path, p)),
                            "NAS staging overlaps an operational path"
                        );
                        ensure!(
                            !roots.iter().any(|p| overlaps(&path, p)),
                            "NAS staging roots overlap"
                        );
                        ensure!(
                            !self
                                .allowed_final_parent_prefixes()
                                .iter()
                                .map(|p| resolved(p))
                                .collect::<Result<Vec<_>>>()?
                                .contains(&path),
                            "Use a NAS staging subdirectory"
                        );
                    }
                    roots.push(path);
                    Ok(())
                })(),
            )?;
        }
        if let Some(id) = self.get("default_nas_staging_id").as_str() {
            require_fields(
                &["default_nas_staging_id"],
                ids.contains(id),
                "NAS default is not a configured location",
            )?;
        }
        require_fields(
            &["default_nas_staging_id"],
            locations.len() <= 1 || self.get("default_nas_staging_id").is_string(),
            "Choose exactly one NAS default",
        )?;
        let scratch = self.string("archive_scratch_dir");
        let marker = self.string("archive_scratch_mount_marker");
        if !marker.is_empty() {
            require_fields(
                &["archive_scratch_dir", "archive_scratch_mount_marker"],
                !scratch.is_empty(),
                "Set archive scratch directory before its marker",
            )?;
            let m = with_fields(&["archive_scratch_mount_marker"], resolved(&marker))?;
            let s = with_fields(&["archive_scratch_dir"], resolved(&scratch))?;
            require_fields(
                &["archive_scratch_mount_marker"],
                m.starts_with(&s) && m != s,
                "Archive marker must be inside scratch directory",
            )?;
        }
        if !scratch.is_empty() {
            let workspace =
                with_fields(&["archive_scratch_dir"], resolved(&scratch))?.join("archive-scan");
            for root in roots.iter().chain(
                [
                    resolved(&self.string("quarantine_root"))?,
                    resolved(&self.string("event_dir"))?,
                    resolved("/copy-target")?,
                ]
                .iter(),
            ) {
                require_fields(
                    &["archive_scratch_dir"],
                    !overlaps(&workspace, root),
                    "Archive scratch overlaps content or operational storage",
                )?;
            }
        }
        Ok(())
    }
    /// Return a candidate and redacted change list. No file or service is changed.
    pub fn draft(&self, updates: &Value) -> Result<(Self, Vec<Value>)> {
        let updates = updates.as_object().context("Edit at least one setting")?;
        ensure!(!updates.is_empty(), "Edit at least one setting");
        let mut candidate = self.clone();
        let mut changes = vec![];
        for (name, value) in updates {
            require_fields(
                &[name],
                ui_editable(name),
                format!("{name} is deployment-only"),
            )?;
            require_fields(
                &[name],
                !self.overrides.contains(name),
                format!(
                    "Remove TI_{} from the environment before editing",
                    name.to_uppercase()
                ),
            )?;
            let spec = spec(name).context("Unknown setting")?;
            if spec["sensitive"] == true && value == "" {
                continue;
            }
            let normalized = with_fields(&[name], draft_value(self.get(name), value))?;
            candidate.values[name] = normalized.clone();
            if &normalized != self.get(name) {
                changes.push(json!({
                    "name": name,
                    "label": spec["label"],
                    "before": display(name, self.get(name)),
                    "after": display(name, &normalized),
                    "advanced": advanced(name)
                }));
            }
        }
        candidate.validate()?;
        Ok((candidate, changes))
    }
    pub fn template_values(&self) -> Value {
        let mut result = self.values.clone();
        // Templates only receive redacted credentials, even when a template is
        // accidentally edited to print the whole settings object in the future.
        for name in ["qbt_password", "completion_event_token"] {
            result[name] = Value::Null;
        }
        result["qbt_host"] = json!(safe_url(&self.string("qbt_host")));
        result["qbt_web_url"] = if self.get("qbt_web_url").is_null() {
            Value::Null
        } else {
            json!(safe_url(&self.string("qbt_web_url")))
        };
        result["effective_nas_locations"] = json!(self.effective_nas_locations());
        result["default_nas_location"] = self.default_nas_location().unwrap_or(Value::Null);
        result["extra_final_parent_prefixes"] = json!(self
            .allowed_final_parent_prefixes()
            .into_iter()
            .filter(|s| s != &self.string("final_parent_prefix"))
            .collect::<Vec<_>>());
        result
    }
    pub fn catalog(&self) -> Value {
        let meta = metadata();
        let defaults = Self::defaults();
        let pending = if self.path("data_dir").join("restart-required").exists() {
            std::fs::read(self.path("data_dir").join("settings.json"))
                .ok()
                .and_then(|x| serde_json::from_slice::<Value>(&x).ok())
                .map(|v| v["settings"].clone())
        } else {
            None
        };
        let mut groups = vec![];
        for section in ["connection", "storage", "scanner", "general", "deployment"] {
            let mut items = vec![];
            for spec in meta["specs"].as_array().unwrap() {
                let name = spec["name"].as_str().unwrap();
                let can_edit = ui_editable(name);
                let category = if !can_edit {
                    "deployment"
                } else {
                    match spec["category"].as_str().unwrap() {
                        "qBittorrent" => "connection",
                        "Storage and placement" => "storage",
                        "ClamAV scanner" | "Scan scheduling" => "scanner",
                        _ => "general",
                    }
                };
                if category != section {
                    continue;
                }
                let value = self.get(name);
                let hidden = spec["sensitive"] == true
                    || (spec["url_value"] == true
                        && value.as_str().is_some_and(|x| safe_url(x) != x));
                let permission = if !can_edit {
                    "deployment"
                } else if self.overrides.contains(name) {
                    "environment"
                } else if advanced(name) {
                    "advanced"
                } else {
                    "editable"
                };
                let (min, max) = number_limits(name);
                let unit = [
                    ("_seconds", "seconds"),
                    ("_hours", "hours"),
                    ("_mib", "MiB"),
                    ("_kib", "KiB"),
                    ("_gib", "GiB"),
                ]
                .into_iter()
                .find(|(suffix, _)| name.ends_with(suffix))
                .map(|(_, unit)| unit)
                .unwrap_or("");
                let current = display(name, value);
                let lock_reason = match permission {
                    "deployment" => "Edit deployment configuration while Intake is stopped.",
                    "environment" => {
                        "Remove the environment override and redeploy before editing here."
                    }
                    "advanced" => "Unlock administration; advanced changes require confirmation.",
                    _ => "Unlock administration to edit.",
                };
                let input_type = if hidden {
                    "password"
                } else if value.is_boolean() {
                    "boolean"
                } else if value.is_number() {
                    "number"
                } else {
                    "text"
                };
                items.push(json!({
                    "name":name,
                    "env_name":format!("TI_{}",name.to_uppercase()),
                    "label":spec["label"],
                    "description":spec["description"],
                    "current":current,
                    "default":display(name,defaults.get(name)),
                    "current_effect":spec["value_explanations"][&current],
                    "sensitive":spec["sensitive"],
                    "safety_critical":spec["safety_critical"],
                    "change_hint":spec.get("change_hint").unwrap_or(&meta["default_change_hint"]),
                    "source":if self.overrides.contains(name){"Environment override"}else{"Saved locally"},
                    "editable":can_edit&&!self.overrides.contains(name),
                    "permission":permission,
                    "lock_reason":lock_reason,
                    "legacy":name=="app_name",
                    "advanced":advanced(name),
                    "input_type":input_type,
                    "input_value":if hidden{Value::Null}else{value.clone()},
                    "choices":if name=="local_overflow_policy"{json!(["queue","nas"])}else{json!([])},
                    "minimum":min,
                    "maximum":max,
                    "unit":unit,
                    "pending":pending.as_ref().and_then(|p| if p[name]!=*value {Some(display(name,&p[name]))}else{None})
                }));
            }
            groups.push(json!({
                "id": section,
                "name": meta["sections"][section][0],
                "description": meta["sections"][section][1],
                "settings": items
            }));
        }
        json!(groups)
    }
}
fn metadata() -> &'static Value {
    static META: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    META.get_or_init(|| {
        serde_json::from_str(include_str!("../resources/settings-catalog.json"))
            .expect("compiled catalog")
    })
}
fn spec(name: &str) -> Option<&'static Value> {
    metadata()["specs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == name)
}
pub fn advanced(name: &str) -> bool {
    metadata()["advanced"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s == name)
}
pub fn ui_editable(name: &str) -> bool {
    spec(name).is_some_and(|s| {
        (s["safety_critical"] != true || advanced(name))
            && !["app_name", "data_dir", "database_url"].contains(&name)
    })
}
fn number_limits(name: &str) -> (u64, Option<u64>) {
    let v = &metadata()["number_limits"][name];
    (v[0].as_u64().unwrap_or(1), v[1].as_u64())
}
fn safe_url(text: &str) -> String {
    if text.starts_with("sqlite:") {
        return text.into();
    }
    match url::Url::parse(text) {
        Ok(mut u) => {
            let credentials = !u.username().is_empty() || u.password().is_some();
            let _ = u.set_username(if credentials { "hidden" } else { "" });
            let _ = u.set_password(None);
            u.set_query(None);
            u.set_fragment(None);
            u.to_string().trim_end_matches('/').to_string()
        }
        Err(_) => "Configured URL (details hidden)".into(),
    }
}
fn display(name: &str, value: &Value) -> String {
    if spec(name).is_some_and(|s| s["sensitive"] == true) {
        return if value
            .as_str()
            .is_some_and(|s| !s.trim().is_empty() && !s.to_uppercase().starts_with("REPLACE_"))
        {
            "Configured (hidden)"
        } else {
            "Not configured"
        }
        .into();
    }
    if value.is_null() || value == "" {
        "Not configured".into()
    } else if spec(name).is_some_and(|s| s["url_value"] == true) {
        safe_url(value.as_str().unwrap_or(""))
    } else if let Some(b) = value.as_bool() {
        if b { "Enabled" } else { "Disabled" }.into()
    } else if let Some(s) = value.as_str() {
        s.into()
    } else {
        value.to_string()
    }
}
fn absolute(value: &str) -> Result<PathBuf> {
    let p = Path::new(value);
    ensure!(
        p.is_absolute()
            && !value.chars().any(char::is_control)
            && !p.components().any(|c| matches!(c, Component::ParentDir)),
        "Use an absolute path without traversal or control characters"
    );
    Ok(p.to_path_buf())
}
fn resolved(value: &str) -> Result<PathBuf> {
    absolute(value)?;
    crate::persistence::paths::clean_absolute(value, "storage path")
}
fn overlaps(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.starts_with(b)
        || b.starts_with(a)
        || match (std::fs::metadata(a), std::fs::metadata(b)) {
            (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
            _ => false,
        }
}
fn copy_destination(value: &str) -> Result<PathBuf> {
    let p = absolute(value)?;
    ensure!(
        p.starts_with("/copy-target"),
        "Copy destination must be under /copy-target"
    );
    let resolved = resolved(value)?;
    ensure!(
        resolved.starts_with(crate::persistence::paths::clean_absolute(
            "/copy-target",
            "copy root"
        )?),
        "Copy destination escapes /copy-target through a symlink"
    );
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_match_catalog_and_validate() {
        let config = Config::defaults();
        config.validate().unwrap();
        for name in config.values.as_object().unwrap().keys() {
            assert!(spec(name).is_some(), "{name}");
        }
    }
    #[test]
    fn secrets_never_appear_in_catalog() {
        let mut c = Config::defaults();
        c.values["qbt_password"] = json!("very-sensitive-value");
        c.values["qbt_host"] = json!("https://user:secret@host/path?token=passkey");
        let text = c.catalog().to_string();
        for secret in ["very-sensitive-value", "passkey", "user:secret"] {
            assert!(!text.contains(secret));
        }
    }
    #[test]
    fn environment_overrides_and_destructive_settings_are_locked() {
        let mut c = Config::defaults();
        c.overrides.insert("qbt_host".into());
        assert!(c.draft(&json!({"qbt_host":"http://other:8080"})).is_err());
        assert!(c.draft(&json!({"infected_action":"delete"})).is_err());
    }
    #[test]
    fn blank_secret_draft_preserves_password() {
        let c = Config::defaults();
        let (next, changes) = c.draft(&json!({"qbt_password":""})).unwrap();
        assert_eq!(next.get("qbt_password"), c.get("qbt_password"));
        assert!(changes.is_empty());
    }
    #[test]
    fn draft_scalar_coercion_matches_the_legacy_settings_form() {
        let config = Config::defaults();
        // Confirmed against the original Pydantic 2.11.7 draft behavior.
        for value in [
            json!("256"),
            json!("  +256  "),
            json!("256.00"),
            json!("2_56"),
            json!(256.0),
        ] {
            let (candidate, _) = config
                .draft(&json!({"large_media_chunk_mib":value}))
                .unwrap();
            assert_eq!(candidate.get("large_media_chunk_mib"), &json!(256));
        }
        let (_, changes) = config
            .draft(&json!({"large_media_chunk_mib":"512"}))
            .unwrap();
        assert!(
            changes.is_empty(),
            "equivalent number text is not a settings change"
        );
        assert_eq!(
            draft_integer(&json!("18446744073709551615.0")),
            Some(u64::MAX)
        );
        assert_eq!(draft_integer(&json!("-0.0")), Some(0));
        assert_eq!(draft_integer(&json!(true)), Some(1));
        for value in [
            json!(""),
            json!("256."),
            json!("256.01"),
            json!("2.56e2"),
            json!("2__56"),
            json!("256.0_0"),
            json!("18446744073709551616"),
            json!(-1),
            json!(256.5),
            json!([]),
            Value::Null,
        ] {
            assert!(draft_integer(&value).is_none(), "must reject {value}");
        }
        for (input, expected) in [
            (json!("TRUE"), true),
            (json!("y"), true),
            (json!(1.0), true),
            (json!("off"), false),
            (json!(0), false),
        ] {
            assert_eq!(draft_value(&json!(false), &input).unwrap(), json!(expected));
        }
        for input in [json!(" true "), json!("maybe"), json!(2), Value::Null] {
            assert!(draft_value(&json!(false), &input).is_err());
        }
    }
    #[test]
    fn nas_cannot_overlap_custom_state_or_alias_staging() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let data = root.join("state");
        let local = root.join("staging");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&local).unwrap();
        let mut c = Config::defaults();
        c.values["data_dir"] = json!(data);
        c.values["local_staging_root"] = json!(local);
        c.values["nas_staging_locations"] =
            json!([{"id":"test","label":"Test","path":data.join("nested")}]);
        assert!(c.validate().is_err());
        let alias = root.join("alias");
        std::os::unix::fs::symlink(local, &alias).unwrap();
        c.values["nas_staging_locations"] = json!([{"id":"test","label":"Test","path":alias}]);
        assert!(c.validate().is_err());
    }
    #[test]
    fn bad_limits_and_nas_defaults_are_rejected() {
        let mut c = Config::defaults();
        c.values["scanner_max_file_mib"] = json!(2001);
        assert!(c.validate().is_err());
        let mut c = Config::defaults();
        c.values["default_nas_staging_id"] = json!("missing");
        assert!(c.validate().is_err());
    }
}
