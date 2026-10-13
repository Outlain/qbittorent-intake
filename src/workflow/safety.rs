//! Central ownership, completion and filesystem boundaries used before every
//! destructive operation. A callback can wake the worker; it cannot bypass these.
use super::{qbt::tags, string, Workflow};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
};

pub fn normalize_tags(values: &Value, managed: &str) -> Result<Vec<String>> {
    let mut output = Vec::new();
    if values.is_null() {
        return Ok(output);
    }
    for value in values.as_array().context("custom_tags must be an array")? {
        let tag = value.as_str().context("tags must be strings")?.trim();
        if tag.is_empty()
            || tag.contains(',')
            || tag.chars().count() > 64
            || tag.chars().any(char::is_control)
        {
            bail!("tags must contain 1–64 printable characters and no commas");
        }
        if tag.to_lowercase().starts_with("ti_job_") || tag.to_lowercase() == managed.to_lowercase()
        {
            bail!("tag is reserved for Torrent Intake: {tag}");
        }
        if !output.iter().any(|existing| existing == tag) {
            output.push(tag.to_owned());
        }
    }
    if output.len() > 20 {
        bail!("at most 20 custom tags are allowed");
    }
    Ok(output)
}

pub fn complete(torrent: &Value) -> bool {
    torrent["progress"].as_f64().unwrap_or(0.0) >= 1.0
        && torrent["amount_left"].as_i64().unwrap_or(0) <= 0
        && !matches!(
            string(torrent, "state"),
            "moving"
                | "allocating"
                | "missingFiles"
                | "error"
                | "unknown"
                | "downloading"
                | "queuedDL"
                | "stalledDL"
                | "forcedDL"
                | "metaDL"
                | "forcedMetaDL"
                | "checkingDL"
                | "checkingUP"
                | "checkingResumeData"
        )
}
pub fn paused(torrent: &Value) -> bool {
    let state = string(torrent, "state").to_ascii_lowercase();
    state.contains("paused") || state.contains("stopped")
}

/// Resolve existing paths only, rejecting symlinks in *every* component.
/// This intentionally does not create a missing NAS mountpoint on the root disk.
pub fn checked(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        bail!(
            "path must be absolute and traversal-free: {}",
            path.display()
        );
    }
    let mut current = PathBuf::new();
    for part in path.components() {
        current.push(part);
        if fs::symlink_metadata(&current)?.file_type().is_symlink() {
            bail!("symlink is not allowed: {}", current.display());
        }
    }
    path.canonicalize()
        .with_context(|| format!("path unavailable: {}", path.display()))
}
pub fn within(path: &Path, root: &Path) -> Result<PathBuf> {
    let root = checked(root)?;
    let path = checked(path)?;
    if !path.starts_with(&root) {
        bail!("path escaped its permitted storage root");
    }
    Ok(path)
}
pub fn storage(path: &str, marker: &str) -> Result<()> {
    crate::persistence::paths::require_storage(
        path,
        if marker.is_empty() {
            None
        } else {
            Some(marker)
        },
    )
}

impl Workflow {
    pub(super) fn guard(
        &self,
        job: &Value,
        torrent: &Value,
        require_paused: bool,
        require_complete: bool,
    ) -> Result<String> {
        let hash = string(torrent, "hash");
        if hash.is_empty() {
            bail!("qBittorrent returned no torrent hash");
        }
        let expected = string(job, "qbt_hash");
        if !expected.is_empty() && !expected.eq_ignore_ascii_case(hash) {
            bail!("torrent hash no longer matches job ownership");
        }
        let present = tags(torrent);
        if !present.contains(string(job, "managed_tag"))
            || !present.contains(string(job, "unique_tag"))
        {
            bail!("required Torrent Intake ownership tags are missing");
        }
        let other_owner: bool = self.db.connect()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM jobs WHERE is_terminal=0 AND id!=?1
             AND (qbt_hash=?2 COLLATE NOCASE OR unique_tag=?3))",
            rusqlite::params![string(job, "id"), hash, string(job, "unique_tag")],
            |row| row.get(0),
        )?;
        if other_owner {
            bail!("another active job owns this torrent");
        }
        if require_complete && !complete(torrent) {
            bail!("torrent is not complete");
        }
        if require_paused && !paused(torrent) {
            bail!("torrent pause has not been confirmed");
        }
        Ok(hash.to_owned())
    }
    pub(super) fn guard_staging(&self, job: &Value, torrent: &Value) -> Result<PathBuf> {
        self.guard(job, torrent, true, true)?;
        let root = string(job, "staging_root_actual");
        let root = if root.is_empty() {
            string(job, "staging_root_initial")
        } else {
            root
        };
        if string(job, "staging_actual") == "nas" {
            storage(root, string(job, "nas_mount_marker"))?;
        }
        within(Path::new(string(torrent, "save_path")), Path::new(root))?;
        within(Path::new(string(torrent, "content_path")), Path::new(root))
    }
    pub(super) fn guard_destination(
        &self,
        job: &Value,
        torrent: &Value,
        destination: &Path,
        require_paused: bool,
    ) -> Result<PathBuf> {
        self.guard(job, torrent, require_paused, true)?;
        let destination = checked(destination)?;
        if checked(Path::new(string(torrent, "save_path")))? != destination {
            bail!("torrent has not reached its verified destination");
        }
        within(Path::new(string(torrent, "content_path")), &destination)
    }
    pub(super) fn final_parent(&self, value: &str) -> Result<String> {
        crate::persistence::paths::canonical_final_parent(
            value,
            &self.config.allowed_final_parent_prefixes(),
            &self.config.blocked_roots(),
        )
    }
    pub(super) fn require_final_storage(&self, path: &Path) -> Result<()> {
        crate::persistence::paths::require_final_storage(
            path.to_str().context("invalid final path")?,
            &self.config.allowed_final_parent_prefixes(),
            &self.config.effective_nas_locations(),
        )
    }
}

/// The full identity is a checkpoint key, rather than just a name and a length.
/// Renaming an unscanned file over a clean path therefore invalidates the result.
pub fn fingerprint(path: &Path) -> Result<Value> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("only regular files can be scanned or copied");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            bail!("hard-linked content is not allowed");
        }
        Ok(json!({
            "size_bytes": metadata.len(),
            "mtime_ns": metadata.mtime() * 1_000_000_000 + metadata.mtime_nsec(),
            "ctime_ns": metadata.ctime() * 1_000_000_000 + metadata.ctime_nsec(),
            "device": metadata.dev(),
            "inode": metadata.ino(),
        }))
    }
    #[cfg(not(unix))]
    {
        Ok(json!({
            "size_bytes": metadata.len(),
            "mtime_ns": metadata
                .modified()?
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos() as u64,
        }))
    }
}
pub fn manifest(root: &Path) -> Result<Vec<Value>> {
    manifest_with(root, &|| Ok(()))
}

/// Long directory walks are work too: renew leases and honor shutdown before
/// inspecting each entry, rather than only when antivirus requests begin.
pub fn manifest_with(root: &Path, checkpoint: &dyn Fn() -> Result<()>) -> Result<Vec<Value>> {
    let root = checked(root)?;
    let mut files = Vec::new();
    let mut names = BTreeSet::new();
    for entry in walkdir::WalkDir::new(&root)
        .follow_links(false)
        .sort_by_file_name()
    {
        checkpoint()?;
        let entry = entry?;
        if entry.file_type().is_symlink() {
            bail!("symlink found in torrent content");
        }
        if entry.file_type().is_dir() {
            continue;
        }
        let relative = if root.is_file() {
            ".".to_owned()
        } else {
            entry
                .path()
                .strip_prefix(&root)?
                .to_str()
                .context("non-UTF8 torrent filename")?
                .to_owned()
        };
        if !names.insert(relative.clone()) {
            bail!("duplicate manifest path");
        }
        let mut item = fingerprint(entry.path())?;
        item["relative_path"] = json!(relative);
        files.push(item);
    }
    if files.is_empty() {
        bail!("torrent content contains no regular files");
    }
    files.sort_by_key(|v| v["size_bytes"].as_u64().unwrap_or(0));
    Ok(files)
}
pub fn same_fingerprint(left: &Value, right: &Value) -> bool {
    ["size_bytes", "mtime_ns", "ctime_ns", "device", "inode"]
        .iter()
        .all(|key| left[key] == right[key])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completion_is_conservative() {
        assert!(!complete(
            &json!({"progress":1.0,"amount_left":0,"state":"checkingUP"})
        ));
        assert!(!complete(
            &json!({"progress":1.0,"amount_left":2,"state":"pausedUP"})
        ));
        assert!(complete(
            &json!({"progress":1.0,"amount_left":0,"state":"stoppedUP"})
        ));
    }
    #[test]
    fn private_tags_cannot_be_injected() {
        assert!(normalize_tags(&json!(["TI_JOB_abc"]), "intake").is_err());
        assert!(normalize_tags(&json!(["Intake"]), "intake").is_err());
        assert_eq!(
            normalize_tags(&json!([" media ", "media"]), "intake").unwrap(),
            vec!["media"]
        );
    }
}
