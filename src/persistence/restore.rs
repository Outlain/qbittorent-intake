//! Restore has two phases. An authenticated upload is validated and staged while
//! the controller is paused. Installation happens next startup, while the
//! process owns the controller lock and before any worker opens SQLite.
use super::{
    backup::{self, CHUNK, MAX_DATABASE_BYTES},
    state,
};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};

pub fn stage_restore(
    upload: &Path,
    directory: &Path,
    settings: &Value,
    passphrase: &str,
) -> Result<Value> {
    let root = Path::new(settings["data_dir"].as_str().context("Missing data_dir")?);
    let pending = root.join(".restore-pending");
    state::reject_symlink(&pending)?;
    if pending.exists() {
        bail!("A restore is already pending; restart the controller first");
    }
    let target = backup::database_path(settings)?;
    let mut previous_size = fs::metadata(&target).map(|m| m.len()).unwrap_or(0);
    if previous_size > MAX_DATABASE_BYTES {
        bail!("Current database needs an offline backup before replacement");
    }
    let journal = PathBuf::from(format!("{}-wal", target.display()));
    state::reject_symlink(&journal)?;
    previous_size += fs::metadata(journal).map(|m| m.len()).unwrap_or(0);
    if fs2::available_space(root)? < fs::metadata(upload)?.len() * 3 + previous_size + 32 * CHUNK {
        bail!("Not enough local free space to validate and stage this restore");
    }
    let archive = directory.join("decrypted.zip");
    backup::decrypt_archive(upload, &archive, passphrase)?;
    let staged = directory.join("validated");
    if staged.exists() {
        bail!("Restore validation directory already exists");
    }
    state::private_directory(&staged)?;
    let restored_values = backup::unpack_backup(&archive, &staged)?;
    // Validate with the same rules as normal startup. Defaults allow older backups
    // to omit settings introduced by a later release; unknown keys remain errors.
    let mut restored = crate::config::Config::defaults();
    for (key, value) in restored_values
        .as_object()
        .context("Backup settings are not an object")?
    {
        if restored.values.get(key).is_none() {
            bail!("Backup requires a newer Torrent Intake version: unknown setting {key}");
        }
        restored.values[key] = value.clone();
    }
    restored.values["data_dir"] = settings["data_dir"].clone();
    restored.values["database_url"] = settings["database_url"].clone();
    restored.validate()?;
    state::write_json(
        &staged.join("settings.json"),
        &json!({"schema_version":1,"settings":restored.values}),
    )?;
    let identifier = uuid::Uuid::new_v4().simple().to_string();
    let mut hashes = serde_json::Map::new();
    for name in ["torrent_intake.db", "settings.json", "deployment-notes.txt"] {
        hashes.insert(name.into(), backup::file_digest(&staged.join(name))?.into());
    }
    state::write_json(
        &staged.join("apply.json"),
        &json!({"version":1,"id":identifier,"database_target":target.to_string_lossy(),"saved_previous":false,"hashes":hashes}),
    )?;
    state::sync_directory(&staged)?;
    fs::rename(&staged, &pending)?;
    state::sync_directory(root)?;
    Ok(
        json!({"restart_required":true,"message":"Restore staged. Restart the controller; it will remain paused."}),
    )
}
fn copy_atomic(source: &Path, target: &Path) -> Result<()> {
    state::reject_symlink(target)?;
    let parent = target.parent().context("Restore target has no parent")?;
    state::private_directory(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    state::make_private(temporary.path())?;
    std::io::copy(&mut File::open(source)?, &mut temporary)?;
    temporary.as_file().sync_all()?;
    temporary.persist(target).map_err(|e| e.error)?;
    state::sync_directory(parent)
}
/// The caller must hold `ControllerLock` and must not open the application
/// database until this function returns. Its journal checkpoint additionally
/// detects SQLite users which do not participate in the controller lock.
pub fn apply_pending_restore(settings: &Value) -> Result<()> {
    let root = Path::new(settings["data_dir"].as_str().context("Missing data_dir")?);
    let pending = root.join(".restore-pending");
    state::reject_symlink(&pending)?;
    if !pending.exists() {
        return Ok(());
    }
    if !pending.is_dir() {
        bail!("Invalid pending restore directory");
    }
    let mut manifest: Value = serde_json::from_slice(&state::read_private(
        &pending.join("apply.json"),
        CHUNK as usize,
    )?)?;
    let identifier = manifest["id"].as_str().unwrap_or("").to_owned();
    if manifest["version"] != 1
        || identifier.len() != 32
        || !identifier
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("Invalid pending restore manifest");
    }
    let target = backup::database_path(settings)?;
    if manifest["database_target"].as_str() != Some(target.to_string_lossy().as_ref()) {
        bail!("Database target changed after upload; refusing pending restore");
    }
    for name in ["torrent_intake.db", "settings.json", "deployment-notes.txt"] {
        if backup::file_digest(&pending.join(name))?.as_str()
            != manifest["hashes"][name].as_str().unwrap_or("")
        {
            bail!("Staged restore changed after validation");
        }
    }
    backup::check_database(&pending.join("torrent_intake.db"))?;
    let saved = manifest["saved_previous"] == true;
    let mut required = fs::metadata(pending.join("torrent_intake.db"))?.len() + 32 * CHUNK;
    for suffix in ["", "-wal", "-shm"] {
        let path = PathBuf::from(format!("{}{suffix}", target.display()));
        state::reject_symlink(&path)?;
        if !saved {
            required += fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        }
    }
    if fs2::available_space(root)? < required {
        bail!("Not enough space to apply restore and retain rollback data");
    }
    let rollback = root.join(format!("before-restore-{identifier}"));
    state::private_directory(&rollback)?;
    state::write_json(
        &root.join("controller-paused.json"),
        &json!({"reason":"Restored backup: verify qBittorrent and mounts before resuming"}),
    )?;
    if !saved {
        if target.exists() {
            let previous = rollback.join("database.snapshot");
            if previous.exists() {
                state::reject_symlink(&previous)?;
                fs::remove_file(&previous)?;
            }
            backup::snapshot_database(&target, &previous)?;
            fs::rename(previous, rollback.join("torrent_intake.db"))?;
        }
        for name in ["settings.json", "deployment-notes.txt"] {
            match state::read_private(&root.join(name), CHUNK as usize) {
                Ok(bytes) => state::write_private(&rollback.join(name), &bytes)?,
                Err(e)
                    if e.downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
                Err(e) => return Err(e),
            }
        }
        state::sync_directory(&rollback)?;
        manifest["saved_previous"] = json!(true);
        state::write_json(&pending.join("apply.json"), &manifest)?;
    }
    if target.exists() {
        let c = rusqlite::Connection::open(&target)?;
        c.busy_timeout(std::time::Duration::from_secs(3))?;
        let busy: i64 = c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
        if busy != 0 {
            bail!("Another process is using the database; stop it before restoring");
        }
        drop(c);
        for suffix in ["-wal", "-shm"] {
            let path = PathBuf::from(format!("{}{suffix}", target.display()));
            state::reject_symlink(&path)?;
            if path.exists() {
                fs::remove_file(path)?;
            }
        }
    }
    copy_atomic(&pending.join("torrent_intake.db"), &target)?;
    for name in ["settings.json", "deployment-notes.txt"] {
        copy_atomic(&pending.join(name), &root.join(name))?;
    }
    state::write_json(
        &root.join("last-restore.json"),
        &json!({"rollback_directory":rollback.to_string_lossy(),"id":identifier}),
    )?;
    let completed = root.join(format!(".restore-complete-{identifier}"));
    if completed.exists() {
        bail!("Restore completion directory already exists");
    }
    fs::rename(&pending, &completed)?;
    state::sync_directory(root)?;
    fs::remove_dir_all(completed)?;
    Ok(())
}
