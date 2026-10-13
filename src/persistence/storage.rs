//! NAS choices are pinned to each job. Editing the current registry must never
//! redirect a running job to another mount, including jobs created before named
//! NAS locations were introduced.
pub use super::paths::{require_final_storage, require_storage};
use super::{
    db::{job_columns, query_values},
    Database,
};
use crate::config::Config;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub fn pin_nas_choice(job: &mut Value, location: &Value) {
    for (job_key, location_key) in [
        ("nas_staging_id", "id"),
        ("nas_staging_label", "label"),
        ("nas_staging_path", "path"),
        ("nas_mount_marker", "mount_marker"),
    ] {
        job[job_key] = location[location_key].clone();
    }
}
pub fn ensure_nas_choice(job: &mut Value, settings: &Config) -> bool {
    if job["nas_staging_path"]
        .as_str()
        .is_some_and(|s| !s.is_empty())
    {
        return false;
    }
    let actual = job["staging_actual"]
        .as_str()
        .filter(|s| !s.is_empty())
        .or_else(|| job["staging_preference"].as_str());
    let path = if actual == Some("nas") {
        job["staging_root_actual"]
            .as_str()
            .filter(|s| !s.is_empty())
            .or_else(|| job["staging_root_initial"].as_str())
            .unwrap_or("")
            .to_owned()
    } else {
        settings.string("nas_staging_root")
    };
    let location = settings
        .effective_nas_locations()
        .into_iter()
        .find(|v| v["path"].as_str() == Some(&path))
        .unwrap_or_else(|| {
            json!({
                "id": format!("legacy-{}", &hex::encode(Sha256::digest(path.as_bytes()))[..12]),
                "label": "Previous NAS",
                "path": path,
                "mount_marker": null
            })
        });
    pin_nas_choice(job, &location);
    true
}
pub fn pin_existing_jobs(database: &Database, settings: &Config) -> Result<()> {
    let connection = database.connect()?;
    // Retired history and already-pinned jobs cannot require migration. Apply
    // that filter in SQLite before allocating complete JSON rows.
    let jobs = query_values(&connection, &format!(
        "SELECT {} FROM jobs WHERE NOT COALESCE(is_terminal,0) AND (nas_staging_path IS NULL OR nas_staging_path='')",
        job_columns()
    ), [])?;
    drop(connection);
    for mut job in jobs {
        if ensure_nas_choice(&mut job, settings) {
            database.update_job(
                job["id"].as_str().unwrap_or(""),
                &json!({
                    "nas_staging_id": job["nas_staging_id"],
                    "nas_staging_label": job["nas_staging_label"],
                    "nas_staging_path": job["nas_staging_path"],
                    "nas_mount_marker": job["nas_mount_marker"]
                }),
            )?;
        }
    }
    Ok(())
}
pub fn validate_location_changes(
    database: &Database,
    current: &Config,
    candidate: &Config,
) -> Result<()> {
    if current.get("nas_staging_locations") == candidate.get("nas_staging_locations")
        && current.get("nas_staging_root") == candidate.get("nas_staging_root")
    {
        return Ok(());
    }
    let old = current.effective_nas_locations();
    let new = candidate.effective_nas_locations();
    let connection = database.connect()?;
    let jobs = query_values(
        &connection,
        &format!(
            "SELECT {} FROM jobs WHERE NOT COALESCE(is_terminal,0)",
            job_columns()
        ),
        [],
    )?;
    drop(connection);
    for mut job in jobs {
        ensure_nas_choice(&mut job, current);
        let Some(previous) = old.iter().find(|v| v["id"] == job["nas_staging_id"]) else {
            // A grandfathered job can retain a retired mount. An unrelated
            // registry edit does not alter its saved destination.
            continue;
        };
        let location = new.iter().find(|v| v["id"] == job["nas_staging_id"]);
        if location.is_some_and(|v| {
            v["path"] == previous["path"] && v["mount_marker"] == previous["mount_marker"]
        }) {
            continue;
        }
        if !location.is_some_and(|v| {
            v["path"] == job["nas_staging_path"] && v["mount_marker"] == job["nas_mount_marker"]
        }) {
            bail!("NAS location used by active job {} cannot be removed or have its path/marker changed",job["id"].as_str().unwrap_or(""));
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn old_jobs_keep_actual_mount_or_legacy_local_fallback() {
        let mut settings = Config::defaults();
        settings.values["nas_staging_locations"] =
            json!([{"id":"new","label":"New NAS","path":"/new-nas","mount_marker":null}]);
        let mut nas = json!({"staging_actual":"nas","staging_root_actual":"/retired-nas","staging_preference":"local"});
        assert!(ensure_nas_choice(&mut nas, &settings));
        assert_eq!(nas["nas_staging_path"], "/retired-nas");
        assert!(nas["nas_staging_id"]
            .as_str()
            .unwrap()
            .starts_with("legacy-"));
        let mut local = json!({"staging_actual":"local","staging_root_initial":"/staging"});
        ensure_nas_choice(&mut local, &settings);
        assert_eq!(
            local["nas_staging_path"],
            settings.values["nas_staging_root"]
        );
        assert!(!ensure_nas_choice(&mut nas, &settings));
    }
    #[test]
    fn pinning_skips_terminal_and_existing_choices_and_preserves_checkpoints() {
        let directory = tempfile::tempdir().unwrap();
        let database = Database::open(directory.path().join("database.sqlite")).unwrap();
        for (id, terminal, pinned) in [
            ("legacy", false, None),
            ("done", true, None),
            ("pinned", false, Some("/original-nas")),
        ] {
            database
                .insert_job(&json!({
                    "id":id,"unique_tag":id,"magnet_uri":"magnet:?xt=urn:btih:123",
                    "final_parent":"/media","staging_preference":"nas",
                    "staging_root_initial":"/retired-nas","managed_tag":"intake",
                    "is_terminal":terminal,"nas_staging_path":pinned
                }))
                .unwrap();
        }
        database
            .save_scan_file(
                "legacy",
                &json!({
                    "relative_path":"payload","size_bytes":42,"mtime_ns":123,"status":"clean"
                }),
            )
            .unwrap();
        let mut settings = Config::defaults();
        settings.values["nas_staging_locations"] = json!([
            {"id":"new","label":"New NAS","path":"/new-nas","mount_marker":null}
        ]);
        pin_existing_jobs(&database, &settings).unwrap();
        pin_existing_jobs(&database, &settings).unwrap();
        assert_eq!(
            database.get_job("legacy").unwrap().unwrap()["nas_staging_path"],
            "/retired-nas"
        );
        assert!(database.get_job("done").unwrap().unwrap()["nas_staging_path"].is_null());
        assert_eq!(
            database.get_job("pinned").unwrap().unwrap()["nas_staging_path"],
            "/original-nas"
        );
        assert_eq!(
            database.list_scan_files("legacy").unwrap()[0]["status"],
            "clean"
        );
        let mut changed = settings.clone();
        changed.values["nas_staging_locations"][0]["label"] = "New label".into();
        // Both active jobs are grandfathered, so unrelated edits remain valid.
        validate_location_changes(&database, &settings, &changed).unwrap();
        database
            .update_job(
                "legacy",
                &json!({"nas_staging_id":"new","nas_staging_path":"/new-nas"}),
            )
            .unwrap();
        changed.values["nas_staging_locations"][0]["path"] = "/moved-nas".into();
        assert!(validate_location_changes(&database, &settings, &changed).is_err());
        database
            .update_job("legacy", &json!({"is_terminal":true}))
            .unwrap();
        validate_location_changes(&database, &settings, &changed).unwrap();
    }
}
