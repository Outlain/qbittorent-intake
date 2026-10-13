//! Containment uses path components, never string prefixes (`/media2` is not
//! inside `/media`). Existing symlinks are resolved before checking boundaries.
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{
    fs,
    path::{Component, Path, PathBuf},
};

pub fn clean_absolute(value: &str, label: &str) -> Result<PathBuf> {
    if value.is_empty() || value.chars().any(|c| c.is_control()) {
        bail!("{label} must be a nonempty path without control characters");
    }
    let path = Path::new(value.trim());
    if !path.is_absolute() {
        bail!("{label} must be an absolute path");
    }
    let mut result = PathBuf::new();
    for part in path.components() {
        match part {
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => {}
            other => result.push(other.as_os_str()),
        }
        match fs::symlink_metadata(&result) {
            Ok(_) => {
                result = fs::canonicalize(&result)
                    .with_context(|| format!("{label} cannot be resolved safely"))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(result)
}
pub fn path_is_within(candidate: &Path, root: &Path) -> bool {
    candidate.starts_with(root)
}
pub fn canonical_existing_path_within(
    value: &str,
    root_value: &str,
    label: &str,
) -> Result<PathBuf> {
    let root = fs::canonicalize(clean_absolute(root_value, "staging root")?)?;
    let path = fs::canonicalize(clean_absolute(value, label)?)?;
    if !path_is_within(&path, &root) {
        bail!("{label} escaped expected staging root");
    }
    Ok(path)
}
pub fn canonical_final_parent(
    value: &str,
    allowed_roots: &[String],
    blocked_roots: &[String],
) -> Result<String> {
    let path = clean_absolute(value, "final_parent")?;
    let allowed = allowed_roots
        .iter()
        .map(|v| clean_absolute(v, "final parent prefix"))
        .collect::<Result<Vec<_>>>()?;
    if !allowed.iter().any(|r| path_is_within(&path, r)) {
        bail!("final_parent must be inside a configured media root");
    }
    let fixed = [
        "/downloads/docker",
        "/app",
        "/state",
        "/var/lib/clamav",
        "/quarantine",
        "/copy-target",
    ];
    for raw in fixed
        .into_iter()
        .chain(blocked_roots.iter().map(String::as_str))
    {
        let root = clean_absolute(raw, "operational path")?;
        if path_is_within(&path, &root) {
            bail!(
                "final_parent points into an operational path: {}",
                root.display()
            );
        }
    }
    Ok(path.to_string_lossy().into())
}
pub fn require_storage(path: &str, marker: Option<&str>) -> Result<()> {
    let root = Path::new(path);
    if !root.is_dir() {
        bail!("Storage is missing or inaccessible: {path}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(root.as_os_str().as_bytes())?;
        if unsafe { libc::access(c.as_ptr(), libc::R_OK | libc::W_OK | libc::X_OK) } != 0 {
            bail!("Storage is read-only or inaccessible: {path}");
        }
    }
    if let Some(marker) = marker.filter(|s| !s.is_empty()) {
        let m = Path::new(marker);
        super::state::reject_symlink(m)?;
        if !m.is_file() {
            bail!("NAS mount marker is missing: {marker}");
        }
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(m).context("NAS mount marker is unreadable")?;
        if !file.metadata()?.is_file() {
            bail!("NAS mount marker must be a regular file");
        }
    }
    Ok(())
}
pub fn require_final_storage(
    destination: &str,
    allowed_roots: &[String],
    nas_locations: &[Value],
) -> Result<()> {
    let target = clean_absolute(destination, "final destination")?;
    let roots = allowed_roots
        .iter()
        .map(|s| clean_absolute(s, "final root"))
        .collect::<Result<Vec<_>>>()?;
    let root = roots
        .iter()
        .filter(|r| target.starts_with(r))
        .max_by_key(|r| r.components().count())
        .context("Final destination is outside configured media roots")?;
    require_storage(&root.to_string_lossy(), None)?;
    for location in nas_locations {
        if let Some(marker) = location["mount_marker"].as_str().filter(|s| !s.is_empty()) {
            if let Some(parent) = Path::new(marker).parent() {
                if target.starts_with(clean_absolute(&parent.to_string_lossy(), "marker root")?) {
                    require_storage(&root.to_string_lossy(), Some(marker))?;
                }
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn path_boundaries_are_component_based() {
        assert!(!path_is_within(
            Path::new("/media2/payload"),
            Path::new("/media")
        ));
        assert!(path_is_within(
            Path::new("/media/payload"),
            Path::new("/media")
        ));
        assert!(clean_absolute("relative/path", "root").is_err());
    }
    #[test]
    fn nas_marker_may_be_a_sibling_of_staging() {
        let directory = tempfile::tempdir().unwrap();
        let staging = directory.path().join("staging");
        let marker = directory.path().join(".mounted");
        fs::create_dir(&staging).unwrap();
        fs::write(&marker, b"mounted").unwrap();
        require_storage(&staging.to_string_lossy(), Some(&marker.to_string_lossy())).unwrap();
        fs::remove_file(&marker).unwrap();
        assert!(
            require_storage(&staging.to_string_lossy(), Some(&marker.to_string_lossy())).is_err()
        );
        assert!(!marker.exists());
    }
    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_rejected() {
        let d = tempfile::tempdir().unwrap();
        let inside = d.path().join("inside");
        let outside = d.path().join("outside");
        fs::create_dir_all(&inside).unwrap();
        fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, inside.join("escape")).unwrap();
        assert!(canonical_existing_path_within(
            &inside.join("escape").to_string_lossy(),
            &inside.to_string_lossy(),
            "payload"
        )
        .is_err());
    }
}
