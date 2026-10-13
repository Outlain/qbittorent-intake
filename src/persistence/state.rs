//! Private state uses atomic replacement: a crash exposes the old complete file
//! or the new complete file, never half a JSON document.
use anyhow::{bail, Context, Result};
use fs2::FileExt;
use rand::RngCore;
use serde_json::Value;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

pub fn data_directory() -> Result<PathBuf> {
    let path = PathBuf::from(std::env::var("TI_DATA_DIR").unwrap_or_else(|_| "/app/data".into()));
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        bail!("TI_DATA_DIR must be an absolute path without '..'");
    }
    Ok(path)
}
pub fn reject_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!("Refusing symbolic-link state file: {}", path.display())
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
pub fn make_private(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            bail!("Refusing symbolic-link state file: {}", path.display());
        }
        // chmod changes inode metadata even when the mode is already right.
        // Repair permissive files, but leave already-private files untouched.
        if metadata.permissions().mode() & 0o7777 != 0o600 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}
pub fn private_directory(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
            fs::symlink_metadata(path)?
        }
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!(
            "Expected a real application state directory: {}",
            path.display()
        );
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o7777 != 0o700 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
pub fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}
pub fn read_private(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("Expected a regular application state file");
    }
    if metadata.len() > maximum as u64 {
        bail!("Application state file exceeds its size limit");
    }
    // Reserve one extra byte for the bounded EOF check. This avoids repeated
    // growth and doubling the allocation for an exactly sized ordinary file.
    // The read limit still applies if another writer grows the opened file.
    let mut value = Vec::with_capacity((metadata.len() as usize).saturating_add(1));
    file.take((maximum as u64).saturating_add(1))
        .read_to_end(&mut value)?;
    if value.len() > maximum {
        bail!("Application state file exceeds its size limit");
    }
    Ok(value)
}
pub fn create_private(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    Ok(options.open(path)?)
}
pub fn write_private(path: &Path, value: &[u8]) -> Result<()> {
    reject_symlink(path)?;
    let parent = path.parent().context("State path has no parent")?;
    private_directory(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    make_private(temporary.path())?;
    temporary.write_all(value)?;
    temporary.as_file().sync_all()?;
    // Persist uses an atomic rename on the same volume.
    temporary.persist(path).map_err(|e| e.error)?;
    sync_directory(parent)
}
pub fn write_json(path: &Path, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_private(path, &bytes)
}
pub fn admin_token(root: &Path) -> Result<String> {
    let path = root.join("admin-token");
    let token = match read_private(&path, 256) {
        Ok(bytes) => String::from_utf8(bytes)?.trim().to_owned(),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            let mut random = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut random);
            let token = hex::encode(random);
            write_private(&path, format!("{token}\n").as_bytes())?;
            token
        }
        Err(error) => return Err(error),
    };
    if token.len() < 32 {
        bail!("admin-token must contain at least 32 characters");
    }
    make_private(&path)?;
    Ok(token)
}
pub fn authorized(supplied: &str, expected: &str) -> bool {
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;
    // Compare equal-length digests so a length difference cannot skip the
    // comparison. The secret itself is never included in logs or errors.
    bool::from(Sha256::digest(supplied.as_bytes()).ct_eq(&Sha256::digest(expected.as_bytes())))
}
/// Keep this value alive for the entire process. Dropping it releases the lock.
pub struct ControllerLock {
    _file: File,
}
impl ControllerLock {
    pub fn acquire(root: &Path) -> Result<Self> {
        private_directory(root)?;
        // SQLite auxiliary files inherit the process umask on Unix.
        #[cfg(unix)]
        unsafe {
            libc::umask(0o077);
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        let file = options.open(root.join("controller.lock"))?;
        if !file.metadata()?.is_file() {
            bail!("Controller lock must be a regular file");
        }
        file.try_lock_exclusive()
            .context("Another Torrent Intake controller is already using this data directory")?;
        Ok(Self { _file: file })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_files_are_atomic_and_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("state");
        write_private(&p, b"abc").unwrap();
        assert_eq!(read_private(&p, 3).unwrap(), b"abc");
        assert!(read_private(&p, 2).is_err());
        write_json(&p, &serde_json::json!({"done":true})).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&read_private(&p, 100).unwrap()).unwrap()["done"],
            true
        );
    }
    #[cfg(unix)]
    #[test]
    fn symlinks_and_duplicate_controllers_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("link");
        std::os::unix::fs::symlink("missing", &p).unwrap();
        assert!(write_private(&p, b"no").is_err());
        assert!(read_private(&p, 100).is_err());
        let _lock = ControllerLock::acquire(dir.path()).unwrap();
        assert!(ControllerLock::acquire(dir.path()).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn private_permissions_are_repaired_without_rewriting_correct_metadata() {
        use std::os::unix::fs::MetadataExt;
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("state");
        fs::write(&file, b"private").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        make_private(&file).unwrap();
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        private_directory(directory.path()).unwrap();
        assert_eq!(
            fs::metadata(directory.path()).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        let changed_at = |path: &Path| {
            let metadata = fs::metadata(path).unwrap();
            (metadata.ctime(), metadata.ctime_nsec())
        };
        let file_before = changed_at(&file);
        let directory_before = changed_at(directory.path());
        make_private(&file).unwrap();
        private_directory(directory.path()).unwrap();
        assert_eq!(changed_at(&file), file_before);
        assert_eq!(changed_at(directory.path()), directory_before);
        let alias = directory.path().join("alias");
        std::os::unix::fs::symlink(&file, &alias).unwrap();
        assert!(make_private(&alias).is_err());
        assert!(private_directory(&alias).is_err());
    }
}
