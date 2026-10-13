//! Bounded ZIP/RAR extraction runs in a separate restricted process. It uses
//! generated filenames and waits for the parent to scan each leaf before moving
//! on. Nested containers share one expansion/entry budget.
mod framing;
mod library;
use super::*;
use std::{
    ffi::CString,
    io::{BufRead, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::PermissionsExt},
    },
    process::{Command, Stdio},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ArchiveLimits {
    pub expanded_bytes: u64,
    pub files: u64,
    pub depth: u64,
    pub reserve_bytes: u64,
    pub timeout_seconds: u64,
}
impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            expanded_bytes: 20 * 1024 * MIB,
            files: 10000,
            depth: 4,
            reserve_bytes: 1024 * MIB,
            timeout_seconds: 7200,
        }
    }
}
impl ArchiveLimits {
    pub(crate) fn validate(&self) -> Result<(), ScanError> {
        if self.expanded_bytes == 0
            || self.files == 0
            || self.files > 100000
            || !(1..=8).contains(&self.depth)
            || self.timeout_seconds == 0
        {
            return Err(blocked("invalid archive limits"));
        }
        Ok(())
    }
}
fn blocked(message: impl Into<String>) -> ScanError {
    ScanError::Policy(message.into())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    Zip,
    Rar,
    Rar5,
}
pub(crate) fn archive_format(file: &File) -> Result<Option<Format>, ScanError> {
    use std::os::unix::fs::FileExt;
    let mut magic = [0; 8];
    let n = file.read_at(&mut magic, 0)?;
    Ok(if n >= 7 && magic[..7] == *b"Rar!\x1a\x07\x00" {
        Some(Format::Rar)
    } else if n == 8 && magic == *b"Rar!\x1a\x07\x01\x00" {
        Some(Format::Rar5)
    } else if n >= 4
        && [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"]
            .iter()
            .any(|p| magic[..4] == p[..])
    {
        Some(Format::Zip)
    } else {
        None
    })
}
fn check_storage(base: &Path, marker: Option<&Path>) -> Result<(), ScanError> {
    if !base.is_absolute() || !base.is_dir() || std::fs::canonicalize(base)? != base {
        return Err(blocked(
            "archive scratch storage must be an existing absolute nonsymlink path",
        ));
    }
    if let Some(marker) = marker {
        if !marker.starts_with(base)
            || !marker.is_file()
            || std::fs::canonicalize(marker)? != marker
        {
            return Err(blocked(
                "archive scratch mount marker is missing or symlinked",
            ));
        }
        let _ = File::open(marker)?;
    }
    Ok(())
}
fn available_bytes(path: &Path) -> Result<u64, ScanError> {
    let path =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| blocked("invalid scratch path"))?;
    let mut info: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut info) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok((info.f_bavail as u64).saturating_mul(info.f_frsize as u64))
}
fn private_owned(path: &Path, directory: bool) -> Result<(), ScanError> {
    let m = std::fs::symlink_metadata(path)?;
    if m.uid() != unsafe { libc::getuid() }
        || m.mode() & 0o077 != 0
        || if directory { !m.is_dir() } else { !m.is_file() }
    {
        return Err(blocked(
            "archive scratch directory/lock must be private, owned, and nonsymlinked",
        ));
    }
    Ok(())
}
fn workspace(settings: &ScanSettings) -> Result<PathBuf, ScanError> {
    let base = settings
        .archive_scratch_dir
        .as_ref()
        .unwrap_or(&settings.data_dir);
    if settings.archive_scratch_dir.is_some() {
        check_storage(base, settings.archive_mount_marker.as_deref())?;
    } else {
        std::fs::create_dir_all(base)?;
    }
    let root = base.join("archive-scan");
    match std::fs::create_dir(&root) {
        Ok(()) => std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    };
    private_owned(&root, true)?;
    Ok(root)
}
fn valid_generated_filename(name: &str) -> bool {
    let Some(tail) = name.strip_prefix("member-") else {
        return false;
    };
    let mut parts = tail.split('.');
    let number = parts.next().unwrap_or("");
    if !(6..=12).contains(&number.len()) || !number.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if let Some(suffix) = parts.next() {
        if suffix.is_empty()
            || suffix.len() > 10
            || !suffix
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            return false;
        }
    }
    parts.next().is_none()
}
impl Scanner {
    /// Run during controller startup while its exclusive controller lock is
    /// held. An exclusive workspace lock avoids deleting another controller's
    /// active scans when several controllers share scratch storage.
    pub fn cleanup_archive_workspaces(&self) -> Result<(), ScanError> {
        let root = workspace(&self.settings)?;
        let lock_path = root.join("workspace.lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)?;
        private_owned(&lock_path, false)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(());
            }
            return Err(error.into());
        }
        for item in std::fs::read_dir(&root)? {
            let item = item?;
            let name = item.file_name();
            let name = name.to_string_lossy();
            let Some(suffix) = name.strip_prefix("scan-") else {
                continue;
            };
            if suffix.len() == 8
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                && item.file_type()?.is_dir()
            {
                std::fs::remove_dir_all(item.path())?;
            }
        }
        Ok(())
    }

    pub(crate) fn scan_archive(
        &self,
        file: &File,
        path: &Path,
        id: FileIdentity,
        ctx: &Context<'_>,
    ) -> Result<Verdict, ScanError> {
        if !self.settings.archive_enabled || id.size > self.settings.archive_max_file_bytes {
            return Err(blocked(
                "archive extraction disabled or archive exceeds configured ceiling",
            ));
        }
        let ctx = ctx.bounded(self.settings.archive_limits.timeout_seconds);
        ctx.check()?;
        let root = workspace(&self.settings)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(root.join("workspace.lock"))?;
        private_owned(&root.join("workspace.lock"), false)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } < 0 {
            return Err(blocked("archive workspace cleanup is in progress"));
        }
        let temp = tempfile::Builder::new()
            .prefix("scan-")
            .rand_bytes(8)
            .tempdir_in(&root)?;
        let executable = match &self.settings.helper_executable {
            Some(path) => path.clone(),
            None => std::env::current_exe()?,
        };
        let mut command = Command::new(executable);
        command
            .arg("--archive-helper")
            .arg(file.as_raw_fd().to_string())
            .arg(
                serde_json::to_string(&self.settings.archive_limits)
                    .map_err(|e| blocked(e.to_string()))?,
            )
            .current_dir(temp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        process::prepare(
            &mut command,
            file.as_raw_fd(),
            1024 * MIB,
            self.settings.archive_limits.expanded_bytes,
            self.settings.archive_limits.timeout_seconds,
        );
        let mut child = process::ChildGuard(command.spawn()?);
        let mut stdout = child.0.stdout.take().unwrap();
        let mut stderr = child.0.stderr.take().unwrap();
        let mut stdin = child.0.stdin.take().unwrap();
        process::nonblocking(stdout.as_raw_fd())?;
        process::nonblocking(stderr.as_raw_fd())?;
        let (mut buffer, mut errors) = (Vec::new(), Vec::new());
        let (mut out_done, mut err_done) = (false, false);
        let mut completed: Option<serde_json::Value> = None;
        let mut scanned = 0u64;
        loop {
            ctx.check()?;
            id.verify(file, path)?;
            if let Some(base) = &self.settings.archive_scratch_dir {
                check_storage(base, self.settings.archive_mount_marker.as_deref())?;
            }
            if !out_done {
                out_done = process::read_available(&mut stdout, &mut buffer, 64 * 1024)?;
            }
            if !err_done {
                err_done = process::read_available(&mut stderr, &mut errors, 64 * 1024)?;
            }
            while let Some(end) = buffer.iter().position(|b| *b == b'\n') {
                let line: Vec<_> = buffer.drain(..=end).collect();
                let message: serde_json::Value = serde_json::from_slice(&line)
                    .map_err(|_| blocked("invalid archive helper JSON"))?;
                if completed.is_some() {
                    return Err(blocked("archive helper emitted data after completion"));
                }
                match message["type"].as_str() {
                    Some("done") => {
                        completed = Some(message);
                    }
                    Some("member") => {
                        let filename = message["file"]
                            .as_str()
                            .filter(|s| valid_generated_filename(s))
                            .ok_or_else(|| blocked("invalid generated archive filename"))?;
                        let name = message["name"]
                            .as_str()
                            .filter(|s| s.len() <= 20000)
                            .ok_or_else(|| blocked("invalid archive member label"))?;
                        let size = message["size"]
                            .as_u64()
                            .filter(|s| *s <= self.settings.archive_limits.expanded_bytes)
                            .ok_or_else(|| blocked("invalid archive member size"))?;
                        let member = temp.path().join(filename);
                        let info = std::fs::symlink_metadata(&member)?;
                        if !info.is_file() || info.nlink() != 1 || info.size() != size {
                            return Err(blocked("extracted member identity/size is invalid"));
                        }
                        scanned += 1;
                        if scanned > self.settings.archive_limits.files {
                            return Err(blocked("archive member count exceeds policy"));
                        }
                        let (verdict, _, _) = self.inspect(
                            &member,
                            Some(FileIdentity::from_metadata(&info)),
                            &ctx,
                            false,
                        )?;
                        if verdict.infected {
                            return Ok(Verdict {
                                output: format!("archive member={name:?}: {}", verdict.output),
                                ..verdict
                            });
                        }
                        ctx.check()?;
                        stdin.write_all(b"ok\n")?;
                        stdin.flush()?;
                    }
                    _ => return Err(blocked("unexpected archive helper message")),
                }
            }
            if let Some(status) = child.0.try_wait()? {
                if out_done && err_done {
                    if !status.success() {
                        return Err(blocked(format!(
                            "archive extraction failed ({status}): {:?}",
                            String::from_utf8_lossy(&errors)
                                .chars()
                                .take(1000)
                                .collect::<String>()
                        )));
                    }
                    let done = completed.ok_or_else(|| {
                        blocked("archive extraction ended without complete manifest")
                    })?;
                    if !buffer.is_empty()
                        || done["scanned"].as_u64() != Some(scanned)
                        || done["entries"]
                            .as_u64()
                            .is_none_or(|n| n > self.settings.archive_limits.files)
                        || done["expanded"]
                            .as_u64()
                            .is_none_or(|n| n > self.settings.archive_limits.expanded_bytes)
                    {
                        return Err(blocked(
                            "archive manifest counts were incomplete or inconsistent",
                        ));
                    }
                    return Ok(Verdict::clean(format!(
                        "archive members={scanned} entries={} expanded_bytes={}",
                        done["entries"], done["expanded"]
                    )));
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
fn member_name(name: &str) -> Result<String, ScanError> {
    let normalized = name.replace('\\', "/");
    if name.is_empty()
        || name.len() > 4096
        || name.chars().any(|c| c < ' ' || c == '\u{7f}')
        || normalized.starts_with('/')
        || normalized.split('/').any(|p| p == "..")
        || name.as_bytes().get(1) == Some(&b':')
    {
        return Err(blocked("unsafe archive member path"));
    }
    Ok(normalized)
}
struct Extractor {
    limits: ArchiveLimits,
    entries: u64,
    expanded: u64,
    scanned: u64,
}
impl Extractor {
    fn extract(&mut self, file: &mut File, depth: u64, parents: &str) -> Result<(), ScanError> {
        if depth > self.limits.depth {
            return Err(blocked("archive nesting depth exceeds policy"));
        }
        let format = archive_format(file)?.ok_or_else(|| blocked("unsupported archive format"))?;
        let manifest = framing::validate(file, format, self.limits.files * 4 + 1024)?;
        let mut reader = library::Reader::new(file, format)?;
        let mut index = 0;
        let mut buffer = vec![0u8; MIB as usize];
        while let Some(entry) = reader.next()? {
            self.entries += 1;
            if self.entries > self.limits.files {
                return Err(blocked("archive entry count exceeds policy"));
            }
            let name = member_name(&entry.name)?;
            let label = if parents.is_empty() {
                name.clone()
            } else {
                format!("{parents}!/{name}")
            };
            if entry.encrypted
                || entry.link
                || ![libc::S_IFREG as u32, libc::S_IFDIR as u32].contains(&entry.kind)
            {
                return Err(blocked(
                    "archive contains encryption, links or special files",
                ));
            }
            let size = entry
                .size
                .ok_or_else(|| blocked("archive member lacks declared size"))?;
            let declared = if let Some(manifest) = &manifest {
                let m = manifest
                    .get(index)
                    .ok_or_else(|| blocked("archive parser emitted undeclared member"))?;
                if m.size != size {
                    return Err(blocked(
                        "archive parser disagrees with declared member size",
                    ));
                }
                index += 1;
                Some(m)
            } else {
                None
            };
            if size > self.limits.expanded_bytes.saturating_sub(self.expanded) {
                return Err(blocked("archive expanded-byte budget exceeded"));
            }
            if entry.kind == libc::S_IFDIR as u32 {
                if size > 0 || declared.is_some_and(|d| d.packed > 0) {
                    return Err(blocked("archive directory contains hidden payload"));
                }
                if declared.is_some() {
                    reader.skip()?;
                } else if reader.read(&mut buffer)? > 0 {
                    return Err(blocked("archive directory contains hidden payload"));
                }
                continue;
            }
            if available_bytes(Path::new("."))? < size.saturating_add(self.limits.reserve_bytes) {
                return Err(blocked(
                    "archive scratch free-space reserve would be exceeded",
                ));
            }
            let suffix = Path::new(&name)
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let suffix = if !suffix.is_empty()
                && suffix.len() <= 10
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            {
                format!(".{suffix}")
            } else {
                String::new()
            };
            let filename = format!("member-{:06}{suffix}", self.entries);
            let mut target = OpenOptions::new()
                .write(true)
                .read(true)
                .create_new(true)
                .mode(0o600)
                .open(&filename)?;
            let mut written = 0;
            let mut hash = crc32fast::Hasher::new();
            loop {
                let n = reader.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                let n64 = n as u64;
                if n64 > size.saturating_sub(written)
                    || n64 > self.limits.expanded_bytes.saturating_sub(self.expanded)
                {
                    return Err(blocked(
                        "archive member exceeds declared size or expansion budget",
                    ));
                }
                if available_bytes(Path::new("."))? < n64.saturating_add(self.limits.reserve_bytes)
                {
                    return Err(blocked("archive scratch free-space reserve reached"));
                }
                target.write_all(&buffer[..n])?;
                hash.update(&buffer[..n]);
                written += n64;
                self.expanded += n64;
            }
            if written != size
                || declared
                    .and_then(|d| d.crc)
                    .is_some_and(|crc| crc != hash.finalize())
            {
                return Err(blocked(
                    "archive member is truncated or its checksum is invalid",
                ));
            }
            target.flush()?;
            std::fs::set_permissions(&filename, std::fs::Permissions::from_mode(0o400))?;
            if archive_format(&target)?.is_some() {
                self.extract(&mut target, depth + 1, &label)?;
            } else {
                println!(
                    "{}",
                    serde_json::json!({"type":"member","file":filename,"name":label,"size":size})
                );
                io::stdout().flush()?;
                let mut ack = String::new();
                io::stdin().lock().take(16).read_line(&mut ack)?;
                if ack != "ok\n" {
                    return Err(blocked("archive member was not acknowledged"));
                }
                self.scanned += 1;
            }
            drop(target);
            std::fs::remove_file(filename)?;
        }
        if manifest.as_ref().is_some_and(|m| index != m.len()) {
            return Err(blocked(
                "archive parser did not inspect every declared member",
            ));
        }
        Ok(())
    }
}
/// Must run before the async runtime/HTTP server is initialized. Returns None in
/// normal service mode, or an exit code for the internal helper invocation.
pub fn helper_main() -> Option<i32> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) != Some("--archive-helper") {
        return None;
    }
    let result = (|| {
        if args.len() != 4 {
            return Err(blocked("invalid archive helper arguments"));
        }
        let fd: i32 = args[2]
            .parse()
            .map_err(|_| blocked("invalid archive descriptor"))?;
        if fd < 3 {
            return Err(blocked("invalid archive descriptor"));
        }
        let limits: ArchiveLimits =
            serde_json::from_str(&args[3]).map_err(|_| blocked("invalid archive policy"))?;
        limits.validate()?;
        // The descriptor is explicitly inherited from the spawning scanner.
        let mut file = unsafe { File::from_raw_fd(fd) };
        let mut extractor = Extractor {
            limits,
            entries: 0,
            expanded: 0,
            scanned: 0,
        };
        extractor.extract(&mut file, 1, "")?;
        println!(
            "{}",
            serde_json::json!({"type":"done","entries":extractor.entries,"expanded":extractor.expanded,"scanned":extractor.scanned})
        );
        io::stdout().flush()?;
        Ok(())
    })();
    Some(match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e}");
            1
        }
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn traversal_and_windows_drives_are_blocked() {
        for name in [
            "../x",
            "a/../../x",
            "/root",
            "C:\\x",
            "a\\..\\x",
            "\\\\server\\x",
            "a\nb",
        ] {
            assert!(member_name(name).is_err(), "{name}");
        }
        assert_eq!(member_name("folder\\file.txt").unwrap(), "folder/file.txt");
    }
    #[test]
    fn helper_paths_are_generated_names_only() {
        assert!(valid_generated_filename("member-000123.mkv"));
        for name in [
            "../member-000123",
            "member-1",
            "member-000001.exe/x",
            "member-000001.a.b",
        ] {
            assert!(!valid_generated_filename(name));
        }
    }
}
