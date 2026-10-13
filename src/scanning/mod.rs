//! Fail-closed content inspection. A successful scan is a *complete policy
//! decision*, not merely a successful connection to the antivirus daemon.
mod archive;
mod media;
mod process;
mod protocol;

pub use archive::{helper_main, ArchiveLimits};
use chrono::{DateTime, Utc};
pub use media::{parse_media_probe, MediaAttachment, MediaProbe};
pub use protocol::{parse_scan_response, parse_scanner_version};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, Metadata, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Condvar, Mutex},
    time::{Duration, Instant},
};
use thiserror::Error;

pub const MIB: u64 = 1024 * 1024;

/// All quantities are bytes or seconds. Configuration translation lives outside
/// the scanner so the security policy can be tested without starting a server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanSettings {
    pub socket_path: PathBuf,
    pub policy_version: String,
    pub max_file_bytes: u64,
    pub connect_timeout_seconds: u64,
    pub health_cache_seconds: u64,
    pub scan_timeout_seconds: u64,
    pub definitions_warn_hours: u64,
    pub definitions_stale_hours: u64,
    pub large_media_enabled: bool,
    pub large_media_max_file_bytes: u64,
    pub large_media_chunk_bytes: u64,
    pub large_media_min_chunk_bytes: u64,
    pub large_media_overlap_bytes: u64,
    pub large_media_scan_timeout_seconds: u64,
    pub probe_timeout_seconds: u64,
    pub ffprobe_binary: PathBuf,
    pub ffmpeg_binary: PathBuf,
    pub attachment_max_bytes: u64,
    pub attachment_total_bytes: u64,
    pub archive_enabled: bool,
    pub archive_max_file_bytes: u64,
    pub archive_limits: ArchiveLimits,
    pub data_dir: PathBuf,
    pub archive_scratch_dir: Option<PathBuf>,
    pub archive_mount_marker: Option<PathBuf>,
    pub max_inflight_requests: usize,
    pub per_job_scan_workers: usize,
    /// Embedders/tests can point at the service binary implementing helper_main.
    /// Normal service operation re-executes the currently running executable.
    pub helper_executable: Option<PathBuf>,
}
impl Default for ScanSettings {
    fn default() -> Self {
        Self {
            socket_path: "/run/clamav/clamd.sock".into(),
            policy_version: "clamav-policy-v5-media-attachments".into(),
            max_file_bytes: 2000 * MIB,
            connect_timeout_seconds: 5,
            health_cache_seconds: 15,
            scan_timeout_seconds: 1200,
            definitions_warn_hours: 36,
            definitions_stale_hours: 72,
            large_media_enabled: true,
            large_media_max_file_bytes: 100 * 1024 * MIB,
            large_media_chunk_bytes: 512 * MIB,
            large_media_min_chunk_bytes: 64 * MIB,
            large_media_overlap_bytes: MIB,
            large_media_scan_timeout_seconds: 172800,
            probe_timeout_seconds: 120,
            ffprobe_binary: "/usr/bin/ffprobe".into(),
            ffmpeg_binary: "/usr/bin/ffmpeg".into(),
            attachment_max_bytes: 16 * MIB,
            attachment_total_bytes: 64 * MIB,
            archive_enabled: true,
            archive_max_file_bytes: 100 * 1024 * MIB,
            archive_limits: ArchiveLimits::default(),
            data_dir: "/data".into(),
            archive_scratch_dir: None,
            archive_mount_marker: None,
            max_inflight_requests: 4,
            per_job_scan_workers: 1,
            helper_executable: None,
        }
    }
}
impl ScanSettings {
    pub fn validate(&self) -> Result<(), ScanError> {
        if !(1..=2000 * MIB).contains(&self.max_file_bytes)
            || self.large_media_max_file_bytes == 0
            || self.large_media_chunk_bytes == 0
            || self.large_media_chunk_bytes > self.max_file_bytes
            || self.large_media_overlap_bytes >= self.large_media_min_chunk_bytes
            || self.large_media_min_chunk_bytes > self.large_media_chunk_bytes
            || !(1..=4).contains(&self.max_inflight_requests)
            || !(1..=self.max_inflight_requests).contains(&self.per_job_scan_workers)
            || !(1..=64 * MIB).contains(&self.attachment_max_bytes)
            || self.attachment_total_bytes < self.attachment_max_bytes
            || self.attachment_total_bytes > 256 * MIB
            || self.scan_timeout_seconds == 0
            || self.connect_timeout_seconds == 0
            || self.definitions_stale_hours == 0
            || self.probe_timeout_seconds == 0
            || self.large_media_scan_timeout_seconds == 0
        {
            return Err(ScanError::Policy(
                "invalid scanner size, timeout, or concurrency policy".into(),
            ));
        }
        self.archive_limits.validate()?;
        for binary in [&self.ffprobe_binary, &self.ffmpeg_binary] {
            let info = std::fs::metadata(binary)
                .map_err(|e| ScanError::Policy(format!("media tool {}: {e}", binary.display())))?;
            if !binary.is_absolute() || !info.is_file() || info.mode() & 0o111 == 0 {
                return Err(ScanError::Policy(format!(
                    "media tool is not an executable absolute path: {}",
                    binary.display()
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("scanner I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("scan policy blocked inspection: {0}")]
    Policy(String),
    #[error("scanner inspection limit ({name}): {message}")]
    Limit { name: String, message: String },
    #[error("scanner is unavailable: {0}")]
    Unavailable(String),
    #[error("scan interrupted or its lease was lost")]
    Cancelled,
    #[error("scan deadline exceeded")]
    Timeout,
    #[error("file identity changed during inspection: {0}")]
    Changed(String),
}
impl ScanError {
    fn can_fallback(&self) -> bool {
        matches!(self, Self::Limit{name,..} if matches!(name.as_str(), "maxfilesize"|"streammaxlength"|"maxscansize"))
    }
    fn can_subdivide(&self) -> bool {
        matches!(self, Self::Limit{name,..} if matches!(name.as_str(), "maxfilesize"|"streammaxlength"))
    }
}

/// Nanosecond timestamps, inode, device, and size tie a verdict to actual bytes.
/// Both the open descriptor and the pathname must still match before promotion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
    pub changed_seconds: i64,
    pub changed_nanoseconds: i64,
}
impl FileIdentity {
    pub fn from_metadata(m: &Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            size: m.size(),
            modified_seconds: m.mtime(),
            modified_nanoseconds: m.mtime_nsec(),
            changed_seconds: m.ctime(),
            changed_nanoseconds: m.ctime_nsec(),
        }
    }
    pub fn read(path: &Path) -> Result<Self, ScanError> {
        let m = std::fs::symlink_metadata(path)?;
        if !m.is_file() {
            return Err(ScanError::Policy(
                "scan target must be a regular file".into(),
            ));
        }
        Ok(Self::from_metadata(&m))
    }
    fn verify(&self, file: &File, path: &Path) -> Result<(), ScanError> {
        let current = std::fs::symlink_metadata(path)
            .map_err(|_| ScanError::Changed(path.display().to_string()))?;
        if !current.is_file()
            || *self != Self::from_metadata(&current)
            || *self != Self::from_metadata(&file.metadata()?)
        {
            return Err(ScanError::Changed(path.display().to_string()));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerIdentity {
    pub backend: String,
    pub engine_version: Option<String>,
    pub database_version: Option<String>,
    pub database_updated_at: Option<DateTime<Utc>>,
    pub policy_version: String,
    pub raw_version: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerHealth {
    pub status: String,
    pub can_scan: bool,
    pub message: String,
    pub checked_at: DateTime<Utc>,
    pub identity: Option<ScannerIdentity>,
    pub definitions_age_hours: Option<f64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub clean: bool,
    pub infected: bool,
    pub identity: ScannerIdentity,
    pub scan_started_at: DateTime<Utc>,
    pub duration_seconds: f64,
    pub threat_name: Option<String>,
    pub raw_output: String,
    pub scan_method: String,
    pub file_identity: FileIdentity,
}
#[derive(Debug)]
pub(crate) struct Verdict {
    infected: bool,
    threat: Option<String>,
    output: String,
}
impl Verdict {
    fn clean(output: impl Into<String>) -> Self {
        Self {
            infected: false,
            threat: None,
            output: output.into(),
        }
    }
}

/// The controller supplies one callback that becomes true on shutdown, cancel,
/// or lease loss. Every bounded wait checks it, including subprocess monitoring.
pub(crate) struct Context<'a> {
    deadline: Instant,
    cancelled: &'a (dyn Fn() -> bool + Sync),
}
impl<'a> Context<'a> {
    fn check(&self) -> Result<(), ScanError> {
        if (self.cancelled)() {
            return Err(ScanError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(ScanError::Timeout);
        }
        Ok(())
    }
    fn bounded(&self, seconds: u64) -> Self {
        Self {
            deadline: self
                .deadline
                .min(Instant::now() + Duration::from_secs(seconds)),
            cancelled: self.cancelled,
        }
    }
}

/// Blocking, thread-safe scanner. Call it from a blocking worker rather than an
/// async executor thread. Capacity is shared across every request on this value.
pub struct Scanner {
    pub settings: ScanSettings,
    slots: Mutex<usize>,
    available: Condvar,
    cached_health: Mutex<Option<(Instant, ScannerHealth)>>,
}
impl Scanner {
    pub fn new(settings: ScanSettings) -> Self {
        Self {
            settings,
            slots: Mutex::new(0),
            available: Condvar::new(),
            cached_health: Mutex::new(None),
        }
    }
    pub fn policy_version(&self) -> String {
        // Hash only inspection policy; changing a socket path does not change a verdict.
        let policy = serde_json::json!({"implementation":"rust-bounded-media-archive-v1","configured":self.settings.policy_version,
            "native":self.settings.max_file_bytes,"media":self.settings.large_media_enabled,"media_max":self.settings.large_media_max_file_bytes,
            "chunk":self.settings.large_media_chunk_bytes,"minimum":self.settings.large_media_min_chunk_bytes,"overlap":self.settings.large_media_overlap_bytes,
            "attachment_max":self.settings.attachment_max_bytes,"attachment_total":self.settings.attachment_total_bytes,
            "archive":self.settings.archive_enabled,"archive_max":self.settings.archive_max_file_bytes,"limits":self.settings.archive_limits});
        let hash = hex::encode(Sha256::digest(policy.to_string()));
        format!("{}:{}", self.settings.policy_version, &hash[..12])
    }
    pub fn health(&self) -> ScannerHealth {
        self.health_with_refresh(false)
    }
    fn health_with_refresh(&self, force: bool) -> ScannerHealth {
        let mut cache = self.cached_health.lock().unwrap_or_else(|e| e.into_inner());
        if !force {
            if let Some((at, health)) = cache.as_ref() {
                if at.elapsed() < Duration::from_secs(self.settings.health_cache_seconds.max(1)) {
                    return health.clone();
                }
            }
        }
        let health = self.load_health();
        *cache = Some((Instant::now(), health.clone()));
        health
    }
    fn load_health(&self) -> ScannerHealth {
        let now = Utc::now();
        let result = (|| {
            self.settings.validate()?;
            let raw = protocol::version(&self.settings)?;
            let (engine, db, date) = parse_scanner_version(&raw);
            let identity = ScannerIdentity {
                backend: "clamd-instream".into(),
                engine_version: engine,
                database_version: db,
                database_updated_at: date,
                policy_version: self.policy_version(),
                raw_version: raw.chars().take(255).collect(),
            };
            let date = identity.database_updated_at.ok_or_else(|| {
                ScanError::Unavailable("signature freshness could not be verified".into())
            })?;
            if identity.engine_version.is_none() || identity.database_version.is_none() {
                return Err(ScanError::Unavailable(
                    "engine or database version could not be verified".into(),
                ));
            }
            let age = ((now - date).num_seconds() as f64 / 3600.0).max(0.0);
            let stale = age >= self.settings.definitions_stale_hours as f64;
            let warning = age
                >= self
                    .settings
                    .definitions_warn_hours
                    .min(self.settings.definitions_stale_hours) as f64;
            Ok(ScannerHealth {
                status: if stale {
                    "stale"
                } else if warning {
                    "warning"
                } else {
                    "healthy"
                }
                .into(),
                can_scan: !stale,
                message: format!(
                    "ClamAV definitions are {age:.1} hours old{}",
                    if stale { "; scans are blocked" } else { "" }
                ),
                checked_at: now,
                identity: Some(identity),
                definitions_age_hours: Some(age),
            })
        })();
        result.unwrap_or_else(|e: ScanError| ScannerHealth {
            status: "unavailable".into(),
            can_scan: false,
            message: e.to_string(),
            checked_at: now,
            identity: None,
            definitions_age_hours: None,
        })
    }
    pub fn scan_path(
        &self,
        path: &Path,
        expected: Option<FileIdentity>,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<ScanResult, ScanError> {
        if cancelled() {
            return Err(ScanError::Cancelled);
        }
        // Never let a cached status authorize a new scan with stale definitions.
        let health = self.health_with_refresh(true);
        if !health.can_scan {
            return Err(ScanError::Unavailable(health.message));
        }
        let identity = health
            .identity
            .ok_or_else(|| ScanError::Unavailable("missing scanner identity".into()))?;
        let start = Instant::now();
        let started_at = Utc::now();
        let ctx = Context {
            deadline: start
                + Duration::from_secs(
                    self.settings
                        .large_media_scan_timeout_seconds
                        .max(self.settings.archive_limits.timeout_seconds)
                        .max(self.settings.scan_timeout_seconds),
                ),
            cancelled,
        };
        let (verdict, method, file_identity) = self.inspect(path, expected, &ctx, true)?;
        ctx.check()?;
        Ok(ScanResult {
            clean: !verdict.infected,
            infected: verdict.infected,
            identity,
            scan_started_at: started_at,
            duration_seconds: start.elapsed().as_secs_f64(),
            threat_name: verdict.threat,
            raw_output: verdict.output,
            scan_method: method.into(),
            file_identity,
        })
    }
    fn inspect(
        &self,
        path: &Path,
        expected: Option<FileIdentity>,
        ctx: &Context<'_>,
        allow_archive: bool,
    ) -> Result<(Verdict, &'static str, FileIdentity), ScanError> {
        ctx.check()?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let m = file.metadata()?;
        if !m.is_file() {
            return Err(ScanError::Policy(
                "scan target must be a regular file".into(),
            ));
        }
        let identity = FileIdentity::from_metadata(&m);
        if expected.is_some_and(|e| e != identity) {
            return Err(ScanError::Changed(path.display().to_string()));
        }
        let is_archive = allow_archive && archive::archive_format(&file)?.is_some();
        let (verdict, method) = if identity.size <= self.settings.max_file_bytes {
            // Native Matroska's extra attachment inspection belongs to this
            // same native scan deadline. Only an explicit large-media/archive
            // fallback gets the separate, longer policy deadline.
            let native_ctx = ctx.bounded(self.settings.scan_timeout_seconds);
            match self.native(&file, 0, identity.size, &native_ctx) {
                Ok(mut v) => {
                    identity.verify(&file, path)?;
                    let mut method = "clamd_native";
                    use std::os::unix::fs::FileExt;
                    let mut magic = [0u8; 4];
                    let count = file.read_at(&mut magic, 0)?;
                    if !v.infected && count == 4 && magic == [0x1a, 0x45, 0xdf, 0xa3] {
                        let probe = self.probe_media(&file, path, false, &native_ctx)?;
                        let attachments =
                            self.scan_attachments(&file, path, identity, &probe, &native_ctx)?;
                        if !probe.attachments.is_empty() {
                            method = "clamd_native_with_attachments";
                            v = attachments;
                        }
                    }
                    (v, method)
                }
                Err(e) if e.can_fallback() => {
                    self.fallback(&file, path, identity, is_archive, ctx)?
                }
                Err(e) => return Err(e),
            }
        } else {
            self.fallback(&file, path, identity, is_archive, ctx)?
        };
        identity.verify(&file, path)?;
        ctx.check()?;
        Ok((verdict, method, identity))
    }
    fn fallback(
        &self,
        file: &File,
        path: &Path,
        identity: FileIdentity,
        is_archive: bool,
        ctx: &Context<'_>,
    ) -> Result<(Verdict, &'static str), ScanError> {
        if is_archive {
            Ok((
                self.scan_archive(file, path, identity, ctx)?,
                "archive_members",
            ))
        } else {
            Ok((
                self.scan_media(file, path, identity, ctx)?,
                "media_windows_and_attachments",
            ))
        }
    }
}

impl ScanSettings {
    /// Translate the existing TI_* configuration names and MiB/GiB units. This
    /// prevents a rewrite from silently changing an operator's inspection limits.
    pub fn from_values(values: &serde_json::Value) -> Result<Self, ScanError> {
        let mut settings = Self::default();
        let error =
            |name: &str| ScanError::Policy(format!("invalid scanner configuration field: {name}"));
        macro_rules! number {
            ($field:ident,$key:literal,$mult:expr) => {
                if let Some(v) = values.get($key) {
                    settings.$field = v
                        .as_u64()
                        .and_then(|n| n.checked_mul($mult))
                        .ok_or_else(|| error($key))?;
                }
            };
        }
        macro_rules! flag {
            ($field:ident,$key:literal) => {
                if let Some(v) = values.get($key) {
                    settings.$field = v.as_bool().ok_or_else(|| error($key))?;
                }
            };
        }
        macro_rules! path {
            ($field:ident,$key:literal) => {
                if let Some(v) = values.get($key) {
                    settings.$field = PathBuf::from(v.as_str().ok_or_else(|| error($key))?);
                }
            };
        }
        path!(socket_path, "clamd_socket_path");
        path!(data_dir, "data_dir");
        path!(ffprobe_binary, "ffprobe_binary");
        path!(ffmpeg_binary, "ffmpeg_binary");
        if let Some(v) = values.get("scanner_policy_version") {
            settings.policy_version = v
                .as_str()
                .ok_or_else(|| error("scanner_policy_version"))?
                .into();
        }
        number!(max_file_bytes, "scanner_max_file_mib", MIB);
        number!(
            connect_timeout_seconds,
            "scanner_connect_timeout_seconds",
            1
        );
        number!(scan_timeout_seconds, "scanner_scan_timeout_seconds", 1);
        number!(health_cache_seconds, "scanner_health_cache_seconds", 1);
        number!(definitions_warn_hours, "scanner_definitions_warn_hours", 1);
        number!(
            definitions_stale_hours,
            "scanner_definitions_stale_hours",
            1
        );
        flag!(large_media_enabled, "large_media_enabled");
        number!(
            large_media_max_file_bytes,
            "large_media_max_file_gib",
            1024 * MIB
        );
        number!(large_media_chunk_bytes, "large_media_chunk_mib", MIB);
        number!(
            large_media_min_chunk_bytes,
            "large_media_min_chunk_mib",
            MIB
        );
        number!(large_media_overlap_bytes, "large_media_overlap_kib", 1024);
        number!(
            large_media_scan_timeout_seconds,
            "large_media_scan_timeout_seconds",
            1
        );
        number!(
            probe_timeout_seconds,
            "large_media_probe_timeout_seconds",
            1
        );
        number!(attachment_max_bytes, "media_attachment_max_mib", MIB);
        number!(attachment_total_bytes, "media_attachment_total_mib", MIB);
        flag!(archive_enabled, "archive_enabled");
        number!(archive_max_file_bytes, "archive_max_file_gib", 1024 * MIB);
        if let Some(v) = values.get("clamd_max_inflight_requests") {
            settings.max_inflight_requests = v
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .ok_or_else(|| error("clamd_max_inflight_requests"))?;
        }
        if let Some(v) = values.get("per_job_scan_workers") {
            settings.per_job_scan_workers = v
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .ok_or_else(|| error("per_job_scan_workers"))?;
        }
        for (key, target, mult) in [
            (
                "archive_max_expanded_gib",
                &mut settings.archive_limits.expanded_bytes,
                1024 * MIB,
            ),
            ("archive_max_files", &mut settings.archive_limits.files, 1),
            ("archive_max_depth", &mut settings.archive_limits.depth, 1),
            (
                "archive_free_space_buffer_gib",
                &mut settings.archive_limits.reserve_bytes,
                1024 * MIB,
            ),
            (
                "archive_scan_timeout_seconds",
                &mut settings.archive_limits.timeout_seconds,
                1,
            ),
        ] {
            if let Some(v) = values.get(key) {
                *target = v
                    .as_u64()
                    .and_then(|n| n.checked_mul(mult))
                    .ok_or_else(|| error(key))?;
            }
        }
        for (key, target) in [
            ("archive_scratch_dir", &mut settings.archive_scratch_dir),
            (
                "archive_scratch_mount_marker",
                &mut settings.archive_mount_marker,
            ),
        ] {
            if let Some(v) = values.get(key).filter(|v| !v.is_null()) {
                let text = v.as_str().ok_or_else(|| error(key))?;
                *target = if text.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(text))
                };
            }
        }
        Ok(settings)
    }
}
