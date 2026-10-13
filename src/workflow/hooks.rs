//! Optional effects after verified promotion. Claims are committed before a
//! process starts; interrupted claims require explicit review and retry.
use super::*;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration as Wait, Instant},
};

struct HookOutcome {
    output: String,
    exit_code: Option<i32>,
    error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct HookNotReady(String);

#[cfg(test)]
thread_local! {
    static COPY_READ_BYTES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The standalone copy hook uses the same copier as the controller, without
/// opening its database or connecting to qBittorrent. The controller has already
/// verified the clean promotion before invoking its trusted hook executable.
pub struct CopyHookRequest {
    pub source: PathBuf,
    pub destination: PathBuf,
    pub torrent_hash: String,
    pub torrent_name: String,
    pub job_id: String,
    pub source_root: Option<PathBuf>,
    pub relative_path: Option<PathBuf>,
}

pub fn run_copy_hook(request: &CopyHookRequest) -> Result<String> {
    if !request
        .job_id
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
    {
        bail!("copy job identifier must begin with a letter or digit");
    }
    let source = safety::checked(&request.source)?;
    if matches!(
        source.file_name().and_then(|name| name.to_str()),
        Some(".intake-copy-complete.json" | ".intake-copy-complete.pending")
    ) {
        bail!("source name conflicts with a reserved completion marker");
    }
    let route = match (&request.source_root, &request.relative_path) {
        (None, None) => "",
        (Some(root), Some(relative)) => {
            let root = safety::checked(root)?;
            if !root.is_dir() || !safe_relative(relative) || root.join(relative) != source {
                bail!(
                    "routed copy source must equal source root joined with its safe relative path"
                );
            }
            relative
                .to_str()
                .context("copy route must be valid UTF-8")?
        }
        _ => bail!("routed copying requires both source root and relative path"),
    };
    copy_promoted(
        &source,
        &request.destination,
        route,
        &request.job_id,
        &request.torrent_hash,
        &request.torrent_name,
        &|| false,
    )
}

impl Workflow {
    pub(super) fn hook_patch(&self, job: &Value) -> Result<Value> {
        if !job["hook_status"].is_null()
            || string(job, "state") != "done"
            || job["promoted_at"].is_null()
            || job["scan_completed_at"].is_null()
        {
            return Ok(json!({}));
        }
        let mut patch = json!({
            "hook_status": "pending",
            "hook_due_at": after(self.config.u64("post_promotion_delay_seconds") as i64),
            "hook_error": null,
            "hook_output": null,
            "hook_exit_code": null,
            "hook_started_at": null,
            "hook_finished_at": null,
        });
        let kind = if !string(job, "hook_kind").is_empty() {
            string(job, "hook_kind")
        } else if !string(job, "hook_script").is_empty() {
            "script"
        } else if self.config.bool("post_promotion_copy_enabled") {
            "copy"
        } else {
            "script"
        };
        if kind == "copy" && self.config.bool("post_promotion_copy_enabled") {
            patch["hook_kind"] = json!("copy");
            patch["hook_script"] = Value::Null;
            if !string(job, "hook_destination").is_empty() {
                // Explicit retries retain the route pinned by the original
                // promotion, even if the default routing registry changed.
                for key in [
                    "hook_destination",
                    "hook_copy_source_root",
                    "hook_copy_relative_path",
                ] {
                    patch[key] = job[key].clone();
                }
                return Ok(patch);
            }
            let rules = self
                .config
                .get("post_promotion_copy_rules")
                .as_array()
                .cloned()
                .unwrap_or_default();
            let rule = rules
                .iter()
                .filter(|rule| {
                    rule["enabled"].as_bool().unwrap_or(true)
                        && Path::new(string(job, "final_parent"))
                            .starts_with(string(rule, "source"))
                })
                .max_by_key(|rule| Path::new(string(rule, "source")).components().count());
            let Some(rule) = rule else {
                return Ok(json!({}));
            };
            let source = Path::new(string(job, "content_path"));
            let Ok(relative) = source.strip_prefix(string(rule, "source")) else {
                return Ok(json!({}));
            };
            if !source.is_absolute() || !safe_relative(relative) {
                return Ok(json!({}));
            }
            patch["hook_kind"] = json!("copy");
            patch["hook_destination"] = rule["destination"].clone();
            patch["hook_copy_source_root"] = rule["source"].clone();
            patch["hook_copy_relative_path"] = json!(relative);
        } else if kind == "script"
            && self.config.bool("post_promotion_enabled")
            && !self.config.string("post_promotion_script").is_empty()
        {
            patch["hook_kind"] = json!("script");
            patch["hook_script"] = self.config.get("post_promotion_script").clone();
            for key in [
                "hook_destination",
                "hook_copy_source_root",
                "hook_copy_relative_path",
            ] {
                patch[key] = Value::Null;
            }
        } else {
            return Ok(json!({}));
        }
        Ok(patch)
    }
    fn validate_hook(&self, job: &Value) -> Result<()> {
        if string(job, "state") != "done"
            || !boolean(job, "is_terminal")
            || job["scan_completed_at"].is_null()
            || job["promoted_at"].is_null()
        {
            bail!("hook requires a verified clean promoted job");
        }
        let parent = self.final_parent(string(job, "final_parent"))?;
        let source = Path::new(string(job, "content_path"));
        // Cheap readiness and route checks precede an expensive source walk.
        // An offline copy mount should not repeatedly enumerate a large library.
        match string(job, "hook_kind") {
            "copy" => {
                let destination = copy_destination(Path::new(string(job, "hook_destination")))?;
                if source.starts_with(&destination) || destination.starts_with(source) {
                    bail!("copy source and destination cannot overlap");
                }
                if let Some((root, relative)) = pinned_copy_route(job)? {
                    if self.final_parent(root.to_str().context("invalid copy root")?)?
                        != root.to_string_lossy()
                        || !safe_relative(relative)
                        || root.join(relative) != source
                        || !Path::new(&parent).starts_with(root)
                    {
                        bail!("pinned copy route does not match promoted content");
                    }
                }
            }
            "script" | "" => {
                let script = string(job, "hook_script");
                if script != self.config.string("post_promotion_script") {
                    bail!("queued script differs from configured trusted script");
                }
                let path = Path::new(script);
                if !path.starts_with("/hooks") || path == Path::new("/hooks") {
                    bail!("trusted hook must be inside /hooks");
                }
                safety::checked(path).map_err(|error| {
                    anyhow::anyhow!("configured trusted hook is unavailable: {error:#}")
                })?;
                use std::os::unix::fs::PermissionsExt;
                if !path.is_file() || fs::metadata(path)?.permissions().mode() & 0o111 == 0 {
                    bail!("hook is not an executable regular file");
                }
            }
            _ => bail!("unknown post-promotion action kind"),
        }
        self.require_final_storage(Path::new(&parent))
            .map_err(|error| {
                HookNotReady(format!(
                    "promoted content/mount is temporarily unavailable: {error:#}"
                ))
            })?;
        let source = safety::within(source, Path::new(&parent))?;
        if source == Path::new(&parent) {
            bail!("hook content cannot equal the entire destination root");
        }
        let actual = layout(&safety::manifest(&source)?);
        let scanned = query_values(
            &self.db.connect()?,
            "SELECT relative_path,size_bytes,status FROM scan_files WHERE job_id=?1",
            [string(job, "id")],
        )?;
        if scanned.is_empty()
            || scanned.iter().any(|file| string(file, "status") != "clean")
            || actual != layout(&scanned)
        {
            bail!("promoted content no longer matches the complete clean manifest");
        }
        // Live ownership is deliberately checked after the source walk: a
        // torrent may have begun moving or checking while it was enumerated.
        let torrent = self
            .find_torrent(job)?
            .ok_or_else(|| HookNotReady("qBittorrent torrent is temporarily unavailable".into()))?;
        self.guard(job, &torrent, false, false)?;
        require_hook_complete(&torrent)?;
        if self.guard_destination(job, &torrent, Path::new(&parent), false)? != source {
            bail!("hook source changed after promotion");
        }
        Ok(())
    }
    pub(super) fn schedule_hook(&self) -> Result<()> {
        if self.is_stopping() || self.active_hooks.load(Ordering::SeqCst) > 0 {
            return Ok(());
        }
        for job in self.jobs_query(
            "WHERE hook_status='pending' AND (hook_due_at IS NULL OR hook_due_at<=?1)
             ORDER BY created_at ASC,id DESC",
            [now()],
        )? {
            let enabled = if string(&job, "hook_kind") == "copy" {
                self.config.bool("post_promotion_copy_enabled")
            } else {
                self.config.bool("post_promotion_enabled")
            };
            if !enabled {
                continue;
            }
            let id = string(&job, "id").to_owned();
            if let Err(error) = self.validate_hook(&job) {
                // Preflight has no external effects. Offline destinations and
                // qBittorrent outages remain pending and can recover themselves.
                let retry = retryable_hook_error(&error);
                self.update(
                    &id,
                    json!({
                        "hook_error": format!("Preflight: {error:#}"),
                        "hook_due_at": after(15),
                        "hook_status": if retry { "pending" } else { "failed" },
                        "hook_finished_at": if retry { Value::Null } else { json!(now()) },
                    }),
                )?;
                continue;
            }
            if self.is_stopping() {
                return Ok(());
            }
            let attempts = number(&job, "hook_attempts") + 1;
            let changed = self.db.connect()?.execute(
                "UPDATE jobs SET hook_status='running', hook_started_at=?1, hook_attempts=?2,
                    hook_error=NULL, hook_output=NULL, hook_exit_code=NULL
                 WHERE id=?3 AND hook_status='pending'",
                rusqlite::params![now(), attempts, id],
            )?;
            if changed != 1 {
                continue;
            }
            self.active_hooks.fetch_add(1, Ordering::SeqCst);
            let workflow = self.clone();
            thread::spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    workflow.run_hook(&job)
                }));
                let (status, error, output, code) = match outcome {
                    Ok(Ok(result)) => (
                        if result.error.is_some() && workflow.is_stopping() {
                            "interrupted"
                        } else if result.exit_code == Some(0) && result.error.is_none() {
                            "succeeded"
                        } else {
                            "failed"
                        },
                        result.error,
                        result.output,
                        result.exit_code,
                    ),
                    Ok(Err(error)) => (
                        if workflow.is_stopping() {
                            "interrupted"
                        } else {
                            "failed"
                        },
                        Some(format!("{error:#}")),
                        String::new(),
                        None,
                    ),
                    Err(_) => (
                        "interrupted",
                        Some("hook worker panicked".into()),
                        String::new(),
                        None,
                    ),
                };
                if let Ok(connection) = workflow.db.connect() {
                    let _ = connection.execute(
                        "UPDATE jobs SET hook_status=?1, hook_error=?2, hook_output=?3,
                            hook_exit_code=?4, hook_finished_at=?5
                         WHERE id=?6 AND hook_status='running' AND hook_attempts=?7",
                        rusqlite::params![status, error, output, code, now(), id, attempts],
                    );
                }
                let _ = workflow.event(
                    &id,
                    &format!("post_promotion_hook_{status}"),
                    if status == "succeeded" {
                        "info"
                    } else {
                        "warning"
                    },
                    &format!("Post-promotion action {status}"),
                    json!({"error":error,"hook_attempt":attempts}),
                );
                workflow.active_hooks.fetch_sub(1, Ordering::SeqCst);
            });
            break;
        }
        Ok(())
    }
    fn run_hook(&self, job: &Value) -> Result<HookOutcome> {
        let deadline = Instant::now()
            + Wait::from_secs(self.config.u64("post_promotion_timeout_seconds").max(1));
        let cancelled = || self.is_stopping() || Instant::now() >= deadline;
        if cancelled() {
            bail!("controller stopped before the claimed hook could start");
        }
        if string(job, "hook_kind") == "copy" {
            let output = copy_promoted(
                Path::new(string(job, "content_path")),
                Path::new(string(job, "hook_destination")),
                string(job, "hook_copy_relative_path"),
                string(job, "id"),
                string(job, "qbt_hash"),
                string(job, "torrent_name"),
                &cancelled,
            )?;
            return Ok(HookOutcome {
                output,
                exit_code: Some(0),
                error: None,
            });
        }
        use std::os::unix::process::CommandExt;
        let mut command = Command::new(string(job, "hook_script"));
        command
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .env("TMPDIR", "/tmp")
            .current_dir("/tmp");
        command
            .args([
                "--source",
                string(job, "content_path"),
                "--torrent-hash",
                string(job, "qbt_hash"),
            ])
            .arg(format!("--torrent-name={}", string(job, "torrent_name")))
            .args(["--job-id", string(job, "id")])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = command
            .spawn()
            .context("trusted post-promotion script failed to start")?;
        let mut stdout = child.stdout.take().context("missing stdout")?;
        let mut stderr = child.stderr.take().context("missing stderr")?;
        nonblocking(&stdout)?;
        nonblocking(&stderr)?;
        let mut output = Vec::new();
        let result = loop {
            capture_available(&mut stdout, &mut output)?;
            capture_available(&mut stderr, &mut output)?;
            if let Some(status) = child.try_wait()? {
                break Ok(status.code());
            }
            if cancelled() {
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGTERM);
                }
                let end = Instant::now() + Wait::from_secs(2);
                while Instant::now() < end && child.try_wait()?.is_none() {
                    thread::sleep(Wait::from_millis(25));
                }
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                let _ = child.wait();
                break Err(anyhow::anyhow!(
                    "hook interrupted or timed out; inspect external side effects before retry"
                ));
            }
            thread::sleep(Wait::from_millis(50));
        };
        // Never wait indefinitely for inherited pipes: even a detached child
        // cannot prevent a bounded hook from finishing its bookkeeping.
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
        let (code, mut error) = match result {
            Ok(code) => (
                code,
                if code == Some(0) {
                    None
                } else {
                    Some(format!("Hook exited with status {code:?}"))
                },
            ),
            Err(error) => (
                child.try_wait()?.and_then(|status| status.code()),
                Some(error.to_string()),
            ),
        };
        let drain_deadline = Instant::now() + Wait::from_secs(2);
        loop {
            let stdout_done = capture_available(&mut stdout, &mut output)?;
            let stderr_done = capture_available(&mut stderr, &mut output)?;
            if stdout_done && stderr_done {
                break;
            }
            if Instant::now() >= drain_deadline {
                error=Some("Hook exited but a background process kept its output pipe open; review external effects before retrying".into());
                break;
            }
            thread::sleep(Wait::from_millis(25));
        }
        if output.len() == 64 * 1024 {
            let suffix = b"\n[output truncated]\n";
            output.truncate(output.len() - suffix.len());
            output.extend_from_slice(suffix);
        }
        Ok(HookOutcome {
            output: String::from_utf8_lossy(&output).into_owned(),
            exit_code: code,
            error,
        })
    }
}
fn nonblocking(pipe: &impl std::os::fd::AsRawFd) -> Result<()> {
    let descriptor = pipe.as_raw_fd();
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
fn capture_available(input: &mut impl Read, output: &mut Vec<u8>) -> Result<bool> {
    let mut buffer = [0u8; 8192];
    // Bound each drain too: an aggressively writing script must not starve the
    // timeout/cancellation checks even though excess output is discarded.
    for _ in 0..128 {
        match input.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error.into()),
            Ok(count) => {
                let keep = count.min((64 * 1024usize).saturating_sub(output.len()));
                output.extend_from_slice(&buffer[..keep]);
            }
        }
    }
    Ok(false)
}
fn layout(manifest: &[Value]) -> BTreeMap<String, u64> {
    manifest
        .iter()
        .map(|file| {
            (
                string(file, "relative_path").to_owned(),
                number(file, "size_bytes"),
            )
        })
        .collect()
}
fn safe_relative(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

fn pinned_copy_route(job: &Value) -> Result<Option<(&Path, &Path)>> {
    if job["hook_copy_source_root"].is_null() && job["hook_copy_relative_path"].is_null() {
        return Ok(None); // Historical work uses the original per-job wrapper.
    }
    let root = Path::new(string(job, "hook_copy_source_root"));
    let relative = Path::new(string(job, "hook_copy_relative_path"));
    if root.as_os_str().is_empty() || relative.as_os_str().is_empty() {
        bail!("mapped copy has incomplete pinned routing");
    }
    if !safe_relative(relative) {
        bail!("pinned copy route is not a safe relative path");
    }
    Ok(Some((root, relative)))
}

fn require_hook_complete(torrent: &Value) -> Result<()> {
    if !safety::complete(torrent) {
        return Err(HookNotReady(
            "torrent is incomplete, moving or checking; hook remains queued".into(),
        )
        .into());
    }
    Ok(())
}

fn retryable_hook_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<std::io::Error>().is_some()
        || error.downcast_ref::<reqwest::Error>().is_some()
        || error.downcast_ref::<HookNotReady>().is_some()
}
pub(crate) fn copy_destination(path: &Path) -> Result<PathBuf> {
    if !path.starts_with("/copy-target") {
        bail!("copy destination must be inside /copy-target");
    }
    let root = safety::checked(Path::new("/copy-target"))?;
    let destination = safety::within(path, &root)?;
    if !destination.is_dir() {
        bail!("copy destination must be an existing mounted directory");
    }
    let marker = destination.join(".intake-copy-mount");
    safety::checked(&marker)?;
    if !marker.is_file() {
        bail!("required .intake-copy-mount marker is not a regular file");
    }
    OpenOptions::new().read(true).open(marker)?;
    Ok(destination)
}

/// Use exclusive reservations and a completion receipt to publish a copy. The
/// caller supplies a pinned relative route; existing destinations are compared
/// byte-for-byte and are never replaced. Completion records make retries safe.
fn copy_promoted(
    source: &Path,
    destination: &Path,
    route: &str,
    id: &str,
    hash: &str,
    torrent_name: &str,
    cancelled: &dyn Fn() -> bool,
) -> Result<String> {
    let source = safety::checked(source)?;
    let destination = copy_destination(destination)?;
    let marker = destination.join(".intake-copy-mount");
    let identity = safety::fingerprint(&marker)?;
    let cancelled_or_unmounted = || {
        cancelled()
            || safety::fingerprint(&marker)
                .map(|current| !safety::same_fingerprint(&identity, &current))
                .unwrap_or(true)
    };
    let output = copy_into(
        &source,
        &destination,
        route,
        id,
        hash,
        torrent_name,
        &cancelled_or_unmounted,
    )?;
    if cancelled_or_unmounted() {
        bail!("destination mount marker changed during copying");
    }
    Ok(output)
}
fn copy_into(
    source: &Path,
    destination: &Path,
    route: &str,
    id: &str,
    hash: &str,
    torrent_name: &str,
    cancelled: &dyn Fn() -> bool,
) -> Result<String> {
    if source.starts_with(destination) || destination.starts_with(source) {
        bail!("copy source and target cannot overlap");
    }
    if id.is_empty()
        || id.len() > 80
        || !id
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || v == b'_' || v == b'-')
    {
        bail!("invalid copy job identifier");
    }
    let relative = if route.is_empty() {
        PathBuf::from(format!("intake-job-{id}"))
            .join(source.file_name().context("missing source filename")?)
    } else {
        PathBuf::from(route)
    };
    if !safe_relative(&relative)
        || matches!(
            relative
                .components()
                .next()
                .and_then(|c| c.as_os_str().to_str()),
            Some(".intake-copy-state" | ".intake-copy-mount")
        )
    {
        bail!("copy route must be a safe relative path without reserved state names");
    }
    let target = destination.join(relative);
    let state_root = destination.join(".intake-copy-state");
    if !state_root.exists() {
        fs::create_dir(&state_root)?;
    }
    safety::within(&state_root, destination)?;
    let state = state_root.join(id);
    if !state.exists() {
        fs::create_dir(&state)?;
    }
    safety::within(&state, destination)?;
    let lock_path = state.join("copy.lock");
    use std::os::unix::fs::OpenOptionsExt;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(lock_path)?;
    fs2::FileExt::try_lock_exclusive(&lock).context("another copy attempt owns this job")?;
    let before = safety::manifest(source)?;
    let directories = directory_layout(source)?;
    use std::os::unix::fs::MetadataExt;
    let destination_info = fs::metadata(destination)?;
    for entry in walkdir::WalkDir::new(source).follow_links(false) {
        let entry = entry?;
        let info = entry.metadata()?;
        if (info.dev(), info.ino()) == (destination_info.dev(), destination_info.ino()) {
            bail!("copy destination aliases source content");
        }
    }
    let record_path = if route.is_empty() {
        target
            .parent()
            .context("missing legacy wrapper")?
            .join(".intake-copy-complete.json")
    } else {
        state.join("complete.json")
    };
    if record_path.exists() {
        let record: Value = serde_json::from_slice(&fs::read(safety::checked(&record_path)?)?)?;
        // Python receipts have request/snapshot fields; Rust receipts add a
        // digest. Either can be recognized, but neither bypasses byte checks.
        let request = record.get("request").unwrap_or(&record);
        let saved_hash = if request["torrent_hash"].is_string() {
            string(request, "torrent_hash")
        } else {
            string(request, "hash")
        };
        if request["source"] != json!(source) || saved_hash != hash {
            bail!("completion record does not match current copy request");
        }
        if target.exists() {
            let digest = content_digest(source, &before, cancelled)?;
            if directory_layout(&target)? != directories
                || content_digest(&target, &safety::manifest(&target)?, cancelled)? != digest
            {
                bail!("previously copied destination has changed");
            }
            return Ok(format!("Already copied and verified: {}", target.display()));
        }
    }
    ensure_directories(target.parent().context("missing copy parent")?, destination)?;
    let digest = if target.exists() {
        let digest = content_digest(source, &before, cancelled)?;
        if directory_layout(&target)? != directories
            || content_digest(&target, &safety::manifest(&target)?, cancelled)? != digest
        {
            bail!("copy destination exists with different content; no files were replaced");
        }
        digest
    } else {
        let attempt = state.join(format!("attempt-{}", uuid::Uuid::new_v4().simple()));
        fs::create_dir(&attempt)?;
        let temporary = if source.is_dir() {
            // mkdir is an atomic no-replace reservation on local disks and
            // NFS. The payload is visible until the completion receipt exists.
            fs::create_dir(&target)?;
            target.clone()
        } else {
            attempt.join("payload")
        };
        let result = (|| {
            // Hash exactly the source bytes sent to the new copy. This replaces
            // a separate full source read; destination verification still reads
            // every written byte independently after fsync and identity checks.
            let mut digest = Sha256::new();
            for relative in &directories {
                if relative != "." {
                    ensure_directories(&temporary.join(relative), destination)?;
                }
            }
            for item in digest_order(&before) {
                if cancelled() {
                    bail!("copy cancelled or timed out");
                }
                let name = string(item, "relative_path");
                let from = if name == "." {
                    source.to_path_buf()
                } else {
                    source.join(name)
                };
                let to = if name == "." {
                    temporary.clone()
                } else {
                    temporary.join(name)
                };
                if let Some(parent) = to.parent() {
                    ensure_directories(parent, destination)?;
                }
                copy_file(&from, &to, item, &mut digest, cancelled)?;
            }
            let digest = format!("{:x}", digest.finalize());
            if safety::manifest(source)? != before {
                bail!("source content changed during copy");
            }
            if content_digest(&temporary, &safety::manifest(&temporary)?, cancelled)? != digest {
                bail!("copied bytes do not match source");
            }
            safety::checked(destination)?;
            safety::checked(target.parent().context("missing copy parent")?)?;
            if !source.is_dir() {
                fs::hard_link(&temporary, &target)
                    .context("destination exists or exclusive file publication failed")?;
                fs::remove_file(&temporary)?;
            }
            Ok::<String, anyhow::Error>(digest)
        })();
        // Failed attempts are evidence. Preserve their private files and any
        // directory reservation for the operator to inspect before retrying.
        result?
    };
    if cancelled() {
        bail!("copy cancelled or mount changed before completion");
    }
    let mut request =
        json!({"source":source,"torrent_hash":hash,"torrent_name":torrent_name,"job_id":id});
    if !route.is_empty() {
        let mut source_root = source.to_path_buf();
        for _ in Path::new(route).components() {
            source_root.pop();
        }
        request["source_root"] = json!(source_root);
        request["relative_path"] = json!(route);
        request["destination"] = json!(destination);
    }
    // Keep the original receipt schema as well as an optional Rust digest, so
    // switching controllers does not discard copy history or change routing.
    let record = json!({
        "request": request,
        "source_snapshot": receipt_snapshot(source)?,
        "destination_snapshot": receipt_snapshot(&target)?,
        "digest": digest,
    });
    let temporary = state.join(format!(".{}.json.tmp", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec_pretty(&record)?)?;
    file.sync_all()?;
    if record_path.exists() {
        let previous = state.join(format!(
            "complete-{}.previous.json",
            uuid::Uuid::new_v4().simple()
        ));
        fs::hard_link(&record_path, &previous)?;
        fs::rename(&temporary, &record_path)?;
    } else {
        fs::hard_link(&temporary, &record_path)?;
        fs::remove_file(&temporary)?;
    }
    Ok(format!("Copied and verified: {}", target.display()))
}
fn receipt_snapshot(root: &Path) -> Result<Value> {
    use std::os::unix::fs::MetadataExt;
    let mut snapshot = serde_json::Map::new();
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        let info = fs::symlink_metadata(entry.path())?;
        if info.file_type().is_symlink() || (!info.is_file() && !info.is_dir()) {
            bail!("receipt path is not a regular file or directory");
        }
        let name = entry.path().strip_prefix(root)?;
        let name = if name.as_os_str().is_empty() {
            ".".into()
        } else {
            name.to_string_lossy().into_owned()
        };
        snapshot.insert(
            name,
            json!([
                if info.is_dir() { "directory" } else { "file" },
                if info.is_dir() { 0 } else { info.len() },
                info.dev(),
                info.ino(),
                info.mtime() * 1_000_000_000 + info.mtime_nsec(),
                info.ctime() * 1_000_000_000 + info.ctime_nsec()
            ]),
        );
    }
    Ok(Value::Object(snapshot))
}
fn ensure_directories(path: &Path, boundary: &Path) -> Result<()> {
    if !path.starts_with(boundary) {
        bail!("copy directory escaped boundary");
    }
    let mut current = boundary.to_path_buf();
    safety::checked(&current)?;
    for component in path.strip_prefix(boundary)?.components() {
        if !matches!(component, Component::Normal(_)) {
            bail!("unsafe copy directory component");
        }
        current.push(component);
        match fs::create_dir(&current) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        if !safety::checked(&current)?.is_dir() {
            bail!("copy ancestor is not a directory");
        }
    }
    Ok(())
}
fn copy_file(
    source: &Path,
    target: &Path,
    expected: &Value,
    digest: &mut Sha256,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    if !safety::same_fingerprint(expected, &safety::fingerprint(source)?) {
        bail!("source changed before copying");
    }
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source)?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(target)?;
    let mut buffer = vec![0u8; 1024 * 1024];
    digest_header(digest, expected);
    loop {
        if cancelled() {
            bail!("copy cancelled or timed out");
        }
        let count = input.read(&mut buffer)?;
        #[cfg(test)]
        COPY_READ_BYTES.with(|bytes| bytes.set(bytes.get() + count as u64));
        if count == 0 {
            break;
        }
        output.write_all(&buffer[..count])?;
        digest.update(&buffer[..count]);
    }
    output.set_times(fs::FileTimes::new().set_modified(input.metadata()?.modified()?))?;
    output.sync_all()?;
    if !safety::same_fingerprint(expected, &safety::fingerprint(source)?) {
        bail!("source changed during copying");
    }
    Ok(())
}
fn directory_layout(root: &Path) -> Result<std::collections::BTreeSet<String>> {
    let mut output = std::collections::BTreeSet::new();
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            bail!("symlink in copy tree");
        }
        if entry.file_type().is_dir() {
            let relative = entry.path().strip_prefix(root)?;
            output.insert(if relative.as_os_str().is_empty() {
                ".".into()
            } else {
                relative.to_string_lossy().into_owned()
            });
        }
    }
    Ok(output)
}
fn content_digest(root: &Path, manifest: &[Value], cancelled: &dyn Fn() -> bool) -> Result<String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut hash = Sha256::new();
    for item in digest_order(manifest) {
        let name = string(item, "relative_path");
        digest_header(&mut hash, item);
        let path = if name == "." {
            root.to_path_buf()
        } else {
            root.join(name)
        };
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        let mut buffer = [0u8; 65536];
        loop {
            if cancelled() {
                bail!("copy verification cancelled or timed out");
            }
            let count = file.read(&mut buffer)?;
            #[cfg(test)]
            COPY_READ_BYTES.with(|bytes| bytes.set(bytes.get() + count as u64));
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
        }
        if !safety::same_fingerprint(item, &safety::fingerprint(&path)?) {
            bail!("file changed during copy verification");
        }
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn digest_order(manifest: &[Value]) -> Vec<&Value> {
    let mut ordered: Vec<_> = manifest.iter().collect();
    ordered.sort_by(|a, b| string(a, "relative_path").cmp(string(b, "relative_path")));
    ordered
}

fn digest_header(digest: &mut Sha256, file: &Value) {
    let name = string(file, "relative_path");
    digest.update((name.len() as u64).to_le_bytes());
    digest.update(name.as_bytes());
    digest.update(number(file, "size_bytes").to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn incomplete_live_torrent_defers_hook_while_policy_errors_do_not() {
        for (state, progress) in [
            ("moving", 1.0),
            ("downloading", 0.9),
            ("checkingDL", 1.0),
            ("checkingUP", 1.0),
        ] {
            let torrent = json!({"state": state, "progress": progress, "amount_left": 0});
            let error = require_hook_complete(&torrent).unwrap_err();
            assert!(
                retryable_hook_error(&error),
                "{state} should remain pending"
            );
        }
        assert!(!retryable_hook_error(&anyhow::anyhow!(
            "ownership tags are missing"
        )));
    }
    #[test]
    fn incomplete_pinned_route_cannot_fall_back_to_legacy_copy_layout() {
        assert!(pinned_copy_route(&json!({})).unwrap().is_none());
        for job in [
            json!({"hook_copy_source_root": "/media"}),
            json!({"hook_copy_relative_path": "media.mkv"}),
            json!({"hook_copy_source_root": "/media", "hook_copy_relative_path": ""}),
            json!({"hook_copy_source_root": "/media", "hook_copy_relative_path": "../outside"}),
        ] {
            assert!(pinned_copy_route(&job).is_err());
        }
        assert!(pinned_copy_route(&json!({
            "hook_copy_source_root": "/media", "hook_copy_relative_path": "Media/media.mkv",
        }))
        .unwrap()
        .is_some());
    }
    #[test]
    fn new_large_copy_reads_each_payload_once_and_verifies_destination() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let source = root.join("media.mkv");
        let destination = root.join("destination");
        fs::create_dir(&destination).unwrap();
        let size = 8 * 1024 * 1024;
        fs::write(&source, vec![0x5a; size]).unwrap();
        COPY_READ_BYTES.with(|bytes| bytes.set(0));
        copy_into(
            &source,
            &destination,
            "media.mkv",
            "job",
            "hash",
            "Media",
            &|| false,
        )
        .unwrap();
        let read_bytes = COPY_READ_BYTES.with(|bytes| bytes.get());
        eprintln!("new copy: {size} payload bytes, {read_bytes} total bytes read");
        assert_eq!(read_bytes, 2 * size as u64);
        COPY_READ_BYTES.with(|bytes| bytes.set(0));
        copy_into(
            &source,
            &destination,
            "media.mkv",
            "job",
            "hash",
            "Media",
            &|| false,
        )
        .unwrap();
        assert_eq!(
            COPY_READ_BYTES.with(|bytes| bytes.get()),
            2 * size as u64,
            "a retry independently verifies both existing payloads"
        );
    }
    #[test]
    fn streamed_copy_refuses_source_changes_and_corrupted_output_before_receipt() {
        use std::cell::Cell;
        for corrupt_source in [true, false] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap();
            let source = root.join("media.mkv");
            let destination = root.join("destination");
            fs::create_dir(&destination).unwrap();
            let size = 2 * 1024 * 1024;
            fs::write(&source, vec![0x5a; size]).unwrap();
            COPY_READ_BYTES.with(|bytes| bytes.set(0));
            let changed = Cell::new(false);
            let result = copy_into(
                &source,
                &destination,
                "media.mkv",
                "job",
                "hash",
                "Media",
                &|| {
                    let read = COPY_READ_BYTES.with(|bytes| bytes.get());
                    if !changed.get()
                        && read
                            >= if corrupt_source {
                                1024 * 1024
                            } else {
                                size as u64
                            }
                    {
                        let path = if corrupt_source {
                            source.clone()
                        } else {
                            fs::read_dir(destination.join(".intake-copy-state/job"))
                                .unwrap()
                                .map(|entry| entry.unwrap().path())
                                .find(|path| {
                                    path.file_name()
                                        .unwrap()
                                        .to_string_lossy()
                                        .starts_with("attempt-")
                                })
                                .unwrap()
                                .join("payload")
                        };
                        OpenOptions::new()
                            .write(true)
                            .open(path)
                            .unwrap()
                            .write_all(b"changed")
                            .unwrap();
                        changed.set(true);
                    }
                    false
                },
            );
            assert!(changed.get());
            assert!(result.is_err());
            assert!(!destination.join("media.mkv").exists());
            assert!(!destination
                .join(".intake-copy-state/job/complete.json")
                .exists());
            assert!(source.exists());
        }
    }
    #[test]
    fn copy_is_idempotent_and_refuses_changed_destination() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let source = base.join("source");
        let destination = base.join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(source.join("media.bin"), b"safe bytes").unwrap();
        copy_into(
            &source,
            &destination,
            "Media/Payload",
            "job",
            "hash",
            "Example",
            &|| false,
        )
        .unwrap();
        assert_eq!(
            fs::read(destination.join("Media/Payload/media.bin")).unwrap(),
            b"safe bytes"
        );
        assert!(copy_into(
            &source,
            &destination,
            "Media/Payload",
            "job",
            "hash",
            "Example",
            &|| { false }
        )
        .unwrap()
        .starts_with("Already"));
        fs::write(destination.join("Media/Payload/media.bin"), b"changed").unwrap();
        assert!(copy_into(
            &source,
            &destination,
            "Media/Payload",
            "job",
            "hash",
            "Example",
            &|| { false }
        )
        .is_err());
    }
    #[test]
    fn copy_rejects_symlinks_and_traversal() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let source = base.join("source");
        let destination = base.join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(source.join("file"), b"data").unwrap();
        assert!(copy_into(
            &source,
            &destination,
            "../outside",
            "job",
            "hash",
            "Example",
            &|| { false }
        )
        .is_err());
        std::os::unix::fs::symlink(source.join("file"), source.join("link")).unwrap();
        assert!(copy_into(
            &source,
            &destination,
            "safe",
            "job",
            "hash",
            "Example",
            &|| false
        )
        .is_err());
    }
}
