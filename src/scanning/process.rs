//! Subprocess boundaries for untrusted parsers. Only async-signal-safe libc calls
//! run between fork and exec; allocation and Rust error formatting stay outside.
use super::*;
use std::{
    io::Read,
    os::{
        fd::{AsRawFd, RawFd},
        unix::process::CommandExt,
    },
    process::{Child, Command, Stdio},
};

pub(crate) fn prepare(
    command: &mut Command,
    fd: RawFd,
    address_space: u64,
    file_limit: u64,
    cpu: u64,
) {
    // SAFETY: the closure calls only fcntl, setrlimit, setsid, and umask. It owns
    // primitive integers and does not acquire locks or allocate in the child.
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            for (resource, value) in [
                (libc::RLIMIT_AS, address_space),
                (libc::RLIMIT_FSIZE, file_limit),
                (libc::RLIMIT_CPU, cpu),
                (libc::RLIMIT_CORE, 0),
            ] {
                let limit = libc::rlimit {
                    rlim_cur: value as _,
                    rlim_max: value as _,
                };
                if libc::setrlimit(resource, &limit) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            libc::umask(0o077);
            Ok(())
        });
    }
}
pub(crate) fn nonblocking(fd: RawFd) -> Result<(), ScanError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}
/// Drop kills/reaps the parser even when an early error, cancellation, or malware
/// verdict skips the normal wait path. Process groups include parser children.
pub(crate) struct ChildGuard(pub Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        unsafe {
            libc::kill(-(self.0.id() as i32), libc::SIGKILL);
        };
        let _ = self.0.wait();
    }
}

pub(crate) fn read_available(
    reader: &mut impl Read,
    buffer: &mut Vec<u8>,
    maximum: usize,
) -> Result<bool, ScanError> {
    let mut chunk = [0u8; 65536];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return Ok(true),
            Ok(n) => {
                if n > maximum.saturating_sub(buffer.len()) {
                    return Err(ScanError::Policy(
                        "parser output exceeded its byte limit".into(),
                    ));
                }
                buffer.extend_from_slice(&chunk[..n]);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
}
pub(crate) fn run(
    binary: &Path,
    args: &[String],
    file: &File,
    ctx: &Context<'_>,
    maximum: usize,
) -> Result<(Vec<u8>, Vec<u8>), ScanError> {
    ctx.check()?;
    let mut cmd = Command::new(binary);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    prepare(
        &mut cmd,
        file.as_raw_fd(),
        512 * MIB,
        0,
        ctx.deadline
            .saturating_duration_since(Instant::now())
            .as_secs()
            .max(1),
    );
    let mut child = ChildGuard(cmd.spawn()?);
    let mut out = child.0.stdout.take().unwrap();
    let mut err = child.0.stderr.take().unwrap();
    nonblocking(out.as_raw_fd())?;
    nonblocking(err.as_raw_fd())?;
    let (mut output, mut errors) = (Vec::new(), Vec::new());
    let (mut out_done, mut err_done) = (false, false);
    loop {
        ctx.check()?;
        if !out_done {
            out_done = read_available(&mut out, &mut output, maximum)?;
        }
        if !err_done {
            err_done = read_available(&mut err, &mut errors, 64 * 1024)?;
        }
        if let Some(status) = child.0.try_wait()? {
            if out_done && err_done {
                if !status.success() {
                    return Err(ScanError::Policy(format!(
                        "media parser failed ({status}): {:?}",
                        String::from_utf8_lossy(&errors)
                            .chars()
                            .take(500)
                            .collect::<String>()
                    )));
                }
                return Ok((output, errors));
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
pub(crate) fn fd_path(file: &File) -> String {
    #[cfg(target_os = "linux")]
    {
        format!("/proc/self/fd/{}", file.as_raw_fd())
    }
    #[cfg(not(target_os = "linux"))]
    {
        format!("/dev/fd/{}", file.as_raw_fd())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn shell(
        script: &str,
        maximum: usize,
        ctx: &Context<'_>,
    ) -> Result<(Vec<u8>, Vec<u8>), ScanError> {
        let source = tempfile::tempfile().unwrap();
        run(
            Path::new("/bin/sh"),
            &["-c".into(), script.into()],
            &source,
            ctx,
            maximum,
        )
    }

    #[test]
    fn parser_both_pipes_are_bounded_and_regular_file_writes_are_denied() {
        let ctx = Context {
            deadline: Instant::now() + Duration::from_secs(3),
            cancelled: &|| false,
        };
        for script in ["printf 12345", "head -c 65537 /dev/zero >&2"] {
            assert!(matches!(shell(script, 4, &ctx), Err(ScanError::Policy(_))));
        }
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("forbidden");
        let script = format!("printf payload > '{}'", target.display());
        assert!(shell(&script, 1024, &ctx).is_err());
        assert!(std::fs::metadata(&target).is_ok_and(|metadata| metadata.len() == 0));
    }

    #[test]
    fn timeout_and_cancellation_reap_a_parser_after_it_closes_both_pipes() {
        for cancel in [false, true] {
            let started = Instant::now();
            let cancelled = || cancel && started.elapsed() >= Duration::from_millis(100);
            let ctx = Context {
                deadline: started + Duration::from_millis(200),
                cancelled: &cancelled,
            };
            let error = shell("exec 1>&- 2>&-; sleep 30", 1024, &ctx).unwrap_err();
            assert!(matches!(
                (&error, cancel),
                (ScanError::Cancelled, true) | (ScanError::Timeout, false)
            ));
            assert!(started.elapsed() < Duration::from_secs(2));
        }
    }
}
