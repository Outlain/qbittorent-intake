//! ClamD's NUL-terminated protocol. Every byte is streamed from an already-open
//! descriptor; the daemon never resolves a torrent-controlled filesystem path.
use super::*;
use chrono::NaiveDateTime;
use std::{
    io::{Read, Write},
    os::unix::{fs::FileExt, net::UnixStream},
};
const MAX_REPLY: usize = 1024 * 1024;

pub fn parse_scanner_version(raw: &str) -> (Option<String>, Option<String>, Option<DateTime<Utc>>) {
    let raw = raw.trim_matches(['\0', ' ', '\n', '\r']);
    let Some(raw) = raw.strip_prefix("ClamAV ") else {
        return (None, None, None);
    };
    let mut parts = raw.splitn(3, '/');
    let valid_version = |v: &&str| !v.is_empty() && !v.chars().any(char::is_whitespace);
    let engine = parts.next().filter(valid_version).map(str::to_owned);
    let db = parts.next().filter(valid_version).map(str::to_owned);
    let date = parts.next().unwrap_or("").trim();
    let parsed = DateTime::parse_from_rfc2822(date)
        .map(|d| d.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            ["%a %b %e %H:%M:%S %Y", "%b %e %H:%M:%S %Y"]
                .iter()
                .find_map(|fmt| {
                    NaiveDateTime::parse_from_str(date, fmt)
                        .ok()
                        .map(|d| d.and_utc())
                })
        });
    (engine, db, parsed)
}
/// Limit/encryption/corruption heuristics mean incomplete inspection. They are
/// neither clean results nor positive malware detections.
pub fn parse_scan_response(raw: &str) -> Result<(bool, Option<String>), ScanError> {
    let response = raw.trim_matches(['\0', ' ', '\n', '\r']);
    let lower = response.to_lowercase();
    if [
        "heuristics.limits.exceeded",
        "size limit exceeded",
        "scan limit exceeded",
        "limits exceeded",
        "stream size limit exceeded",
    ]
    .iter()
    .any(|s| lower.contains(s))
    {
        let name = if lower.contains("instream size limit exceeded") {
            "streammaxlength".into()
        } else {
            lower
                .split_once("heuristics.limits.exceeded.")
                .map(|(_, s)| {
                    s.chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect()
                })
                .unwrap_or("unknown".into())
        };
        return Err(ScanError::Limit {
            name,
            message: response.chars().take(500).collect(),
        });
    }
    if response == "OK" || response.ends_with(": OK") {
        return Ok((false, None));
    }
    if let Some(found) = response.strip_suffix(" FOUND") {
        let threat = found.rsplit(": ").next().unwrap_or("unknown").trim();
        if [
            "heuristics.encrypted.",
            "heuristics.broken.",
            "broken.executable",
            "broken.media",
        ]
        .iter()
        .any(|p| threat.to_lowercase().starts_with(p))
        {
            return Err(ScanError::Policy(format!(
                "encrypted or malformed content requires review: {threat}"
            )));
        }
        return Ok((
            true,
            Some(if threat.is_empty() { "unknown" } else { threat }.into()),
        ));
    }
    Err(ScanError::Unavailable(format!(
        "unexpected or incomplete scanner response: {}",
        response.chars().take(500).collect::<String>()
    )))
}

fn connect(settings: &ScanSettings, ctx: &Context<'_>) -> Result<UnixStream, ScanError> {
    ctx.check()?;
    // Nonblocking connect prevents a full Unix-socket backlog from hanging a
    // worker indefinitely. SO_ERROR is checked after poll reports completion.
    use std::os::fd::{AsRawFd, FromRawFd};
    let bytes = std::os::unix::ffi::OsStrExt::as_bytes(settings.socket_path.as_os_str());
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= addr.sun_path.len() || bytes.contains(&0) {
        return Err(ScanError::Policy("invalid ClamD socket path".into()));
    }
    addr.sun_family = libc::AF_UNIX as _;
    #[cfg(target_os = "macos")]
    {
        addr.sun_len = std::mem::size_of_val(&addr) as u8;
    }
    for (to, from) in addr.sun_path.iter_mut().zip(bytes) {
        *to = *from as _;
    }
    // Parser children inherit only their explicitly supplied source descriptor.
    // Set CLOEXEC atomically on Linux: setting it later would race another
    // worker's concurrent fork/exec and leak this daemon connection to a parser.
    #[cfg(target_os = "linux")]
    let socket_type = libc::SOCK_STREAM | libc::SOCK_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let socket_type = libc::SOCK_STREAM;
    let fd = unsafe { libc::socket(libc::AF_UNIX, socket_type, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    #[cfg(not(target_os = "linux"))]
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    stream.set_nonblocking(true)?;
    let rc = unsafe {
        libc::connect(
            fd,
            (&addr as *const libc::sockaddr_un).cast(),
            std::mem::size_of_val(&addr) as _,
        )
    };
    if rc < 0 {
        let e = io::Error::last_os_error();
        if !matches!(
            e.raw_os_error(),
            Some(libc::EINPROGRESS) | Some(libc::EAGAIN)
        ) {
            return Err(e.into());
        }
        let local = ctx.bounded(settings.connect_timeout_seconds);
        loop {
            local.check()?;
            let mut pfd = libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            let n = unsafe { libc::poll(&mut pfd, 1, 100) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e.into());
            }
            if n > 0 {
                if let Some(e) = stream.take_error()? {
                    return Err(e.into());
                }
                break;
            }
        }
    }
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_millis(250)))?;
    stream.set_write_timeout(Some(Duration::from_millis(250)))?;
    Ok(stream)
}
fn retryable(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}
fn send(stream: &mut UnixStream, mut bytes: &[u8], ctx: &Context<'_>) -> Result<(), ScanError> {
    while !bytes.is_empty() {
        ctx.check()?;
        match stream.write(bytes) {
            Ok(0) => return Err(ScanError::Unavailable("ClamD closed its input".into())),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if retryable(&e) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn receive(stream: &mut UnixStream, ctx: &Context<'_>) -> Result<String, ScanError> {
    let mut output = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        ctx.check()?;
        match stream.read(&mut buffer) {
            Ok(0) => {
                return Err(ScanError::Unavailable(
                    "ClamD closed without a complete NUL-terminated reply".into(),
                ))
            }
            Ok(n) => {
                let terminator = buffer[..n].iter().position(|b| *b == 0);
                let bytes = &buffer[..terminator.unwrap_or(n)];
                if output.len() + bytes.len() > MAX_REPLY {
                    return Err(ScanError::Unavailable("oversized ClamD reply".into()));
                }
                output.extend_from_slice(bytes);
                if terminator.is_some() {
                    return Ok(String::from_utf8_lossy(&output).into_owned());
                }
            }
            Err(e) if retryable(&e) => {}
            Err(e) => return Err(e.into()),
        }
    }
}
pub(crate) fn version(settings: &ScanSettings) -> Result<String, ScanError> {
    let no_cancel = || false;
    let ctx = Context {
        deadline: Instant::now() + Duration::from_secs(settings.connect_timeout_seconds),
        cancelled: &no_cancel,
    };
    let mut stream = connect(settings, &ctx)?;
    send(&mut stream, b"zVERSION\0", &ctx)?;
    receive(&mut stream, &ctx)
}
struct Slot<'a>(&'a Scanner);
impl Drop for Slot<'_> {
    fn drop(&mut self) {
        let mut slots = self.0.slots.lock().unwrap_or_else(|e| e.into_inner());
        *slots -= 1;
        self.0.available.notify_one();
    }
}
impl Scanner {
    pub(crate) fn native(
        &self,
        file: &File,
        offset: u64,
        length: u64,
        ctx: &Context<'_>,
    ) -> Result<Verdict, ScanError> {
        self.native_stream(ctx, |stream| {
            // File windows remain bounded by 1 MiB per active request, never
            // by the window (or media) size. Tiny objects need only tiny buffers.
            let mut buffer = vec![0u8; length.min(MIB) as usize];
            let mut position = offset;
            let mut remaining = length;
            while remaining > 0 {
                ctx.check()?;
                let wanted = remaining.min(buffer.len() as u64) as usize;
                let count = file.read_at(&mut buffer[..wanted], position)?;
                if count == 0 {
                    return Err(ScanError::Changed(
                        "file became shorter while streaming".into(),
                    ));
                }
                send_chunk(stream, &buffer[..count], ctx)?;
                position += count as u64;
                remaining -= count as u64;
            }
            Ok(())
        })
    }

    /// Extracted attachments already occupy a bounded immutable byte vector.
    /// Stream it directly: a temporary file would duplicate those same bytes on
    /// disk and require another read buffer without adding inspection coverage.
    pub(crate) fn native_bytes(
        &self,
        bytes: &[u8],
        ctx: &Context<'_>,
    ) -> Result<Verdict, ScanError> {
        self.native_stream(ctx, |stream| {
            for chunk in bytes.chunks(MIB as usize) {
                send_chunk(stream, chunk, ctx)?;
            }
            Ok(())
        })
    }

    fn native_stream(
        &self,
        ctx: &Context<'_>,
        write_payload: impl FnOnce(&mut UnixStream) -> Result<(), ScanError>,
    ) -> Result<Verdict, ScanError> {
        let result = self.native_request(ctx, write_payload);
        if matches!(
            result,
            Err(ScanError::Io(_) | ScanError::Unavailable(_) | ScanError::Timeout)
        ) {
            *self.cached_health.lock().unwrap_or_else(|e| e.into_inner()) = None;
        }
        result
    }
    fn native_request(
        &self,
        ctx: &Context<'_>,
        write_payload: impl FnOnce(&mut UnixStream) -> Result<(), ScanError>,
    ) -> Result<Verdict, ScanError> {
        let mut slots = self
            .slots
            .lock()
            .map_err(|_| ScanError::Unavailable("scan capacity lock poisoned".into()))?;
        while *slots >= self.settings.max_inflight_requests {
            ctx.check()?;
            slots = self
                .available
                .wait_timeout(slots, Duration::from_millis(200))
                .map_err(|_| ScanError::Unavailable("scan capacity lock poisoned".into()))?
                .0;
        }
        *slots += 1;
        drop(slots);
        let _slot = Slot(self);
        let mut stream = connect(&self.settings, ctx)?;
        send(&mut stream, b"zINSTREAM\0", ctx)?;
        write_payload(&mut stream)?;
        send(&mut stream, &0u32.to_be_bytes(), ctx)?;
        let output = receive(&mut stream, ctx)?;
        let (infected, threat) = parse_scan_response(&output)?;
        Ok(Verdict {
            infected,
            threat,
            output,
        })
    }
}
fn send_chunk(stream: &mut UnixStream, bytes: &[u8], ctx: &Context<'_>) -> Result<(), ScanError> {
    send(stream, &(bytes.len() as u32).to_be_bytes(), ctx)?;
    send(stream, bytes, ctx)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ambiguous_verdicts_never_pass() {
        for s in [
            "",
            "stream: unknown",
            "stream: ERROR",
            "stream: Heuristics.Encrypted.Zip FOUND",
            "stream: Broken.Media FOUND",
        ] {
            assert!(parse_scan_response(s).is_err());
        }
    }
    #[test]
    fn detects_limits_before_found() {
        assert!(
            matches!(parse_scan_response("stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND"),Err(ScanError::Limit{name,..})if name=="maxscansize")
        );
        assert_eq!(
            parse_scan_response("stream: Eicar-Test-Signature FOUND").unwrap(),
            (true, Some("Eicar-Test-Signature".into()))
        );
    }
    #[test]
    fn parses_both_clamav_date_formats() {
        assert!(
            parse_scanner_version("ClamAV 1.4.3/27790/Mon Oct 12 12:20:30 2026")
                .2
                .is_some()
        );
        assert!(
            parse_scanner_version("ClamAV 1.4.3/27790/Mon, 12 Oct 2026 12:20:30 +0000")
                .2
                .is_some()
        );
        assert!(parse_scanner_version("broken").2.is_none());
    }
    #[test]
    fn eof_is_not_reply_termination() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        b.write_all(b"stream: OK").unwrap();
        drop(b);
        let ctx = Context {
            deadline: Instant::now() + Duration::from_secs(1),
            cancelled: &|| false,
        };
        assert!(receive(&mut a, &ctx).is_err());
    }
    #[test]
    fn replacement_changes_identity() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("file");
        std::fs::write(&p, b"old").unwrap();
        let f = File::open(&p).unwrap();
        let id = FileIdentity::read(&p).unwrap();
        let q = d.path().join("other");
        std::fs::write(&q, b"old").unwrap();
        std::fs::rename(&q, &p).unwrap();
        assert!(id.verify(&f, &p).is_err());
    }

    #[test]
    fn daemon_socket_is_not_inherited_by_parser_children() {
        use std::os::{fd::AsRawFd, unix::net::UnixListener};
        let directory = tempfile::Builder::new()
            .prefix("ti-fd-")
            .tempdir_in("/tmp")
            .unwrap();
        let path = directory.path().join("clamd.sock");
        let _listener = UnixListener::bind(&path).unwrap();
        let settings = ScanSettings {
            socket_path: path,
            ..Default::default()
        };
        let ctx = Context {
            deadline: Instant::now() + Duration::from_secs(3),
            cancelled: &|| false,
        };
        let socket = connect(&settings, &ctx).unwrap();
        let flags = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }

    #[test]
    fn only_explicit_size_limits_authorize_fallback_or_subdivision() {
        for (limit, fallback, subdivide) in [
            ("MaxFileSize", true, true),
            ("MaxScanSize", true, false),
            ("MaxRecursion", false, false),
            ("MaxFiles", false, false),
            ("PCREMatchLimit", false, false),
            ("NewUnknownLimit", false, false),
        ] {
            let error =
                parse_scan_response(&format!("stream: Heuristics.Limits.Exceeded.{limit} FOUND"))
                    .unwrap_err();
            assert_eq!(error.can_fallback(), fallback, "{limit}");
            assert_eq!(error.can_subdivide(), subdivide, "{limit}");
        }
        let error = parse_scan_response("INSTREAM size limit exceeded. ERROR").unwrap_err();
        assert!(error.can_fallback() && error.can_subdivide());
    }

    #[test]
    fn native_protocol_streams_only_the_requested_range() {
        use std::os::unix::net::UnixListener;
        let directory = tempfile::Builder::new()
            .prefix("ti-test-")
            .tempdir_in("/tmp")
            .unwrap();
        let socket = directory.path().join("clamd.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut command = [0; 10];
            stream.read_exact(&mut command).unwrap();
            assert_eq!(&command, b"zINSTREAM\0");
            let mut payload = Vec::new();
            loop {
                let mut length = [0; 4];
                stream.read_exact(&mut length).unwrap();
                let length = u32::from_be_bytes(length) as usize;
                if length == 0 {
                    break;
                }
                let mut part = vec![0; length];
                stream.read_exact(&mut part).unwrap();
                payload.extend(part);
            }
            stream.write_all(b"stream: OK\0").unwrap();
            payload
        });
        let settings = ScanSettings {
            socket_path: socket,
            ..Default::default()
        };
        let scanner = Scanner::new(settings);
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"prefix selected suffix").unwrap();
        let ctx = Context {
            deadline: Instant::now() + Duration::from_secs(3),
            cancelled: &|| false,
        };
        assert!(!scanner.native(&file, 7, 8, &ctx).unwrap().infected);
        assert_eq!(server.join().unwrap(), b"selected");
    }

    #[test]
    fn cancellation_interrupts_a_silent_daemon_and_releases_capacity() {
        use std::os::unix::net::UnixListener;
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        let directory = tempfile::Builder::new()
            .prefix("ti-test-")
            .tempdir_in("/tmp")
            .unwrap();
        let socket = directory.path().join("clamd.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = stop.clone();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut command = [0; 14];
            stream.read_exact(&mut command).unwrap();
            server_stop.store(true, Ordering::Release);
            std::thread::sleep(Duration::from_millis(350));
        });
        let scanner = Scanner::new(ScanSettings {
            socket_path: socket,
            ..Default::default()
        });
        let file = tempfile::tempfile().unwrap();
        let cancelled = || stop.load(Ordering::Acquire);
        let ctx = Context {
            deadline: Instant::now() + Duration::from_secs(3),
            cancelled: &cancelled,
        };
        assert!(matches!(
            scanner.native(&file, 0, 0, &ctx),
            Err(ScanError::Cancelled)
        ));
        assert_eq!(*scanner.slots.lock().unwrap(), 0);
        server.join().unwrap();
    }

    #[test]
    fn stale_or_unverifiable_definitions_block_health() {
        use std::os::unix::net::UnixListener;
        let current = Utc::now().format("%a %b %e %H:%M:%S %Y");
        for version in [
            "ClamAV 1.4.3/1/Sat Jan  1 00:00:00 2000".into(),
            "ClamAV 1.4.3".into(),
            format!("ClamAV 1.4.3//{current}"),
            format!("ClamAV 1.4.3/ /{current}"),
            format!("ClamAV /valid/{current}"),
        ] {
            let directory = tempfile::Builder::new()
                .prefix("ti-health-")
                .tempdir_in("/tmp")
                .unwrap();
            let socket = directory.path().join("clamd.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut command = [0; 9];
                stream.read_exact(&mut command).unwrap();
                assert_eq!(&command, b"zVERSION\0");
                stream.write_all(version.as_bytes()).unwrap();
                stream.write_all(&[0]).unwrap();
            });
            let scanner = Scanner::new(ScanSettings {
                socket_path: socket,
                ffmpeg_binary: "/usr/bin/true".into(),
                ffprobe_binary: "/usr/bin/true".into(),
                ..Default::default()
            });
            let health = scanner.health();
            assert!(!health.can_scan);
            assert!(health.status == "stale" || health.status == "unavailable");
            server.join().unwrap();
        }
    }

    #[test]
    fn optional_empty_archive_paths_keep_default_storage() {
        let settings = ScanSettings::from_values(
            &serde_json::json!({"archive_scratch_dir":"","archive_scratch_mount_marker":""}),
        )
        .unwrap();
        assert!(settings.archive_scratch_dir.is_none());
        assert!(settings.archive_mount_marker.is_none());
        assert!(
            ScanSettings::from_values(&serde_json::json!({"scanner_max_file_mib":u64::MAX}))
                .is_err()
        );
    }

    #[test]
    fn extracted_bytes_use_identical_framing_and_never_retry_limits() {
        use std::os::unix::net::UnixListener;
        for reply in [
            "stream: OK\0",
            "stream: Test.EICAR FOUND\0",
            "stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\0",
        ] {
            let directory = tempfile::Builder::new()
                .prefix("ti-bytes-")
                .tempdir_in("/tmp")
                .unwrap();
            let socket = directory.path().join("clamd.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let payload: Vec<u8> = (0..MIB as usize + 257).map(|n| (n % 251) as u8).collect();
            let expected = payload.clone();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut command = [0; 10];
                stream.read_exact(&mut command).unwrap();
                assert_eq!(&command, b"zINSTREAM\0");
                let mut actual = Vec::new();
                let mut lengths = Vec::new();
                loop {
                    let mut header = [0; 4];
                    stream.read_exact(&mut header).unwrap();
                    let n = u32::from_be_bytes(header) as usize;
                    if n == 0 {
                        break;
                    }
                    lengths.push(n);
                    let start = actual.len();
                    actual.resize(start + n, 0);
                    stream.read_exact(&mut actual[start..]).unwrap();
                }
                assert_eq!(lengths, [MIB as usize, 257]);
                assert_eq!(actual, expected);
                stream.write_all(reply.as_bytes()).unwrap();
            });
            let scanner = Scanner::new(ScanSettings {
                socket_path: socket,
                ..Default::default()
            });
            let ctx = Context {
                deadline: Instant::now() + Duration::from_secs(3),
                cancelled: &|| false,
            };
            let result = scanner.native_bytes(&payload, &ctx);
            if reply.contains("Limits") {
                assert!(matches!(result, Err(ScanError::Limit { .. })));
            } else {
                assert_eq!(result.unwrap().infected, reply.contains("FOUND"));
            }
            assert_eq!(*scanner.slots.lock().unwrap(), 0);
            server.join().unwrap();
        }
    }

    /// Isolated transport microbenchmark: run this test alone in a fresh process
    /// with TI_TRANSPORT_BENCH=legacy or direct. The legacy branch deliberately
    /// reproduces the removed attachment tempfile path for a fair same-binary
    /// comparison. The receiver drains bytes without antivirus work or buffering.
    #[test]
    #[ignore = "manual transport benchmark; measures warm-cache mock ClamD, not engine throughput"]
    fn attachment_transport_benchmark() {
        use std::os::unix::net::UnixListener;
        let mode = std::env::var("TI_TRANSPORT_BENCH").expect("set legacy or direct");
        assert!(["legacy", "direct"].contains(&mode.as_str()));
        let directory = tempfile::Builder::new()
            .prefix("ti-bench-")
            .tempdir_in("/tmp")
            .unwrap();
        let socket = directory.path().join("clamd.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        const ITERATIONS: usize = 32;
        let server = std::thread::spawn(move || {
            let mut buffer = vec![0; MIB as usize];
            for _ in 0..ITERATIONS {
                let (mut stream, _) = listener.accept().unwrap();
                let mut command = [0; 10];
                stream.read_exact(&mut command).unwrap();
                assert_eq!(&command, b"zINSTREAM\0");
                let mut received = 0;
                loop {
                    let mut header = [0; 4];
                    stream.read_exact(&mut header).unwrap();
                    let count = u32::from_be_bytes(header) as usize;
                    if count == 0 {
                        break;
                    }
                    assert!(count <= buffer.len());
                    stream.read_exact(&mut buffer[..count]).unwrap();
                    received += count;
                }
                assert_eq!(received, 16 * MIB as usize);
                stream.write_all(b"stream: OK\0").unwrap();
            }
        });
        let scanner = Scanner::new(ScanSettings {
            socket_path: socket,
            ..Default::default()
        });
        let payload = vec![b'x'; 16 * MIB as usize];
        let ctx = Context {
            deadline: Instant::now() + Duration::from_secs(60),
            cancelled: &|| false,
        };
        let started = Instant::now();
        for _ in 0..ITERATIONS {
            let verdict = if mode == "legacy" {
                let mut file = tempfile::tempfile().unwrap();
                file.write_all(&payload).unwrap();
                file.flush().unwrap();
                scanner.native(&file, 0, payload.len() as u64, &ctx)
            } else {
                scanner.native_bytes(&payload, &ctx)
            }
            .unwrap();
            assert!(!verdict.infected);
        }
        let elapsed = started.elapsed().as_secs_f64();
        server.join().unwrap();
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) }, 0);
        let bytes = payload.len() * ITERATIONS;
        println!("transport={mode} payload_bytes={bytes} seconds={elapsed:.6} mib_per_second={:.2} maxrss_platform_units={} attachment_temp_write_bytes={} attachment_temp_read_bytes={}", bytes as f64 / MIB as f64 / elapsed, usage.ru_maxrss, if mode == "legacy" {bytes} else {0}, if mode == "legacy" {bytes} else {0});
    }
}
