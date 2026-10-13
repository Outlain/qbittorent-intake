//! Run with `cargo test --test scanner_integration -- --ignored --nocapture`.
//! Requires libarchive and (for media cases) FFmpeg. Set TI_TEST_CLAMD_SOCKET to
//! route INSTREAM requests through a real daemon with the synthetic EICAR DB.
//! The proxy supplies a fresh *test* identity because custom .ndb databases do
//! not carry FreshClam timestamps. Production freshness checks stay enabled.
use std::{
    fs,
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use torrent_intake::scanning::{ScanSettings, Scanner, MIB};
const EICAR: &[u8] = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
struct Fixture {
    directory: tempfile::TempDir,
    settings: ScanSettings,
    stop: Arc<AtomicBool>,
    server: Option<thread::JoinHandle<()>>,
}
impl Fixture {
    fn new(media: bool) -> Self {
        let directory = tempfile::Builder::new()
            .prefix("ti-rust-")
            .tempdir_in("/tmp")
            .unwrap();
        let socket = directory.path().join("proxy.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = stop.clone();
        let backend = std::env::var_os("TI_TEST_CLAMD_SOCKET").map(PathBuf::from);
        let server = thread::spawn(move || {
            let mut threads = vec![];
            while !server_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let backend = backend.clone();
                        threads.push(thread::spawn(move || handle(stream, backend.as_deref())));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(e) => panic!("{e}"),
                }
            }
            for t in threads {
                t.join().unwrap();
            }
        });
        let settings = ScanSettings {
            socket_path: socket,
            data_dir: directory.path().join("data"),
            ffmpeg_binary: if media {
                "/usr/bin/ffmpeg"
            } else {
                "/usr/bin/true"
            }
            .into(),
            ffprobe_binary: if media {
                "/usr/bin/ffprobe"
            } else {
                "/usr/bin/true"
            }
            .into(),
            helper_executable: Some(env!("CARGO_BIN_EXE_torrent-intake").into()),
            max_file_bytes: 1024 * MIB,
            large_media_chunk_bytes: 512 * MIB,
            large_media_min_chunk_bytes: 64 * MIB,
            archive_limits: torrent_intake::scanning::ArchiveLimits {
                reserve_bytes: 0,
                timeout_seconds: 30,
                ..Default::default()
            },
            ..Default::default()
        };
        Self {
            directory,
            settings,
            stop,
            server: Some(server),
        }
    }
    fn write(&self, name: &str, data: &[u8]) -> PathBuf {
        let path = self.directory.path().join(name);
        fs::write(&path, data).unwrap();
        path
    }
    fn scanner(&self) -> Scanner {
        Scanner::new(self.settings.clone())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.server.take().unwrap().join().unwrap();
    }
}
fn handle(mut stream: UnixStream, backend: Option<&Path>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut command = Vec::new();
    loop {
        let mut b = [0];
        if stream.read_exact(&mut b).is_err() {
            return;
        }
        command.push(b[0]);
        if b[0] == 0 {
            break;
        }
    }
    if command == b"zVERSION\0" {
        let version = format!(
            "ClamAV 1.4.3/test/{}\0",
            chrono::Utc::now().format("%a %b %e %H:%M:%S %Y")
        );
        let _ = stream.write_all(version.as_bytes());
        return;
    }
    assert_eq!(command, b"zINSTREAM\0");
    let mut bytes = Vec::new();
    loop {
        let mut n = [0; 4];
        if stream.read_exact(&mut n).is_err() {
            return;
        }
        let n = u32::from_be_bytes(n) as usize;
        if n == 0 {
            break;
        }
        assert!(bytes.len() + n < 64 * MIB as usize);
        let start = bytes.len();
        bytes.resize(start + n, 0);
        if stream.read_exact(&mut bytes[start..]).is_err() {
            return;
        }
    }
    if bytes.starts_with(b"PK") || bytes.starts_with(b"Rar!") {
        let _ = stream.write_all(b"stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\0");
        return;
    }
    if let Some(backend) = backend {
        let mut target = UnixStream::connect(backend).expect("real ClamD must be running");
        target.write_all(b"zINSTREAM\0").unwrap();
        for chunk in bytes.chunks(MIB as usize) {
            target
                .write_all(&(chunk.len() as u32).to_be_bytes())
                .unwrap();
            target.write_all(chunk).unwrap();
        }
        target.write_all(&0u32.to_be_bytes()).unwrap();
        let mut b = [0; 4096];
        loop {
            let n = target.read(&mut b).unwrap();
            assert!(n > 0, "real daemon returned incomplete reply");
            let _ = stream.write_all(&b[..n]);
            if b[..n].contains(&0) {
                break;
            }
        }
        return;
    }
    // An exact standalone marker demonstrates that an opaque Matroska native
    // scan cannot replace the separate complete-attachment scan.
    let infected = bytes.windows(EICAR.len()).any(|b| b == EICAR)
        || bytes == b"Synthetic complete attachment marker"
        || bytes.starts_with(b"\x89PNG\r\n\x1a\n");
    let _ = stream.write_all(if infected {
        b"stream: Test.EICAR FOUND\0"
    } else {
        b"stream: OK\0"
    });
}
fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, bytes) in entries {
        writer
            .start_file(
                *name,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

// Stored RAR fixtures mirror tests/archive_fixtures.py. They deliberately expose
// the header flags and directory payload lengths needed for malicious cases.
fn rar4(entries: &[(&str, &[u8])], flags: u16, directory_size: Option<u32>) -> Vec<u8> {
    fn header(kind: u8, flags: u16, payload: &[u8]) -> Vec<u8> {
        let mut body = vec![kind];
        body.extend_from_slice(&flags.to_le_bytes());
        body.extend_from_slice(&((payload.len() + 7) as u16).to_le_bytes());
        body.extend_from_slice(payload);
        let mut output = (crc32fast::hash(&body) as u16).to_le_bytes().to_vec();
        output.extend(body);
        output
    }
    let mut output = b"Rar!\x1a\x07\0".to_vec();
    output.extend(header(0x73, flags, &[0; 6]));
    for (name, data) in entries {
        let directory = name.ends_with('/');
        let size = if directory {
            directory_size.unwrap_or(data.len() as u32)
        } else {
            data.len() as u32
        };
        let mut payload = (data.len() as u32).to_le_bytes().to_vec();
        payload.extend_from_slice(&size.to_le_bytes());
        payload.push(3);
        payload.extend_from_slice(&crc32fast::hash(data).to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&[20, 0x30]);
        payload.extend_from_slice(&(name.len() as u16).to_le_bytes());
        payload
            .extend_from_slice(&(if directory { 0o040755u32 } else { 0o100644u32 }).to_le_bytes());
        payload.extend_from_slice(name.as_bytes());
        output.extend(header(
            0x74,
            0x8000 | if directory { 0xe0 } else { 0 },
            &payload,
        ));
        output.extend_from_slice(data);
    }
    output.extend(header(0x7b, 0, &[]));
    output
}
fn rar5(entries: &[(&str, &[u8])], flags: u16, directory_size: Option<u32>) -> Vec<u8> {
    fn vint(mut value: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        while value > 127 {
            bytes.push((value as u8 & 127) | 128);
            value >>= 7;
        }
        bytes.push(value as u8);
        bytes
    }
    fn header(payload: &[u8]) -> Vec<u8> {
        let mut body = vint(payload.len() as u64);
        body.extend_from_slice(payload);
        let mut output = crc32fast::hash(&body).to_le_bytes().to_vec();
        output.extend(body);
        output
    }
    let mut output = b"Rar!\x1a\x07\x01\0".to_vec();
    let mut main = vec![1, 0];
    main.extend(vint(flags as u64));
    output.extend(header(&main));
    for (name, data) in entries {
        let directory = name.ends_with('/');
        let size = if directory {
            directory_size.map(u64::from).unwrap_or(data.len() as u64)
        } else {
            data.len() as u64
        };
        let mut payload = vec![2, 2];
        payload.extend(vint(data.len() as u64));
        payload.extend(vint(if directory { 1 } else { 4 }));
        payload.extend(vint(size));
        payload.extend(vint(if directory { 0o040755 } else { 0o100644 }));
        if !directory {
            payload.extend_from_slice(&crc32fast::hash(data).to_le_bytes());
        }
        payload.extend_from_slice(&[0, 1]);
        payload.extend(vint(name.len() as u64));
        payload.extend_from_slice(name.as_bytes());
        output.extend(header(&payload));
        output.extend_from_slice(data);
    }
    output.extend(header(&[5, 0, 0]));
    output
}
fn decode_uu(source: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for line in source
        .lines()
        .skip_while(|l| !l.starts_with("begin "))
        .skip(1)
    {
        if line == "end" {
            break;
        }
        let bytes = line.as_bytes();
        if bytes.is_empty() {
            continue;
        }
        let length = ((bytes[0].wrapping_sub(32)) & 63) as usize;
        let mut decoded = Vec::new();
        for c in bytes[1..].chunks(4) {
            if c.len() < 4 {
                break;
            }
            let a = (c[0].wrapping_sub(32)) & 63;
            let b = (c[1].wrapping_sub(32)) & 63;
            let d = (c[2].wrapping_sub(32)) & 63;
            let e = (c[3].wrapping_sub(32)) & 63;
            decoded.extend([(a << 2) | (b >> 4), (b << 4) | (d >> 2), (d << 6) | e]);
        }
        assert!(decoded.len() >= length);
        decoded.truncate(length);
        out.append(&mut decoded);
    }
    out
}

#[test]
#[ignore = "requires a service binary and Linux libarchive"]
fn archive_clean_infected_nested_and_limits() {
    let fixture = Fixture::new(false);
    let nested = zip(&[("deep/test.txt", EICAR)]);
    for (name, bytes, infected) in [
        ("clean.zip", zip(&[("a.txt", b"clean")]), false),
        ("infected.zip", zip(&[("a.txt", EICAR)]), true),
        ("nested.zip", zip(&[("inner.zip", &nested)]), true),
    ] {
        let path = fixture.write(name, &bytes);
        let before = fs::read(&path).unwrap();
        let result = fixture.scanner().scan_path(&path, None, &|| false).unwrap();
        assert_eq!(result.infected, infected);
        assert_eq!(result.scan_method, "archive_members");
        assert_eq!(fs::read(&path).unwrap(), before);
    }
    let path = fixture.write("too-many.zip", &zip(&[("a.txt", b"a"), ("b.txt", b"b")]));
    let mut settings = fixture.settings.clone();
    settings.archive_limits.files = 1;
    assert!(Scanner::new(settings)
        .scan_path(&path, None, &|| false)
        .is_err());
    let root = fixture.settings.data_dir.join("archive-scan");
    assert!(
        !fs::read_dir(root).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("scan-")),
        "scratch directories leaked"
    );
}
#[test]
#[ignore = "requires a service binary and Linux libarchive"]
fn archive_traversal_corruption_and_expansion_fail_closed() {
    let fixture = Fixture::new(false);
    let mut truncated = zip(&[("a.txt", b"a")]);
    truncated.truncate(truncated.len() - 10);
    for (name, bytes) in [
        ("traversal.zip", zip(&[("../escape", b"a")])),
        ("truncated.zip", truncated),
    ] {
        let path = fixture.write(name, &bytes);
        assert!(fixture.scanner().scan_path(&path, None, &|| false).is_err());
    }
    let path = fixture.write("expansion.zip", &zip(&[("big.txt", b"123456789")]));
    let mut settings = fixture.settings.clone();
    settings.archive_limits.expanded_bytes = 8;
    assert!(Scanner::new(settings)
        .scan_path(&path, None, &|| false)
        .is_err());
}

#[test]
#[ignore = "requires a service binary and Linux libarchive"]
fn rar_directory_payloads_corruption_end_markers_and_multivolume_are_held() {
    let fixture = Fixture::new(false);
    for make in [rar4, rar5] {
        let clean = make(
            &[
                ("Photos/", b""),
                ("Photos/a.jpg", b"unique-image-payload"),
                ("Empty/", b""),
            ],
            0,
            None,
        );
        let path = fixture.write("clean-archive", &clean);
        let result = fixture.scanner().scan_path(&path, None, &|| false).unwrap();
        assert!(result.clean && result.raw_output.contains("entries=3"));
        let corrupt_at = clean
            .windows(20)
            .position(|bytes| bytes == b"unique-image-payload")
            .unwrap();
        let mut corrupt = clean.clone();
        corrupt[corrupt_at] ^= 1;
        let mut trailing = clean.clone();
        trailing.extend_from_slice(b"unaccounted payload");
        let cases = [
            make(&[("Photos/", b"hidden payload")], 0, Some(0)),
            make(&[("Photos/", b"hidden payload")], 0, None),
            make(&[], 1, None),
            clean[..clean.len() - 7].to_vec(),
            trailing,
            corrupt,
        ];
        for (index, bytes) in cases.iter().enumerate() {
            let path = fixture.write(&format!("blocked-{index}"), bytes);
            assert!(
                fixture.scanner().scan_path(&path, None, &|| false).is_err(),
                "RAR case {index}"
            );
            assert_eq!(fs::read(&path).unwrap(), *bytes);
        }
    }
    let encrypted = fixture.write("encrypted.rar", &rar4(&[], 0x80, None));
    assert!(fixture
        .scanner()
        .scan_path(&encrypted, None, &|| false)
        .is_err());
}

#[test]
#[ignore = "requires a service binary and Linux libarchive"]
fn archive_nested_budgets_reserve_and_symlinks_fail_closed() {
    let fixture = Fixture::new(false);
    let inner = zip(&[("a.txt", &[b'x'; 1000])]);
    let path = fixture.write("nested.zip", &zip(&[("inner.zip", &inner)]));
    let mut settings = fixture.settings.clone();
    settings.archive_limits.depth = 1;
    assert!(Scanner::new(settings)
        .scan_path(&path, None, &|| false)
        .unwrap_err()
        .to_string()
        .contains("nesting"));
    let mut settings = fixture.settings.clone();
    settings.archive_limits.expanded_bytes = inner.len() as u64 + 500;
    assert!(Scanner::new(settings)
        .scan_path(&path, None, &|| false)
        .unwrap_err()
        .to_string()
        .contains("expanded-byte"));
    let mut settings = fixture.settings.clone();
    settings.archive_limits.reserve_bytes = 1 << 62;
    assert!(Scanner::new(settings)
        .scan_path(&path, None, &|| false)
        .unwrap_err()
        .to_string()
        .contains("reserve"));
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    writer
        .add_symlink(
            "link",
            "../../outside",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
    let symlink = fixture.write("symlink.zip", &writer.finish().unwrap().into_inner());
    assert!(fixture
        .scanner()
        .scan_path(&symlink, None, &|| false)
        .is_err());
    let root = fixture.settings.data_dir.join("archive-scan");
    assert!(!fs::read_dir(root).unwrap().any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("scan-")));
}
#[test]
#[ignore = "requires ffmpeg and ffprobe at /usr/bin"]
fn matroska_embedded_object_gets_a_complete_scan() {
    let fixture = Fixture::new(true);
    let attachment = fixture.write("marker.ttf", b"Synthetic complete attachment marker");
    let media = fixture.directory.path().join("media.mkv");
    let status = Command::new("/usr/bin/ffmpeg")
        .args([
            "-v",
            "error",
            "-nostdin",
            "-f",
            "lavfi",
            "-i",
            "color=size=32x32:rate=1",
            "-t",
            "1",
            "-threads",
            "1",
            "-c:v",
            "ffv1",
            "-attach",
        ])
        .arg(&attachment)
        .args([
            "-metadata:s:t",
            "filename=../../escape.ttf",
            "-metadata:s:t",
            "mimetype=application/x-truetype-font",
        ])
        .arg(&media)
        .status()
        .unwrap();
    assert!(status.success());
    let result = fixture
        .scanner()
        .scan_path(&media, None, &|| false)
        .unwrap();
    assert_eq!(result.scan_method, "clamd_native_with_attachments");
    if std::env::var_os("TI_TEST_CLAMD_SOCKET").is_none() {
        assert!(result.infected, "whole attachment marker was not scanned");
    }
    assert!(!fixture.directory.path().join("escape.ttf").exists());
}
#[test]
#[ignore = "requires TI_TEST_CLAMD_SOCKET with synthetic EICAR definitions"]
fn real_clamd_native_clean_and_eicar() {
    assert!(
        std::env::var_os("TI_TEST_CLAMD_SOCKET").is_some(),
        "set TI_TEST_CLAMD_SOCKET"
    );
    let fixture = Fixture::new(false);
    for (name, data, infected) in [
        ("clean.txt", &b"clean fixture"[..], false),
        ("eicar.txt", EICAR, true),
    ] {
        let path = fixture.write(name, data);
        let result = fixture.scanner().scan_path(&path, None, &|| false).unwrap();
        assert_eq!(result.infected, infected);
    }
}

#[test]
#[ignore = "requires Linux libarchive with RAR5 support"]
fn upstream_compressed_solid_and_encrypted_rar5_fixtures() {
    let fixture = Fixture::new(false);
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/libarchive");
    for (name, clean) in [
        ("test_read_format_rar5_compressed.rar.uu", true),
        ("test_read_format_rar5_solid.rar.uu", true),
        ("test_read_format_rar5_encrypted.rar.uu", false),
        ("test_read_format_rar5_encrypted_filenames.rar.uu", false),
    ] {
        let bytes = decode_uu(&fs::read_to_string(root.join(name)).unwrap());
        let path = fixture.write(name, &bytes);
        let result = fixture.scanner().scan_path(&path, None, &|| false);
        if clean {
            assert!(result.unwrap().clean, "{name}");
        } else {
            assert!(result.is_err(), "encrypted archive accepted: {name}");
        }
    }
}

fn tiny_media_settings(fixture: &Fixture) -> ScanSettings {
    ScanSettings {
        max_file_bytes: 512,
        large_media_chunk_bytes: 512,
        large_media_min_chunk_bytes: 128,
        large_media_overlap_bytes: 64,
        per_job_scan_workers: 4,
        ..fixture.settings.clone()
    }
}

#[test]
#[ignore = "requires ffmpeg and ffprobe at /usr/bin"]
fn mp4_chapter_packets_and_parallel_windows() {
    let fixture = Fixture::new(true);
    for infected in [false, true] {
        let title = if infected {
            std::str::from_utf8(EICAR).unwrap()
        } else {
            "Opening chapter"
        };
        let escaped = title
            .replace('\\', "\\\\")
            .replace('=', "\\=")
            .replace(';', "\\;")
            .replace('#', "\\#");
        let metadata = fixture.write(
            "chapters.txt",
            format!(
                ";FFMETADATA1\n[CHAPTER]\nTIMEBASE=1/1000\nSTART=0\nEND=1000\ntitle={escaped}\n"
            )
            .as_bytes(),
        );
        let media = fixture
            .directory
            .path()
            .join(format!("chapters-{infected}.mp4"));
        assert!(Command::new("/usr/bin/ffmpeg")
            .args([
                "-v",
                "error",
                "-nostdin",
                "-f",
                "lavfi",
                "-i",
                "color=size=32x32:rate=1",
                "-f",
                "ffmetadata",
                "-i"
            ])
            .arg(metadata)
            .args([
                "-map",
                "0:v:0",
                "-map_chapters",
                "1",
                "-t",
                "1",
                "-threads",
                "1",
                "-c:v",
                "mpeg4"
            ])
            .arg(&media)
            .status()
            .unwrap()
            .success());
        let result = Scanner::new(tiny_media_settings(&fixture))
            .scan_path(&media, None, &|| false)
            .unwrap();
        assert_eq!(result.infected, infected);
        assert_eq!(result.scan_method, "media_windows_and_attachments");
        if !infected {
            assert!(result.raw_output.contains("coverage=all-bytes"));
        }
    }
}

#[test]
#[ignore = "requires ffmpeg and ffprobe at /usr/bin"]
fn nameless_mp4_cover_is_extracted_and_scanned_whole() {
    let fixture = Fixture::new(true);
    let picture = fixture.directory.path().join("cover.png");
    assert!(Command::new("/usr/bin/ffmpeg")
        .args([
            "-v",
            "error",
            "-nostdin",
            "-f",
            "lavfi",
            "-i",
            "color=c=red:size=32x32",
            "-frames:v",
            "1",
            "-threads",
            "1"
        ])
        .arg(&picture)
        .status()
        .unwrap()
        .success());
    let media = fixture.directory.path().join("covered.mp4");
    assert!(Command::new("/usr/bin/ffmpeg")
        .args([
            "-v",
            "error",
            "-nostdin",
            "-f",
            "lavfi",
            "-i",
            "color=size=32x32:rate=1",
            "-i"
        ])
        .arg(&picture)
        .args([
            "-map",
            "0:v:0",
            "-map",
            "1:v:0",
            "-t",
            "1",
            "-threads",
            "1",
            "-c:v:0",
            "mpeg4",
            "-c:v:1",
            "copy",
            "-disposition:v:1",
            "attached_pic"
        ])
        .arg(&media)
        .status()
        .unwrap()
        .success());
    let result = Scanner::new(tiny_media_settings(&fixture))
        .scan_path(&media, None, &|| false)
        .unwrap();
    assert_eq!(result.scan_method, "media_windows_and_attachments");
    // The mock marker matches only an entire PNG stream, never an MP4 window.
    // The real daemon is expected to report this synthetic image clean.
    assert_eq!(
        result.infected,
        std::env::var_os("TI_TEST_CLAMD_SOCKET").is_none()
    );
}
