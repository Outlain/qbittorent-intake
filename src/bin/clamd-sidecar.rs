//! Minimal Rust replacement for the two Python ClamD supervisor scripts.
//! ClamAV itself remains the antivirus engine; this program only verifies
//! definitions, writes its bounded runtime override, and execs the daemon.
use anyhow::{bail, ensure, Context, Result};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::OpenOptionsExt, net::UnixStream, process::CommandExt},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant, SystemTime},
};
fn main() -> Result<()> {
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        let (daily, age) = definitions_ready()?;
        ensure!(command("PING")? == "PONG", "ClamD did not answer PONG");
        let version = command("VERSION")?;
        ensure!(version.starts_with("ClamAV "), "Invalid ClamD version");
        println!("healthy: {version}; daily={} age={age}s", daily.display());
        return Ok(());
    }
    let limit = std::env::var("CLAMD_MAX_SCAN_SIZE_MIB")
        .unwrap_or_else(|_| "2000".into())
        .trim()
        .parse::<u64>()
        .context("CLAMD_MAX_SCAN_SIZE_MIB must be a whole number")?;
    let base = fs::read_to_string("/etc/clamav/clamd.conf")?;
    let rendered = render_config(&base, limit)?;
    let directory = Path::new("/tmp/clamav");
    torrent_intake::persistence::state::private_directory(directory)?;
    let runtime = directory.join("clamd.runtime.conf");
    torrent_intake::persistence::state::write_private(&runtime, rendered.as_bytes())?;
    let log = directory.join("clamd.log");
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o640)
        .open(&log)?;
    let mut tail = Command::new("tail")
        .args(["-n", "0", "-F"])
        .arg(log)
        .spawn()?;
    let timeout = std::env::var("DEFINITIONS_WAIT_TIMEOUT")
        .unwrap_or_else(|_| "1800".into())
        .parse::<u64>()?
        .max(1);
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let mut last_error = String::new();
    while Instant::now() < deadline {
        match definitions_ready() {
            Ok((daily, age)) => {
                println!(
                    "definitions ready: daily={} age={age}s; MaxScanSize={limit}M",
                    daily.display()
                );
                let error = Command::new("clamd")
                    .arg(format!("--config-file={}", runtime.display()))
                    .exec();
                let _ = tail.kill();
                let _ = tail.wait();
                return Err(error.into());
            }
            Err(error) => last_error = error.to_string(),
        }
        std::thread::sleep(
            Duration::from_secs(2).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
    let _ = tail.kill();
    let _ = tail.wait();
    bail!("Definitions not ready within {timeout}s: {last_error}")
}
fn render_config(base: &str, limit: u64) -> Result<String> {
    ensure!(
        (1..=4000).contains(&limit),
        "CLAMD_MAX_SCAN_SIZE_MIB must be between 1 and 4000"
    );
    let mut count = 0;
    let lines = base
        .lines()
        .map(|line| {
            let mut words = line.split_whitespace();
            if words.next() == Some("MaxScanSize") {
                count += 1;
                let comment = line
                    .find('#')
                    .map(|i| format!(" {}", &line[i..]))
                    .unwrap_or_default();
                format!("MaxScanSize {limit}M{comment}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>();
    ensure!(
        count == 1,
        "Base ClamD configuration must contain exactly one active MaxScanSize directive"
    );
    Ok(lines.join("\n") + "\n")
}
fn definitions_ready() -> Result<(PathBuf, u64)> {
    let root = PathBuf::from(
        std::env::var("DEFINITIONS_DIR").unwrap_or_else(|_| "/var/lib/clamav".into()),
    );
    let candidate = |stem: &str| -> Result<PathBuf> {
        let mut choices = Vec::new();
        for suffix in ["cld", "cvd"] {
            let path = root.join(format!("{stem}.{suffix}"));
            if let Ok(metadata) = fs::symlink_metadata(&path) {
                if metadata.is_file() && metadata.len() > 0 && fs::File::open(&path).is_ok() {
                    choices.push((metadata.modified()?, path));
                }
            }
        }
        choices.sort_by_key(|(time, _)| *time);
        choices
            .pop()
            .map(|(_, path)| path)
            .with_context(|| format!("Missing readable {stem} database"))
    };
    candidate("main")?;
    let daily = candidate("daily")?;
    let age = SystemTime::now()
        .duration_since(fs::metadata(&daily)?.modified()?)
        .unwrap_or_default()
        .as_secs();
    let maximum = std::env::var("DEFINITIONS_MAX_AGE_SECONDS")
        .unwrap_or_else(|_| "172800".into())
        .parse::<u64>()?
        .max(300);
    ensure!(
        age <= maximum,
        "Daily definitions are stale: age={age}s max={maximum}s"
    );
    Ok((daily, age))
}
fn command(command: &str) -> Result<String> {
    let path = std::env::var("CLAMD_SOCKET").unwrap_or_else(|_| "/run/clamav/clamd.sock".into());
    let mut socket = UnixStream::connect(path)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    socket.write_all(format!("z{command}\0").as_bytes())?;
    let mut result = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = socket.read(&mut chunk)?;
        ensure!(n > 0, "ClamD closed health connection");
        if let Some(end) = chunk[..n].iter().position(|b| *b == 0) {
            result.extend_from_slice(&chunk[..end]);
            break;
        }
        result.extend_from_slice(&chunk[..n]);
        ensure!(result.len() <= 1024 * 1024, "ClamD health reply too large");
    }
    Ok(String::from_utf8(result)?)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn override_changes_only_expansion_limit() {
        let base = "MaxFileSize 2000M\nMaxScanSize 2000M # expansion\nStreamMaxLength 2000M\n";
        let output = render_config(base, 4000).unwrap();
        assert!(output.contains("MaxFileSize 2000M"));
        assert!(output.contains("MaxScanSize 4000M # expansion"));
        assert!(output.contains("StreamMaxLength 2000M"));
    }
    #[test]
    fn invalid_or_ambiguous_config_is_rejected() {
        assert!(render_config("MaxScanSize 2000M", 4001).is_err());
        assert!(render_config("MaxScanSize 1M\nMaxScanSize 2M", 2000).is_err());
        assert!(render_config("# MaxScanSize 1M", 2000).is_err());
    }
}
