//! Exercise the executable's real startup/HTTP/shutdown path and controller lock.
//! Everything lives in a temporary directory. No download or scan is started.
#![cfg(unix)]

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{
    fs,
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl Server {
    fn start(root: &Path, port: u16, log: &str) -> Result<Self> {
        let output = fs::File::create(root.join(log))?;
        let child = Command::new(env!("CARGO_BIN_EXE_torrent-intake"))
            .args(["--host", "127.0.0.1", "--port", &port.to_string()])
            .env_clear()
            .env("TI_DATA_DIR", root.join("data"))
            .env("TI_CLAMD_SOCKET_PATH", root.join("absent-scanner.sock"))
            .current_dir(root)
            .stdin(Stdio::null())
            .stdout(output.try_clone()?)
            .stderr(output)
            .spawn()?;
        Ok(Self(child))
    }
    fn wait_for_exit(&mut self) -> Result<std::process::ExitStatus> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.0.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                bail!("Server did not exit within ten seconds");
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
    fn terminate(&mut self) -> Result<()> {
        // SIGTERM is the container stop signal and must release the lock cleanly.
        let result = unsafe { libc::kill(self.0.id() as libc::pid_t, libc::SIGTERM) };
        anyhow::ensure!(result == 0, "Could not send SIGTERM");
        anyhow::ensure!(self.wait_for_exit()?.success(), "Shutdown failed");
        Ok(())
    }
}

fn wait_for_http(server: &mut Server, url: &str, log: &Path) -> Result<Value> {
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(1))
        .build()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = server.0.try_wait()? {
            bail!("Server exited {status}: {}", fs::read_to_string(log)?);
        }
        if let Ok(response) = client.get(url).send() {
            if response.status().is_success() {
                return response.json().context("Expected controller JSON");
            }
        }
        if Instant::now() >= deadline {
            bail!("Server did not become ready: {}", fs::read_to_string(log)?);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn executable_starts_paused_excludes_second_controller_and_releases_lock() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().canonicalize()?;
    let reservation = TcpListener::bind(("127.0.0.1", 0))?;
    let port = reservation.local_addr()?.port();
    drop(reservation);
    let url = format!("http://127.0.0.1:{port}/controller/status");

    let mut first = Server::start(&root, port, "first.log")?;
    let status = wait_for_http(&mut first, &url, &root.join("first.log"))?;
    assert_eq!(status["paused"], true);
    assert_eq!(status["drained"], true);

    let mut second = Server::start(&root, 0, "second.log")?;
    assert!(!second.wait_for_exit()?.success());
    assert!(fs::read_to_string(root.join("second.log"))?.contains("controller"));
    first.terminate()?;

    let mut replacement = Server::start(&root, port, "replacement.log")?;
    let status = wait_for_http(&mut replacement, &url, &root.join("replacement.log"))?;
    assert_eq!(status["paused"], true);
    replacement.terminate()?;
    Ok(())
}
