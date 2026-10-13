//! Shared native-only harness for the independently produced upstream backup.
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use torrent_intake::{
    config::Config,
    persistence::{restore, state},
};

pub const PASSPHRASE: &str = "correct horse battery staple";
pub const BACKUP: &[u8] = include_bytes!("../fixtures/python-current-upstream-backup.tibak");
pub fn expected() -> Value {
    serde_json::from_str(include_str!(
        "../fixtures/python-current-upstream-backup.json"
    ))
    .unwrap()
}
pub fn receiver(root: &Path) -> Result<Config> {
    let mut config = Config::defaults();
    config.values["data_dir"] = json!(root.join("data"));
    config.values["database_url"] =
        json!(format!("sqlite:///{}", root.join("data/jobs.db").display()));
    state::private_directory(&config.path("data_dir"))?;
    config.persist()?;
    Ok(config)
}
pub fn stage(config: &Config) -> Result<()> {
    let root = config.path("data_dir");
    let input = root.join("upstream.tibak");
    fs::write(&input, BACKUP)?;
    let staging = root.join("stage");
    state::private_directory(&staging)?;
    restore::stage_restore(&input, &staging, &config.values, PASSPHRASE)?;
    Ok(())
}
pub fn restored_config(config: &Config) -> Result<Config> {
    let data: Value =
        serde_json::from_slice(&fs::read(config.path("data_dir").join("settings.json"))?)?;
    let mut restored = Config::defaults();
    restored.values = data["settings"].clone();
    restored.validate()?;
    Ok(restored)
}

pub struct Controller {
    child: Child,
    pub host: String,
    log: PathBuf,
}
impl Drop for Controller {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Controller {
    pub fn start(config: &Config, qbt_host: &str) -> Result<Self> {
        let reservation = TcpListener::bind(("127.0.0.1", 0))?;
        let port = reservation.local_addr()?.port();
        drop(reservation);
        let root = config.path("data_dir");
        let log = root.join("controller-test.log");
        let output = fs::File::create(&log)?;
        let child = Command::new(env!("CARGO_BIN_EXE_torrent-intake"))
            .args(["--host", "127.0.0.1", "--port", &port.to_string()])
            .env_clear()
            .env("TI_DATA_DIR", &root)
            .env("TI_QBT_HOST", qbt_host)
            .env("TI_CLAMD_SOCKET_PATH", root.join("absent-clamd.sock"))
            .current_dir(&root)
            .stdin(Stdio::null())
            .stdout(output.try_clone()?)
            .stderr(output)
            .spawn()?;
        let mut controller = Self {
            child,
            host: format!("http://127.0.0.1:{port}"),
            log,
        };
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = controller.child.try_wait()? {
                bail!(
                    "Controller exited {status}: {}",
                    fs::read_to_string(&controller.log)?
                );
            }
            if let Ok(status) = controller.get("/controller/status") {
                assert_eq!(status["paused"], true);
                assert_eq!(status["drained"], true);
                break;
            }
            if Instant::now() >= deadline {
                bail!(
                    "Controller did not start: {}",
                    fs::read_to_string(&controller.log)?
                );
            }
            thread::sleep(Duration::from_millis(50));
        }
        Ok(controller)
    }
    pub fn get(&self, path: &str) -> Result<Value> {
        reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(1))
            .build()?
            .get(format!("{}{path}", self.host))
            .send()?
            .error_for_status()?
            .json()
            .context("Expected JSON")
    }
}
