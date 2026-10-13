//! Real qBittorrent transport/durability test, with no Python runtime or ClamD.
//!
//! Run explicitly inside the disposable, network-disabled validation container:
//! `cargo test --test qbt_integration -- --ignored --nocapture`.
//! The temporary profile bypasses authentication only for loopback, disables
//! peer discovery, and uses an unreachable loopback-only synthetic tracker.
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    fs::{self, File},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use torrent_intake::{
    config::Config,
    persistence::{parse_torrent, state, Database},
    workflow::{
        qbt::{magnet_hashes, tags, Qbt},
        Workflow,
    },
};

struct QbtProcess {
    child: Child,
    log: PathBuf,
}
impl Drop for QbtProcess {
    fn drop(&mut self) {
        // A failed assertion must not leave a daemon or open test profile behind.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl QbtProcess {
    fn start(root: &Path) -> Result<(Self, String, String)> {
        let profile = root.join("qbt-profile");
        let configuration = profile.join("qBittorrent/config");
        state::private_directory(&configuration)?;
        fs::write(
            configuration.join("qBittorrent.conf"),
            concat!(
                "[LegalNotice]\nAccepted=true\n",
                "[Preferences]\nWebUI\\LocalHostAuth=false\n",
                "WebUI\\Address=127.0.0.1\nWebUI\\HostHeaderValidation=false\n",
                "Connection\\UPnP=false\nConnection\\RandomPort=true\n",
                "Bittorrent\\DHT=false\nBittorrent\\PeX=false\nBittorrent\\LSD=false\n",
                "[BitTorrent]\nSession\\DHTEnabled=false\nSession\\PeXEnabled=false\n",
                "Session\\LSDEnabled=false\nSession\\Port=0\n"
            ),
        )?;
        let reservation = TcpListener::bind(("127.0.0.1", 0))?;
        let port = reservation.local_addr()?.port();
        drop(reservation);
        let log = root.join("qbittorrent.log");
        let output = File::create(&log)?;
        let child = Command::new("qbittorrent-nox")
            .arg(format!("--profile={}", profile.display()))
            .arg(format!("--webui-port={port}"))
            .stdin(Stdio::null())
            .stdout(Stdio::from(output.try_clone()?))
            .stderr(Stdio::from(output))
            .spawn()
            .context("Install qbittorrent-nox in the disposable test image")?;
        let mut daemon = Self { child, log };
        let host = format!("http://127.0.0.1:{port}");
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(1))
            .build()?;
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = daemon.child.try_wait()? {
                bail!(
                    "qBittorrent exited ({status}): {}",
                    fs::read_to_string(&daemon.log)?
                );
            }
            if let Ok(response) = client.get(format!("{host}/api/v2/app/version")).send() {
                if response.status().is_success() {
                    return Ok((daemon, host, response.text()?.trim().to_owned()));
                }
            }
            if Instant::now() >= deadline {
                bail!(
                    "qBittorrent did not start: {}",
                    fs::read_to_string(&daemon.log)?
                );
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

/// This tiny encoder only constructs synthetic test inputs; production torrent
/// decoding remains bounded and independent in persistence::metainfo.
enum Bencode {
    Bytes(Vec<u8>),
    Integer(u64),
    List(Vec<Self>),
    Dictionary(BTreeMap<Vec<u8>, Self>),
}
impl Bencode {
    fn bytes(value: impl AsRef<[u8]>) -> Self {
        Self::Bytes(value.as_ref().to_vec())
    }
    fn dictionary(entries: impl IntoIterator<Item = (&'static str, Self)>) -> Self {
        Self::Dictionary(
            entries
                .into_iter()
                .map(|(key, value)| (key.as_bytes().to_vec(), value))
                .collect(),
        )
    }
    fn encode(&self, output: &mut Vec<u8>) {
        match self {
            Self::Bytes(bytes) => {
                output.extend(bytes.len().to_string().bytes());
                output.push(b':');
                output.extend(bytes);
            }
            Self::Integer(number) => {
                output.push(b'i');
                output.extend(number.to_string().bytes());
                output.push(b'e');
            }
            Self::List(items) => {
                output.push(b'l');
                for item in items {
                    item.encode(output);
                }
                output.push(b'e');
            }
            Self::Dictionary(entries) => {
                output.push(b'd');
                for (key, value) in entries {
                    Self::Bytes(key.clone()).encode(output);
                    value.encode(output);
                }
                output.push(b'e');
            }
        }
    }
}
fn torrent_file(kind: &str) -> Vec<u8> {
    let name = format!("synthetic-{kind}.txt");
    let content = b"test data"; // Payload is deliberately never supplied or downloaded.
    let mut info = BTreeMap::from([
        (b"name".to_vec(), Bencode::bytes(&name)),
        (b"piece length".to_vec(), Bencode::Integer(16384)),
        (b"private".to_vec(), Bencode::Integer(1)),
    ]);
    if kind != "v2" {
        info.insert(b"length".to_vec(), Bencode::Integer(content.len() as u64));
        info.insert(b"pieces".to_vec(), Bencode::bytes(Sha1::digest(content)));
    }
    if kind != "v1" {
        let leaf = Bencode::dictionary([
            ("length", Bencode::Integer(content.len() as u64)),
            ("pieces root", Bencode::bytes(Sha256::digest(content))),
        ]);
        let branch = Bencode::dictionary([("", leaf)]);
        info.insert(
            b"file tree".to_vec(),
            Bencode::Dictionary(BTreeMap::from([(name.into_bytes(), branch)])),
        );
        info.insert(b"meta version".to_vec(), Bencode::Integer(2));
    }
    let tracker = b"http://127.0.0.1:9/private-synthetic-passkey/announce";
    let metadata = Bencode::dictionary([
        ("announce", Bencode::bytes(tracker)),
        (
            "announce-list",
            Bencode::List(vec![Bencode::List(vec![Bencode::bytes(tracker)])]),
        ),
        ("info", Bencode::Dictionary(info)),
    ]);
    let mut bytes = Vec::new();
    metadata.encode(&mut bytes);
    bytes
}
fn job_id(job: &Value) -> &str {
    job["id"].as_str().expect("job id")
}
fn resolve_job(workflow: &Workflow, database: &Database, id: &str) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let job = database.get_job(id)?.context("job disappeared")?;
        if job["qbt_hash"]
            .as_str()
            .is_some_and(|hash| !hash.is_empty())
        {
            return Ok(job);
        }
        if job["state"] == "error" {
            bail!("Submission entered error: {}", job["last_error"]);
        }
        if Instant::now() >= deadline {
            bail!("qBittorrent did not resolve job hash: {job}");
        }
        workflow.tick()?;
        thread::sleep(Duration::from_millis(100));
    }
}
fn wait_paused(qbt: &Qbt, hash: &str) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let torrent = qbt
            .torrent(hash)?
            .context("torrent disappeared while pausing")?;
        let state = torrent["state"].as_str().unwrap_or("").to_ascii_lowercase();
        if state.contains("paused") || state.contains("stopped") {
            return Ok(torrent);
        }
        if Instant::now() >= deadline {
            bail!("qBittorrent did not pause: {state}");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[test]
#[ignore = "requires qbittorrent-nox inside a disposable --network none container"]
fn real_qbittorrent_accepts_original_v1_v2_hybrid_metadata() -> Result<()> {
    let temporary = tempfile::Builder::new()
        .prefix("ti-rust-qbt-")
        .tempdir_in("/tmp")?;
    let root = temporary.path().canonicalize()?;
    let (_daemon, host, version) = QbtProcess::start(&root)?;
    let mut config = Config::defaults();
    for (setting, directory) in [
        ("data_dir", "app-data"),
        ("local_staging_root", "staging"),
        ("nas_staging_root", "nas-staging"),
        ("final_parent_prefix", "media"),
        ("event_dir", "events"),
        ("quarantine_root", "quarantine"),
    ] {
        let path = root.join(directory);
        state::private_directory(&path)?;
        config.values[setting] = json!(path);
    }
    config.values["database_url"] = json!(format!(
        "sqlite:///{}",
        root.join("app-data/jobs.db").display()
    ));
    config.values["qbt_host"] = json!(host);
    config.values["qbt_username"] = json!("fixture-only");
    config.values["qbt_password"] = json!("fixture-only-loopback-auth-bypass");
    config.values["qbt_request_timeout_seconds"] = json!(3);
    config.values["archive_enabled"] = json!(false);
    config.values["local_free_space_buffer_gib"] = json!(0);
    config.validate()?;
    let _controller = state::ControllerLock::acquire(&config.path("data_dir"))?;
    let database = Database::open(config.database_path()?)?;
    let workflow = Workflow::new(config.clone(), database.clone())?;
    let qbt = Qbt::new(config.clone())?;
    let destination = config.path("final_parent_prefix").join("Media");
    let options = json!({"final_parent":destination,"final_category":"Media","staging_preference":"local","custom_tags":["Review"]});
    let mut tracked = Vec::new();
    for kind in ["v1", "v2", "hybrid"] {
        let bytes = torrent_file(kind);
        let parsed = parse_torrent(&bytes)?;
        let response = workflow.submit(
            options.clone(),
            Some((format!("{kind}.torrent"), bytes.clone())),
        )?;
        assert!(response.get("torrent_file_data").is_none());
        let job = resolve_job(&workflow, &database, job_id(&response))?;
        let hash = job["qbt_hash"]
            .as_str()
            .context("saved qBittorrent hash missing")?;
        qbt.pause(hash)?;
        let live = wait_paused(&qbt, hash)?;
        assert_eq!(
            Path::new(live["save_path"].as_str().unwrap()).canonicalize()?,
            config.path("local_staging_root")
        );
        let present = tags(&live);
        for expected in [
            config.string("managed_tag"),
            job["unique_tag"].as_str().unwrap().to_owned(),
            "Review".into(),
        ] {
            assert!(present.contains(&expected), "missing {expected}: {live}");
        }
        assert!(
            magnet_hashes(&parsed.magnet_uri)?
                .iter()
                .any(|expected| expected.eq_ignore_ascii_case(hash)),
            "saved hash is not a v1/v2 identity: {kind}: {hash}"
        );
        assert_eq!(database.torrent_data(job_id(&job))?.unwrap(), bytes);
        let trackers = qbt.json("torrents/trackers", &[("hash", hash.to_owned())])?;
        assert!(
            trackers
                .as_array()
                .unwrap()
                .iter()
                .any(|tracker| tracker["url"]
                    .as_str()
                    .is_some_and(|url| url.contains("private-synthetic-passkey"))),
            "original tracker missing: {trackers}"
        );
        assert!(
            workflow
                .submit(
                    options.clone(),
                    Some((format!("{kind}.torrent"), bytes.clone()))
                )
                .is_err(),
            "duplicate .torrent accepted"
        );
        let mut magnet_options = options.clone();
        magnet_options["magnet_uri"] = json!(parsed.magnet_uri);
        assert!(
            workflow.submit(magnet_options, None).is_err(),
            "duplicate magnet accepted"
        );

        // Editing a future destination changes the plan, never the live torrent.
        let edited = config
            .path("final_parent_prefix")
            .join(format!("Edited-{kind}"));
        let edit = json!({"final_parent":edited,"expected_final_parent":destination});
        let updated = workflow.action(job_id(&job), "final-destination", edit.clone())?;
        assert_eq!(updated["final_parent"], json!(edited));
        assert!(
            workflow
                .action(job_id(&job), "final-destination", edit)
                .is_err(),
            "stale destination editor accepted"
        );
        let after_edit = qbt.torrent(hash)?.unwrap();
        for key in ["save_path", "category", "tags"] {
            assert_eq!(after_edit[key], live[key], "editing changed live {key}");
        }
        tracked.push((job_id(&job).to_owned(), hash.to_owned(), live));
    }
    assert_eq!(database.list_jobs()?.len(), 3);
    assert_eq!(qbt.list()?.len(), 3);

    // Tracking-only deletion must never call qBittorrent's delete endpoint,
    // including for terminal rows whose torrent continues to exist for seeding.
    let sentinel = config
        .path("local_staging_root")
        .join("tracking-delete-must-preserve.txt");
    fs::write(&sentinel, b"preserve payload ownership")?;
    for (id, hash, original) in tracked {
        database.update_job(&id, &json!({"state":"done","is_terminal":true}))?;
        let result = workflow.action(&id, "delete", json!({}))?;
        assert_eq!(result["deleted"], true);
        assert!(database.get_job(&id)?.is_none());
        let retained = qbt
            .torrent(&hash)?
            .context("tracking deletion removed real torrent")?;
        for key in ["save_path", "category", "tags"] {
            assert_eq!(retained[key], original[key]);
        }
    }
    assert!(database.list_jobs()?.is_empty());
    assert_eq!(qbt.list()?.len(), 3);
    assert_eq!(fs::read(sentinel)?, b"preserve payload ownership");
    workflow.shutdown();
    println!("PASS real qBittorrent {version}: v1/v2/hybrid bytes, tracker preservation, hashes, tags, staging, upload/magnet duplicates, destination edits, tracking-only terminal deletion");
    Ok(())
}

#[path = "support/persistence_fixture.rs"]
mod restore_fixture;

#[test]
#[ignore = "requires qbittorrent-nox inside a disposable --network none container"]
fn real_qbittorrent_and_payloads_survive_upstream_restore_and_paused_restart() -> Result<()> {
    use base64::Engine;
    let temporary = tempfile::Builder::new()
        .prefix("ti-restore-qbt-")
        .tempdir_in("/tmp")?;
    let root = temporary.path().canonicalize()?;
    let (_daemon, host, version) = QbtProcess::start(&root)?;
    let receiver = restore_fixture::receiver(&root)?;
    let expected = restore_fixture::expected();
    let mut transport = Config::defaults();
    transport.values["qbt_host"] = json!(host);
    transport.values["qbt_request_timeout_seconds"] = json!(3);
    let qbt = Qbt::new(transport)?;
    let staging = root.join("payloads");
    state::private_directory(&staging)?;
    let mut retained = Vec::new();
    for job in expected["tables"]["jobs"].as_array().unwrap() {
        let id = job["id"].as_str().unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(expected["torrent_data"][id].as_str().unwrap())?;
        let parsed = parse_torrent(&bytes)?;
        let hash = job["qbt_hash"].as_str().unwrap();
        qbt.add(
            &parsed.magnet_uri,
            Some(bytes),
            job["torrent_file_name"].as_str().unwrap(),
            staging.to_str().unwrap(),
            &["intake".into(), job["unique_tag"].as_str().unwrap().into()],
            "intake",
        )?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while qbt.torrent(hash)?.is_none() {
            anyhow::ensure!(
                Instant::now() < deadline,
                "qBittorrent did not expose expected hash {hash} for {id}; live torrents: {}",
                json!(qbt.list()?)
            );
            thread::sleep(Duration::from_millis(50));
        }
        qbt.pause(hash)?;
        let original = wait_paused(&qbt, hash)?;
        // A payload file belonging to each live torrent must survive unchanged.
        let content = PathBuf::from(
            original["content_path"]
                .as_str()
                .context("missing live content path")?,
        );
        let payload = if content.is_dir() {
            content.join(parsed.name)
        } else {
            content.clone()
        };
        fs::create_dir_all(payload.parent().unwrap())?;
        fs::write(&payload, b"test data")?;
        qbt.post("torrents/recheck", &[("hashes", hash.to_owned())])?;
        let deadline = Instant::now() + Duration::from_secs(15);
        let original = loop {
            let live = qbt
                .torrent(hash)?
                .context("torrent disappeared during recheck")?;
            let state = live["state"].as_str().unwrap_or("").to_ascii_lowercase();
            if live["progress"].as_f64() == Some(1.0)
                && (state.contains("paused") || state.contains("stopped"))
            {
                break live;
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "synthetic payload did not recheck complete: {live}"
            );
            thread::sleep(Duration::from_millis(100));
        };
        retained.push((id.to_owned(), hash.to_owned(), original, payload));
    }
    let unrelated = staging.join("unrelated-payload.bin");
    fs::write(&unrelated, b"unrelated data must survive")?;
    assert_eq!(qbt.list()?.len(), 3);

    // The actual executable installs the untouched Python-produced archive.
    restore_fixture::stage(&receiver)?;
    let controller = restore_fixture::Controller::start(&receiver, &host)?;
    for _ in 0..4 {
        assert_eq!(controller.get("/controller/status")?["paused"], true);
        controller.get("/jobs")?;
        thread::sleep(Duration::from_millis(550));
    }
    for (_, hash, original, payload) in &retained {
        let live = qbt
            .torrent(hash)?
            .context("restore removed a real torrent")?;
        for key in ["save_path", "category", "tags"] {
            assert_eq!(live[key], original[key]);
        }
        assert_eq!(fs::read(payload)?, b"test data");
    }
    drop(controller);

    // Model remounting into a new installation: align only the scratch paths
    // with the live profile, preserving restored states, tags, hashes and the
    // delete policy. Ownership guards would now allow infected deletion after
    // an explicit resume; restarting while paused must still do nothing.
    let mut restored = restore_fixture::restored_config(&receiver)?;
    assert_eq!(restored.values["infected_action"], "delete");
    assert_eq!(restored.values["post_promotion_enabled"], true);
    restored.values["local_staging_root"] = json!(staging);
    restored.values["nas_staging_root"] = json!(root.join("nas-staging"));
    restored.values["final_parent_prefix"] = json!(root.join("media"));
    restored.persist()?;
    let database = Database::open(restored.database_path()?)?;
    for (id, _, original, _) in &retained {
        database.update_job(
            id,
            &json!({
                "staging_actual":"local", "staging_root_initial":staging,
                "staging_root_actual":staging, "content_path":original["content_path"],
                "final_parent":root.join("media/Media"),
            }),
        )?;
    }
    drop(database);
    let controller = restore_fixture::Controller::start(&receiver, &host)?;
    thread::sleep(Duration::from_millis(2200));
    assert_eq!(controller.get("/controller/status")?["paused"], true);
    assert_eq!(qbt.list()?.len(), 3);
    for (_, hash, original, payload) in &retained {
        let live = qbt
            .torrent(hash)?
            .context("paused restart removed a real torrent")?;
        for key in ["save_path", "category", "tags"] {
            assert_eq!(live[key], original[key]);
        }
        assert_eq!(fs::read(payload)?, b"test data");
    }
    assert_eq!(fs::read(unrelated)?, b"unrelated data must survive");
    let database = Database::open(restored.database_path()?)?;
    for job in expected["tables"]["jobs"].as_array().unwrap() {
        let saved = database.get_job(job["id"].as_str().unwrap())?.unwrap();
        assert_eq!(saved["state"], job["state"]);
        assert_eq!(saved["hook_status"], job["hook_status"]);
        assert_eq!(saved["hook_attempts"], job["hook_attempts"]);
    }
    println!("PASS real qBittorrent {version}: upstream Python restore and paused restart retain all torrents, tags, paths and payload bytes with queued infected deletion, promotion and hook work");
    Ok(())
}
