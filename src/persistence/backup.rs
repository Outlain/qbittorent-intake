//! `.tibak` wire compatibility with the Python application is intentional:
//! magic + 16-byte salt + 12-byte nonce + AES-256-GCM ciphertext + 16-byte tag.
//! Scrypt uses N=2^17, r=8, p=1; the complete header is authenticated as AAD.
use super::{db::column_names, paths::clean_absolute, state};
use aes::cipher::{BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use anyhow::{bail, Context, Result};
use ghash::universal_hash::UniversalHash;
use rand::RngCore;
use rusqlite::{
    backup::{Backup, StepResult},
    Connection, OpenFlags,
};
use scrypt::{scrypt, Params};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};
pub const MAGIC: &[u8] = b"TI-BACKUP-1\0";
pub const CHUNK: u64 = 1024 * 1024;
pub const MAX_DATABASE_BYTES: u64 = 512 * CHUNK;
pub const MAX_BACKUP_BYTES: u64 = MAX_DATABASE_BYTES + 4 * CHUNK;
pub const MEMBERS: [&str; 4] = [
    "deployment-notes.txt",
    "manifest.json",
    "settings.json",
    "torrent_intake.db",
];

pub fn sqlite_path(database_url: &str) -> Result<PathBuf> {
    let raw = database_url
        .strip_prefix("sqlite+pysqlite:///")
        .or_else(|| database_url.strip_prefix("sqlite:///"))
        .context("Only a file-backed SQLite database is supported by the Rust controller")?;
    if raw.is_empty() || raw == ":memory:" || raw.contains('?') || raw.contains('#') {
        bail!("SQLite URL must identify a file without query parameters");
    }
    Ok(PathBuf::from(raw))
}
pub fn database_path(settings: &Value) -> Result<PathBuf> {
    let path = sqlite_path(
        settings["database_url"]
            .as_str()
            .context("Missing database_url")?,
    )?;
    let root = clean_absolute(
        settings["data_dir"].as_str().context("Missing data_dir")?,
        "data directory",
    )?;
    state::reject_symlink(&path)?;
    if !path.is_absolute()
        || !clean_absolute(&path.to_string_lossy(), "database")?.starts_with(&root)
    {
        bail!("SQLite database must be a regular file inside TI_DATA_DIR");
    }
    if [
        "settings.json",
        "admin-token",
        "deployment-notes.txt",
        "controller.lock",
        "controller-paused.json",
        "restart-required",
        "last-restore.json",
    ]
    .iter()
    .any(|n| path.file_name().is_some_and(|f| f == *n))
    {
        bail!("Database filename conflicts with an application state file");
    }
    if path.exists() && !path.is_file() {
        bail!("The SQLite database is not a regular file");
    }
    Ok(path)
}
fn readonly(path: &Path) -> Result<Connection> {
    state::reject_symlink(path)?;
    let c = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    c.busy_timeout(Duration::from_secs(3))?;
    c.execute_batch("PRAGMA trusted_schema=OFF;")?;
    Ok(c)
}
pub fn database_size_bytes(settings: &Value) -> Result<u64> {
    let c = readonly(&database_path(settings)?)?;
    c.execute_batch("BEGIN")?;
    let pages: u64 = c.query_row("PRAGMA page_count", [], |r| r.get(0))?;
    let size: u64 = c.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    Ok(pages * size)
}
fn key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    if passphrase.chars().count() < 12 || passphrase.len() > 1024 {
        bail!("Use a backup passphrase of at least 12 characters and at most 1024 UTF-8 bytes");
    }
    let mut key = [0; 32];
    scrypt(
        passphrase.as_bytes(),
        salt,
        &Params::new(17, 8, 1, 32)?,
        &mut key,
    )?;
    Ok(key)
}
/// GCM combines AES in counter mode with GHASH authentication. Keeping these
/// two crate primitives explicit lets us process a large archive one MiB at a
/// time without changing the established Python AES-GCM file format.
struct GcmStream {
    counter: ctr::Ctr32BE<aes::Aes256>,
    authentication: ghash::GHash,
    tag_mask: aes::cipher::Block<aes::Aes256>,
    header_length: u64,
}
impl GcmStream {
    fn new(key: &[u8; 32], nonce: &[u8], header: &[u8]) -> Result<Self> {
        if nonce.len() != 12 {
            bail!("GCM requires a 12-byte nonce");
        }
        let aes = aes::Aes256::new_from_slice(key)?;
        let mut hash_key = aes::cipher::Block::<aes::Aes256>::default();
        aes.encrypt_block(&mut hash_key);
        let mut authentication = ghash::GHash::new(&hash_key);
        authentication.update_padded(header);
        // For a 96-bit nonce, J0 is nonce || 1. It masks the final tag;
        // encrypted payload starts with the next counter block, nonce || 2.
        let mut initial = aes::cipher::Block::<aes::Aes256>::default();
        initial[..12].copy_from_slice(nonce);
        initial[15] = 1;
        let mut tag_mask = initial;
        aes.encrypt_block(&mut tag_mask);
        initial[15] = 2;
        let counter = ctr::Ctr32BE::<aes::Aes256>::new(key.into(), &initial);
        Ok(Self {
            counter,
            authentication,
            tag_mask,
            header_length: header.len() as u64,
        })
    }
    fn authenticate(&mut self, ciphertext: &[u8]) {
        // Every non-final chunk MUST be a multiple of AES's 16-byte block.
        // transfer() reads full CHUNK-sized blocks, then exactly one tail.
        self.authentication.update_padded(ciphertext);
    }
    fn transform(&mut self, bytes: &mut [u8]) -> Result<()> {
        self.counter
            .try_apply_keystream(bytes)
            .map_err(|_| anyhow::anyhow!("AES counter limit exceeded"))
    }
    fn tag(mut self, payload_length: u64) -> [u8; 16] {
        let mut lengths = ghash::Block::default();
        lengths[..8].copy_from_slice(&(self.header_length * 8).to_be_bytes());
        lengths[8..].copy_from_slice(&(payload_length * 8).to_be_bytes());
        self.authentication.update(&[lengths]);
        let mut tag: [u8; 16] = self.authentication.finalize().into();
        for (byte, mask) in tag.iter_mut().zip(self.tag_mask) {
            *byte ^= mask;
        }
        tag
    }
}
fn open_archive(path: &Path, maximum: u64) -> Result<(File, u64)> {
    state::reject_symlink(path)?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum {
        bail!("Invalid or oversized backup file");
    }
    Ok((file, metadata.len()))
}
fn private_output(destination: &Path) -> Result<tempfile::NamedTempFile> {
    state::reject_symlink(destination)?;
    if destination.exists() {
        bail!("Backup output already exists");
    }
    let temporary = tempfile::NamedTempFile::new_in(
        destination
            .parent()
            .context("Backup output has no parent")?,
    )?;
    state::make_private(temporary.path())?;
    Ok(temporary)
}
fn transfer(
    input: &mut File,
    output: &mut File,
    gcm: &mut GcmStream,
    length: u64,
    decrypt: bool,
) -> Result<()> {
    let mut remaining = length;
    let mut buffer = vec![0u8; length.min(CHUNK) as usize];
    while remaining > 0 {
        let count = remaining.min(CHUNK) as usize;
        let chunk = &mut buffer[..count];
        input
            .read_exact(chunk)
            .context("Truncated backup archive")?;
        if decrypt {
            gcm.authenticate(chunk);
            gcm.transform(chunk)?;
        } else {
            gcm.transform(chunk)?;
            gcm.authenticate(chunk);
        }
        output.write_all(chunk)?;
        remaining -= count as u64;
    }
    Ok(())
}
fn publish_output(temporary: tempfile::NamedTempFile, destination: &Path) -> Result<()> {
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(destination)
        .map_err(|e| e.error)?;
    state::sync_directory(
        destination
            .parent()
            .context("Backup output has no parent")?,
    )
}
pub fn encrypt_archive(source: &Path, destination: &Path, passphrase: &str) -> Result<()> {
    let (mut input, length) = open_archive(source, MAX_BACKUP_BYTES)?;
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut header = MAGIC.to_vec();
    header.extend(salt);
    header.extend(nonce);
    let mut gcm = GcmStream::new(&key(passphrase, &salt)?, &nonce, &header)?;
    let mut output = private_output(destination)?;
    output.write_all(&header)?;
    transfer(&mut input, output.as_file_mut(), &mut gcm, length, false)?;
    if input.read(&mut [0])? != 0 {
        bail!("Backup changed while being encrypted");
    }
    output.write_all(&gcm.tag(length))?;
    publish_output(output, destination)
}
pub fn decrypt_archive(source: &Path, destination: &Path, passphrase: &str) -> Result<()> {
    let header_len = MAGIC.len() + 28;
    let (mut input, length) = open_archive(source, MAX_BACKUP_BYTES + header_len as u64 + 16)?;
    if length <= header_len as u64 + 16 {
        bail!("Invalid encrypted backup length");
    }
    let mut header = vec![0u8; header_len];
    input.read_exact(&mut header)?;
    if !header.starts_with(MAGIC) {
        bail!("Unsupported encrypted backup format");
    }
    let mut gcm = GcmStream::new(
        &key(passphrase, &header[MAGIC.len()..MAGIC.len() + 16])?,
        &header[header_len - 12..],
        &header,
    )?;
    let mut output = private_output(destination)?;
    let payload_length = length - header_len as u64 - 16;
    transfer(
        &mut input,
        output.as_file_mut(),
        &mut gcm,
        payload_length,
        true,
    )?;
    let mut supplied_tag = [0u8; 16];
    input.read_exact(&mut supplied_tag)?;
    if input.read(&mut [0])? != 0 || !bool::from(gcm.tag(payload_length).ct_eq(&supplied_tag)) {
        // NamedTempFile removes the private, unauthenticated plaintext on error.
        // The requested destination never becomes visible before verification.
        bail!("Backup authentication failed: incorrect passphrase or damaged backup");
    }
    publish_output(output, destination)
}
pub fn check_database(path: &Path) -> Result<()> {
    if fs::metadata(path)?.len() > MAX_DATABASE_BYTES {
        bail!("SQLite backup exceeds 512 MiB");
    }
    let c = readonly(path)?;
    let deadline = Instant::now() + Duration::from_secs(60);
    c.progress_handler(10_000, Some(move || Instant::now() > deadline))?;
    let checks = c
        .prepare("PRAGMA quick_check")?
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if checks != ["ok"] {
        bail!("SQLite backup failed its integrity check");
    }
    let schema = c
        .prepare("SELECT type,name,sql FROM sqlite_master")?
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let tables = schema
        .iter()
        .filter(|(kind, name, _)| kind == "table" && !name.starts_with("sqlite_"))
        .map(|(_, name, _)| name.as_str())
        .collect::<HashSet<_>>();
    if tables != HashSet::from(["jobs", "scan_runs", "scan_files", "scanner_control"]) {
        bail!("Backup does not contain the expected Torrent Intake database");
    }
    if schema.iter().any(|(kind, _, sql)| {
        !["table", "index"].contains(&kind.as_str())
            || sql
                .as_deref()
                .unwrap_or("")
                .to_uppercase()
                .contains("VIRTUAL TABLE")
    }) {
        bail!("Backup contains unsupported database objects");
    }
    for (table, required) in [
        (
            "jobs",
            &["id", "state", "qbt_hash", "unique_tag", "magnet_uri"][..],
        ),
        ("scan_runs", &["job_id", "root_path", "worker_id"][..]),
        (
            "scan_files",
            &["job_id", "relative_path", "status", "size_bytes"][..],
        ),
        ("scanner_control", &["id", "requested_slots"][..]),
    ] {
        let columns = column_names(&c, table)?;
        if !required.iter().all(|name| columns.contains(*name)) {
            bail!("Backup has an incompatible {table} table");
        }
    }
    if c.prepare("PRAGMA foreign_key_check")?
        .query([])?
        .next()?
        .is_some()
    {
        bail!("Backup has inconsistent database relationships");
    }
    Ok(())
}
pub fn snapshot_database(source: &Path, destination: &Path) -> Result<()> {
    state::reject_symlink(destination)?;
    if destination.exists() {
        bail!("Snapshot destination already exists");
    }
    let source = readonly(source)?;
    let mut target = Connection::open(destination)?;
    state::make_private(destination)?;
    let deadline = Instant::now() + Duration::from_secs(60);
    {
        let backup = Backup::new(&source, &mut target)?;
        loop {
            if Instant::now() > deadline || fs::metadata(destination)?.len() > MAX_DATABASE_BYTES {
                bail!("SQLite snapshot exceeded its time or size budget");
            }
            match backup.step(256)? {
                StepResult::Done => break,
                StepResult::Busy | StepResult::Locked => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                _ => {}
            }
        }
    }
    drop(target);
    check_database(destination)?;
    File::open(destination)?.sync_all()?;
    Ok(())
}
pub fn create_backup(settings: &Value, directory: &Path, passphrase: &str) -> Result<PathBuf> {
    let source = database_path(settings)?;
    let size = fs::metadata(&source)?.len();
    if size > MAX_DATABASE_BYTES {
        bail!("SQLite database exceeds portable backup size limit");
    }
    let journal = PathBuf::from(format!("{}-wal", source.display()));
    state::reject_symlink(&journal)?;
    let estimate = size + fs::metadata(journal).map(|m| m.len()).unwrap_or(0);
    if fs2::available_space(directory)? < estimate * 3 + 32 * CHUNK {
        bail!("Not enough free space for a backup");
    }
    snapshot_database(&source, &directory.join("torrent_intake.db"))?;
    state::write_json(
        &directory.join("settings.json"),
        &json!({"schema_version":1,"settings":settings}),
    )?;
    let notes_path = Path::new(settings["data_dir"].as_str().context("Missing data_dir")?)
        .join("deployment-notes.txt");
    let notes = match state::read_private(&notes_path, CHUNK as usize) {
        Ok(v) => v,
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            b"Save the actual Compose or Portainer stack here before migrating. Host mounts and sidecars are not visible to the application.\n".to_vec()
        }
        Err(e) => return Err(e),
    };
    state::write_private(&directory.join("deployment-notes.txt"), &notes)?;
    state::write_json(
        &directory.join("manifest.json"),
        &json!({
            "application": "torrent-intake",
            "backup_version": 1,
            "created_at": chrono::Utc::now().to_rfc3339(),
            "includes_secrets": true,
            "excludes": [
                "downloaded payload files",
                "qBittorrent state",
                "ClamAV definitions",
                "notifier state and events",
                "Docker images"
            ]
        }),
    )?;
    let archive = directory.join("snapshot.zip");
    let mut zip = ZipWriter::new(state::create_private(&archive)?);
    for name in MEMBERS {
        zip.start_file(
            name,
            SimpleFileOptions::default()
                .compression_method(CompressionMethod::Stored)
                .unix_permissions(0o600),
        )?;
        std::io::copy(&mut File::open(directory.join(name))?, &mut zip)?;
    }
    zip.finish()?.sync_all()?;
    let output = directory.join("torrent-intake.tibak");
    encrypt_archive(&archive, &output, passphrase)?;
    Ok(output)
}
pub fn unpack_backup(archive: &Path, directory: &Path) -> Result<Value> {
    let (mut input, length) = open_archive(archive, MAX_BACKUP_BYTES)?;
    check_zip_directory(&mut input, length)?;
    let mut zip = ZipArchive::new(input)?;
    if zip.len() != MEMBERS.len() {
        bail!("Backup has missing, duplicate, or unexpected paths");
    }
    let mut seen = HashSet::new();
    // Inspect the complete central directory before creating any output. A
    // malformed final entry must not leave earlier extracted files behind.
    for i in 0..zip.len() {
        let member = zip.by_index(i)?;
        let name = member.name().to_owned();
        if !MEMBERS.contains(&name.as_str()) || !seen.insert(name.clone()) {
            bail!("Backup has missing, duplicate, or unexpected paths");
        }
        let maximum = if name == "torrent_intake.db" {
            MAX_DATABASE_BYTES
        } else {
            CHUNK
        };
        let kind = member.unix_mode().unwrap_or(0) & 0o170000;
        if member.compression() != CompressionMethod::Stored
            || member.encrypted()
            || ![0, 0o100000].contains(&kind)
            || member.size() > maximum
            || member.compressed_size() != member.size()
        {
            bail!("Backup must contain bounded, uncompressed regular files");
        }
    }
    for i in 0..zip.len() {
        let mut member = zip.by_index(i)?;
        let name = member.name().to_owned();
        let maximum = if name == "torrent_intake.db" {
            MAX_DATABASE_BYTES
        } else {
            CHUNK
        };
        let mut output = state::create_private(&directory.join(name))?;
        let copied = std::io::copy(&mut (&mut member).take(maximum + 1), &mut output)?;
        if copied > maximum || copied != member.size() {
            bail!("Backup member exceeded declared size");
        }
        output.sync_all()?;
    }
    let manifest: Value = serde_json::from_slice(&state::read_private(
        &directory.join("manifest.json"),
        CHUNK as usize,
    )?)?;
    if manifest["application"] != "torrent-intake" || manifest["backup_version"] != 1 {
        bail!("Unsupported Torrent Intake backup version");
    }
    let payload: Value = serde_json::from_slice(&state::read_private(
        &directory.join("settings.json"),
        CHUNK as usize,
    )?)?;
    if payload["schema_version"] != 1 || !payload["settings"].is_object() {
        bail!("Unsupported settings format in backup");
    }
    check_database(&directory.join("torrent_intake.db"))?;
    Ok(payload["settings"].clone())
}
/// ZIP readers may hide duplicate central-directory names. Check the four raw
/// records before the ZIP library allocates its directory or deduplicates it.
/// Both applications emit ordinary ZIP: their <516-MiB, four-file archives
/// never require ZIP64 or multiple disks.
fn check_zip_directory(input: &mut File, length: u64) -> Result<()> {
    const END_SIZE: usize = 22;
    const MAX_COMMENT: usize = u16::MAX as usize;
    if length < END_SIZE as u64 {
        bail!("Truncated backup ZIP directory");
    }
    // Normal backups have no ZIP comment, so their preflight uses just this
    // stack buffer. Only a commented archive needs the bounded tail buffer.
    let mut end = [0u8; END_SIZE];
    input.seek(SeekFrom::End(-(END_SIZE as i64)))?;
    input.read_exact(&mut end)?;
    let mut end_position = length - END_SIZE as u64;
    if &end[..4] != b"PK\x05\x06" || end[20..22] != [0, 0] {
        let count = length.min((END_SIZE + MAX_COMMENT) as u64) as usize;
        let mut tail = vec![0; count];
        input.seek(SeekFrom::Start(length - count as u64))?;
        input.read_exact(&mut tail)?;
        let offset = (0..=count - END_SIZE)
            .rev()
            .find(|&position| {
                &tail[position..position + 4] == b"PK\x05\x06"
                    && position
                        + END_SIZE
                        + u16::from_le_bytes([tail[position + 20], tail[position + 21]]) as usize
                        == count
            })
            .context("Invalid backup ZIP end record")?;
        end.copy_from_slice(&tail[offset..offset + END_SIZE]);
        end_position = length - count as u64 + offset as u64;
    }
    let u16_at = |offset| u16::from_le_bytes([end[offset], end[offset + 1]]);
    if u16_at(4) != 0 || u16_at(6) != 0 || u16_at(8) != 4 || u16_at(10) != 4 {
        bail!("Backup ZIP must contain exactly four records on one disk");
    }
    let directory_size = u32::from_le_bytes(end[12..16].try_into()?) as u64;
    let directory_offset = u32::from_le_bytes(end[16..20].try_into()?) as u64;
    let start = end_position
        .checked_sub(directory_size)
        .context("Invalid ZIP directory size")?;
    if directory_offset > start || directory_offset == u32::MAX as u64 {
        bail!("Invalid backup ZIP directory offset");
    }
    input.seek(SeekFrom::Start(start))?;
    let mut consumed = 0u64;
    let mut seen = 0u8;
    for _ in 0..MEMBERS.len() {
        let mut header = [0u8; 46];
        input.read_exact(&mut header)?;
        if &header[..4] != b"PK\x01\x02" {
            bail!("Invalid backup ZIP central record");
        }
        let name_length = u16::from_le_bytes(header[28..30].try_into()?) as usize;
        let extra = u16::from_le_bytes(header[30..32].try_into()?) as u64;
        let comment = u16::from_le_bytes(header[32..34].try_into()?) as u64;
        let mut name = [0u8; 32];
        if name_length > name.len() {
            bail!("Unexpected backup ZIP member name");
        }
        input.read_exact(&mut name[..name_length])?;
        let index = MEMBERS
            .iter()
            .position(|member| member.as_bytes() == &name[..name_length])
            .context("Unexpected backup ZIP member name")?;
        if seen & (1 << index) != 0 {
            bail!("Duplicate backup ZIP member");
        }
        seen |= 1 << index;
        consumed += 46 + name_length as u64 + extra + comment;
        if consumed > directory_size {
            bail!("Backup ZIP central record exceeds its directory");
        }
        input.seek(SeekFrom::Current((extra + comment) as i64))?;
    }
    if consumed != directory_size {
        bail!("Backup ZIP contains unexpected extra central records");
    }
    Ok(())
}
pub fn file_digest(path: &Path) -> Result<String> {
    state::reject_symlink(path)?;
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("Expected a regular file");
    }
    let mut hash = Sha256::new();
    // Large archives retain the same one-MiB streaming buffer. Tiny settings
    // and manifest files do not need to allocate that entire buffer.
    let mut buffer = vec![0u8; metadata.len().clamp(1, CHUNK) as usize];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn streaming_gcm_matches_aes_gcm_across_chunk_boundaries() {
        use aes_gcm::aead::{Aead, Payload};
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let header = b"a deliberately non-block-sized authenticated header";
        let reference = aes_gcm::Aes256Gcm::new_from_slice(&key).unwrap();
        for length in [
            1,
            15,
            16,
            17,
            CHUNK as usize - 1,
            CHUNK as usize,
            CHUNK as usize + 1,
            2 * CHUNK as usize + 19,
        ] {
            let plain = (0..length).map(|i| (i % 251) as u8).collect::<Vec<_>>();
            let expected = reference
                .encrypt(
                    aes_gcm::Nonce::from_slice(&nonce),
                    Payload {
                        msg: &plain,
                        aad: header,
                    },
                )
                .unwrap();
            let dir = tempfile::tempdir().unwrap();
            let source = dir.path().join("source");
            let target = dir.path().join("target");
            fs::write(&source, &plain).unwrap();
            let mut gcm = GcmStream::new(&key, &nonce, header).unwrap();
            let mut output = File::create(&target).unwrap();
            transfer(
                &mut File::open(&source).unwrap(),
                &mut output,
                &mut gcm,
                length as u64,
                false,
            )
            .unwrap();
            output.write_all(&gcm.tag(length as u64)).unwrap();
            drop(output);
            assert_eq!(fs::read(target).unwrap(), expected, "length {length}");
        }
    }
    #[test]
    fn python_encryption_fixture_decrypts_with_exact_parameters() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("python.tibak");
        let output = dir.path().join("plaintext");
        fs::write(
            &input,
            include_bytes!("../../tests/fixtures/python-backup-vector.tibak"),
        )
        .unwrap();
        decrypt_archive(&input, &output, "correct horse battery staple").unwrap();
        assert_eq!(
            fs::read(output).unwrap(),
            include_bytes!("../../tests/fixtures/python-backup-vector.txt")
        );
        let mut bytes = fs::read(&input).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&input, bytes).unwrap();
        let rejected = dir.path().join("must-not-exist");
        assert!(decrypt_archive(&input, &rejected, "correct horse battery staple").is_err());
        assert!(!rejected.exists());
    }
    #[test]
    fn archive_paths_are_allowlisted_before_extraction() {
        let dir = tempfile::tempdir().unwrap();
        for bad_position in 0..MEMBERS.len() {
            let path = dir.path().join(format!("bad-{bad_position}.zip"));
            let mut zip = ZipWriter::new(File::create(&path).unwrap());
            for (position, name) in MEMBERS.iter().enumerate() {
                let name = if position == bad_position {
                    "../escape"
                } else {
                    name
                };
                zip.start_file(
                    name,
                    SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
                )
                .unwrap();
                zip.write_all(b"bad").unwrap();
            }
            zip.finish().unwrap();
            let unpack = dir.path().join(format!("unpack-{bad_position}"));
            fs::create_dir(&unpack).unwrap();
            assert!(unpack_backup(&path, &unpack).is_err());
            assert_eq!(fs::read_dir(&unpack).unwrap().count(), 0);
            assert!(!dir.path().join("escape").exists());
        }
    }
    #[test]
    fn raw_zip_directory_rejects_duplicates_hidden_by_the_zip_reader() {
        let directory = tempfile::tempdir().unwrap();
        let archive = directory.path().join("duplicate.zip");
        let mut writer = ZipWriter::new(File::create(&archive).unwrap());
        for name in MEMBERS {
            writer
                .start_file(
                    name,
                    SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
                )
                .unwrap();
            writer.write_all(b"placeholder").unwrap();
        }
        writer.finish().unwrap();
        let original = fs::read(&archive).unwrap();
        let end = original.len() - 22;
        let central_start =
            u32::from_le_bytes(original[end + 16..end + 20].try_into().unwrap()) as usize;
        let first_length = 46
            + [28, 30, 32]
                .iter()
                .map(|offset| {
                    u16::from_le_bytes(
                        original[central_start + offset..central_start + offset + 2]
                            .try_into()
                            .unwrap(),
                    ) as usize
                })
                .sum::<usize>();
        let duplicate = &original[central_start..central_start + first_length];
        // Test both truthful and forged record counts. The ZIP library itself
        // exposes four unique names in either case, hiding the extra record.
        for claimed_count in [4u16, 5] {
            let mut bytes = original[..end].to_vec();
            bytes.extend_from_slice(duplicate);
            bytes.extend_from_slice(&original[end..]);
            let new_end = end + first_length;
            bytes[new_end + 8..new_end + 10].copy_from_slice(&claimed_count.to_le_bytes());
            bytes[new_end + 10..new_end + 12].copy_from_slice(&claimed_count.to_le_bytes());
            bytes[new_end + 12..new_end + 16]
                .copy_from_slice(&((new_end - central_start) as u32).to_le_bytes());
            fs::write(&archive, bytes).unwrap();
            assert_eq!(
                ZipArchive::new(File::open(&archive).unwrap())
                    .unwrap()
                    .len(),
                4
            );
            let unpack = directory.path().join(format!("unpack-{claimed_count}"));
            fs::create_dir(&unpack).unwrap();
            assert!(unpack_backup(&archive, &unpack).is_err());
            assert_eq!(fs::read_dir(unpack).unwrap().count(), 0);
        }
        let mut commented = original;
        let comment = b"A valid archive comment";
        commented[end + 20..end + 22].copy_from_slice(&(comment.len() as u16).to_le_bytes());
        commented.extend_from_slice(comment);
        fs::write(&archive, &commented).unwrap();
        check_zip_directory(&mut File::open(&archive).unwrap(), commented.len() as u64).unwrap();
    }
    #[test]
    fn snapshot_includes_committed_wal_pages() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.db");
        let snapshot = directory.path().join("snapshot.db");
        let database = super::super::Database::open(&source).unwrap();
        // The writer has already closed. Only Database's idle connection keeps
        // these committed pages in the WAL while an online backup reads them.
        database.insert_job(&json!({"id":"wal-job","magnet_uri":"magnet:?xt=urn:btih:test","final_parent":"/media","staging_preference":"local","staging_root_initial":"/staging","managed_tag":"intake","unique_tag":"ti_job_wal"})).unwrap();
        assert!(
            fs::metadata(PathBuf::from(format!("{}-wal", source.display())))
                .unwrap()
                .len()
                > 0
        );
        snapshot_database(&source, &snapshot).unwrap();
        let reader = Connection::open(&snapshot).unwrap();
        let id: String = reader
            .query_row("SELECT id FROM jobs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(id, "wal-job");
    }
    #[test]
    fn sqlite_objects_and_relationships_are_checked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db");
        let db = super::super::Database::open(&path).unwrap();
        check_database(&path).unwrap();
        db.connect()
            .unwrap()
            .execute_batch("CREATE VIEW unexpected AS SELECT id FROM jobs;")
            .unwrap();
        assert!(check_database(&path).is_err());
    }
    #[test]
    fn real_python_backup_restores_and_upgrades_saved_checkpoints() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut config = crate::config::Config::defaults();
        config.values["data_dir"] = json!(root.to_string_lossy());
        config.values["database_url"] = json!(format!("sqlite:///{}/db", root.display()));
        let _lock = state::ControllerLock::acquire(root).unwrap();
        let original = super::super::Database::open(root.join("db")).unwrap();
        drop(original);
        config.persist().unwrap();
        let input = root.join("python.tibak");
        fs::write(
            &input,
            include_bytes!("../../tests/fixtures/python-legacy-backup.tibak"),
        )
        .unwrap();
        let staging = root.join("stage");
        state::private_directory(&staging).unwrap();
        super::super::restore::stage_restore(
            &input,
            &staging,
            &config.values,
            "correct horse battery staple",
        )
        .unwrap();
        super::super::restore::apply_pending_restore(&config.values).unwrap();
        let restored = super::super::Database::open(root.join("db")).unwrap();
        let job = restored.get_job("python-reference-job").unwrap().unwrap();
        assert_eq!(job["staging_overridden"], true);
        assert_eq!(job["is_terminal"], false);
        assert_eq!(job["custom_tags_json"], "[]");
        assert_eq!(job["state"], "scan_paused");
        let run = restored
            .get_scan_run("python-reference-job")
            .unwrap()
            .unwrap();
        assert_eq!(run["pause_requested"], true);
        assert_eq!(run["completed_bytes"], 123);
        let files = restored.list_scan_files("python-reference-job").unwrap();
        assert_eq!(files[0]["status"], "clean");
        assert_eq!(files[0]["mtime_ns"], 456);
        assert!(files[0]["ctime_ns"].is_null());
        assert_eq!(
            restored
                .torrent_data("python-reference-job")
                .unwrap()
                .unwrap(),
            b"d4:infod6:lengthi0e4:name4:test12:piece lengthi16384e6:pieces0:ee"
        );
        // Partial updates must still work after upgrading a Python-created schema.
        restored
            .save_scan_file(
                "python-reference-job",
                &json!({"relative_path":"payload.bin","status":"pending"}),
            )
            .unwrap();
        assert_eq!(
            restored.list_scan_files("python-reference-job").unwrap()[0]["size_bytes"],
            123
        );
        let settings: Value = serde_json::from_slice(
            &state::read_private(&root.join("settings.json"), CHUNK as usize).unwrap(),
        )
        .unwrap();
        assert_eq!(
            settings["settings"]["qbt_password"],
            "fixture-only-password"
        );
        assert_eq!(settings["settings"]["data_dir"], config.values["data_dir"]);
    }
    #[test]
    fn encrypted_roundtrip_stages_and_applies_offline_with_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut settings = crate::config::Config::defaults();
        settings.values["data_dir"] = json!(root.to_string_lossy());
        settings.values["database_url"] = json!(format!("sqlite:///{}/state.db", root.display()));
        let _lock = state::ControllerLock::acquire(root).unwrap();
        let db = super::super::Database::open(root.join("state.db")).unwrap();
        db.insert_job(&json!({"id":"restore-job","magnet_uri":"magnet:?xt=urn:btih:123","final_parent":"/media","staging_preference":"local","staging_root_initial":"/staging","managed_tag":"intake","unique_tag":"ti_job_restore","state":"downloading"})).unwrap();
        settings.persist().unwrap();
        let export = root.join("export");
        state::private_directory(&export).unwrap();
        let encrypted =
            create_backup(&settings.values, &export, "correct horse battery staple").unwrap();
        db.update_job("restore-job", &json!({"state":"error"}))
            .unwrap();
        let staging = root.join("upload");
        state::private_directory(&staging).unwrap();
        super::super::restore::stage_restore(
            &encrypted,
            &staging,
            &settings.values,
            "correct horse battery staple",
        )
        .unwrap();
        assert_eq!(
            db.get_job("restore-job").unwrap().unwrap()["state"],
            "error"
        );
        // Staging is allowed with the paused controller alive. Installation is
        // offline: close every Database handle before replacing the database.
        drop(db);
        super::super::restore::apply_pending_restore(&settings.values).unwrap();
        assert!(!root.join(".restore-pending").exists());
        assert!(root.join("controller-paused.json").exists());
        let db = super::super::Database::open(root.join("state.db")).unwrap();
        assert_eq!(
            db.get_job("restore-job").unwrap().unwrap()["state"],
            "downloading"
        );
        let last: Value = serde_json::from_slice(
            &state::read_private(&root.join("last-restore.json"), 1024).unwrap(),
        )
        .unwrap();
        let rollback = super::super::Database::open(
            Path::new(last["rollback_directory"].as_str().unwrap()).join("torrent_intake.db"),
        )
        .unwrap();
        assert_eq!(
            rollback.get_job("restore-job").unwrap().unwrap()["state"],
            "error"
        );
    }
}
