//! The small, synchronous adapter for qBittorrent's cookie authenticated API.
//!
//! One mutex protects login and requests together. A rejected session is renewed
//! once; a failed mutation is never retried merely because the connection broke.
use crate::config::Config;
use anyhow::{bail, Context, Result};
use reqwest::blocking::{multipart, Client, Response};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone)]
pub struct Qbt {
    client: Client,
    config: Config,
    session: Arc<Mutex<bool>>,
}

/// Multipart retries need independent cursors, not independent copies of a
/// potentially large private torrent file. Arc owns the original byte buffer.
struct TorrentReader {
    bytes: Arc<Vec<u8>>,
    offset: usize,
}
impl std::io::Read for TorrentReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let count = output
            .len()
            .min(self.bytes.len().saturating_sub(self.offset));
        output[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

impl Qbt {
    pub fn new(config: Config) -> Result<Self> {
        Ok(Self {
            client: Client::builder()
                .cookie_store(true)
                .danger_accept_invalid_certs(!config.bool("qbt_verify_certificate"))
                .timeout(Duration::from_secs(
                    config.u64("qbt_request_timeout_seconds").max(1),
                ))
                .build()?,
            config,
            session: Arc::new(Mutex::new(false)),
        })
    }
    fn url(&self, endpoint: &str) -> String {
        format!(
            "{}/api/v2/{endpoint}",
            self.config.string("qbt_host").trim_end_matches('/')
        )
    }
    fn login(&self) -> Result<()> {
        let response = self
            .client
            .post(self.url("auth/login"))
            .form(&[
                ("username", self.config.string("qbt_username")),
                ("password", self.config.string("qbt_password")),
            ])
            .send()
            .context("qBittorrent login connection failed")?;
        let status = response.status();
        let body = response.text()?;
        if !status.is_success() || body.trim() != "Ok." {
            bail!("qBittorrent login was rejected ({status}); check credentials and Web UI access");
        }
        Ok(())
    }
    fn request(&self, endpoint: &str, fields: &[(&str, String)], post: bool) -> Result<Response> {
        let mut authenticated = self
            .session
            .lock()
            .map_err(|_| anyhow::anyhow!("qBittorrent session lock poisoned"))?;
        if !*authenticated {
            self.login()?;
            *authenticated = true;
        }
        for attempt in 0..2 {
            let builder = if post {
                self.client.post(self.url(endpoint)).form(fields)
            } else {
                self.client.get(self.url(endpoint)).query(fields)
            };
            let response = builder
                .send()
                .with_context(|| format!("qBittorrent {endpoint} request failed"))?;
            if response.status() == reqwest::StatusCode::FORBIDDEN && attempt == 0 {
                *authenticated = false;
                self.login()?;
                *authenticated = true;
                continue;
            }
            return response
                .error_for_status()
                .with_context(|| format!("qBittorrent rejected {endpoint}"));
        }
        unreachable!()
    }
    pub fn json(&self, endpoint: &str, fields: &[(&str, String)]) -> Result<Value> {
        self.request(endpoint, fields, false)?
            .json()
            .context("qBittorrent returned invalid JSON")
    }
    pub fn post(&self, endpoint: &str, fields: &[(&str, String)]) -> Result<()> {
        self.request(endpoint, fields, true)?;
        Ok(())
    }
    pub fn list(&self) -> Result<Vec<Value>> {
        match self.json("torrents/info", &[])? {
            Value::Array(torrents) => Ok(torrents),
            _ => bail!("qBittorrent torrent list is not an array"),
        }
    }
    pub fn torrent(&self, hash: &str) -> Result<Option<Value>> {
        if hash.is_empty() {
            return Ok(None);
        }
        match self.json("torrents/info", &[("hashes", hash.to_string())])? {
            Value::Array(torrents) => Ok(torrents.into_iter().next()),
            _ => Ok(None),
        }
    }
    pub fn by_tag(&self, tag: &str) -> Result<Option<Value>> {
        Ok(self
            .list()?
            .into_iter()
            .find(|torrent| tags(torrent).contains(tag)))
    }
    pub fn existing(&self, magnet: &str) -> Result<Option<Value>> {
        self.torrent(&magnet_hashes(magnet)?.join("|"))
    }
    pub fn add(
        &self,
        magnet: &str,
        data: Option<Vec<u8>>,
        filename: &str,
        path: &str,
        tags: &[String],
        category: &str,
    ) -> Result<()> {
        if self.existing(magnet)?.is_some() {
            bail!("torrent already exists in qBittorrent");
        }
        let data = data.map(Arc::new);
        let mut authenticated = self
            .session
            .lock()
            .map_err(|_| anyhow::anyhow!("qBittorrent session lock poisoned"))?;
        if !*authenticated {
            self.login()?;
            *authenticated = true;
        }
        for attempt in 0..2 {
            let mut form = multipart::Form::new()
                .text("savepath", path.to_owned())
                .text("tags", tags.join(","))
                .text("category", category.to_owned())
                .text("paused", "false")
                .text("stopped", "false");
            form = if let Some(bytes) = &data {
                form.part(
                    "torrents",
                    multipart::Part::reader_with_length(
                        TorrentReader {
                            bytes: bytes.clone(),
                            offset: 0,
                        },
                        bytes.len() as u64,
                    )
                    .file_name(filename.to_owned()),
                )
            } else {
                form.text("urls", magnet.to_owned())
            };
            let response = self
                .client
                .post(self.url("torrents/add"))
                .multipart(form)
                .send()?;
            if response.status() == reqwest::StatusCode::FORBIDDEN && attempt == 0 {
                *authenticated = false;
                self.login()?;
                *authenticated = true;
                continue;
            }
            let body = response.error_for_status()?.text()?;
            if body.trim() != "Ok." {
                bail!(
                    "qBittorrent rejected torrent addition: {}",
                    body.chars().take(200).collect::<String>()
                );
            }
            return Ok(());
        }
        unreachable!()
    }
    pub fn pause(&self, hash: &str) -> Result<()> {
        self.pause_resume(hash, "stop", "pause")
    }
    pub fn resume(&self, hash: &str) -> Result<()> {
        self.pause_resume(hash, "start", "resume")
    }
    fn pause_resume(&self, hash: &str, modern: &str, legacy: &str) -> Result<()> {
        let fields = [("hashes", hash.to_owned())];
        match self.request(&format!("torrents/{modern}"), &fields, true) {
            Ok(_) => Ok(()),
            Err(error)
                if error
                    .downcast_ref::<reqwest::Error>()
                    .and_then(|e| e.status())
                    == Some(reqwest::StatusCode::NOT_FOUND) =>
            {
                self.post(&format!("torrents/{legacy}"), &fields)
            }
            Err(error) => Err(error),
        }
    }
    pub fn location(&self, hash: &str, path: &str) -> Result<()> {
        self.post(
            "torrents/setLocation",
            &[("hashes", hash.to_owned()), ("location", path.to_owned())],
        )
    }
    pub fn delete_with_files(&self, hash: &str) -> Result<()> {
        self.post(
            "torrents/delete",
            &[("hashes", hash.to_owned()), ("deleteFiles", "true".into())],
        )
    }
    pub fn category(&self, hash: &str, requested: &str) -> Result<String> {
        let categories = self.json("torrents/categories", &[])?;
        let found = categories
            .as_object()
            .and_then(|map| map.keys().find(|name| name.eq_ignore_ascii_case(requested)))
            .cloned();
        let name = match found {
            Some(name) => name,
            None if self.config.bool("auto_create_final_category") => {
                self.post(
                    "torrents/createCategory",
                    &[("category", requested.to_owned())],
                )?;
                requested.to_owned()
            }
            None => bail!(
                "final category does not exist; create it or enable automatic category creation"
            ),
        };
        self.post(
            "torrents/setCategory",
            &[("hashes", hash.to_owned()), ("category", name.clone())],
        )?;
        Ok(name)
    }
}

pub fn tags(torrent: &Value) -> BTreeSet<String> {
    torrent["tags"]
        .as_str()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Decode both conventional hexadecimal and RFC4648 base32 BTIH magnets.
/// A v2 digest is queried by full SHA-256 and qBittorrent's truncated TorrentID.
pub fn magnet_hashes(magnet: &str) -> Result<Vec<String>> {
    let url = url::Url::parse(magnet).context("invalid magnet URI")?;
    if url.scheme() != "magnet" {
        bail!("a magnet URI is required");
    }
    let mut hashes = Vec::new();
    for (key, value) in url.query_pairs() {
        if key != "xt" {
            continue;
        }
        let value = value.to_ascii_lowercase();
        if let Some(raw) = value.strip_prefix("urn:btih:") {
            if raw.len() == 40 && raw.bytes().all(|v| v.is_ascii_hexdigit()) {
                hashes.push(raw.into());
            } else if raw.len() == 32 {
                let mut bits = 0u32;
                let mut count = 0;
                let mut bytes = Vec::new();
                for byte in raw.bytes() {
                    let digit = match byte {
                        b'a'..=b'z' => byte - b'a',
                        b'2'..=b'7' => byte - b'2' + 26,
                        _ => bail!("invalid base32 BTIH"),
                    };
                    bits = (bits << 5) | digit as u32;
                    count += 5;
                    if count >= 8 {
                        count -= 8;
                        bytes.push((bits >> count) as u8);
                    }
                }
                hashes.push(bytes.iter().map(|byte| format!("{byte:02x}")).collect());
            } else {
                bail!("BTIH must contain 40 hexadecimal or 32 base32 characters");
            }
        } else if let Some(raw) = value.strip_prefix("urn:btmh:1220") {
            if raw.len() != 64 || !raw.bytes().all(|v| v.is_ascii_hexdigit()) {
                bail!("invalid v2 torrent hash");
            }
            hashes.push(raw[..40].into());
            hashes.push(raw.into());
        }
    }
    if hashes.is_empty() {
        bail!("magnet URI contains no supported torrent hash");
    }
    hashes.sort();
    hashes.dedup();
    Ok(hashes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn multipart_retry_cursors_share_original_bytes_and_start_at_zero() {
        use std::io::Read;
        let original = vec![0x5a; 1024 * 1024];
        let original_buffer = original.as_ptr();
        let bytes = Arc::new(original);
        assert_eq!(
            bytes.as_ptr(),
            original_buffer,
            "Arc must retain the original allocation"
        );
        for _ in 0..2 {
            let mut reader = TorrentReader {
                bytes: bytes.clone(),
                offset: 0,
            };
            let mut received = Vec::new();
            reader.read_to_end(&mut received).unwrap();
            assert_eq!(received, **bytes);
            assert_eq!(reader.read(&mut [0; 1]).unwrap(), 0);
        }
    }
    #[test]
    fn hash_aliases_are_decoded() {
        assert_eq!(
            magnet_hashes("magnet:?xt=urn:btih:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            vec!["0".repeat(40)]
        );
        assert!(magnet_hashes("https://example.com").is_err());
        assert!(magnet_hashes("magnet:?xt=urn:btih:invalid").is_err());
        assert_eq!(
            magnet_hashes(&format!("magnet:?xt=urn:btmh:1220{}", "a".repeat(64)))
                .unwrap()
                .len(),
            2
        );
    }
}
