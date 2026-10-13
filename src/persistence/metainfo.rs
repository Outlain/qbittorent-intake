//! Bencode is deliberately decoded here instead of through an unbounded generic
//! deserializer. Torrent identity hashes the original `info` byte range: decoding
//! and re-encoding can change the hash and silently select a different torrent.
use anyhow::{bail, Context, Result};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::collections::{BTreeMap, HashSet};
pub const MAX_TORRENT_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_METAINFO_NODES: usize = 300_000;
pub const MAX_METAINFO_DEPTH: usize = 64;
#[derive(Debug, Clone)]
pub struct TorrentMetainfo {
    pub data: Vec<u8>,
    pub magnet_uri: String,
    pub name: String,
    pub size_bytes: u64,
}
#[derive(Debug)]
enum Node<'a> {
    Bytes(&'a [u8]),
    Integer(i64),
    List(Vec<Node<'a>>),
    Dict(BTreeMap<&'a [u8], Node<'a>>),
}
impl<'a> Node<'a> {
    fn bytes(&self) -> Option<&'a [u8]> {
        if let Self::Bytes(v) = self {
            Some(v)
        } else {
            None
        }
    }
    fn int(&self) -> Option<i64> {
        if let Self::Integer(v) = self {
            Some(*v)
        } else {
            None
        }
    }
    fn dict(&self) -> Option<&BTreeMap<&'a [u8], Node<'a>>> {
        if let Self::Dict(v) = self {
            Some(v)
        } else {
            None
        }
    }
    fn list(&self) -> Option<&Vec<Node<'a>>> {
        if let Self::List(v) = self {
            Some(v)
        } else {
            None
        }
    }
}
type Dictionary<'a> = BTreeMap<&'a [u8], Node<'a>>;
struct Decoder<'a> {
    data: &'a [u8],
    offset: usize,
    nodes: usize,
    info: Option<&'a [u8]>,
}
impl<'a> Decoder<'a> {
    fn read(&mut self, depth: usize) -> Result<Node<'a>> {
        self.nodes += 1;
        if depth > MAX_METAINFO_DEPTH || self.nodes > MAX_METAINFO_NODES {
            bail!("Torrent metadata is too deeply nested or has too many entries");
        }
        let token = *self
            .data
            .get(self.offset)
            .context("Truncated torrent metadata")?;
        match token {
            b'l' => {
                self.offset += 1;
                let mut values = Vec::new();
                while self.data.get(self.offset) != Some(&b'e') {
                    values.push(self.read(depth + 1)?);
                }
                self.offset += 1;
                Ok(Node::List(values))
            }
            b'd' => {
                self.offset += 1;
                let mut values = BTreeMap::new();
                let mut previous: Option<&[u8]> = None;
                while self.data.get(self.offset) != Some(&b'e') {
                    let key = self
                        .read(depth + 1)?
                        .bytes()
                        .context("Torrent dictionary keys must be byte strings")?;
                    if previous.is_some_and(|v| key <= v) {
                        bail!("Torrent dictionary keys must be unique and ordered");
                    }
                    previous = Some(key);
                    let start = self.offset;
                    let value = self.read(depth + 1)?;
                    if depth == 0 && key == b"info" {
                        self.info = Some(&self.data[start..self.offset]);
                    }
                    values.insert(key, value);
                }
                self.offset += 1;
                Ok(Node::Dict(values))
            }
            b'i' => {
                let start = self.offset + 1;
                let end = self.data[start..self.data.len().min(self.offset + 23)]
                    .iter()
                    .position(|v| *v == b'e')
                    .map(|v| v + start)
                    .context("Invalid or oversized torrent integer")?;
                let raw = std::str::from_utf8(&self.data[start..end])?;
                let value = raw
                    .parse::<i64>()
                    .context("Invalid or oversized torrent integer")?;
                if value.to_string() != raw {
                    bail!("Torrent integer must use canonical encoding");
                }
                self.offset = end + 1;
                Ok(Node::Integer(value))
            }
            b'0'..=b'9' => {
                let start = self.offset;
                let end = self.data[start..self.data.len().min(start + 12)]
                    .iter()
                    .position(|v| *v == b':')
                    .map(|v| v + start)
                    .context("Invalid torrent byte string")?;
                let raw = &self.data[start..end];
                if raw.is_empty()
                    || !raw.iter().all(u8::is_ascii_digit)
                    || (raw.len() > 1 && raw[0] == b'0')
                {
                    bail!("Invalid torrent byte string length");
                }
                let length = std::str::from_utf8(raw)?.parse::<usize>()?;
                self.offset = end + 1;
                let end = self
                    .offset
                    .checked_add(length)
                    .filter(|e| *e <= self.data.len())
                    .context("Truncated torrent byte string")?;
                let value = &self.data[self.offset..end];
                self.offset = end;
                Ok(Node::Bytes(value))
            }
            _ => bail!("Invalid bencoded torrent metadata"),
        }
    }
}
fn component(value: &[u8]) -> Result<&[u8]> {
    if value.is_empty()
        || value == b"."
        || value == b".."
        || value.iter().any(|b| [b'/', b'\\', 0].contains(b))
        || (value.len() >= 2 && value[1] == b':')
    {
        bail!("Torrent contains an unsafe file or directory name");
    }
    Ok(value)
}
fn file_size(entry: &Dictionary<'_>) -> Result<u64> {
    if let Some(attributes) = entry.get(b"attr".as_slice()) {
        let attrs = attributes.bytes().context("Invalid torrent attributes")?;
        if attrs.contains(&b'l') {
            bail!("Symlink entries are not supported in torrent uploads");
        }
    }
    if entry.contains_key(b"symlink path".as_slice()) {
        bail!("Symlink entries are not supported in torrent uploads");
    }
    let size = entry
        .get(b"length".as_slice())
        .and_then(Node::int)
        .filter(|v| *v >= 0)
        .context("Torrent file length must be a nonnegative integer")?;
    Ok(size as u64)
}
fn add_size(total: u64, size: u64) -> Result<u64> {
    total
        .checked_add(size)
        .filter(|s| *s <= i64::MAX as u64)
        .context("Torrent content size is too large")
}
fn add_path<'a>(paths: &mut HashSet<Vec<&'a [u8]>>, path: Vec<&'a [u8]>) -> Result<()> {
    if !paths.insert(path) {
        bail!("Torrent contains duplicate file paths");
    }
    Ok(())
}
fn check_paths(paths: &HashSet<Vec<&[u8]>>) -> Result<()> {
    for path in paths {
        for i in 1..path.len() {
            if paths.contains(&path[..i]) {
                bail!("Torrent file paths overlap a directory path");
            }
        }
    }
    Ok(())
}
fn visit_tree<'a>(
    branch: &Dictionary<'a>,
    prefix: Vec<&'a [u8]>,
    paths: &mut HashSet<Vec<&'a [u8]>>,
) -> Result<u64> {
    let mut total = 0;
    for (key, value) in branch {
        let child = value.dict().context("Invalid v2 torrent file tree")?;
        if key.is_empty() {
            if prefix.is_empty() || branch.len() != 1 {
                bail!("Invalid v2 torrent file leaf");
            }
            add_path(paths, prefix.clone())?;
            let length = file_size(child)?;
            if length > 0
                && child
                    .get(b"pieces root".as_slice())
                    .and_then(Node::bytes)
                    .map(|v| v.len())
                    != Some(32)
            {
                bail!("Invalid v2 torrent file hash");
            }
            total = add_size(total, length)?;
        } else {
            if child.is_empty() {
                bail!("Empty v2 torrent directory");
            }
            let mut path = prefix.clone();
            path.push(component(key)?);
            total = add_size(total, visit_tree(child, path, paths)?)?;
        }
    }
    Ok(total)
}
pub fn parse_torrent(data: &[u8]) -> Result<TorrentMetainfo> {
    if data.is_empty() || data.len() > MAX_TORRENT_BYTES {
        bail!("Upload a nonempty .torrent metadata file of at most 32 MiB");
    }
    let mut decoder = Decoder {
        data,
        offset: 0,
        nodes: 0,
        info: None,
    };
    let decoded = decoder.read(0)?;
    if decoder.offset != data.len() {
        bail!("Expected one complete torrent dictionary without trailing data");
    }
    let metadata = decoded.dict().context("Expected a torrent dictionary")?;
    let info = metadata
        .get(b"info".as_slice())
        .and_then(Node::dict)
        .context("Torrent metadata is missing its info dictionary")?;
    let info_bytes = decoder.info.context("Missing torrent info byte range")?;
    let name = component(
        info.get(b"name".as_slice())
            .and_then(Node::bytes)
            .context("Missing torrent name")?,
    )?;
    if let Some(value) = info.get(b"name.utf-8".as_slice()) {
        component(value.bytes().context("Invalid alternate torrent name")?)?;
    }
    let piece_length = info
        .get(b"piece length".as_slice())
        .and_then(Node::int)
        .filter(|v| *v > 0)
        .context("Torrent piece length must be positive")? as u64;
    if let Some(value) = info.get(b"private".as_slice()) {
        if !matches!(value.int(), Some(0 | 1)) {
            bail!("Invalid private-torrent flag");
        }
    }
    let version = info.get(b"meta version".as_slice());
    if version.is_some() && version.and_then(Node::int) != Some(2) {
        bail!("Unsupported torrent metadata version");
    }
    let v2 = version.is_some();
    let mut size = 0;
    let mut paths = HashSet::new();
    let mut magnet = String::new();
    if let Some(pieces) = info.get(b"pieces".as_slice()) {
        let files = info.get(b"files".as_slice());
        let length = info.get(b"length".as_slice());
        if files.is_some() == length.is_some() {
            bail!("Torrent must contain either one file length or a file list");
        }
        if length.is_some() {
            size = file_size(info)?;
        } else {
            let files = files
                .and_then(Node::list)
                .filter(|v| !v.is_empty())
                .context("Torrent file list must not be empty")?;
            for entry in files {
                let entry = entry.dict().context("Invalid torrent file entry")?;
                size = add_size(size, file_size(entry)?)?;
                let parts = entry
                    .get(b"path".as_slice())
                    .and_then(Node::list)
                    .filter(|v| !v.is_empty())
                    .context("Torrent file path must not be empty")?;
                let path = parts
                    .iter()
                    .map(|v| component(v.bytes().context("Invalid torrent path component")?))
                    .collect::<Result<Vec<_>>>()?;
                add_path(&mut paths, path)?;
                if let Some(alternate) = entry.get(b"path.utf-8".as_slice()) {
                    for part in alternate
                        .list()
                        .filter(|v| !v.is_empty())
                        .context("Invalid alternate torrent file path")?
                    {
                        component(part.bytes().context("Invalid alternate path component")?)?;
                    }
                }
            }
        }
        let pieces = pieces
            .bytes()
            .context("Torrent piece hashes must be bytes")?;
        let count = size.div_ceil(piece_length);
        if count.checked_mul(20) != Some(pieces.len() as u64) {
            bail!("Torrent piece hashes do not match declared content size");
        }
        magnet = format!(
            "magnet:?xt=urn:btih:{}",
            hex::encode(Sha1::digest(info_bytes))
        );
        check_paths(&paths)?;
    } else if !v2 {
        bail!("Torrent metadata is missing its piece hashes");
    }
    if v2 {
        if piece_length < 16384 || !piece_length.is_power_of_two() {
            bail!("Invalid v2 torrent piece length");
        }
        let tree = info
            .get(b"file tree".as_slice())
            .and_then(Node::dict)
            .filter(|v| !v.is_empty())
            .context("V2 torrent metadata is missing its file tree")?;
        paths.clear();
        let v2_size = visit_tree(tree, vec![], &mut paths)?;
        let identity = format!(
            "xt=urn:btmh:1220{}",
            hex::encode(Sha256::digest(info_bytes))
        );
        if magnet.is_empty() {
            magnet = format!("magnet:?{identity}");
            size = v2_size;
        } else {
            magnet.push('&');
            magnet.push_str(&identity);
        }
    }
    check_paths(&paths)?;
    Ok(TorrentMetainfo {
        data: data.to_vec(),
        magnet_uri: magnet,
        name: String::from_utf8_lossy(name).into(),
        size_bytes: size,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decisions_match_python_reference_vectors() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/python-metainfo-vectors.json"
        ))
        .unwrap();
        for vector in vectors.as_array().unwrap() {
            let data = hex::decode(vector["hex"].as_str().unwrap()).unwrap();
            let parsed = parse_torrent(&data);
            if vector["expected"].is_null() {
                assert!(parsed.is_err(), "{}", vector["description"]);
            } else {
                let value = parsed.unwrap_or_else(|e| panic!("{}: {e}", vector["description"]));
                assert_eq!(value.name, vector["expected"]["name"]);
                assert_eq!(value.magnet_uri, vector["expected"]["magnet_uri"]);
                assert_eq!(
                    value.size_bytes,
                    vector["expected"]["size_bytes"].as_u64().unwrap()
                );
                assert_eq!(value.data, data);
            }
        }
    }
    #[test]
    fn node_budget_stops_large_metadata() {
        let mut data = b"l".to_vec();
        for _ in 0..MAX_METAINFO_NODES {
            data.extend(b"0:");
        }
        data.push(b'e');
        assert!(parse_torrent(&data)
            .unwrap_err()
            .to_string()
            .contains("too many entries"));
    }
    #[test]
    fn exact_info_bytes_define_identity() {
        let info = b"d6:lengthi0e4:name4:test12:piece lengthi16384e6:pieces0:e";
        let mut torrent = b"d4:info".to_vec();
        torrent.extend(info);
        torrent.push(b'e');
        let parsed = parse_torrent(&torrent).unwrap();
        assert_eq!(parsed.size_bytes, 0);
        assert_eq!(parsed.name, "test");
        assert_eq!(
            parsed.magnet_uri,
            format!("magnet:?xt=urn:btih:{}", hex::encode(Sha1::digest(info)))
        );
        assert_eq!(parsed.data, torrent);
    }
    #[test]
    fn hostile_bencode_is_rejected() {
        for input in [
            b"d4:infoi-0ee".as_slice(),
            b"d4:infoi01ee",
            b"d1:bi1e1:ai2ee",
            b"d4:infod4:name2:..ee",
            b"degarbage",
            b"d4:infoi9223372036854775808ee",
        ] {
            assert!(parse_torrent(input).is_err(), "{:?}", input);
        }
        let deep = format!("{}{}", "l".repeat(66), "e".repeat(66));
        assert!(parse_torrent(deep.as_bytes()).is_err());
    }
    #[test]
    fn v2_empty_file_is_supported() {
        let torrent=b"d4:infod9:file treed4:testd0:d6:lengthi0eeee12:meta versioni2e4:name4:test12:piece lengthi16384eee";
        let value = parse_torrent(torrent).unwrap();
        assert!(value.magnet_uri.starts_with("magnet:?xt=urn:btmh:1220"));
        assert_eq!(value.size_bytes, 0);
    }
}
