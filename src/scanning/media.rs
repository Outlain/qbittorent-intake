//! Large media is eligible for byte windows only after a bounded structural
//! probe. Embedded files, cover pictures, and chapter packets are scanned whole.
use super::*;
use serde_json::Value;
use std::{collections::BTreeSet, os::unix::fs::FileExt};
const FORMATS: &str = "asf,avi,flv,matroska,mov,mp4,mpeg,mpegts,ogg,truehd,webm";
const ATTACHMENTS: [&str; 15] = [
    "ass", "gif", "jpeg", "jpg", "nfo", "otf", "png", "srt", "ssa", "ttc", "ttf", "txt", "webp",
    "woff", "woff2",
];
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaAttachment {
    pub index: u64,
    pub filename: String,
    pub size_bytes: Option<u64>,
    pub is_picture: bool,
    pub chapter_samples: Option<u64>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaProbe {
    pub format_name: String,
    pub attachments: Vec<MediaAttachment>,
}
fn policy(message: impl Into<String>) -> ScanError {
    ScanError::Policy(message.into())
}
/// Rejected media files need useful diagnostics, but metadata is untrusted. Log only
/// selected fields, cap their length, and JSON-escape control characters. Never
/// include packet bytes, all tags, or the original parser output in an error.
fn media_policy(
    reason: &str,
    path: &Path,
    container: &Value,
    stream: Option<&Value>,
    details: &[(&str, Value)],
) -> ScanError {
    fn display(value: &Value, maximum: usize) -> String {
        let value = match value {
            Value::Null => Value::String("unknown".into()),
            Value::String(s) if s.is_empty() => Value::String("unknown".into()),
            Value::String(s) => {
                let mut chars = s.chars();
                let mut text: String = chars.by_ref().take(maximum).collect();
                if chars.next().is_some() {
                    text.push_str("...[truncated]");
                }
                Value::String(text)
            }
            Value::Number(_) | Value::Bool(_) => value.clone(),
            _ => Value::String("invalid metadata type".into()),
        };
        value.to_string()
    }
    let mut message = format!(
        "{reason}; path={}; container={}",
        display(&Value::String(path.to_string_lossy().into_owned()), 4096),
        display(container, 256)
    );
    if let Some(stream) = stream {
        for (label, value) in [
            ("stream_index", &stream["index"]),
            ("stream_type", &stream["codec_type"]),
            ("codec", &stream["codec_name"]),
            ("codec_tag", &stream["codec_tag_string"]),
            ("handler", &stream["tags"]["handler_name"]),
        ] {
            message.push_str(&format!("; {label}={}", display(value, 256)));
        }
        let picture = stream["disposition"]["attached_pic"].as_u64() == Some(1);
        if picture {
            message.push_str("; attached_pic=1");
        }
        if stream["codec_type"] == "attachment" || picture || !stream["tags"]["filename"].is_null()
        {
            let extension = stream["tags"]["filename"]
                .as_str()
                .and_then(|name| Path::new(name).extension())
                .and_then(|suffix| suffix.to_str())
                .map(|suffix| Value::String(format!(".{}", suffix.to_ascii_lowercase())))
                .unwrap_or(Value::Null);
            for (label, value) in [
                ("attachment", &stream["tags"]["filename"]),
                ("extension", &extension),
                ("mime", &stream["tags"]["mimetype"]),
                ("declared_bytes", &stream["extradata_size"]),
            ] {
                message.push_str(&format!("; {label}={}", display(value, 256)));
            }
        }
    }
    for (label, value) in details {
        message.push_str(&format!("; {label}={}", display(value, 256)));
    }
    policy(message)
}
fn integer(value: &Value) -> Result<u64, ScanError> {
    value
        .as_u64()
        .or_else(|| {
            value
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 20 && s.bytes().all(|c| c.is_ascii_digit()))
                .and_then(|s| s.parse().ok())
        })
        .ok_or_else(|| policy("expected a non-negative integer"))
}
/// Parse only metadata requested from ffprobe. Unknown stream types and unknown
/// embedded content fail closed. A filename/MIME permits extraction, never trust.
pub fn parse_media_probe(
    raw: &[u8],
    path: &Path,
    require_video: bool,
    maximum: u64,
    total: u64,
) -> Result<MediaProbe, ScanError> {
    let payload: Value = serde_json::from_slice(raw).map_err(|_| {
        media_policy(
            "ffprobe returned invalid JSON",
            path,
            &Value::Null,
            None,
            &[],
        )
    })?;
    let rejected = |reason, stream, details: &[(&str, Value)]| {
        media_policy(
            reason,
            path,
            &payload["format"]["format_name"],
            stream,
            details,
        )
    };
    let formats: BTreeSet<&str> = payload["format"]["format_name"]
        .as_str()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let allowed: BTreeSet<&str> = FORMATS.split(',').filter(|s| *s != "truehd").collect();
    let approved: Vec<&str> = formats.intersection(&allowed).copied().collect();
    let truehd = formats.len() == 1 && formats.contains("truehd");
    if approved.is_empty() && !truehd {
        return Err(rejected(
            "content is not an approved video container or raw TrueHD audio stream",
            None,
            &[],
        ));
    }
    let streams = payload["streams"]
        .as_array()
        .filter(|a| a.len() <= 1024)
        .ok_or_else(|| rejected("invalid or excessive media stream table", None, &[]))?;
    if truehd {
        let suffix = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !["thd", "truehd"].contains(&suffix.as_str())
            || streams.len() != 1
            || streams[0]["codec_type"] != "audio"
            || streams[0]["codec_name"] != "truehd"
        {
            return Err(rejected(
                "raw TrueHD requires .thd/.truehd and exactly one TrueHD audio stream",
                None,
                &[],
            ));
        }
        return Ok(MediaProbe {
            format_name: "truehd".into(),
            attachments: vec![],
        });
    }
    let mut video_count = 0;
    let mut attachments = vec![];
    let mut reserved = 0u64;
    let mut indices = BTreeSet::new();
    for stream in streams {
        if !stream.is_object() {
            return Err(rejected("malformed media stream entry", None, &[]));
        }
        let kind = stream["codec_type"].as_str().unwrap_or("");
        let codec = stream["codec_name"].as_str().unwrap_or("");
        let chapter = (formats.contains("mov") || formats.contains("mp4"))
            && kind == "data"
            && codec == "bin_data"
            && stream["codec_tag_string"] == "text";
        if !["video", "audio", "subtitle", "attachment"].contains(&kind) && !chapter {
            return Err(rejected("unsupported media stream type", Some(stream), &[]));
        }
        let picture = stream["disposition"]["attached_pic"].as_u64() == Some(1);
        let picture_suffix = match codec {
            "mjpeg" => Some("jpg"),
            "png" => Some("png"),
            "gif" => Some("gif"),
            "webp" => Some("webp"),
            _ => None,
        };
        if picture && (kind != "video" || picture_suffix.is_none()) {
            return Err(rejected(
                "unsupported attached-picture type/codec",
                Some(stream),
                &[],
            ));
        }
        if kind == "video" && !picture {
            video_count += 1;
        }
        if kind == "attachment" || picture || chapter {
            if attachments.len() >= 64 {
                return Err(rejected(
                    "too many media attachments",
                    Some(stream),
                    &[("max_attachments", 64.into())],
                ));
            }
            let name = stream["tags"]["filename"].as_str().unwrap_or("");
            let mime = stream["tags"]["mimetype"]
                .as_str()
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            let suffix = Path::new(name)
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let kodi = formats.contains("matroska")
                && ["kodi-metadata", "kodi-override-metadata"].contains(&name)
                && ["application/xml", "text/xml", "text/plain"].contains(&mime.as_str());
            if !picture && !chapter && !kodi && !ATTACHMENTS.contains(&suffix.as_str()) {
                return Err(rejected(
                    "unsupported attachment filename",
                    Some(stream),
                    &[],
                ));
            }
            let index = stream["index"]
                .as_u64()
                .ok_or_else(|| rejected("invalid attachment stream index", Some(stream), &[]))?;
            if !indices.insert(index) {
                return Err(rejected(
                    "duplicate attachment stream index",
                    Some(stream),
                    &[],
                ));
            }
            let samples = if chapter {
                let n = integer(&stream["nb_frames"])
                    .map_err(|_| rejected("invalid chapter sample count", Some(stream), &[]))?;
                if !(1..=4096).contains(&n) {
                    return Err(rejected(
                        "chapter sample count must be 1..4096",
                        Some(stream),
                        &[],
                    ));
                }
                Some(n)
            } else {
                None
            };
            let size = if picture || chapter {
                None
            } else {
                Some(
                    stream["extradata_size"]
                        .as_u64()
                        .filter(|n| *n > 0 && *n <= maximum)
                        .ok_or_else(|| {
                            rejected(
                                "missing, empty or excessive attachment size",
                                Some(stream),
                                &[("max_attachment_bytes", maximum.into())],
                            )
                        })?,
                )
            };
            reserved = reserved
                .checked_add(size.unwrap_or(maximum))
                .ok_or_else(|| policy("attachment size overflow"))?;
            if reserved > total {
                return Err(rejected(
                    "media attachments exceed total extraction budget",
                    Some(stream),
                    &[
                        ("reserved_bytes", reserved.into()),
                        ("max_total_bytes", total.into()),
                    ],
                ));
            }
            let filename = if chapter {
                format!("chapter-track-{index}.text")
            } else if picture && name.is_empty() {
                format!("attached-picture-{index}.{}", picture_suffix.unwrap())
            } else {
                name.into()
            };
            attachments.push(MediaAttachment {
                index,
                filename,
                size_bytes: size,
                is_picture: picture,
                chapter_samples: samples,
            });
        }
    }
    if require_video && video_count == 0 {
        return Err(rejected(
            "container does not contain a video stream",
            None,
            &[],
        ));
    }
    Ok(MediaProbe {
        format_name: approved.join(","),
        attachments,
    })
}
/// Every byte is covered. Overlap protects signatures crossing window edges.
pub fn window_ranges(total: u64, window: u64, overlap: u64) -> Result<Vec<(u64, u64)>, ScanError> {
    if window == 0 || overlap >= window {
        return Err(policy("invalid media window geometry"));
    }
    let mut ranges = Vec::new();
    let mut offset = 0;
    loop {
        let length = window.min(total - offset);
        ranges.push((offset, length));
        if length == total - offset {
            break;
        }
        offset = offset
            .checked_add(window - overlap)
            .ok_or_else(|| policy("window overflow"))?;
        if ranges.len() > 1_000_000 {
            return Err(policy("too many media windows"));
        }
    }
    Ok(ranges)
}
fn split_window(offset: u64, length: u64, minimum: u64, overlap: u64) -> Option<[(u64, u64); 2]> {
    let left = length.checked_add(overlap)? / 2;
    let right_offset = offset.checked_add(left)?.checked_sub(overlap)?;
    let right = offset.checked_add(length)?.checked_sub(right_offset)?;
    if left < minimum || right < minimum || left >= length || right >= length {
        None
    } else {
        Some([(offset, left), (right_offset, right)])
    }
}
fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| s.to_string()).collect()
}
impl Scanner {
    pub(crate) fn probe_media(
        &self,
        file: &File,
        path: &Path,
        require_video: bool,
        ctx: &Context<'_>,
    ) -> Result<MediaProbe, ScanError> {
        let mut args=arguments(&["-v","error","-threads","1","-max_alloc","67108864","-protocol_whitelist","file,pipe","-format_whitelist",FORMATS,"-show_entries","format=format_name:stream=index,codec_type,codec_name,codec_tag_string,extradata_size,nb_frames:stream_tags=filename,mimetype,handler_name:stream_disposition=attached_pic","-of","json"]);
        args.push(process::fd_path(file));
        let (output, errors) = process::run(
            &self.settings.ffprobe_binary,
            &args,
            file,
            &ctx.bounded(self.settings.probe_timeout_seconds),
            MIB as usize,
        )?;
        if !errors.is_empty() {
            return Err(policy("ffprobe reported a demuxing error"));
        }
        parse_media_probe(
            &output,
            path,
            require_video,
            self.settings.attachment_max_bytes,
            self.settings.attachment_total_bytes,
        )
    }
    pub(crate) fn scan_media(
        &self,
        file: &File,
        path: &Path,
        id: FileIdentity,
        ctx: &Context<'_>,
    ) -> Result<Verdict, ScanError> {
        if !self.settings.large_media_enabled || id.size > self.settings.large_media_max_file_bytes
        {
            return Err(policy(
                "large-media scanning disabled or file exceeds its ceiling",
            ));
        }
        let ctx = ctx.bounded(self.settings.large_media_scan_timeout_seconds);
        let probe = self.probe_media(file, path, true, &ctx)?;
        id.verify(file, path)?;
        let attachments = self.scan_attachments(file, path, id, &probe, &ctx)?;
        if attachments.infected {
            return Ok(attachments);
        }
        let ranges = window_ranges(
            id.size,
            self.settings.large_media_chunk_bytes,
            self.settings.large_media_overlap_bytes,
        )?;
        use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
        let next = AtomicUsize::new(0);
        let requests = AtomicU64::new(0);
        let stop_siblings = AtomicBool::new(false);
        let completed = AtomicUsize::new(0);
        // Clean window replies contain no information needed after this point.
        // Keep only a terminal result, so even very long media files do not retain a
        // String and Result allocation for every completed window.
        let terminal_outcome = Mutex::new(None);
        let workers = self.settings.per_job_scan_workers.min(ranges.len());
        // Scoped threads borrow the already-open descriptor. pread gives every
        // worker its own offset without racing a shared file seek position.
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| {
                    let cancelled = || stop_siblings.load(Ordering::Acquire) || (ctx.cancelled)();
                    let worker_context = Context {
                        deadline: ctx.deadline,
                        cancelled: &cancelled,
                    };
                    while !cancelled() {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(&(offset, length)) = ranges.get(index) else {
                            break;
                        };
                        let mut count = 0;
                        let result = self.media_window(
                            file,
                            path,
                            id,
                            (offset, length),
                            &worker_context,
                            &mut count,
                        );
                        requests.fetch_add(count, Ordering::Relaxed);
                        // A sibling cancellation is not the original failure.
                        // Its terminal result remains in the outcome list.
                        if matches!(result, Err(ScanError::Cancelled))
                            && stop_siblings.load(Ordering::Acquire)
                            && !(ctx.cancelled)()
                        {
                            break;
                        }
                        let terminal = result.as_ref().map_or(true, |v| v.infected);
                        completed.fetch_add(1, Ordering::Relaxed);
                        if terminal {
                            let mut outcome = terminal_outcome.lock().unwrap();
                            // A definite infection has priority over a concurrent
                            // error, just as when every result was collected.
                            if outcome.is_none()
                                || (outcome.as_ref().is_some_and(Result::is_err)
                                    && result.as_ref().is_ok_and(|v| v.infected))
                            {
                                *outcome = Some(result);
                            }
                            stop_siblings.store(true, Ordering::Release);
                            break;
                        }
                    }
                });
            }
        });
        id.verify(file, path)?;
        if let Some(result) = terminal_outcome.into_inner().unwrap() {
            return result;
        }
        ctx.check()?;
        if completed.load(Ordering::Relaxed) != ranges.len() {
            return Err(ScanError::Cancelled);
        }
        Ok(Verdict::clean(format!(
            "large-media format={} initial_windows={} clamd_requests={} coverage=all-bytes; {}",
            probe.format_name,
            ranges.len(),
            requests.load(Ordering::Relaxed),
            attachments.output
        )))
    }
    fn media_window(
        &self,
        file: &File,
        path: &Path,
        id: FileIdentity,
        range: (u64, u64),
        ctx: &Context<'_>,
        count: &mut u64,
    ) -> Result<Verdict, ScanError> {
        let (offset, length) = range;
        ctx.check()?;
        *count += 1;
        let result = self.native(file, offset, length, ctx);
        id.verify(file, path)?;
        match result {
            Err(e) if e.can_subdivide() => {
                let children = split_window(
                    offset,
                    length,
                    self.settings.large_media_min_chunk_bytes,
                    self.settings.large_media_overlap_bytes,
                )
                .ok_or_else(|| {
                    policy(format!(
                        "inspection limit persists at minimum media window: {e}"
                    ))
                })?;
                for (offset, length) in children {
                    let verdict =
                        self.media_window(file, path, id, (offset, length), ctx, count)?;
                    if verdict.infected {
                        return Ok(verdict);
                    }
                }
                Ok(Verdict::clean("complete subdivided window"))
            }
            other => other,
        }
    }
    pub(crate) fn scan_attachments(
        &self,
        file: &File,
        path: &Path,
        id: FileIdentity,
        probe: &MediaProbe,
        ctx: &Context<'_>,
    ) -> Result<Verdict, ScanError> {
        let mut total = 0;
        for attachment in &probe.attachments {
            ctx.check()?;
            id.verify(file, path)?;
            let max = self
                .settings
                .attachment_max_bytes
                .min(self.settings.attachment_total_bytes.saturating_sub(total))
                .min(self.settings.max_file_bytes)
                .min(attachment.size_bytes.unwrap_or(u64::MAX));
            if max == 0 {
                return Err(policy("attachment extraction budget exhausted"));
            }
            let data = if attachment.chapter_samples.is_some() {
                self.chapter_data(file, path, id, attachment, max, ctx)?
            } else {
                let mut args = arguments(&[
                    "-v",
                    "error",
                    "-nostdin",
                    "-n",
                    "-max_alloc",
                    "67108864",
                    "-protocol_whitelist",
                    "file,pipe",
                    "-format_whitelist",
                    FORMATS,
                    "-threads",
                    "1",
                ]);
                if !attachment.is_picture {
                    args.extend([
                        format!("-dump_attachment:{}", attachment.index),
                        "pipe:1".into(),
                    ]);
                }
                args.extend(["-i".into(), process::fd_path(file)]);
                if attachment.is_picture {
                    args.extend(["-map".into(), format!("0:{}", attachment.index)]);
                    args.extend(arguments(&[
                        "-c",
                        "copy",
                        "-frames:v",
                        "1",
                        "-f",
                        "image2pipe",
                        "pipe:1",
                    ]));
                } else {
                    args.extend(arguments(&[
                        "-map", "0:v:0?", "-map", "0:a:0?", "-c", "copy", "-t", "0", "-f", "null",
                        "-",
                    ]));
                }
                let (data, errors) = process::run(
                    &self.settings.ffmpeg_binary,
                    &args,
                    file,
                    &ctx.bounded(self.settings.probe_timeout_seconds),
                    max as usize,
                )?;
                if !errors.is_empty() {
                    return Err(policy("attachment extraction reported a demuxing error"));
                }
                data
            };
            id.verify(file, path)?;
            if data.is_empty()
                || data.len() as u64 > max
                || attachment
                    .size_bytes
                    .is_some_and(|n| n != data.len() as u64)
            {
                return Err(policy("attachment extraction was incomplete"));
            }
            total += data.len() as u64;
            // Native scan only: splitting an attachment could bypass a parser's
            // encryption, expansion, or recursive inspection limits.
            let verdict = self.native_bytes(&data, ctx)?;
            id.verify(file, path)?;
            if verdict.infected {
                return Ok(verdict);
            }
        }
        Ok(Verdict::clean(format!(
            "attachments={} attachment_bytes={total}",
            probe.attachments.len()
        )))
    }
    fn chapter_data(
        &self,
        file: &File,
        path: &Path,
        id: FileIdentity,
        track: &MediaAttachment,
        maximum: u64,
        ctx: &Context<'_>,
    ) -> Result<Vec<u8>, ScanError> {
        let ctx = ctx.bounded(self.settings.probe_timeout_seconds);
        let mut args = arguments(&[
            "-v",
            "error",
            "-threads",
            "1",
            "-max_alloc",
            "67108864",
            "-protocol_whitelist",
            "file,pipe",
            "-format_whitelist",
            "mov",
            "-ignore_chapters",
            "1",
            "-select_streams",
        ]);
        args.push(track.index.to_string());
        args.extend(arguments(&["-show_packets","-show_entries","stream=index,codec_type,codec_name,codec_tag_string,nb_frames:packet=stream_index,pos,size,flags","-of","json"]));
        args.push(process::fd_path(file));
        let (out, err) = process::run(
            &self.settings.ffprobe_binary,
            &args,
            file,
            &ctx,
            MIB as usize,
        )?;
        if !err.is_empty() {
            return Err(policy("MP4 chapter track reported a demuxing error"));
        }
        id.verify(file, path)?;
        let payload: Value =
            serde_json::from_slice(&out).map_err(|_| policy("invalid chapter packet manifest"))?;
        read_chapter_packets(file, id, track, maximum, &payload, &ctx)
    }
}
fn read_chapter_packets(
    file: &File,
    id: FileIdentity,
    track: &MediaAttachment,
    maximum: u64,
    payload: &Value,
    ctx: &Context<'_>,
) -> Result<Vec<u8>, ScanError> {
    let streams = payload["streams"]
        .as_array()
        .filter(|s| s.len() == 1)
        .ok_or_else(|| policy("invalid chapter stream manifest"))?;
    let stream = &streams[0];
    if integer(&stream["index"])? != track.index
        || stream["codec_type"] != "subtitle"
        || stream["codec_name"] != "mov_text"
        || stream["codec_tag_string"] != "text"
    {
        return Err(policy("chapter stream changed classification"));
    }
    let packets = payload["packets"]
        .as_array()
        .ok_or_else(|| policy("missing chapter packets"))?;
    let count = integer(&stream["nb_frames"])?;
    if !(1..=4096).contains(&count)
        || Some(count) != track.chapter_samples
        || packets.len() as u64 != count
    {
        return Err(policy("incomplete or inconsistent chapter sample count"));
    }
    let mut content = Vec::new();
    let mut previous_end = 0;
    for packet in packets {
        ctx.check()?;
        let position = integer(&packet["pos"])?;
        let size = integer(&packet["size"])?;
        let end = position
            .checked_add(size)
            .ok_or_else(|| policy("chapter packet offset overflow"))?;
        if integer(&packet["stream_index"])? != track.index
            || packet["flags"].as_str().is_none_or(|s| s.contains('C'))
            || size < 2
            || position < previous_end
            || end > id.size
            || size > maximum.saturating_sub(content.len() as u64)
        {
            return Err(policy(
                "chapter packet corrupt, overlapping, out-of-file or oversized",
            ));
        }
        let start = content.len();
        content.resize(start + size as usize, 0);
        let data = &mut content[start..];
        file.read_exact_at(data, position)?;
        if u16::from_be_bytes([data[0], data[1]]) as usize > data.len() - 2 {
            return Err(policy("chapter packet text length is truncated"));
        }
        // Preserve trailing boxes and binary data, not only human-readable titles.
        previous_end = end;
    }
    Ok(content)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn window_coverage_and_overlap() {
        assert_eq!(
            window_ranges(25, 10, 2).unwrap(),
            vec![(0, 10), (8, 10), (16, 9)]
        );
        assert_eq!(split_window(20, 20, 6, 2), Some([(20, 11), (29, 11)]));
        assert!(split_window(0, 8, 6, 2).is_none());
    }
    #[test]
    fn unknown_streams_block_and_cover_does_not_count_as_video() {
        let raw=br#"{"format":{"format_name":"mp4"},"streams":[{"index":0,"codec_type":"video","codec_name":"png","disposition":{"attached_pic":1}}]}"#;
        assert!(parse_media_probe(raw, Path::new("media.mp4"), true, 16, 64).is_err());
        let raw=br#"{"format":{"format_name":"mp4"},"streams":[{"codec_type":"video"},{"codec_type":"data","codec_tag_string":"tmcd"}]}"#;
        assert!(parse_media_probe(raw, Path::new("media.mp4"), true, 16, 64).is_err());
    }
    #[test]
    fn attachment_budget_includes_unknown_picture_size() {
        let raw=br#"{"format":{"format_name":"matroska"},"streams":[{"codec_type":"video"},{"index":1,"codec_type":"attachment","extradata_size":1,"tags":{"filename":"font.ttf"}},{"index":2,"codec_type":"video","codec_name":"png","disposition":{"attached_pic":1}}]}"#;
        assert!(parse_media_probe(raw, Path::new("x.mkv"), true, 16, 16).is_err());
        assert_eq!(
            parse_media_probe(raw, Path::new("x.mkv"), true, 16, 32)
                .unwrap()
                .attachments
                .len(),
            2
        );
    }
    #[test]
    fn chapter_packet_includes_all_trailing_bytes() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"xxx\0\x02HiHIDDEN").unwrap();
        let id = FileIdentity::from_metadata(&file.metadata().unwrap());
        let track = MediaAttachment {
            index: 3,
            filename: "chapter".into(),
            size_bytes: None,
            is_picture: false,
            chapter_samples: Some(1),
        };
        let manifest = serde_json::json!({"streams":[{"index":3,"codec_type":"subtitle","codec_name":"mov_text","codec_tag_string":"text","nb_frames":"1"}],"packets":[{"stream_index":3,"pos":"3","size":"10","flags":"K_"}]});
        let ctx = Context {
            deadline: Instant::now() + Duration::from_secs(1),
            cancelled: &|| false,
        };
        assert_eq!(
            read_chapter_packets(&file, id, &track, 20, &manifest, &ctx).unwrap(),
            b"\0\x02HiHIDDEN"
        );
    }

    fn chapter_fixture() -> (File, FileIdentity, MediaAttachment, Value) {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"xxx\0\x02HiHIDDEN\0\x03End").unwrap();
        let id = FileIdentity::from_metadata(&file.metadata().unwrap());
        let track = MediaAttachment {
            index: 3,
            filename: "chapter".into(),
            size_bytes: None,
            is_picture: false,
            chapter_samples: Some(2),
        };
        let manifest = serde_json::json!({"streams":[{"index":3,"codec_type":"subtitle","codec_name":"mov_text","codec_tag_string":"text","nb_frames":"2"}],"packets":[{"stream_index":3,"pos":"3","size":"10","flags":"K_"},{"stream_index":3,"pos":"13","size":"5","flags":"K_"}]});
        (file, id, track, manifest)
    }

    #[test]
    fn hostile_chapter_packet_manifests_never_produce_partial_clean_payloads() {
        let (file, id, track, manifest) = chapter_fixture();
        let ctx = Context {
            deadline: Instant::now() + Duration::from_secs(3),
            cancelled: &|| false,
        };
        for (field, invalid) in [
            ("pos", serde_json::json!(-1)),
            ("pos", serde_json::json!(true)),
            ("pos", serde_json::json!(u64::MAX)),
            ("size", serde_json::json!(1)),
            ("size", serde_json::json!(999)),
            ("size", serde_json::json!("1.0")),
            ("stream_index", serde_json::json!(0)),
            ("flags", serde_json::json!("C_")),
            ("flags", Value::Null),
        ] {
            let mut bad = manifest.clone();
            bad["packets"][0][field] = invalid;
            assert!(
                read_chapter_packets(&file, id, &track, 32, &bad, &ctx).is_err(),
                "{field}"
            );
        }
        for (field, invalid) in [
            ("codec_name", serde_json::json!("bin_data")),
            ("codec_type", serde_json::json!("data")),
            ("codec_tag_string", serde_json::json!("tx3g")),
            ("nb_frames", serde_json::json!(3)),
            ("index", serde_json::json!(true)),
        ] {
            let mut bad = manifest.clone();
            bad["streams"][0][field] = invalid;
            assert!(
                read_chapter_packets(&file, id, &track, 32, &bad, &ctx).is_err(),
                "{field}"
            );
        }
        for packets in [
            serde_json::json!([]),
            serde_json::json!([manifest["packets"][0]]),
            Value::Null,
        ] {
            let mut bad = manifest.clone();
            bad["packets"] = packets;
            assert!(read_chapter_packets(&file, id, &track, 32, &bad, &ctx).is_err());
        }
        let mut overlapping = manifest.clone();
        overlapping["packets"][1]["pos"] = serde_json::json!(3);
        assert!(read_chapter_packets(&file, id, &track, 32, &overlapping, &ctx).is_err());
        assert!(read_chapter_packets(&file, id, &track, 14, &manifest, &ctx).is_err());
        file.write_all_at(b"\xff\xff", 3).unwrap();
        assert!(read_chapter_packets(&file, id, &track, 32, &manifest, &ctx).is_err());
        file.set_len(6).unwrap();
        assert!(read_chapter_packets(&file, id, &track, 32, &manifest, &ctx).is_err());
    }

    #[test]
    fn unsupported_metadata_diagnostics_are_useful_bounded_and_escaped() {
        let payload = serde_json::json!({"format":{"format_name":"matroska"},"streams":[{"codec_type":"attachment","tags":{"filename":"unexpected\n\u{1b}[31m.bin","mimetype":"x".repeat(10000),"unrelated_private_metadata":"must-not-be-logged"}}]});
        let error = parse_media_probe(
            &serde_json::to_vec(&payload).unwrap(),
            Path::new("/downloads/sample.mkv"),
            true,
            16,
            64,
        )
        .unwrap_err()
        .to_string();
        for expected in [
            "path=\"/downloads/sample.mkv\"",
            "container=\"matroska\"",
            "stream_index=\"unknown\"",
            "codec=\"unknown\"",
            "declared_bytes=\"unknown\"",
            "\\n",
            "\\u001b",
            "[truncated]",
        ] {
            assert!(error.contains(expected), "missing {expected}: {error}");
        }
        for forbidden in ["\n", "\u{1b}", "must-not-be-logged"] {
            assert!(!error.contains(forbidden));
        }
        assert!(error.len() < 1500);
        let payload = serde_json::json!({"format":{"format_name":"mp4"},"streams":[{"index":2,"codec_type":"data","codec_name":"bin_data","codec_tag_string":"tmcd","tags":{"handler_name":"TimeCodeHandler"}}]});
        let error = parse_media_probe(
            &serde_json::to_vec(&payload).unwrap(),
            Path::new("sample.mp4"),
            true,
            16,
            64,
        )
        .unwrap_err()
        .to_string();
        for expected in [
            "stream_index=2",
            "codec_tag=\"tmcd\"",
            "handler=\"TimeCodeHandler\"",
        ] {
            assert!(error.contains(expected));
        }
    }

    #[test]
    fn attachment_metadata_and_budgets_fail_before_extraction() {
        let mut payload = serde_json::json!({"format":{"format_name":"matroska"},"streams":[{"codec_type":"video"},{"index":1,"codec_type":"attachment","extradata_size":12,"tags":{"filename":"font.TTC","mimetype":"application/octet-stream"}}]});
        let parse = |payload: &Value, total| {
            parse_media_probe(
                &serde_json::to_vec(payload).unwrap(),
                Path::new("sample.mkv"),
                true,
                16,
                total,
            )
        };
        assert!(parse(&payload, 64).is_ok());
        for invalid in [
            Value::Null,
            serde_json::json!(0),
            serde_json::json!(-1),
            serde_json::json!("12"),
            serde_json::json!(true),
            serde_json::json!(17),
        ] {
            payload["streams"][1]["extradata_size"] = invalid;
            let error = parse(&payload, 64).unwrap_err().to_string();
            assert!(error.contains("declared_bytes=") && error.contains("max_attachment_bytes=16"));
        }
        payload["streams"][1]["extradata_size"] = serde_json::json!(12);
        let mut duplicate = payload["streams"][1].clone();
        duplicate["index"] = serde_json::json!(2);
        payload["streams"].as_array_mut().unwrap().push(duplicate);
        let error = parse(&payload, 20).unwrap_err().to_string();
        assert!(error.contains("reserved_bytes=24") && error.contains("max_total_bytes=20"));
        payload["streams"][2]["index"] = serde_json::json!(1);
        assert!(parse(&payload, 64)
            .unwrap_err()
            .to_string()
            .contains("duplicate"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_matroska_attachment_scan_keeps_the_original_native_deadline() {
        use std::{
            io::Read,
            os::unix::{fs::PermissionsExt, net::UnixListener},
        };
        let directory = tempfile::Builder::new()
            .prefix("ti-deadline-")
            .tempdir_in("/tmp")
            .unwrap();
        let source = directory.path().join("media.mkv");
        std::fs::write(&source, b"\x1aE\xdf\xa3source bytes").unwrap();
        let probe = directory.path().join("ffprobe");
        std::fs::write(&probe, b"#!/bin/sh\nprintf '%s' '{\"format\":{\"format_name\":\"matroska\"},\"streams\":[{\"index\":1,\"codec_type\":\"attachment\",\"extradata_size\":3,\"tags\":{\"filename\":\"font.ttf\"}}]}'\n").unwrap();
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o700)).unwrap();
        let extract = directory.path().join("ffmpeg");
        std::fs::write(&extract, b"#!/bin/sh\nprintf abc\n").unwrap();
        std::fs::set_permissions(&extract, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.path().join("clamd.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut command = [0; 10];
                stream.read_exact(&mut command).unwrap();
                loop {
                    let mut header = [0; 4];
                    stream.read_exact(&mut header).unwrap();
                    let n = u32::from_be_bytes(header) as usize;
                    if n == 0 {
                        break;
                    }
                    let mut payload = vec![0; n];
                    stream.read_exact(&mut payload).unwrap();
                }
                std::thread::sleep(Duration::from_millis(650));
                let _ = stream.write_all(b"stream: OK\0");
            }
        });
        let scanner = Scanner::new(ScanSettings {
            socket_path: socket,
            scan_timeout_seconds: 1,
            ffprobe_binary: probe,
            ffmpeg_binary: extract,
            ..Default::default()
        });
        let ctx = Context {
            deadline: Instant::now() + Duration::from_secs(5),
            cancelled: &|| false,
        };
        assert!(matches!(
            scanner.inspect(&source, None, &ctx, true),
            Err(ScanError::Timeout)
        ));
        server.join().unwrap();
    }
}
