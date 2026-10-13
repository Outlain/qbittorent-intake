# How the Rust scanner decides whether a file may proceed

The scanner returns a clean result only after every inspection required by its
policy succeeds. A connection error, timeout, unexpected response, parser warning,
changed file, lost lease, encrypted object, or exhausted inspection limit returns
an error. The workflow must keep that content held. An error is never converted
into a clean verdict.

The word **clean** has a specific scope: the configured inspection completed
without a malware detection. Antivirus scanning cannot establish that arbitrary
software or media is harmless. Large-media byte windows in particular do not
provide the same parser context as one complete native scan. They implement the
upstream application's explicit large-media policy, with separate inspection of
embedded objects.

## A map of the implementation

| Module | Question it answers |
| --- | --- |
| `src/scanning/mod.rs` | Which policy applies, and are the engine and file identity valid? |
| `src/scanning/protocol.rs` | How do bytes reach ClamD, and what does its reply mean? |
| `src/scanning/media.rs` | Which media is eligible, and how are all bytes and embedded objects inspected? |
| `src/scanning/process.rs` | How are FFmpeg/FFprobe processes bounded and stopped? |
| `src/scanning/archive.rs` | How can archive members be extracted and scanned without trusting their filenames? |
| `src/scanning/archive/framing.rs` | Does an archive have complete, single-volume framing and valid headers? |
| `src/scanning/archive/library.rs` | Where are the small, explicitly unsafe libarchive calls contained? |

The public `Scanner` is synchronous. The HTTP service should call it from a
blocking worker, not directly on a Tokio executor thread. One shared
`Arc<Scanner>` keeps its ClamD capacity limit global across jobs. Creating one
scanner per file would create independent limits and could overload the daemon.

## Public interface and ownership

```rust,ignore
let settings = ScanSettings::from_values(&configuration)?;
let scanner = Scanner::new(settings);
let before = FileIdentity::read(path)?;
let result = scanner.scan_path(path, Some(before), &cancelled)?;
```

`cancelled` is a thread-safe callback returning `true` when the job is cancelled,
the service is stopping, or the database lease has been lost. The workflow owns
lease renewal and can combine all three conditions in that callback. The scanner
checks it while waiting for daemon capacity, sending bytes, receiving replies,
running parsers, processing chapter packets, and scanning archive members. Media
workers may invoke it concurrently; a lease heartbeat implementation must protect
any mutable state with a mutex or atomics.

`Result<ScanResult, ScanError>` makes three outcomes explicit:

- `Ok` with `clean == true`: every required inspection completed.
- `Ok` with `infected == true`: ClamD reported a malware signature.
- `Err`: inspection did not complete under the configured policy.

The first two include scanner identity, policy fingerprint, start time, duration,
method, output summary, and the inspected file identity. The error carries a typed
reason; a caller must not treat `Err` as a negative malware detection.

`FileIdentity` includes device, inode, size, and modification/change timestamps
with nanosecond components. The scanner opens with `O_NOFOLLOW` and validates a
regular file. `O_NONBLOCK` prevents a replaced FIFO from hanging the open before
that check. It compares both the descriptor and the pathname with the original
identity after inspection. A replacement inode containing identical text still
fails this check. This binds the verdict to the object inspected; the workflow
must separately check its manifest again before moving or promoting content.

## Scanner freshness and policy identity

Before each public scan, the scanner sends `zVERSION\0` to ClamD's Unix socket.
The response must contain nonempty engine and database versions without
whitespace, plus a parseable definition timestamp. The parser accepts ClamD's
traditional date form and RFC 2822 dates. Missing versions or dates block
scanning. Definition age produces a healthy, warning, or stale health state;
stale definitions block new scans.

Status requests may reuse a health result for `scanner_health_cache_seconds`.
Starting a scan always refreshes it; a cached healthy UI badge cannot authorize
a scan after the definitions become stale. Daemon I/O failures clear the cache.

The policy fingerprint is a SHA-256 digest of the inspection choices, including
native size, media ceiling, window geometry, attachment budgets, archive settings,
and the implementation version. A setting that changes what is inspected changes
that fingerprint. The Rust implementation intentionally has a distinct policy
identity from Python, so the workflow should not reuse an old clean result solely
because the engine and definition versions match.

Configuration translation preserves the existing public `TI_*` names. The
application stores names without the prefix, for example
`scanner_max_file_mib`. `ScanSettings::from_values` converts MiB/GiB to checked byte
counts; an overflowing or incorrectly typed value is an error. Internal fields
use explicit `*_bytes` and `*_seconds` names to make comparisons readable.

## ClamD INSTREAM, step by step

The scanner never asks ClamD to open a torrent-controlled path. It opens the file
itself and sends its contents through the INSTREAM protocol:

1. Connect to the configured local Unix socket within the connection deadline.
2. Send `zINSTREAM` followed by a NUL byte.
3. For each chunk, send a four-byte **big-endian** length, then exactly that many
   bytes. Chunks are at most 1 MiB.
4. Send a zero length to end the stream.
5. Read a reply ending with a NUL byte. An EOF without that terminator is an error.

File-backed reads use `pread` (`FileExt::read_at`), which takes an explicit byte
offset. Parallel windows cannot change one another's seek positions. Each active
file request allocates at most `min(request bytes, 1 MiB)` for its read buffer;
the scanner does not load a whole media or window into memory. Short reads are
handled; an unexpected end of file blocks the scan. Already-extracted attachment
bytes use the same request protocol directly from their bounded immutable buffer.
Writes account for partial progress. Socket timeouts wake the worker periodically
so it can check its overall deadline and cancellation callback.

On Linux, daemon sockets are created with `SOCK_CLOEXEC` atomically. This prevents
a concurrently launched parser from inheriting another worker's ClamD connection.
Non-Linux development builds set `FD_CLOEXEC` after socket creation instead.

Only `OK` or a response ending in `: OK` is clean. A signature ending in ` FOUND`
is infected, except for encryption/corruption heuristics, which mean inspection
was incomplete. Limit heuristics are recognized before the general `FOUND` case.
Responses are capped at 1 MiB.

The global capacity guard is released on every return path, including errors and
cancellation. Waiting for a slot has the same cancellation/deadline checks as an
active request.

## Choosing native, media, or archive inspection

A file within the native byte ceiling first gets a complete INSTREAM scan. If
that succeeds, it normally finishes. Matroska is the special case: its magic
bytes trigger a structural probe and complete attachment scans even below the
native ceiling, because a native ClamD scan need not expose every attachment.
That native scan, structural probe, and attachment inspection share the original
native deadline. The longer media/archive deadline applies only when an explicit
fallback is selected.

A file above the native ceiling, or a native scan hitting `MaxFileSize`,
`StreamMaxLength`, or `MaxScanSize`, may use a bounded fallback. ZIP/RAR magic
selects archive inspection. Everything else must pass the media policy.
Unknown, recursion, and unrelated parser limits do not qualify for fallback.
A filename extension never turns an arbitrary oversized file into eligible media.

## Large media and complete embedded objects

FFprobe is restricted to the approved container formats and to the `file` and
`pipe` protocols. Its metadata output is bounded. The policy permits video,
audio, subtitle, and recognized attachment streams. It rejects unknown stream
types, excessive stream/attachment tables, duplicate attachment indices, and
missing or invalid declared attachment sizes. Rejection messages identify the
source, container, stream, codec, and relevant attachment sizes/budgets. Only
selected metadata is included; values are bounded and escaped so control
characters and arbitrary private tags do not enter the diagnostic output.

Raw TrueHD is a narrow exception: it must probe as exactly one TrueHD audio
stream and have a `.thd` or `.truehd` filename. A cover picture does not satisfy
the real-video requirement for a video container.

Attachments must have an approved font/image/subtitle/text extension, or the
specific Matroska Kodi metadata name and text/XML MIME combination. This is
permission to **extract and scan** the attachment, not permission to trust it.
Attached JPEG/PNG/GIF/WebP pictures are identified by codec and stream index.
Picture and chapter sizes are initially unknown, so each reserves the full
per-object allowance before extraction. Known-size objects reserve their stated
size. This prevents many unknown-size objects from bypassing the total budget.

FFmpeg sends each extracted object to a bounded pipe. Embedded filenames are
never used as output paths. The parent requires a nonempty object, the stated
size when one exists, and the per-object/total limits. It sends that complete
bounded byte buffer directly through one ClamD INSTREAM request, without writing
or rereading an attachment temporary file or allocating a second transfer buffer.
This uses the same global capacity, deadline, cancellation, and response checks as
file-backed requests. Attachment limits do not cause subdivision or a second
fallback. ClamD's own internal temporary storage is separate and unchanged.

MP4 chapter text deserves a separate path. FFprobe normally presents QuickTime
chapter tracks as `bin_data`. The scanner only admits the exact MP4/MOV
`bin_data` + `text` combination with a bounded sample count. A second probe using
`-ignore_chapters 1` must classify it as `mov_text` subtitle data and return the
complete packet manifest. Every offset, size, stream index, count, and corruption
flag is checked. Packets must be ordered, nonoverlapping, within the source file,
and within the extraction budget. The scanner reads raw packets directly into
the final bounded payload buffer, preserving their two-byte text length and
**all trailing bytes/boxes** without a duplicate per-packet buffer. Exporting
only readable chapter titles would discard content that still needs inspection.

Once embedded objects are complete, overlapping windows cover all source bytes.
For example, a 25-byte file with 10-byte windows and 2-byte overlap produces
`[0,10)`, `[8,18)`, and `[16,25)`. There are no sampled or skipped regions.
Configured workers inspect initial windows in parallel, capped by the shared
ClamD slots. A malware finding or error cancels sibling work; all threads finish
before the descriptor can close. An observed infection takes priority over a
sibling error. Successful windows are counted and their clean reply strings
discarded; only a terminal error or infection is retained. This keeps result
storage from growing with the number of windows. Without an infection,
incomplete coverage cannot become clean.

Only a window's `MaxFileSize` or `StreamMaxLength` limit can trigger subdivision.
The two child ranges still overlap and cover the entire parent. `MaxScanSize`
inside a window, recursion limits, and unknown limits remain errors: splitting
those could bypass limits on expanded or parsed content. Subdivision stops at the
configured minimum size, where a continuing limit keeps the file held.

## Parser processes and resource budgets

FFmpeg/FFprobe run in separate process groups. Their address space is limited to
512 MiB, individual FFmpeg allocations to 64 MiB, file output to zero, CPU time
to the remaining operation budget, and core dumps to zero. Stdout and stderr have
separate byte caps. The input is the inherited descriptor (`/proc/self/fd/N` on
Linux), not a second lookup of the torrent path.

The fork-to-exec callback only performs the small libc operations needed for
resource limits, descriptor inheritance, process-group creation, and umask. Rust
allocation, logging, parser loading, and formatting occur outside that callback.
The parent monitors output without blocking indefinitely. A guard kills the
process group and reaps the child on cancellation, deadline, excessive output,
parser failure, or any early return.

## Archive extraction without trusting archive paths

Archive inspection re-executes the service binary in its internal
`--archive-helper` mode. `helper_main()` must run before Tokio or the HTTP server
starts. The helper gets 1 GiB address space, a CPU budget, a file-size ceiling,
no core dumps, and a private working directory. Production uses libarchive's
ZIP/RAR/RAR5 readers; the service remains Rust and has no Python runtime.

Before libarchive extracts anything, a framing pass checks a complete ZIP end
record or walks bounded RAR headers. RAR checks include header CRCs, required end
markers, single-volume flags, encryption flags, declared unpacked/packed sizes,
and member CRC32 checksums. Missing ends and trailing data fail. RAR5 files
without the required CRC32 are held. Parser warnings also fail inspection.

Every archive entry counts against the shared entry limit, including directories
and nested archives. Extraction rejects absolute/traversing/control-character
paths, Windows drive paths, links, special files, encryption, and unknown sizes.
Valid directory entries are allowed only when they contain no declared or hidden
payload. Directory names never create paths on disk.

A generated name such as `member-000042.mkv` receives an extracted member. Its
original name remains a diagnostic label. The extension is retained only when it
is a short ASCII alphanumeric suffix; this allows nested raw TrueHD policy checks
without trusting a path. Writes check actual expanded bytes, declared size,
checksums, and remaining disk space plus reserve. Nested archive copies consume
the same expansion budget as their parent; each nesting level counts toward the
depth limit.

For a leaf, the helper emits one bounded JSON record and waits. The parent checks
that the generated name, regular-file type, link count, and size agree, then
scans that leaf. Only a complete clean result earns an `ok` acknowledgement. The
helper then removes that member before continuing. At completion the helper's
manifest counts must match the parent's count. A missing completion record,
helper crash, or incomplete acknowledgement is an error.

Custom scratch storage must already exist, resolve to its exact absolute path,
and have its configured readable mount marker. It is rechecked while scanning.
There is no fallback to the data disk when that storage is missing. The private
workspace and lock must belong to the current user and exclude group/other
permissions. Shared locks protect active scans; startup cleanup takes an
exclusive nonblocking lock and removes only generated stale workspace names.

## Verification and practical boundaries

`cargo test` covers response classification, date/version validation, actual local
socket INSTREAM framing for file and attachment bytes, descriptor inheritance,
cancellation while waiting on a silent daemon, capacity release, file replacement,
media admission, attachment budgets and diagnostics, chapter payload retention
and malformed manifests, window geometry, traversal rejection, malformed archive
framing, and generated helper filenames. Linux tests also check the shared native
Matroska deadline, both parser output caps, prohibited regular-file writes, and
parser termination after its output pipes close. Unix socket tests need permission
to bind local Unix sockets.

The ignored `scanner_integration` suite runs real subprocesses. It tests clean,
infected and nested ZIP members, shared expansion/entry/depth limits, disk reserve,
traversal, symlinks, truncation, RAR4/RAR5 directory payloads and framing/checksum
failures, complete Matroska attachment extraction, nameless MP4 cover extraction,
raw MP4 chapter packets with parallel windows, and the repository's upstream
compressed, solid and encrypted RAR5 fixtures. `scripts/scanner-integration.sh`
runs it on Linux with FFmpeg, libarchive, and a temporary ClamD using synthetic
EICAR definitions.
It first uses a mock daemon that recognizes an exact complete attachment; it then
routes scans through the real daemon. The proxy supplies a **test-only** fresh
version response because standalone synthetic definitions lack FreshClam dates.
The public production scan entry point never bypasses freshness checks.

`sh scripts/scanner-transport-benchmark.sh` compares the previous attachment
tempfile path with direct byte streaming in fresh test processes. It measures
controller transport and RSS against a draining mock daemon. Its throughput is
not a measurement of production antivirus or end-to-end media scanning speed.

Linux is the production target for the scanner and its resource limits. Core Rust
and protocol tests also build on macOS; system libarchive capabilities and memory
limit behavior can differ. Windows is not supported by this Unix-descriptor
implementation. Runtime dependencies remain ClamD, FFmpeg/FFprobe, and libarchive;
rewriting the controller does not replace those mature parsing engines.

Passing unit tests alone is not a production parity claim. Run the Linux parser
suite and deployment tests, and validate qBittorrent behavior in a disposable
staging environment before switching a live intake installation to this rewrite.
