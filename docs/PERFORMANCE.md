# Edge cases, memory, and storage I/O audit

This audit compares the initial Rust rewrite with the revised Rust code on
12 October 2026. The expected workload is mostly large media files.
The original Python implementation and its regression cases were used as the
behavior reference. Measurements below are **Rust before versus Rust after**,
not a Rust-versus-Python speed comparison.

The changes remove redundant work while retaining scan coverage, window overlap,
scan concurrency, scan-progress checkpoint frequency, copy verification, and
durable commits.
They do not establish a universal minimum memory footprint or a guaranteed
end-to-end speedup on a particular NAS. Large payloads remain streamed through
bounded buffers; they are not loaded into memory as whole media files.

## Measured improvements from the initial audit

These first measurements precede the approved idle-connection follow-up. Its
additional savings and the patched SQLite version are recorded below.

| Workload | Before | After | What this means |
| --- | ---: | ---: | --- |
| New verified copy of an 8 MiB payload | 24 MiB read | 16 MiB read | Hash the source during copying; still reread and hash the entire destination. Both versions write 8 MiB. |
| Ten unchanged download polls | 20 job UPDATEs | 0 | Live progress remains available; durable state changes still commit immediately. |
| Ten recovery passes for an already paused, unowned scan | 10 scan-run UPDATEs | 0 | Avoid rewriting facts that already match. |
| Worker selection with 1,000 terminal jobs and one active job | 1,001 decoded rows | 1 active row | Filter in SQLite before allocating job JSON; public history remains complete. |
| Render the same 1,000-job UI | 7,528,641 bytes peak extra Rust heap | 4,165,610 bytes | About 45% less temporary heap, with byte-identical HTML. |
| Wrap 1,000 existing job objects for JSON output | 4,259,648 bytes peak extra Rust heap | 1,179,648 bytes | Transfer ownership instead of cloning the job list; serialized output is identical. |
| Read a 4 KiB private state file, 1,000 times | 9,000 Rust allocations | 1,000 | Size the bounded allocation once instead of repeatedly growing it. |
| Hash a 4 KiB state file | 1,048,640 bytes peak extra Rust heap | 4,160 bytes | Small files use a small buffer; large files keep the existing 1 MiB buffer. |
| Send 512 MiB of already-extracted attachments | 512 MiB temporary writes plus 512 MiB readback | Neither temporary operation | Send the existing bounded bytes directly to ClamD. |

Copy and polling counts come from regression instrumentation on the real
application paths. A retry of an already completed 8 MiB copy still reads both
source and destination, totaling 16 MiB: an old receipt never substitutes for
content verification. Source changes during copying and corrupted output both
prevent publication and the completion receipt.

UI measurements use a release build on macOS ARM64 with an allocation-counting
allocator. Three renders confirmed identical HTML for the two compared versions.
The published probe later received generic example labels, so those historical
HTML byte counts are not a checksum of this release.
After the first render, measured times were 6.92–7.45 ms before and 5.07–5.28 ms
after. These are small instrumented measurements, not a server latency promise;
the heap figures exclude SQLite's C allocator, ClamD, and operating-system caches.

The attachment benchmark uses three alternating fresh-process runs on Linux
ARM64, each sending 32 attachments of 16 MiB to a mock daemon. Median process
RSS was 25,716 KiB before and 24,684 KiB after; median transport throughput was
1,064.59 versus 6,143.15 MiB/s. This isolates transport overhead and **does not
measure antivirus or whole-media throughput**. Media without attachments do
not receive that attachment-specific benefit. ClamD may still use its own
temporary storage for INSTREAM requests.

A separate Linux persistence probe performed 1,000 operations of each type.
Across the probe, `chmod` calls fell from 17,012 to 2, `fsync` calls from 10,021
to 5,021, and `pwrite` calls from 43,128 to 36,128. Repeated identical indexed
checkpoints fell from 15,000 to 8,000 write calls. Real changed-job operations
retained their 12,000 write calls and the same durability. The remaining writes
include SQLite shared-memory lifecycle work when the final connection closes.
Five alternating release runs without tracing reduced the median time for
1,000 identical indexed checkpoints from 1,427.424 ms to 170.441 ms. The matching
4 KiB state-read medians were 5.473 ms and 1.842 ms. Storage-sensitive timings
were noisy, so allocation and syscall counts provide stronger evidence than
small timing differences.
These syscall counts are not counts of physical drive writes or a prediction
of SSD lifetime: page cache, filesystem journaling, controller caches, and the
storage device all affect the physical result.

## Why these changes preserve behavior

Database UPDATEs use NULL-safe comparisons: a transition to or from NULL still
writes. Changed leases, timestamps, scan checkpoints and progress facts remain
durable. Permission checks avoid `chmod` only when the existing private mode is
already correct; incorrect permissions are still repaired and symlinks refused.

Torrent uploads keep their original bytes, including tracker and v2 metadata.
The workflow saves those bytes once and transfers the buffer to qBittorrent's
multipart request. Authentication retries create independent cursors over the
same allocation rather than copying it or reloading it from SQLite.

Job enrichment uses bulk queries and hash maps instead of per-job database
lookups and repeated linear searches. Scan status uses SQL counts and existence
checks. ETA retains the original minimum of three samples, bounded 100-sample
history, size/time regression, confidence levels, elapsed-current adjustment,
and suppression when the current file is unexpectedly slow.

File-backed ClamD requests allocate at most `min(request size, 1 MiB)`. Embedded
objects retain their existing size bounds and are scanned completely. MP4
chapter packets are read directly into their final buffer. Clean media-window
responses are discarded after counting completion; infections and errors remain
available, with infection taking precedence. None of these changes removes a
window, an overlap, an attachment, or an integrity check.

## Edge cases repaired and checked

- Temporary qBittorrent lookup failures retain queued work for retry instead of
  prematurely making the job terminal. Historical completion callbacks remain
  harmless; conflicting active ownership still fails.
- Incomplete, moving, or checking torrents defer post-promotion actions. A
  missing copy destination is checked before enumerating a large source tree.
  Incomplete pinned routes fail instead of silently choosing a legacy layout.
- Recovery clears stale ownership and interrupted file start times while
  preserving valid completed checkpoints.
- Linux ClamD sockets use atomic close-on-exec, preventing media parser children
  from inheriting another scan's connection. Malformed scanner/database version
  replies cannot authorize scans.
- A native Matroska scan, its metadata probe, and its attachment scans share the
  native deadline. Explicit fallback retains its configured longer budget.
- Backup ZIP metadata is bounded and validated before extraction. Duplicate
  central-directory entries are rejected even when the ZIP library hides them
  behind one unique filename. Unexpected paths cannot cause partial extraction.
- Private-state reads reject symlinks and nonregular files, including FIFOs.
  Existing permissions and file-size limits remain enforced.
- Extra HTTP path segments cannot invoke job actions. Pause/drain accounts for
  an unfinished upload and releases its guard on disconnect. Untrusted names
  and error text remain escaped in HTML.
- Expanded archive regressions cover RAR4/RAR5 directory entries, hidden payloads,
  corrupt CRCs, missing end markers, trailing data, encryption, multipart input,
  nested shared budgets, depth limits, disk reserve, symlinks and scratch cleanup.

See [the validation record](PARITY.md) for final test results and supported
environments. These tests increase confidence; they cannot prove the absence
of every production race, malformed media case, or storage failure.

At the end of that performance audit, validation passed 98 ordinary tests on
macOS ARM64 and 101 on Linux ARM64,
eight mock/parser integrations, nine real ClamD/FFmpeg/libarchive integrations,
and the real qBittorrent v4.5.2 integration. Formatting and all-target Clippy with
warnings denied passed. The audited release image built with Rust 1.90 and
passed a non-root, read-only, network-isolated startup/HTTP/SIGTERM smoke test.
It contains no Python interpreter. The disposable local image is
`torrent-intake:rust-audited`; no deployed container was replaced.
The follow-up reran the full suites, real qBittorrent and scanner integrations,
and runtime smoke test after enabling the connection and updating SQLite.

## The approved idle SQLite connection

An experimental idle SQLite connection kept the WAL lifecycle open while normal
operations continued using their own connections. In the probe, repeated reads
and identical updates made zero database write calls; 1,000 changed-job operations
fell from 12,000 to 2,002 write calls. It retained about 84 KiB of additional
SQLite allocation plus a small Rust wrapper, including a test with 10,000 history
rows and a roughly 47 MiB database. The actual cost depends on the schema and
SQLite build; this is not a hard memory ceiling.

**The user approved this option, and it is now enabled.** One private connection
stays open until the last `Database` clone is dropped. Normal operations still
use independent connections. The idle connection has no read transaction, so
it cannot pin a snapshot or prevent checkpoints. It is opened after closing the
migration connection, avoiding retention of that connection's migration cache.

The tradeoff is a small persistent RAM allocation and WAL/SHM files remaining
between operations. FULL commit synchronization and ordinary 1,000-page
automatic checkpointing remain in place. SQLite can reuse the journal instead
of repeatedly cleaning it up and recreating it after individual operations.
See SQLite's [connection and checkpoint lifecycle](https://www.sqlite.org/wal.html).

The dependency was also updated from bundled SQLite 3.46.0 to 3.53.2 through
`rusqlite` 0.40.2. The older version predates the fix for SQLite's rare WAL-reset
race between concurrent writes and checkpoints. A regression now checks that
the bundled version includes the fix. See the
[SQLite advisory](https://www.sqlite.org/wal.html#walresetbug) and
[rusqlite release notes](https://github.com/rusqlite/rusqlite/releases/tag/v0.40.2).

The original 84 KiB and write-call figures above describe the pre-approval
experiment on SQLite 3.46.0. The shipped implementation is measured again with
the patched SQLite version; do not treat the experimental memory figure as a
guaranteed allocation limit.

With SQLite 3.53.2, opening the production `Database` retained 86,672 bytes in
SQLite's allocator (about 85 KiB) and 207 Rust bytes including the path and shared
handle in the probe. Its 1,000 repeated reads, identical job patches and identical
checkpoint patches each issued zero write calls. The 1,000 changed-job patches
issued 2,012 write calls, compared with the pre-approval 12,000-call result.
This comparison includes the SQLite update, not just the idle handle. The new
probe's cold-start RSS includes initialization and migration; it does not isolate
the incremental idle-connection cost. Timing samples taken while other builds
ran are excluded from speed comparisons.

### Write calls and SSD wear

A write call is the application's request for the operating system to write
some bytes. It is not necessarily a separate physical write to the SSD. The OS
may combine or cancel writes, and the SSD may perform additional internal writes
when managing flash blocks. Reducing actual NAND writes can reduce wear, but
the reduction in application write calls cannot establish a percentage increase
in drive life. Kingston explains the distinction between host writes and NAND
writes in its [flash memory guide](https://media.kingston.com/pdfs/MKF-283.3-Flash-Memory-Guide_EN.pdf).

Here, keeping the connection open removes repeated database housekeeping and
reduces unnecessary checkpoint work. It does not reduce the bytes needed to
download and store a media. In particular, many of the old shared-memory-file
writes were canceled by the OS before reaching storage; eliminating them is
still useful overhead reduction, but it is not equivalent to avoiding that many
physical SSD writes. No drive-level endurance measurement was made.

### What reducing concurrency would mean

Concurrency is how much work may be in progress at the same time. This app has
separate limits for simultaneous torrent scans, large-job scans, per-job media
window workers, and total ClamD requests. For example, reducing a two-job limit
to one makes the second job wait, while reducing four window workers to one
processes a media's ranges one at a time. The same bytes still need inspection.

Fewer active workers can reduce buffers, parser processes and ClamD work in
memory, but may leave CPU or storage capacity idle and make the queue finish
later. It can also reduce competing I/O, so the actual speed effect depends on
the hardware and workload. It is not a reliable way to reduce the total bytes
written. **No concurrency limit was changed.** The supplied defaults remain two
simultaneous jobs, one large job, and one window worker per job.

Other resource reductions would involve tradeoffs and were left unchanged:

| Possible change | Benefit | Cost |
| --- | --- | --- |
| Fewer concurrent scans/windows | Lower peak controller/ClamD memory | Potentially lower throughput |
| Less frequent durable checkpoints or weaker SQLite synchronization | Fewer sync operations | More lost progress after a crash; weaker power-loss guarantees |
| Move ClamD scratch from tmpfs to disk | Lower RAM pressure | More disk writes and potentially slower scanning |
| Hold archive extraction in RAM | Fewer scratch-file writes | Potentially much higher peak RAM |
| Skip the destination reread after copying | Fewer reads | Lose the current complete-content verification |

The existing deployment already disables concurrent ClamAV database reload to
limit the reload memory spike; scans may wait during a reload. This was not
changed in the audit. ClamD's signatures and tmpfs usage are separate from the
controller heap, so lowering controller allocations does not establish the
memory footprint of the whole stack. The relevant behavior is described in
[ClamAV's Docker guidance](https://docs.clamav.net/manual/Installing/Docker.html).
SQLite's durability distinctions are documented in
[PRAGMA synchronous](https://www.sqlite.org/pragma.html#pragma_synchronous).
Backup encryption also retains its approximately 128 MiB scrypt working memory;
lowering that cost would change the password-hardening properties and compatible
backup parameters. The small-buffer improvements do not remove that peak.

## Legacy cleanup without losing supported behavior

The review separates code that still provides compatibility from redundant work:

| Item | Change or reason to retain it |
| --- | --- |
| qBittorrent response handling | Move the owned JSON array/row instead of deep-cloning it before discarding the original. No cache or changed request behavior. |
| SQLite's unused prepared-statement cache and WebAssembly backend | Disable these optional dependency features; application queries never used the statement cache. SQLite's actual page cache is unchanged. |
| Template filesystem loader | Remove the unused dependency feature. Templates remain embedded in the binary. |
| Independent AES-GCM reference and HTTP test helpers | Keep as development dependencies; production encryption still uses its existing AES/CTR/GHASH implementation. |
| Application image build | Compile only the controller and copy helper it ships. The separate ClamD image builds its own launcher. |
| Original Python application/tests/helpers | Removed when Rust became primary. Retained synthetic encrypted backup fixtures prove compatibility without a Python runtime. The prior implementation remains upstream. |
| Old qBittorrent endpoint names | Keep support for qBittorrent v4 as well as newer versions. The real v4.5.2 integration exercises this fallback. |
| Historical NAS choices, copy routes/receipts, missing hook-kind fields | Keep so existing jobs resume and retries go to the originally pinned destination. Removing these branches can change where files are copied. |
| Original settings keys, torrent metadata and encrypted backup format | Keep existing configuration imports, backups, private trackers, v2 metadata, and restart retries working. Small inactive settings do not create background tasks or repeated I/O. |
| Custom hooks and bundled `rsync` | Keep the supported hook environment. Built-in copying does not invoke rsync, but a configured custom hook may. |

The build cleanups reduce dependency and build complexity; no runtime RSS saving
is claimed for merely moving a dependency to the test section. The qBittorrent
change removes an actual temporary duplicate allocation on each affected call.
Removing the old Python sources simplifies the repository; it does not itself
make the already-native Rust process scan faster or write less.

The root Dockerfiles and `.github/workflows/publish-ghcr.yml` now build and
publish the Rust images after validation. The redundant Rust-only workflow was
removed. Publishing images does not update an existing deployment; see
[the release guide](RELEASING.md).

## Reproducing the measurements

Run from the repository root, using the same toolchain, fixture sizes, and build
mode for both source revisions:

```sh
cargo run --release --locked --manifest-path Cargo.toml \
  --example http_profile -- 1000
cargo run --release --locked --manifest-path Cargo.toml \
  --example persistence_probe -- 1000
# Seed 10,000 historical rows; the same production idle connection is retained:
cargo run --release --locked --manifest-path Cargo.toml \
  --example persistence_probe -- 1000 10000
sh scripts/scanner-transport-benchmark.sh
```

The probes use disposable state and generated data, not an existing database or
media library. Linux `/proc/self/io` counters are available only on Linux;
Rust allocation counters do not include SQLite unless explicitly reported.
Use `strace -c` around the compiled persistence executable to count syscalls,
and run timing samples separately because tracing adds overhead. The scanner
script uses a mock Unix-socket daemon and prints its own measurement boundaries.

The before/after audit did not use a real production signature database, a
multi-gigabyte media transfer, a physical NAS, or drive-level write telemetry.
No production deployment, database, downloaded media, or credentials were
modified. Test representative large media files and folders on the intended mounts
before replacing an established controller.
