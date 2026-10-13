# Compatibility and validation record

## What was rewritten

The behavior reference is upstream `Outlain/torrent-intake` commit `886d75a`.
The application controller, HTTP server, persistence layer, scanner integration,
job scheduler, copying and hook execution, backup/restore, ClamD sidecar
launcher, and optional copy-hook helper are implemented in Rust. The Rust
application images do not include or call the original Python application.

The existing HTML, CSS, and browser JavaScript are reused. Those are the browser
interface, and keeping them preserves the established interaction and appearance.
The Rust crate and production Dockerfiles now live at the repository root.
Obsolete Python application, helper and test sources have been removed. Synthetic
Python-produced backup/metadata fixtures retain compatibility evidence; the
original upstream repository remains the reference for its implementation.
Nothing was deployed to an existing installation during this rewrite.

qBittorrent still downloads torrents. ClamD still performs antivirus inspection.
FFmpeg/FFprobe still inspect media, and libarchive still decodes archive members
inside a constrained child process. These external engines are dependencies of
the intended behavior, not Python runtime dependencies.

## Preserved behavior and evidence

| Area | Rust behavior | Verification performed |
| --- | --- | --- |
| Submissions | Magnet links and original `.torrent` bytes; v1, v2, hybrid identities; custom tags, category, final path, local/NAS staging, capacity routing and duplicate refusal | Parser fixtures, mock API tests, and real qBittorrent v4.5.2 uploads |
| Ownership | Managed and per-job tags identify controlled torrents; history deletion does not remove downloads | Workflow regressions and real qBittorrent assertions that all torrents and a payload sentinel survive history deletion |
| Job control | Completion callbacks and polling, staging reconciliation, scan priority and pause/retry, move requests and explicit error states | Workflow state and transport tests, including actual scan-worker threads |
| Destination edits | Update planned destination with revision checking; do not move an active download just because its planned destination changes | Real qBittorrent test, including stale-editor rejection |
| Scanning | Unix-socket INSTREAM, definition freshness, bounded native scans, media windows, complete embedded objects, bounded ZIP/RAR inspection, identity checks and resumable checkpoints | Unit/protocol tests plus real ClamD, FFmpeg and libarchive scenarios |
| Archives | ZIP and RAR5 framing, nested members, expansion limits, corrupt/encrypted/unsupported input held rather than called clean | Real archive fixtures, synthetic infections, budget and framing failures |
| Large-media policy | Approved containers, overlapping windows, full attachment/cover/chapter scans, resource and output limits | Real Matroska and MP4 cases, window geometry and cancellation tests |
| Final actions | Verified clean promotion; configured infected hold, quarantine or deletion; ownership and path checks before side effects | Workflow action and clean/infected worker tests; test content only |
| Post-promotion work | Destination rules and mount markers, pinned routes, copy receipts and retries, controlled custom scripts, bounded output/time, event files | Filesystem copy/idempotency/conflict tests and workflow regressions |
| Administration | Token and same-origin checks, pause/drain, settings review/save, readiness checks, bounded requests and secret redaction | HTTP contracts plus real-browser settings review/save/restart, field errors, numeric inputs, secret handling and blocked Resume checks |
| Persistence | Existing SQLite tables and additive columns, private state, controller lock and restart recovery | SQLite fixture and state/lock tests |
| Portable backups | Existing `.tibak` envelope, scrypt and AES-GCM, online SQLite snapshot, authenticated staging and offline restore | Current upstream and older-schema Python-produced fixtures, every saved field compared, independent AES-GCM cross-check, tamper/truncation and held-writer WAL tests |
| Startup/shutdown | Fresh installations paused; one controller per state directory; SIGTERM drains tracked work and releases the lock | Real executable/loopback HTTP test, rejected second process, successful restart |
| Packaging | Separate Linux application and sidecar images; non-root runtime, native launchers | Both Linux ARM64 images built; application serves paused status and shuts down cleanly as its non-root user with a read-only root and no network; sidecar refuses missing definitions |

All original application route families are represented. `/openapi.json` contains
the route inventory. `/docs` and `/redoc` serve a small local API explorer rather
than FastAPI's generated Swagger/ReDoc interface. The ordinary browser UI remains
the primary interface, including multipart torrent upload and portable restore.

## Deliberate implementation differences

- The supported database is SQLite. The port does not provide a general
  SQLAlchemy database adapter for other servers.
- Linux is the deployment target. macOS builds and runs the controller tests;
  Linux supplies the resource-limit and external-tool environment used to verify
  media/archive helpers. Windows deployment is not implemented.
- The scan policy fingerprint identifies the Rust implementation separately.
  A Python checkpoint is not accepted as proof of a clean Rust-policy scan merely
  because ClamD and its definitions have the same version. This can cause a
  one-time rescan after migration.
- Some scan activity descriptions are simpler. Fast hash reconciliation
  uses the configured scheduler interval, while the ordinary polling interval is
  respected separately.
- The optional `after-promotion-copy.py` example becomes the native
  `after-promotion-copy` executable with a small shell wrapper for `/hooks`.
  Switch the configured hook path when using this legacy mode. Arbitrary custom
  Python hooks need a separately supplied interpreter; built-in copying does not.
- Backup ciphertext is streamed through bounded buffers. Old backup files remain
  readable; ciphertext need not be byte-for-byte identical because fresh salts
  and nonces are essential to encryption.
- Database upgrades expect a real historical application schema. An artificial
  table containing only an ID, with required original production columns absent,
  is rejected rather than inventing missing placement or ownership facts.
- Rust modules use explicit ownership, state guards and small adapters in place
  of Python's framework objects. Compatibility JSON stays flexible at the
  database/API boundary; the scanner uses typed settings and outcomes internally.

## Reproduce the checks

The normal suite includes parser, storage, backup, workflow, UI-rendering, HTTP,
and executable-startup tests. The final Rust-primary release draft passed all
**109 ordinary tests on macOS ARM64 and 112 on Linux ARM64**. The three
additional Linux tests exercise parser process limits and the shared native
Matroska deadline. Formatting and all-target Clippy passed on macOS with warnings
denied. The final Linux container used Rust 1.90; its minimal toolchain did not
include rustfmt or Clippy. GitHub CI installs both components on each runner.
The SQLite follow-up also checks idle-connection lifetime, automatic checkpoints,
FULL durability settings, and abrupt-exit recovery with an unfinished transaction.
Socket tests require permission to bind local
Unix/TCP sockets:

```sh
cargo fmt --manifest-path Cargo.toml --check
cargo clippy --manifest-path Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path Cargo.toml --locked
```

External-tool integration tests are ignored by the ordinary test command. Run
them explicitly in an isolated Linux environment with the listed programs:

```sh
# Needs clamd, FFmpeg/FFprobe, and libarchive.
# Starts its own private scanner with tiny synthetic signatures.
sh scripts/scanner-integration.sh

# Needs qbittorrent-nox. Creates its own private profile and loopback Web UI.
cargo test --manifest-path Cargo.toml --test qbt_integration \
  --locked -- --ignored --nocapture
```

For a disposable Docker environment, build from the repository root:

```sh
docker build --target test -f Dockerfile -t qbittorent-intake:tests .
docker run --rm --network none --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 256 \
  --memory 3g --cpus 2 qbittorent-intake:tests \
  sh scripts/scanner-integration.sh

docker build -f Dockerfile.qbt-tests -t qbittorent-intake:qbt-tests .
docker run --rm --network none --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 256 \
  --memory 3g --cpus 2 qbittorent-intake:qbt-tests
```

The scanner run passed eight mock-daemon integration cases and nine cases using
real ClamD. Cases exercise RAR4/RAR5 variants, nested ZIPs, corruption and expansion
limits, Matroska attachments, MP4 covers and chapters, parallel windows, and
native EICAR detection. Both real qBittorrent tests passed using v4.5.2, no peer
network, synthetic metadata and loopback tracker addresses. One verifies original
torrent metadata, identity, ownership and history-only deletion. The other
restores an archive generated by the unmodified current upstream Python exporter,
restarts the controller, and confirms all three complete v1/v2/hybrid torrents,
their payload bytes, tags and save paths survive while Intake remains paused.
The archive includes queued infected deletion, promotion and a custom hook;
none runs during restore or paused startup. A separate executable test records
zero qBittorrent requests throughout restore and paused polling. No test
downloaded third-party content. See [the migration guide](MIGRATION.md) for the
exact upstream commit and the explicit Resume boundary.

Both desktop/mobile browser suites passed against the final native image.
Settings coverage includes field-specific errors, numeric inputs,
review/save/restart, secret redaction, environment locks, NAS markers/defaults
and copy rules. It also confirms the active deletion-policy warning,
cancellation before Resume, and individual readiness failures while the
controller remains paused. Intake coverage includes torrent uploads, mixed
submissions, destination changes and stale edits, scan controls, NAS moves,
escaped output, tags/limits, and authenticated copy/script retries and cancellation.

The CI workflow applies formatting, lint and ordinary tests on Linux x86-64,
Linux ARM64 and macOS, with external-tool tests on Linux. That workflow was
written here but has not been executed by GitHub Actions in this local session.
The local external-tool runs used Linux ARM64.

## What the evidence does not establish

This is a substantial new implementation. The checks above support the listed
compatibility claims; they are not a proof that every production history or race
condition behaves identically to the Python version.

No existing production database, credentials, media library or NAS was used. The
validation did not include a full multi-gigabyte download-to-promotion deployment,
real NFS/SMB disconnects, a current production signature database, an external
custom hook, throughput/load benchmarks, every supported qBittorrent release,
or every possible browser and screen size. The [resource audit](PERFORMANCE.md)
adds controlled allocation, I/O and transport measurements; those do not replace
end-to-end production benchmarks. Generated media tests force low thresholds
to exercise large-file policy without constructing multi-gigabyte fixtures.

Before switching an established installation, test a portable backup and
representative content in an isolated installation with the intended mounts and
UID/GID. Run only one controller against each set of torrents and state. The
original image and state should remain available until that migration has been
verified. See the [README](../README.md) for the build and migration entry points.
