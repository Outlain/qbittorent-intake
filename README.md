# qbittorent-intake

A Rust controller that coordinates qBittorrent downloads, antivirus inspection,
and final placement. It accepts magnet links or torrent files, tracks work in
SQLite, scans completed content, and applies your configured actions. The web
interface includes job management, settings, encrypted backups, and restore.

Rust is the primary implementation. Both container images use native launchers;
the application does not need Python. qBittorrent, ClamD, FFmpeg/FFprobe and
libarchive continue to provide their specialized functions.

**New installations and restored backups start paused.** The default infection
action is **hold**. Deletion remains available as an explicit setting. A restored
backup retains its previous infection policy, including `delete` if configured:
restore itself does not delete qBittorrent torrents or downloaded content, but
resuming authorizes the saved policy to run. The settings page displays a warning
when the active policy is deletion.

## Start here

| Need | Guide |
| --- | --- |
| Deploy with Portainer | [Complete stack example](portainer-stack.example.yml) |
| Deploy with Docker Compose | [Compose example](docker-compose.example.yml) |
| Understand every variable | [Configuration reference](CONFIGURATION.md) and [.env.example](.env.example) |
| Replace an existing Python installation | [Migration and backup compatibility](docs/MIGRATION.md) |
| Understand shared directories and permissions | [Storage layout](docs/STORAGE_LAYOUT.md) |
| Understand the Rust code | [Explanation guide](docs/EXPLANATION.md) |
| Review tests and compatibility limits | [Validation record](docs/PARITY.md) |
| Review RAM and disk-I/O choices | [Performance audit](docs/PERFORMANCE.md) |
| Create the repository and publish images | [Release guide](docs/RELEASING.md) |
| Review the publishing privacy boundary | [Privacy guide](docs/PRIVACY.md) |

## Features

- Magnet and `.torrent` submissions, including v1, v2 and hybrid identities;
  duplicate detection, categories, custom tags and planned destinations.
- Local and network storage staging, capacity routing, completion callbacks and
  polling, ownership checks, scan priority, pause/retry and persistent progress.
- ClamD inspection, bounded archive processing, large media inspection and
  complete embedded-object scans. Incomplete inspection does not count as clean.
- Verified clean promotion, infected hold/quarantine/configured deletion,
  destination-based copies, copy verification/receipts and optional trusted hooks.
- Token-protected administration, settings review, pause/drain, readiness checks,
  encrypted `.tibak` exports, compatible imports and recovery copies.

## Deploy

The application and scanner images are published to:

```text
ghcr.io/<owner>/qbittorent-intake:latest
ghcr.io/<owner>/qbittorent-intake-clamd:latest
```

These names become available after the repository's release workflow succeeds.
The owner and repository name are derived from GitHub automatically. The scanner
image uses the same repository name with `-clamd` appended. Successful pushes to
`main` update `latest`; version tags produce versioned images without moving
`latest`. For a repeatable deployment, select a version or commit tag. See the
[release guide](docs/RELEASING.md) for the validation and publishing gates.

1. Provide an existing qBittorrent instance and a shared Docker network. Create
   the host directories and set their ownership for the chosen UID/GID. Confirm
   that the intended network storage is mounted. The examples refuse to create
   missing bind-source directories.
2. Provide an external ClamAV definitions updater. The ClamD sidecar has no
   network access and does not download signatures. Its health check requires
   readable, sufficiently recent definitions.
3. Paste [portainer-stack.example.yml](portainer-stack.example.yml) into a Docker
   Standalone stack, or use [docker-compose.example.yml](docker-compose.example.yml).
   Set `GITHUB_OWNER`, the external network and the actual host paths using the
   [configuration reference](CONFIGURATION.md). Repository names must be lowercase
   in GHCR paths. Preserve the **container-visible paths** used by qBittorrent.
4. Start the stack, open `/ui`, and use the token from `/app/data/admin-token` to
   unlock administration. New state starts paused. Configure settings or restore
   a backup, then follow the restart and verification instructions in the UI.
5. Review the infection action, paths, copy rules and hooks before resuming.
   A failed readiness check leaves the controller paused.

The default published address is `127.0.0.1:8095`. Use a trusted tunnel or an
appropriately secured proxy for remote access. Administration has token and
same-origin checks; ordinary intake routes assume a trusted network. Do not
publish this interface directly to an untrusted network.

All **78 application variables**, the **5 sidecar variables**, and stack controls
are documented. Application overrides in the stack are commented intentionally:
an active `TI_*` variable takes precedence over saved or restored settings and
locks that field in the editor. Enable only the overrides you actually need.
The application uses `/app/data` for persistent state; the ClamD socket and
content mounts must be accessible under the matching container paths.

`/health` remains unavailable until scanner and required directories are ready.
A paused, otherwise healthy installation can serve the UI. Keep the scanner's
health dependency in mind when starting a stack without signature files.

## Restore an existing backup

The Rust restore path reads the original encrypted `.tibak` format. It retains
settings, SQLite history, scan records and original torrent bytes, then applies
an additive database migration. No Python interpreter is needed for restore.

Pause and drain the old controller before exporting, stop it, and restore into
the Rust installation. After the required restart, the receiver stays paused.
Its own data-directory/database locations and administrator token are retained.
Check the restored qBittorrent address, credentials, content paths, infection
policy and hooks before selecting **Verify & resume**. Avoid running two
controllers against the same torrents or state directory.

A portable backup does **not** contain downloaded content, qBittorrent's own
state or antivirus definitions. Those must remain available separately. Custom
hooks require their executable dependencies: the new image does not include a
Python interpreter. The supplied old copy-hook example has a native replacement,
[scripts/after-promotion-copy.sh](scripts/after-promotion-copy.sh); built-in copy
rules need no wrapper. Rust uses its own scan-policy identity, so migration may
require a one-time rescan. Read the [migration guide](docs/MIGRATION.md) for exact
steps, rollback limits and the tested upstream backup version.

## Build and test

Linux is the deployment target, with `amd64` and `arm64` image builds. macOS is
supported for development and controller tests. Windows deployment is not
implemented. Install Rust 1.90 or newer:

```sh
cargo build --release --locked
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked

docker build -t qbittorent-intake:test .
docker build -f Dockerfile.clamd -t qbittorent-intake-clamd:test .
```

`Cargo.lock` fixes dependency versions. The executables are
`target/release/torrent-intake`, `clamd-sidecar`, and `after-promotion-copy`.
The public image names use `qbittorent-intake`; the established executable and
`TI_*` names remain stable for compatibility.

To view a fresh interface in a disposable local directory:

```sh
TI_DATA_DIR="$(mktemp -d)" target/release/torrent-intake --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/ui`. Without scanner/storage setup, readiness checks
fail and the controller stays paused. On macOS, configure the absolute installed
paths for FFmpeg and FFprobe when testing scanning.

Real qBittorrent and ClamD tests use disposable profiles, generated content and
synthetic signatures. They are separate from the ordinary test suite; commands
and coverage are recorded in [PARITY.md](docs/PARITY.md). The CI workflow also
validates browser behavior, configuration references and container packaging.

## Understand and maintain the code

The [explanation guide](docs/EXPLANATION.md) walks through a job and explains the
Rust ownership, errors, guards and recovery design. Detailed guides cover
[scanning](docs/SCANNING.md), [persistence](docs/PERSISTENCE.md), and
[workflow/copying](docs/WORKFLOW.md).

| Behavior | Source |
| --- | --- |
| Startup, lock, recovery, shutdown | `src/main.rs` |
| Settings and validation | `src/config.rs`, `resources/` |
| HTTP routes and administration | `src/http.rs` |
| Job lifecycle and final actions | `src/workflow/` |
| Antivirus/media/archive inspection | `src/scanning/` |
| SQLite, torrent metadata, encrypted backups | `src/persistence/` |
| Native scanner supervisor and copy helper | `src/bin/` |
| Existing browser interface | `templates/` |

The resource audit reduced unnecessary database updates, repeated reads and
temporary allocations while retaining scan coverage, copy verification and
SQLite durability. An idle database connection prevents repeated last-connection
WAL cleanup; it costs a small amount of memory and permits the normal WAL to
remain present. Concurrency defaults have not been reduced. ClamD and filesystem
cache usage remain separate from the controller's own memory. Measurements and
tradeoffs are in [PERFORMANCE.md](docs/PERFORMANCE.md).

The project is licensed under [MIT](LICENSE). See [NOTICE](NOTICE) for upstream
provenance and third-party notices.
