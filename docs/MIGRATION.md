# Moving an existing Python installation to Rust

The Rust controller reads the original SQLite schema and `.tibak` backup
format directly. Python, SQLAlchemy, and cryptography are not needed in the
new runtime. Use a portable backup when moving an existing installation: it
includes both the database and saved configuration, and the receiving
controller remains paused until you explicitly resume it.

## What to preserve

An Intake backup contains its jobs, scan runs, per-file checkpoints, scanner
controls, original uploaded `.torrent` bytes, settings, and deployment notes.
Settings may contain qBittorrent credentials and torrent metadata may contain
private tracker passkeys. Keep the archive and its passphrase private.

The backup does **not** contain downloaded files, qBittorrent's own profile or
resume data, ClamAV definitions, notifier state/events, or Docker images.
Preserve the existing qBittorrent profile and all payload volumes independently.
The receiving installation keeps its own administrator token; a token is never
imported from an archive.

## Migration sequence

1. In the original controller, pause Intake and wait for it to drain. Export an
   encrypted `.tibak` backup and keep the passphrase. Save the actual deployment
   configuration and mount layout separately.
2. Stop the original Intake controller. Only one controller should manage the
   same jobs. Keep qBittorrent's profile and payload volumes intact.
3. Start the Rust controller with a writable application data directory and the
   intended mounts. A new installation starts paused. Set up its administrator
   token as described in the deployment guide.
4. While paused and drained, upload the `.tibak` archive and its passphrase in
   Settings. A successful upload stages a verified restore; it does not replace
   the running database or modify qBittorrent.
5. Restart the Rust controller. Before opening its database or starting workers,
   it installs the verified snapshot and persists the paused state. An existing
   receiving database/settings snapshot is retained in `before-restore-<id>`;
   `last-restore.json` records that directory.
6. Review the restored settings, queued jobs, infection policy, post-promotion
   actions, qBittorrent connection, and mount paths. Keep the same container paths
   where possible. Only the receiving `data_dir` and `database_url` are rebased
   automatically; other saved paths intentionally retain their original meaning.
   Environment settings override saved settings, so review the receiving
   deployment's `TI_*` variables too.
7. Run the controller's readiness checks. Once the settings and external state
   match, explicitly choose **Resume** to permit processing again.

Keep the original archive, old deployment configuration, and rollback snapshot
until the new installation has been verified. To use a rollback snapshot, stop
all controllers before replacing any database or state files; never replace a
live SQLite database underneath open connections.

If you reuse the old data volume instead of importing a backup, **pause and
drain the old controller before changing the image**. Existing data is not a
fresh installation: startup preserves its saved paused/running state. Merely
swapping images over an unpaused database does not provide the restore pause
guarantee. Keep a backup first, preserve UID/GID and container paths, remove any
Python entrypoint override, and review configuration before resuming. The
portable-restore sequence above makes that maintenance boundary explicit.

## Deletion policy after a restore

The default infection action is `hold`. The optional `delete` action remains
available. A backup that previously selected `delete` preserves that selection;
it does not become active merely because you import it or restart the service.
The controller is paused after restore, so queued infected deletion, promotion,
and post-promotion hooks do not execute.

**Resume is the point at which queued work becomes eligible again.** If you do
not want infected payloads deleted, configure `TI_INFECTED_ACTION=hold` in the
receiving deployment and restart before resuming. This environment override also
prevents a saved `delete` setting from becoming effective. Remove an override
only when you intend the saved policy to apply.

The guarantee tested here is no qBittorrent mutations during restore and paused
startup. It is not a promise that the opt-in delete feature can never delete a
torrent after an explicit resume. Likewise, resuming a pending clean job can
move its payload to the planned destination, and a queued hook can run.

## Compatibility evidence and limits

The committed synthetic reference backup was produced by the unmodified
[`Outlain/torrent-intake` backup implementation at commit
`886d75a14f0d8b5663078a91bae4bd09c1336f94`](https://github.com/Outlain/torrent-intake/blob/886d75a14f0d8b5663078a91bae4bd09c1336f94/app/backup.py),
the GitHub HEAD inspected on 2026-10-12. Its source matched the preserved Python
backup/model/configuration implementation. The upstream pinned dependencies used
were SQLAlchemy 2.0.43, Pydantic 2.11.7, Pydantic Settings 2.10.1, and cryptography
50.0.1. Generation happened in a disposable environment outside this repository;
the shipped controller and tests consume the resulting fixture using Rust.

The native restore tests compare every saved row and setting, including booleans,
optional fields, nanosecond file fingerprints, scanner versions, hook state,
private torrent metadata bytes, and committed changes still in SQLite's WAL.
A separate older-schema fixture checks additive migration of missing optional
columns. The real executable test uses a recording qBittorrent endpoint and
asserts zero requests during restore, paused startup, and repeated job polling.
The real qBittorrent test additionally checks torrent and payload survival.

These are synthetic, isolated tests. They do not inspect or change a production
qBittorrent instance, certify a NAS mount, or migrate external qBittorrent state.
The portable format supports SQLite databases up to 512 MiB. Unknown future
settings or incompatible schemas are rejected instead of silently discarded.
No claim is made about backups produced by later, unexamined upstream changes.
