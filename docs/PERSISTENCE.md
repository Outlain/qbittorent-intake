# How persistent state, torrent uploads, and backups work

This guide explains `src/persistence/`. Those modules do not contact qBittorrent,
run a scanner, or serve HTTP. They provide the durable facts and input checks
that those parts of the controller need.

The most useful reading order is `state.rs`, `db.rs`, `metainfo.rs`, `paths.rs`,
`storage.rs`, `backup.rs`, and finally `restore.rs`.

## What survives a restart

The database keeps the original Python table and column names:

| Table | Meaning | Important identity |
| --- | --- | --- |
| `jobs` | One requested download, its placement, lifecycle, tags, and post-promotion action | `id`; `unique_tag` is also unique |
| `scan_runs` | Scheduling and progress for one job's scan | `job_id` |
| `scan_files` | A checkpoint for each relative file path | `(job_id, relative_path)` |
| `scanner_control` | Requested scan slots and maintenance mode | `id = 1` |

A checkpoint records more than the word `clean`. It can also record file size,
modification time, change time, device, inode, scanner version, database version,
and policy version. The workflow decides whether those facts still match. The
persistence layer preserves them without silently interpreting a previous clean
result as permission to promote a changed file.

`schema.rs` spells out the schema in a small table of names and SQL definitions.
`Database::open` creates missing tables, adds missing columns, and creates the
indexes used by job and scan queries. It does not delete old jobs, renumber file
checkpoints, or replace the database. This permits an existing SQLite database
from the Python application to be opened directly.

Existing Python databases have an important detail: some defaults lived in
SQLAlchemy's Python model rather than in SQLite's `CREATE TABLE` statement.
Simply inserting a partial scan update would therefore fail with a `NOT NULL`
error even when the row already exists. `db.rs` handles this explicitly:

1. Start an `IMMEDIATE` transaction, reserving the database's writer.
2. If the row exists, update only the supplied fields.
3. Otherwise, supply the original model defaults and insert the new row.
4. Commit both the existence decision and its write together.

For example, saving `{"relative_path":"payload.bin","status":"clean"}` on an
existing scan file changes its status while retaining its size and timestamps.
It does not replace the whole row with a partly empty object.

An UPDATE also compares the supplied values with the stored values using
SQLite's NULL-safe `IS NOT` operator. If every value is already identical,
there is no row update. A real change, including a transition to or from NULL,
still commits immediately. This avoids redundant checkpoint writes without
batching progress or weakening crash recovery.

## Why the database API uses JSON objects

Jobs have many optional fields that also appear in the HTTP interface. A JSON
object at this boundary keeps the original names visible and lets a caller make
a small patch without constructing an enormous Rust struct. SQLite remains the
source of truth; nested objects must be serialized explicitly into a text field.

Dynamic SQL is limited to the four known tables. Every incoming column name is
checked against that table's actual columns, and values use bound parameters.
User-provided values never become SQL syntax. Unknown fields are errors rather
than silently ignored typos.

Ordinary reads omit `torrent_file_data`, which can contain private tracker
passkeys. `torrent_data()` is a separate, deliberate read for a retry that must
resubmit the original uploaded bytes. Integer columns representing booleans are
converted back to JSON booleans. Timestamp text remains compatible with the
Python database.

A `Database` contains a path and one private idle SQLite connection. Each ordinary
operation still opens its own connection with foreign keys enabled, a 30-second
busy timeout, WAL journaling, and `trusted_schema=OFF`. Work that needs a larger
atomic unit, such as claiming a scan lease, uses `connect()` and one explicit
transaction. Several independent method calls do not become one atomic operation.

The idle connection prevents SQLite from repeatedly deleting and recreating its
WAL and shared-memory files between operations. It is created **after** the
migration connection is dropped, so it does not retain the migration's page cache.
It never runs application queries and never holds a transaction. Consequently it
does not pin an old database snapshot or stop a checkpoint from advancing.

`Arc` gives cloned `Database` handles shared ownership of that idle connection.
The last handle to disappear closes it and permits SQLite's normal final
checkpoint and file cleanup. `Mutex` makes the otherwise non-shareable connection
safe to store in a shared handle; ordinary operations never lock it or reuse it.
Workers therefore retain their independent connections and concurrency.

This is an explicit memory-for-write-reduction tradeoff. One extra connection
retains a small amount of schema and connection memory; its exact size depends
on the SQLite build and schema. It also keeps the journal files present between
operations. `synchronous=FULL` and the normal 1,000-page automatic checkpoint
threshold are unchanged. Every changed commit still receives SQLite's full
synchronization; checkpoints occur at the normal threshold or final close.
An identical update is skipped only when all supplied values already match.

The bundled SQLite dependency includes the fix for the
[SQLite WAL-reset race](https://www.sqlite.org/wal.html#walresetbug).
The regression tests require SQLite 3.51.3 or later, verify FULL synchronization
and the automatic checkpoint threshold, and prove that the idle connection
allows a complete checkpoint. A subprocess test exits without running database
destructors: reopening recovers committed jobs, original torrent bytes, and clean
checkpoints, while its unfinished transaction is rolled back.

Online backup uses SQLite's snapshot API and includes committed pages still in
the WAL. Restore installation remains offline: all `Database` clones must be
dropped before replacing the database. Startup applies a staged restore before
opening `Database`; merely staging a restore while paused does not replace it.

The Rust controller currently requires file-backed SQLite. PostgreSQL URLs and
`:memory:` databases are not supported. Independent worker connections would
otherwise see different in-memory databases. Portable backups additionally
require the database to live inside `TI_DATA_DIR`.

## Small state files and the controller lock

`state.rs` stores settings, deployment notes, the administrator token, pause
state, and restore manifests. On Unix, private files use mode `0600`; application
state directories use `0700`. The controller sets a restrictive process umask so
SQLite journal files inherit private permissions as well.

`write_private` creates a temporary file in the same directory, writes all bytes,
syncs the file, atomically renames it over the destination, and syncs the parent
directory. The rename makes the visible change atomic. The syncs make the file
and its directory entry durable across a crash. A reader sees a complete old or
new document, rather than a half-written JSON document.

`read_private` refuses symbolic links and nonregular files and reads at most the
stated size limit. A FIFO cannot cause it to wait forever for a writer. These
checks matter because state files contain credentials and influence startup.

Reads allocate from the observed length, within the same size limit, and still
detect a file growing beyond that limit. Permission checks call `chmod` only
when the existing mode needs repair. Small-file hashing also sizes its buffer
to the file, up to the existing 1 MiB maximum. Atomic writes and their syncs
remain unchanged; see the [resource audit](PERFORMANCE.md) for measurements.

`ControllerLock::acquire` takes an exclusive advisory lock on `controller.lock`.
The returned value owns the open file. Rust releases the lock when that value is
dropped, so `main` keeps it alive for the complete server lifetime. A second
controller using the same data directory fails before doing work.

The administrator token is created once with operating-system randomness and
kept local. It is intentionally excluded from portable backups. Authentication
compares fixed-size SHA-256 digests with a constant-time equality operation.
The SHA-256 step is for equal comparison lengths; it does not turn a weak
user-selected password into a strong secret. Generated tokens have 256 random
bits.

## Reading a `.torrent` without trusting it

A torrent file is metadata encoded with bencode. It can still contain malicious
paths, huge declarations, or an excessively complicated tree. `metainfo.rs`
therefore parses with explicit limits:

- At most 32 MiB of uploaded torrent metadata.
- At most 300,000 decoded nodes.
- At most 64 nesting levels.
- Canonical signed 64-bit integers and bounded byte-string lengths.
- Strictly ordered, unique byte-string dictionary keys.
- Exactly one complete top-level dictionary, with no trailing bytes.

The decoder borrows byte strings from the input instead of repeatedly copying
them. `Node` is a Rust enum: a value must be exactly one of bytes, integer, list,
or dictionary. Accessors such as `dict()` return `Option`; validation converts a
missing or wrong type into an explanatory error with `Context`.

The parser supports v1, v2, and hybrid metadata. For v1 it validates the declared
file sizes against the number of SHA-1 piece hashes. For v2 it validates the
power-of-two piece size and file-tree leaves. A hybrid produces both identity
parameters in its magnet URI. Names and file paths reject empty components,
`.` and `..`, slashes, backslashes, NUL bytes, and Windows drive prefixes.
Symlink entries, duplicate file paths, and a file path that is also another
file's parent directory are rejected.

A particularly important detail is `Decoder.info`: it remembers the exact byte
slice of the original `info` dictionary. The v1 SHA-1 and v2 SHA-256 identities
are calculated from those original bytes. Re-encoding a parsed object and then
hashing it could change the torrent identity.

The returned magnet URI is only an identity reference. The workflow submits the
original uploaded bytes to qBittorrent, preserving private flags, announce tiers,
web seeds, and v2 piece layers. Metadata validation never follows a tracker URL
or extracts torrent content.

## Paths and missing storage

Containment checks use path components. `/media2` is not inside `/media`, even
though a naive text-prefix check would claim it is. Existing symbolic links are
resolved before containment decisions. A final destination must belong to an
allowed media root and must not be inside an operational path such as staging,
application data, quarantine, or archive scratch space.

A storage check verifies that an existing root is accessible. It never creates
a missing staging directory or a mount marker. Creating that directory when a
NAS is unmounted could accidentally put a large download on the container's
local filesystem. A configured marker must be an existing, readable regular
file and cannot itself be a symlink.

`storage.rs` pins a named NAS location's identity, label, path, and marker onto
each job. Old jobs are upgraded once: an old NAS job keeps its actual NAS path;
an old local job keeps the legacy NAS fallback it had before a registry was
introduced. Retired locations receive a stable `legacy-<hash>` identifier.
Editing an unrelated registry entry does not invalidate such a grandfathered
job. Removing or redirecting a location used by an active job is refused.

## Exactly what a portable backup contains

A backup contains four allowlisted files:

| Member | Contents |
| --- | --- |
| `torrent_intake.db` | A consistent SQLite snapshot, including committed WAL pages |
| `settings.json` | Settings, including credentials required to restore operation |
| `deployment-notes.txt` | Operator-supplied notes about the actual deployment |
| `manifest.json` | Backup version, creation time, and scope |

It does not include downloaded payloads, qBittorrent state, ClamAV definitions,
notifier state or events, Docker images, or the local administrator token. Those
items have separate owners and must be preserved by deployment procedures.

The SQLite backup API creates the database snapshot. Copying the live `.db` file
alone could miss committed pages that still live in its WAL journal. Snapshot
work has a 60-second budget and a 512 MiB database limit. Free-space checks allow
room for the snapshot and temporary archive.

Before accepting a database, `check_database` runs SQLite's integrity and
foreign-key checks with a time budget. It requires the four expected tables,
checks key columns, and rejects views, triggers, and virtual tables. Indexes are
allowed. An encrypted file is not automatically a trusted database merely
because the uploader knows its passphrase.

## Encryption compatibility and bounded memory

The `.tibak` format is byte-compatible with the Python implementation:

```text
"TI-BACKUP-1\0" | 16-byte salt | 12-byte nonce | ciphertext | 16-byte GCM tag
```

Here `\0` denotes one zero byte. The passphrase is encoded as UTF-8. Scrypt uses
`N = 2^17`, `r = 8`, `p = 1`, and produces a 32-byte AES key. AES-256-GCM
authenticates the whole header as associated data. A fresh salt and nonce are
randomly generated for each backup. Passphrases must have at least 12 Unicode
characters and no more than 1024 UTF-8 bytes.

The implementation streams the archive in 1 MiB chunks. Scrypt's deliberate
memory cost is about 128 MiB; encrypting a 500 MiB archive does not require
loading the whole archive into memory.

`GcmStream` composes the standard RustCrypto AES counter-mode and GHASH
primitives. For a 12-byte nonce, `J0 = nonce || 1` masks the authentication tag;
payload counter blocks start at `nonce || 2`. GHASH authenticates the padded
header, then ciphertext, then their bit lengths. Every nonfinal transfer chunk
is a multiple of 16 bytes, so padding is added only where GCM specifies it.
Tests compare this streaming construction against the `aes-gcm` crate for short
inputs and inputs on both sides of the 1 MiB boundary.

During decryption, bytes go to a private temporary file. No ZIP parser or SQLite
connection can inspect that file before authentication succeeds. A wrong
passphrase or modified ciphertext drops and removes the temporary file. Only a
successful constant-time tag comparison publishes the requested output path.
The output is created without replacing an existing file.

The ZIP archive must contain exactly the four expected names. Members must be
uncompressed, unencrypted regular files within their size limits. Restore never
uses general-purpose `extract_all`; each allowlisted member is copied to its
fixed staging path. This prevents path traversal and ZIP decompression bombs.
The complete directory is checked before writing any member. A bounded raw
directory pass detects duplicate records that the ZIP library would otherwise
collapse into one filename. Ordinary four-member backups and ZIP comments are
supported; ZIP64 and multi-disk archives are not part of this bounded format.

## Restore is deliberately a two-phase operation

Uploading a backup does not immediately replace the live database. The HTTP
layer first requires a paused, drained controller. `stage_restore` then:

1. Checks that no earlier restore is pending and enough local space exists.
2. Authenticates and decrypts the upload.
3. Validates the four ZIP members and the SQLite database.
4. Validates restored settings with normal startup rules.
5. Keeps the receiving deployment's `data_dir` and `database_url`.
6. Hashes the staged database, settings, and notes.
7. Atomically moves the verified directory to `.restore-pending`.

The next startup acquires the controller lock before calling
`apply_pending_restore`, and before opening the application database. Apply
checks the staging hashes and destination again, then:

1. Writes a persistent controller pause marker.
2. Saves the previous installation in `before-restore-<id>`.
3. Durably records that the previous installation was saved.
4. Checkpoints and removes old SQLite WAL/SHM files.
5. Atomically copies the restored database, settings, and notes into place.
6. Records the rollback directory in `last-restore.json`.
7. Removes only the verified staging directory.

The durable `saved_previous` flag matters if the process crashes halfway through
applying a restore. On the next start, it does not overwrite the original
rollback snapshot with a partially restored installation. Keeping the original
archive and rollback directory also gives an operator a recovery path.

The controller stays paused after restore. The operator checks qBittorrent,
container mounts, and permissions before resuming. This is required because
application state alone cannot prove that external services or media paths still
refer to the same content.

## Verification and scope

The focused test suite covers Python-produced torrent decisions, original info
hashes, v2 metadata, malformed bencode, nesting/node budgets, symlink escapes,
state-file limits, controller lock contention, partial checkpoint writes,
additive schema upgrades, SQLite schema rejection, ZIP path rejection, streaming
AES-GCM compatibility, encryption tampering, offline restore, and rollback.

`tests/fixtures/python-legacy-backup.tibak` was generated by the repository's
original Python `app.models`, SQLAlchemy, and `app.backup.create_backup`. Several
later optional columns were removed to exercise additive migration. Its test
restores booleans, a paused scan, a completed file checkpoint, and original
torrent bytes, then confirms that partial updates still work after migration.
All fixture credentials are deliberately fake.

These tests establish storage and file-format compatibility. They do not certify
a particular NAS, real qBittorrent installation, container mount layout, or
ClamAV deployment. Those integrations belong to the workflow and deployment
checks described elsewhere in the Rust documentation.

### A backup with deletion enabled still starts paused

The infection policy is a saved setting. A new installation uses `hold`; an
existing backup that explicitly selected `delete` keeps that selection for
compatibility. Importing the archive does not execute that policy. The durable
pause marker is written before replacing the database, and the dispatcher does
not run queued work while paused. This includes infected deletion, clean-file
promotion, and pending post-promotion scripts.

`tests/persistence_upstream_restore.rs` verifies an archive generated by the
unmodified current upstream Python backup implementation at commit
`886d75a14f0d8b5663078a91bae4bd09c1336f94`. It checks every stored database field,
original v1/v2/hybrid torrent bytes, settings, committed WAL changes, deployment
notes, the receiving administrator token, and the rollback snapshot. Its second
test launches the actual Rust executable with a recording qBittorrent endpoint:
restoration, startup, several scheduler cycles, and repeated job reads produce
**zero qBittorrent requests**, despite restored deletion and queued action work.

The ignored real qBittorrent integration test repeats the restore/startup check
in a disposable container. It retains all three torrents, their tags, categories,
save paths, and synthetic payload files. It then aligns the restored job paths
with the scratch installation and restarts again, still paused. This tests both
the untouched upstream archive and a prepared migration with matching live
ownership information.

An explicit **Resume** permits normal processing again. If the restored policy
is `delete`, an infected job can then be deleted according to that policy and
the workflow's ownership checks. Review the policy and queued actions before
resuming; restoring does not silently change a previously selected policy.
See [migration instructions](MIGRATION.md) for the operational sequence.
