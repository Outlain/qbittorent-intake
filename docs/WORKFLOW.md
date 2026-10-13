# How the Rust controller handles a torrent

The controller's job is to coordinate three independent systems: SQLite records
what Intake intends to do, qBittorrent owns downloads and moves, and ClamAV decides
whether particular file bytes are clean. A successful HTTP request to one system
does not establish that another system has finished its work. Most of the design
comes from respecting that distinction.

Read the modules in this order:

1. `src/workflow/mod.rs` contains the public application operations.
2. `src/workflow/qbt.rs` translates those operations into qBittorrent Web API requests.
3. `src/workflow/safety.rs` defines what must be true before content is touched.
4. `src/workflow/actions.rs` reconciles downloads, storage and post-scan moves.
5. `src/workflow/scan.rs` schedules and checkpoints antivirus work.
6. `src/workflow/hooks.rs` performs the optional verified copy or trusted script.
7. `src/workflow/tests.rs` demonstrates the operations against a local fake server.

The HTTP adapter calls `submit`, `get_job`, `list_jobs`, `completion`, `action`,
`bulk`, `scanner_status` and `scanner_control`. The worker calls `tick`. Keeping
HTTP parsing out of these functions means a security rule has one implementation,
whether a browser action, callback, or scheduled poll reaches it.

## A complete clean download

A submission first validates its final destination, staging selection and tags.
Current and historical managed tags and private ownership tags cannot be selected
as custom tags. The tag suggestions use the same rule, including old deployments'
tag names retained in SQLite.
Magnet hashes are decoded before contacting qBittorrent. For an uploaded torrent,
the bounded metainfo parser calculates the magnet used for duplicate detection,
and the **original uploaded bytes** are saved in SQLite. The original bytes are
also sent to qBittorrent: regenerating metadata could lose private tracker or v2
information.

Intake refuses a torrent that already exists in qBittorrent. It then commits a
job with a random `ti_job_...` tag, the deployment's managed tag, and the requested
custom tags. Its `adding_to_qbt` state records the intent before the external add
request. If Intake crashes around that request, it searches for its private tag
before trying another addition. A successful request can precede the torrent's
appearance in qBittorrent's list, so `waiting_for_qbt_hash` is retried on the fast
scheduler cadence instead of waiting for the full management polling interval.

qBittorrent's authenticated live response supplies the hash, name, size and
content path. A callback only identifies a job and requests immediate verification;
an arbitrary callback path never becomes a filesystem authority.

When qBittorrent reports that a download is complete, Intake creates a scan run
and marks the job `scan_pending`. A scanner worker claims the run, pauses the
torrent, waits for qBittorrent to confirm the pause, and validates its staging
boundary. Only then does it enumerate and inspect files.

After every file has a reusable clean checkpoint, the worker walks the complete
filesystem tree again. Newly added or replaced files become pending work. It also
checks that the torrent is still complete, paused, owned by this job and located
at the same staging path. It publishes `scan_clean` only after those checks.

The management worker changes that state to `promoting` and asks qBittorrent to
move the torrent. It does not use `rename` on qBittorrent's payload itself. On a
later pass, it verifies both qBittorrent's save path and the actual content path
under the permitted final root. It resolves or creates the final category if
requested, resumes seeding, writes an event and commits `done`. That same database
write queues any configured post-promotion action, so a crash cannot lose the
action between a separate completion write and a separate queue write.

## Optional completion callback setup

Polling works without a callback. For a faster handoff, set
`completion_event_token` to a random secret, then configure qBittorrent's command
on torrent completion. With the supplied shared Docker network and service name:

```sh
curl -fsS --max-time 15 -X POST "http://qbittorent-intake:8000/events/qbt-complete-form" --data-urlencode "token=REPLACE_WITH_RANDOM_TOKEN" --data-urlencode "qbt_hash=%I" --data-urlencode "tags=%G"
```

Use the same token as Intake, and ensure `curl` is installed in qBittorrent's
container. Enter the command as one line in qBittorrent. The example passes the
torrent hash and tags; the job tag also identifies pure-v2 submissions when a v1
hash is unavailable. Intake verifies names, paths and ownership through the Web
API.
Existing `curl -F` multipart callbacks are also supported, along with URL-encoded
forms and the JSON endpoint `/events/qbt-complete`. If an old command uses a
service name that changed, update its URL. A callback cannot resume a paused
controller or bypass ownership and completion checks; polling remains the
fallback if delivery fails. Keep the command's token private.

## What proves ownership

A hash identifies torrent metadata, but it does not identify an Intake submission.
A user can remove tracking and later add the same torrent again. Delayed callbacks
for the first submission must not control the second.

Before a pause, scan, move or infected-file deletion, the guard checks:

- qBittorrent's hash matches the job's expected hash.
- Both its deployment managed tag and its private job tag are present.
- No other active Intake job owns the same hash or private tag.
- Completion and pause requirements for that operation have been met.
- The save path and content path stay inside the operation's allowed root.

A checking, moving, downloading, missing-files or error state does not pass the
completion check merely because the progress number is `1.0`.

A normal **Remove from Intake** operation deletes SQLite tracking only. It does
not pause, remove or delete the qBittorrent torrent. The separate infected-content
policy is the only automatic operation that can request payload deletion.

## Local space and NAS staging

The local capacity calculation subtracts the configured free-space buffer from
actual filesystem free space. It also reserves the remaining download bytes for
older local jobs and unmanaged torrents using the same staging root. The current
job may use only the unreserved remainder. Already downloaded bytes are already
reflected in filesystem free space and are not counted a second time.

A job exceeding the configured local size threshold is directed to its pinned
NAS location. Ordinary space pressure follows the configured queue-or-NAS policy.
A queued job is paused; it can resume when a later management poll finds enough
space. An unavailable NAS causes `waiting_for_nas`, without creating its absent
mountpoint on the container's root filesystem.

Each job stores its chosen NAS ID, label, path and optional mount marker. A
configuration edit does not silently move an existing job to another NAS. Startup
also migrates historical jobs to pinned choices using the legacy storage rules.
Mount markers may sit beside a staging directory on the same configured mount;
they are not incorrectly restricted to being children of the staging directory.

## Why scans have leases and file checkpoints

A `ScanRun` is scheduling state: priority, pause request, attempt count, current
worker, lease expiration, progress and final verdict. A `ScanFile` is evidence:
relative path, file fingerprint, scanner provenance, method, duration and verdict.
The two are deliberately separate.

A file fingerprint contains its device, inode, byte length, modification time and
change time. Identical names and lengths do not prove identical files. Replacing a
file at an already scanned pathname therefore invalidates its checkpoint. Changes
to the scanner engine or inspection policy invalidate reusable results too. A
routine definition refresh does not discard otherwise valid clean checkpoints,
matching the original application's policy.

Claiming work uses an SQLite `IMMEDIATE` transaction. The transaction conditionally
changes `scan_pending` to `scanning` and assigns a unique worker ID and lease. An
already claimed or paused run cannot be claimed by a second scheduler.

During antivirus work, the cancellation callback also renews the lease. Directory
walks renew it as well. Result publication checks the worker ID while holding the
same management mutex used by recovery and scheduling. A previous worker cannot
publish its old result over a successor's new fingerprint.

Expired leases return to `scan_pending` or `scan_paused`; an unfinished file returns
to pending. At process startup the exclusive controller lock proves no old worker
is still alive, so old scanning leases are reclaimed immediately. Clean checkpoints
remain available for validation and reuse.

**Pause After File** sets a persisted flag. The active file finishes and checkpoints
before the worker releases its lease. Destination editing is permitted only after
the job reaches `scan_paused`, its lease is gone, and no completed verdict or
promotion markers exist. A requested pause alone is insufficient.

Controller pause/shutdown is different: it cancels in-flight scanner and hook work
so backup/restore can wait for the controller to drain. Scan maintenance lets the
current file finish and stops new claims while ordinary download reconciliation
continues.

The scheduler respects requested slots, the hard slot ceiling and the large-job
limit. Explicit priorities move work forward; aged jobs avoid being permanently
starved by small arrivals. Large jobs can yield after a configured number of files
when more urgent or smaller work is waiting. A temporary slot boost returns to the
normal slot count when the pending queue empties. `per_job_scan_workers` controls
parallel bounded media inspection windows inside the scanner; persisted files
within a job are checkpointed one at a time.

Unavailable or stale antivirus definitions defer work without consuming ordinary
failure attempts. Other transient failures use exponential backoff beginning at
the configured base delay. Policy failures and exhausted retries leave the torrent
paused and the job in `error`; a user must explicitly retry it.

## Infected content

`hold` verifies that the torrent remains paused in staging and then records
`infected_held`. `quarantine` allocates a private job directory under the configured
quarantine root, asks qBittorrent to move there, and verifies the final path before
recording `infected_quarantined`. Both preserve the evidence and avoid resuming it.

`delete` commits the deletion intent before asking qBittorrent to remove the
owned torrent and its files. A later pass must find neither the torrent nor any
remaining content before recording `infected_deleted`. A filesystem permission
error is not interpreted as absence. An empty leftover directory is harmless;
a symlink or remaining file is not.

Events use the original schema (`service`, `event_type`, `severity`, timestamp,
job ID and event-specific fields). Writing a private temporary file, syncing it,
and renaming it prevents notification consumers from seeing truncated JSON. Event
IDs for reconciled actions are deterministic, so retrying an action replaces its
receipt instead of inventing contradictory events. Failure notifications and
individual hook attempts use separate IDs so later attempts retain their context.

## Post-promotion actions

Promotion pins the action kind, script or copy destination, routing root and
relative path into the job. Changing the deployment's default route cannot
redirect already queued work.

Before claiming an action, Intake rechecks the complete clean manifest, final
storage, source path and live qBittorrent ownership. It commits `hook_status=running`
before executing the external effect. A claimed action interrupted by a restart
becomes `interrupted`, never automatically executed again: an external script may
already have changed another system.

An administrator may retry only failed or interrupted work, while its corresponding
feature is enabled. Copy retries preserve the original destination; script retries
use the currently configured trusted script. A pending, failed or interrupted copy
can instead be cancelled. Cancellation preserves all existing files and makes that
request permanently ineligible for retry.

Trusted scripts are regular executable files beneath `/hooks`. Arguments are
passed directly to the process, without a shell. Standard output and error are
drained with nonblocking reads and capped at 64 KiB. A timeout or controller pause
terminates the process group. Pipe handling is bounded even if a script leaves
an unusual detached child behind. The process receives a minimal explicit
environment rather than inheriting the controller's credentials.

Built-in copying requires an existing destination under `/copy-target` and a
readable `.intake-copy-mount` file in the selected destination. It rechecks the
marker identity while copying. Source and destination cannot overlap or alias.
Symlinks, hard links, devices and other special files are rejected.

For a new payload, the copier hashes source bytes as it writes them, flushes the
copy, and independently reads the destination to compare its digest. Source
fingerprints and the complete manifest are checked again before publishing the
receipt. This avoids a separate source hashing pass while retaining a complete
destination verification pass. Existing copies still require independent reads
of both source and destination before reuse.

Routed copies preserve the relative payload path and store receipts under
`.intake-copy-state/<job-id>/complete.json`. Historical unrouted work retains
`intake-job-<job-id>/<payload>` and `.intake-copy-complete.json`. Receipts keep the
original Python request and snapshot fields; the Rust copy also records a digest.
Old receipts are accepted only after current bytes are independently verified.

Directories use an atomic exclusive `mkdir` reservation, which works on NFS as
well as local storage. The directory may be visible while copying: consumers must
wait for success or the completion receipt. Files are published with an exclusive
hard link. Existing payloads are compared byte-for-byte and never overwritten or
merged. Failed attempts and partial reservations remain for operator inspection.
Empty directories and file modification times are retained.

### Migrating the optional Python copy hook

Ordinary copies need only the built-in copy settings. Deployments that use the
advanced custom-script mode should replace the mounted
`scripts/after-promotion-copy.py` with `scripts/after-promotion-copy.sh`,
mounted read-only as an executable beneath `/hooks`, and update
`POST_PROMOTION_SCRIPT` to that path. The shell wrapper executes the native
`/usr/local/bin/after-promotion-copy` binary; Python is not needed.

The executable retains `--source`, `--torrent-hash`, `--torrent-name` and
`--job-id`, defaulting to `/copy-target/intake-copies`. Provision that directory
and its `.intake-copy-mount` marker before running it. Without routing options,
it keeps the historical `intake-job-<job-id>/<payload>` layout and
`.intake-copy-complete.json` receipt. Existing receipt contents are checked by
the same copier used for built-in actions.

If the old Python wrapper's `DESTINATION_ROOT` constant was customized, add
`--destination /copy-target/your-directory` before `"$@"` in your mounted shell
wrapper. The optional paired `--source-root` and `--relative-path` arguments also
remain available. `--help` explains the arguments without touching storage.

## Rust concepts used here

`Result<T>` makes failure part of a function's contract. `?` returns an error to
the caller instead of continuing with incomplete evidence. Business operations
use `anyhow::Context` to explain which operation failed; scanner error variants
also distinguish cancellation, temporary unavailability and a policy refusal.

`Arc<T>` shares ownership across threads. Cloning `Workflow` does not duplicate
SQLite contents or create independent qBittorrent sessions: its synchronization
objects and scanner are shared. `Mutex<T>` protects a short critical section.
Dropping its guard automatically unlocks it, including when `?` returns early.
Antivirus processing runs outside the management lock, so the UI can request a
pause while a large file is being scanned.

The qBittorrent adapter has its own mutex around login and requests. It reuses
cookies and retries an explicitly rejected authentication session once. It does
not blindly repeat mutations after a network disconnect, because a server may
have accepted the first request before the response was lost.

Persistence uses JSON-shaped records to retain the existing Python SQLite column
names and API fields. This reduces migration risk and makes patches explicit:
only the supplied columns change. The tradeoff is that field names are checked
by persistence and tests instead of Rust's type checker. The scanner itself uses
concrete Rust types for identities, settings, results and errors, where typed
invariants are most useful.

## Validation boundaries

The workflow tests exercise duplicate submission, shared authentication, live UI
statistics, stale callback isolation, tracking-only deletion, ownership checks,
verified promotion, atomic hook creation, lease recovery, fingerprint invalidation,
copy idempotence and refusal to overwrite changed content. They use a temporary
loopback qBittorrent double and temporary files; they never contact a configured
user daemon.

Archive workspace cleanup runs at startup only when archive inspection is enabled.
An offline scratch mount produces a warning and leaves the controller available
for configuration, native scans and media scans. Each archive scan still requires
the configured scratch storage and marker before extracting content; startup never
creates a missing mountpoint as a substitute.

The ETA estimator preserves the original behavior: it waits for three clean
samples, fits a per-file cost plus a size-dependent cost to the latest 100 samples,
and adjusts for the current file's elapsed time. Unusually slow current files
suppress the estimate instead of showing a misleading countdown. Confidence uses
the original sample-count and prediction-error thresholds. Only the sample sizes
and durations are loaded, rather than every scan-file record.

Timing and presentation are intentionally not byte-for-byte copies of Python.
Fast hash reconciliation
uses the configured scan scheduler cadence. The wire fields and safety decisions
remain compatible, but real NAS behavior, a deployment's trusted scripts and a
particular qBittorrent installation still require deployment integration checks.
