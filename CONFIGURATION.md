# Configuration and Portainer reference

The repository's default images run the Rust controller and Rust ClamD supervisor.
The image names are `qbittorent-intake` and `qbittorent-intake-clamd`. ClamAV,
FFmpeg/FFprobe, libarchive and qBittorrent still provide their respective engines.

[portainer-stack.example.yml](portainer-stack.example.yml) is a complete example
for a **Portainer Docker Standalone** environment. The identical
[docker-compose.example.yml](docker-compose.example.yml) works with Docker Compose.
These examples are not a Docker Swarm manifest: health dependencies, resource
syntax and missing-host-path handling must be adapted for a Swarm deployment.

## Start without locking every setting

There are three separate namespaces:

1. **Stack substitutions** choose images, host directories, ports, networks and
   Docker resource limits. Compose reads a host `.env`; Portainer uses the stack's
   Environment variables. These values enter a container only where YAML maps them.
2. **Application `TI_*` overrides** are optional container environment variables.
   They override saved/restored settings, are persisted at startup, and lock their
   fields in the editor. The complete inventory in the examples is commented out.
3. **ClamD supervisor variables** belong to the scanner sidecar. They cannot be
   edited through the application's settings or restored from its backup.

The standard container paths need **no active application override**. Keep the
application `environment:` block commented unless intentionally fixing selected
values in deployment configuration. Putting a `TI_QBT_PASSWORD` value in a host
`.env` alone does not send it to the service; uncomment its one matching YAML
mapping when an explicit override is wanted. Never uncomment the entire inventory.

Prepare the deployment in this order:

1. Set `GITHUB_OWNER` to the owner of the published images. The repository/image
   base defaults to `qbittorent-intake`; the scanner image adds `-clamd`. The owner
   is required, so the example cannot silently pull another person's image.
2. Review `.env.example` or enter the same stack substitutions in Portainer.
   Select a published tag and record it alongside the deployed stack.
3. Provision each host directory on its intended filesystem and grant the chosen
   numeric UID/GID appropriate access. All binds use `create_host_path: false`.
   Missing storage stops deployment; Docker must not create a local substitute.
4. Create or select an existing network that can reach qBittorrent's Web API.
   Mount identical content at identical container paths in both applications.
5. Supply readable current definitions through one separately managed updater.
   The sidecar has no network and does not download definitions. Its healthy state
   is a startup dependency, so it must be ready before the UI starts in this stack.
6. Deploy, open the loopback-published UI through your chosen access method, and
   obtain the administrator token from `/app/data/admin-token`. A new database
   starts paused. Configure or restore settings, check setup, then explicitly resume.

With Compose, validate substitutions before creating any containers:

```sh
cp .env.example .env
# Edit .env, including GITHUB_OWNER, before running the next command.
docker compose --env-file .env -f docker-compose.example.yml config --quiet
docker compose --env-file .env -f docker-compose.example.yml up -d
```

Keep `.env`, private settings, administrator tokens and backups out of version
control. Published job pages are intended for a private network; administrator
operations additionally require the local token. Loopback is the default host
binding, not an example of a personal network address.

## Stack substitutions

These are **host-side YAML substitutions**, not application settings, even when
some names start with `TI_`. Defaults below match the examples.

| Variable | Type/default | Purpose |
| --- | --- | --- |
| `GITHUB_OWNER` | required string; no fallback | GHCR account or organization publishing your two images. |
| `GITHUB_REPOSITORY_NAME` | string: `qbittorent-intake` | Controller image name; the scanner adds `-clamd`. Use lower-case GHCR names. |
| `IMAGE_TAG` | string: `latest` | Tag used for both images. Prefer recording a tested release tag for recovery. |
| `INTAKE_UID` | integer: `10001` | Numeric user for controller and sidecar; also grant suitable content access to qBittorrent. |
| `INTAKE_GID` | integer: `10001` | Numeric group for controller and sidecar. Choose ownership/ACLs deliberately. |
| `MEDIA_NETWORK` | string: `intake_network` | Existing external Docker network reachable from the qBittorrent API endpoint. |
| `TI_UI_PUBLISH_IP` | bind address: `127.0.0.1` | Host interface for UI/API publishing; set controlled access appropriate to your deployment. |
| `TI_UI_HOST_PORT` | port: `8095` | Host port; container HTTP port stays `8000`. |
| `TI_DATA_HOST_DIR` | absolute path: `/srv/torrent-intake/data` | Local persistent application state, SQLite, settings, tokens, backups/restore work and default archive scratch. |
| `TI_LOCAL_STAGING_HOST_DIR` | absolute path: `/srv/torrent-intake/staging` | Local torrent staging, mounted at `/staging-local` in Intake and qBittorrent. |
| `TI_MEDIA_HOST_DIR` | absolute path: `/srv/torrent-intake/content` | Final content and NAS staging, mounted at `/downloads` in both applications. |
| `TI_EVENTS_HOST_DIR` | absolute path: `/srv/torrent-intake/events` | Persistent structured-event spool; a separately managed notifier may read it. |
| `TI_QUARANTINE_HOST_DIR` | absolute path: `/srv/torrent-intake/quarantine` | Optional infected-content quarantine storage; needed for `infected_action=quarantine`. |
| `TI_CLAMD_SOCKET_HOST_DIR` | absolute path: `/srv/torrent-intake/socket` | Same private socket directory mounted at `/run/clamav` in both containers. |
| `CLAMAV_DEFS_HOST_DIR` | absolute path: `/srv/torrent-intake/definitions` | Existing current definitions, mounted read-only at `/var/lib/clamav`; provided by one updater. |
| `TI_ARCHIVE_SCRATCH_HOST_DIR` | optional existing absolute path; no fallback | Enable the commented `/archive-scratch` bind, then configure that container path in the application. |
| `TI_COPY_TARGET_HOST_DIR` | optional existing mounted absolute path; no fallback | Enable the commented `/copy-target` bind for built-in copying. Each rule destination requires `.intake-copy-mount`. |
| `TI_HOOKS_HOST_DIR` | optional existing absolute path; no fallback | Enable the commented read-only `/hooks` bind for trusted executable scripts. Built-in copying needs no script. |
| `INTAKE_MEMORY_LIMIT` | Docker memory size: `2g` | Controller container memory ceiling, including its processes and populated tmpfs. |
| `INTAKE_CPU_LIMIT` | CPU quota: `2.0` | Controller container CPU ceiling. |
| `INTAKE_PIDS_LIMIT` | integer: `256` | Controller process/thread ceiling, including parser and hook children. |
| `INTAKE_TMPFS_SIZE` | Docker size: `256m` | `/tmp` capacity ceiling in the controller, with `nosuid,nodev,noexec`. It is not preallocated RAM. |
| `INTAKE_STOP_GRACE_PERIOD` | duration: `60s` | Docker's graceful shutdown allowance before it forcibly stops the controller. |
| `CLAMD_MEMORY_LIMIT` | Docker memory size: `8g` | ClamD memory ceiling; signatures, parser allocations and populated tmpfs all contribute. |
| `CLAMD_CPU_LIMIT` | CPU quota: `4.0` | ClamD CPU ceiling. |
| `CLAMD_PIDS_LIMIT` | integer: `128` | Scanner process/thread ceiling. |
| `CLAMD_TMPFS_SIZE` | Docker size: `4g` | ClamD `/tmp` ceiling for INSTREAM staging and parser work. |
| `CONTAINER_NOFILE_SOFT` | integer: `4096` | Soft open-descriptor limit for both containers. |
| `CONTAINER_NOFILE_HARD` | integer: `8192` | Hard open-descriptor limit; must be at least the soft limit. |
| `CONTAINER_LOG_MAX_SIZE` | Docker size: `10m` | Per-file size limit for each container's `json-file` logs. |
| `CONTAINER_LOG_MAX_FILES` | integer string: `3` | Number of Docker log files retained per container. |
| `CONTAINER_RESTART_POLICY` | string: `unless-stopped` | Docker restart policy for both containers. |

Resource limits do not change application scan coverage, window overlap or worker
settings. Overly low limits can stop work or kill a container; raising Docker
limits alone does not raise scanner inspection budgets. For large media, size
ClamD memory and temporary storage for the active streams **and** signature/parser
work. A tmpfs limit reserves capacity, not a fixed amount of physical RAM; pages
actually written count toward the container memory limit. See
[the performance guide](docs/PERFORMANCE.md) for measured boundaries.

## ClamD supervisor variables

These are the **five environment variables explicitly read by `clamd-sidecar`**.
The first three are mapped by the examples; the last two remain commented because
the defaults match the image's daemon configuration.

| Variable | Type/default | Meaning |
| --- | --- | --- |
| `DEFINITIONS_WAIT_TIMEOUT` | nonnegative integer seconds: `1800` | Startup wait for readable main/daily definitions; effective minimum is 1 second. No definitions are downloaded. |
| `DEFINITIONS_MAX_AGE_SECONDS` | nonnegative integer seconds: `172800` | Maximum daily definition file age for startup and sidecar health; effective minimum is 300 seconds. |
| `CLAMD_MAX_SCAN_SIZE_MIB` | integer MiB: `2000`; range 1–4000 | Rewrites only `MaxScanSize`, the cumulative parser/expanded-data budget. Does not alter `MaxFileSize` or `StreamMaxLength`. |
| `DEFINITIONS_DIR` | absolute path: `/var/lib/clamav` | Directory the supervisor inspects for definitions. Changing this alone does not change ClamD's `DatabaseDirectory`. |
| `CLAMD_SOCKET` | absolute path: `/run/clamav/clamd.sock` | Socket used by the sidecar health check. Changing this alone does not change ClamD's `LocalSocket` or the application's `TI_CLAMD_SOCKET_PATH`. |

The image reads `/etc/clamav/clamd.conf`, writes its runtime variant to
`/tmp/clamav/clamd.runtime.conf`, and starts ClamD with it. Logs use
`/tmp/clamav/clamd.log` and are forwarded to container output. Definitions are
read-only; socket and temporary directories are writable. The default config has
`MaxThreads=4`, `MaxQueue=8`, `MaxFileSize=2000M`, `StreamMaxLength=2000M`, bounded
recursion/expansion checks, and alerts for incomplete inspection. These are daemon
configuration directives, not additional environment variables. Preserve their
relationship to the application limits.

Both images set `HOME=/home/torrent-intake`; ordinary operating-system variables
such as `PATH` are not application settings. Application logging is controlled by
`TI_DEBUG`, not a separate `RUST_LOG` configuration contract. Credentials for a
private image registry belong in Docker/Portainer registry settings, not `TI_*`.

## Every application environment variable

The following table and the commented inventories are generated from
`resources/defaults.json` and `resources/settings-catalog.json`. They contain every
supported application setting, including compatibility-only values.
Names in `settings.json` are lower-case without the `TI_` prefix.

Precedence is **process environment → legacy in-container `.env` → saved
`settings.json` → built-in defaults**. The host Compose `.env` is not the
in-container `.env`. `TI_DATA_DIR` is a bootstrap exception: set it in the process
container environment when relocating state, and change the Docker mount too.
A `TI_DATA_DIR` only present in an in-container `.env` cannot relocate startup.

Environment values are strings. Use `true`/`false` for booleans and decimal whole
numbers for integers. Array settings require JSON arrays; quote JSON as one
string in YAML/Portainer. Optional strings shown as `unset` should be omitted
until needed; the literal text `null` is not an environment null value. An empty
override can still lock a field or be invalid. Remove the mapping to restore
normal saved-setting control. Numeric entries also obey the cross-field rules
listed after the table.

<!-- BEGIN GENERATED APPLICATION ENVIRONMENT -->
| Variable | Type | Built-in default | Meaning and limits |
| --- | --- | --- | --- |
| `TI_APP_NAME` | string | `"torrent-intake"` | Accepted for compatibility with old settings files only; it has no effect. Use UI title to change the page heading. |
| `TI_DEBUG` | boolean | `false` | Enables verbose application logging. Leave disabled for normal operation. |
| `TI_DATA_DIR` | string | `"/app/data"` | Bootstrap container directory containing SQLite, settings, and restore state. Keep its host mount on local SSD storage. Only TI_DATA_DIR in the container environment can relocate it. |
| `TI_DATABASE_URL` | string | `"sqlite:////app/data/torrent_intake.db"` | SQLite database containing jobs, checkpoints, migrations and scanner controls. Only a SQLite file inside TI_DATA_DIR is supported; other database engines are not available. |
| `TI_QBT_HOST` | string | `"http://qbittorrent:8080"` | Private Web API endpoint reachable from Torrent Intake, for example http://qbittorrent:8080 on a shared Docker network. This is separate from the URL you open in your browser. |
| `TI_QBT_USERNAME` | string | `"admin"` | Account name used for authenticated qBittorrent API calls. |
| `TI_QBT_PASSWORD` | string | `"REPLACE_WITH_STRONG_PASSWORD"` | Password used for qBittorrent API authentication. The value is never returned to the UI. |
| `TI_QBT_VERIFY_CERTIFICATE` | boolean | `false` | Validates the qBittorrent HTTPS certificate when TLS is used. |
| `TI_QBT_REQUEST_TIMEOUT_SECONDS` | nonnegative integer | `20` | Maximum wait for an individual qBittorrent API request, in seconds. Minimum: 1. |
| `TI_QBT_WEB_URL` | optional string | `unset` | Browser-safe link shown in the UI. This can differ from the private API URL used by the container. |
| `TI_INTAKE_CATEGORY` | string | `"intake"` | qBittorrent category assigned while a torrent is managed by Intake. |
| `TI_MANAGED_TAG` | string | `"torrent_intake"` | Required qBittorrent tag proving that a torrent remains under Torrent Intake control. |
| `TI_AUTO_CREATE_FINAL_CATEGORY` | boolean | `true` | Allows Torrent Intake to create a requested final qBittorrent category when it does not already exist. |
| `TI_LOCAL_STAGING_ROOT` | string | `"/staging-local"` | Exact container path used for locally staged torrents. qBittorrent must see the same content at the same path. |
| `TI_NAS_STAGING_ROOT` | string | `"/downloads/torrent-intake/staging"` | Legacy single NAS path, used only while the named NAS list is empty. Existing job choices stay pinned. qBittorrent must see identical container paths. |
| `TI_NAS_STAGING_LOCATIONS` | JSON array | `[]` | Named temporary download locations mounted at the same paths in Intake and qBittorrent. A marker is an existing file on the NAS (absolute container path); Intake never creates it. Existing job paths cannot be removed while in use. |
| `TI_DEFAULT_NAS_STAGING_ID` | optional string | `unset` | Exactly one named NAS used for new jobs and local overflow. Existing jobs retain their saved fallback. This does not select the final library destination. |
| `TI_FINAL_PARENT_PREFIX` | string | `"/downloads"` | Primary canonical media boundary allowed for clean promotion destinations. |
| `TI_FINAL_PARENT_PREFIXES` | optional string | `unset` | Optional comma-separated canonical media boundaries allowed in addition to the primary final root. |
| `TI_LOCAL_OVERFLOW_POLICY` | string | `"queue"` | Action taken when aggregate local staging capacity is unavailable for another torrent. |
| `TI_LOCAL_MAX_GIB` | nonnegative integer | `200` | A torrent larger than this GiB limit is directed to NAS staging instead of local staging. Minimum: 1. |
| `TI_LOCAL_FREE_SPACE_BUFFER_GIB` | nonnegative integer | `5` | GiB kept unused when Torrent Intake calculates safe local staging capacity. Minimum: 0. |
| `TI_POLLING_INTERVAL_SECONDS` | nonnegative integer | `300` | How often the background reconciliation pass checks qBittorrent when no completion callback arrives. Minimum: 1. |
| `TI_COMPLETION_GRACE_SECONDS` | nonnegative integer | `15` | Delay after a completion signal before Torrent Intake begins its final completion and pause checks. Minimum: 0. |
| `TI_COMPLETION_EVENT_TOKEN` | optional string | `unset` | Authenticates qBittorrent completion callbacks. The value is never returned to the UI. |
| `TI_SCANNER_BACKEND` | string | `"clamd"` | Compatibility selector: only clamd is supported. It may be omitted; there is no clamscan or alternate backend. |
| `TI_CLAMD_SOCKET_PATH` | string | `"/run/clamav/clamd.sock"` | Private Unix socket shared only with the Torrent Intake ClamD sidecar. |
| `TI_SCANNER_POLICY_VERSION` | string | `"clamav-policy-v5-media-attachments"` | Identity of the scan policy stored with checkpoints. Changing it invalidates incompatible clean checkpoints. |
| `TI_SCANNER_MAX_FILE_MIB` | nonnegative integer | `2000` | Raw-size boundary for one native ClamD stream. Larger RAR/ZIP archives use member extraction; verified video and raw TrueHD use bounded windows. Eligible native size-limit failures use the same routes. Allowed: 1 through 2000. |
| `TI_SCANNER_HEALTH_CACHE_SECONDS` | nonnegative integer | `15` | How long a successful ClamD health result may be reused, in seconds. Minimum: 1. |
| `TI_SCANNER_CONNECT_TIMEOUT_SECONDS` | nonnegative integer | `5` | Maximum time to establish a private socket connection, in seconds. Minimum: 1. |
| `TI_SCANNER_SCAN_TIMEOUT_SECONDS` | nonnegative integer | `1200` | Maximum total client wait for one streamed file scan, in seconds. Minimum: 1. |
| `TI_SCANNER_DEFINITIONS_WARN_HOURS` | nonnegative integer | `36` | Definition age in hours at which the UI and events begin warning before scans are blocked. Minimum: 1. |
| `TI_SCANNER_DEFINITIONS_STALE_HOURS` | nonnegative integer | `72` | Definition age in hours at which scanning fails closed until current definitions are available. Minimum: 1. |
| `TI_LARGE_MEDIA_ENABLED` | boolean | `true` | Routes oversized verified videos and narrowly validated raw TrueHD audio, plus eligible media whose native scan reaches a parser/expanded-data limit, through full-byte overlapping ClamD windows. |
| `TI_LARGE_MEDIA_MAX_FILE_GIB` | nonnegative integer | `100` | Hard GiB ceiling for the bounded large-media path. Larger individual files remain held without a clean verdict. Minimum: 1. |
| `TI_LARGE_MEDIA_CHUNK_MIB` | nonnegative integer | `512` | MiB sent in each independent ClamD window. It must remain below the native ClamD stream limit. Minimum: 1. |
| `TI_LARGE_MEDIA_MIN_CHUNK_MIB` | nonnegative integer | `64` | Smallest MiB window allowed for a raw stream/file size limit. Expansion, recursion, and unknown limits within a window remain blocked instead of being subdivided. Minimum: 1. |
| `TI_LARGE_MEDIA_OVERLAP_KIB` | nonnegative integer | `1024` | KiB repeated between neighboring windows to preserve short byte signatures at boundaries; this cannot preserve every signature or container parser context. Minimum: 0. |
| `TI_LARGE_MEDIA_PROBE_TIMEOUT_SECONDS` | nonnegative integer | `120` | Maximum time allowed for ffprobe to verify the real container and stream layout of an oversized file. Minimum: 1. |
| `TI_LARGE_MEDIA_SCAN_TIMEOUT_SECONDS` | nonnegative integer | `172800` | Total deadline for validating and reading every window of one oversized media file. Minimum: 1. |
| `TI_FFPROBE_BINARY` | string | `"/usr/bin/ffprobe"` | Image-provided ffprobe path used to validate oversized media. The Docker image installs it at build time. |
| `TI_FFMPEG_BINARY` | string | `"/usr/bin/ffmpeg"` | Image-provided tool for bounded attachment extraction. It does not transcode media files or unpack torrent archives. |
| `TI_MEDIA_ATTACHMENT_MAX_MIB` | nonnegative integer | `16` | MiB allowed for one extracted attachment, between 1 and 64. Each attachment must complete a native ClamD scan; it is never chunked or skipped. Allowed: 1 through 64. |
| `TI_MEDIA_ATTACHMENT_TOTAL_MIB` | nonnegative integer | `64` | Maximum MiB extracted from one media file, at most 256. Cover images reserve their per-attachment maximum because their size is unknown before extraction. Allowed: 1 through 256. |
| `TI_ARCHIVE_ENABLED` | boolean | `true` | Inspect oversized RAR/ZIP archives and eligible native size-limit failures using temporary extracted copies. Original archives and torrent folders are preserved. |
| `TI_ARCHIVE_SCRATCH_DIR` | optional string | `unset` | Existing container directory on local or NAS storage. Intake uses a private archive-scan subdirectory. Leave blank to use TI_DATA_DIR. Configure the matching writable Docker mount first; unavailable custom storage never falls back to the data disk. |
| `TI_ARCHIVE_SCRATCH_MOUNT_MARKER` | optional string | `unset` | Optional absolute path to an existing readable marker file inside custom scratch storage. A missing marker blocks archive inspection; Intake never creates it. Leave blank to disable the marker check. |
| `TI_ARCHIVE_MAX_FILE_GIB` | nonnegative integer | `100` | Maximum GiB for a source RAR/ZIP archive admitted to member scanning. Allowed: 1 through 1024. |
| `TI_ARCHIVE_MAX_EXPANDED_GIB` | nonnegative integer | `20` | Maximum total GiB extracted per archive, including nested archive copies. Scratch files use the selected scratch filesystem and are removed after inspection. Allowed: 1 through 1024. |
| `TI_ARCHIVE_MAX_FILES` | nonnegative integer | `10000` | Total entries, including directories and nested archives, admitted during one archive inspection. Allowed: 1 through 100000. |
| `TI_ARCHIVE_MAX_DEPTH` | nonnegative integer | `4` | Maximum RAR/ZIP nesting levels sharing the extraction budget; the outer archive is level one. Allowed: 1 through 8. |
| `TI_ARCHIVE_SCAN_TIMEOUT_SECONDS` | nonnegative integer | `7200` | Total seconds allowed for extraction and all member scans of one archive. Allowed: 1 through 172800. |
| `TI_ARCHIVE_FREE_SPACE_BUFFER_GIB` | nonnegative integer | `1` | GiB kept free on the selected scratch filesystem while temporary members are extracted. Allowed: 1 through 1024. |
| `TI_PER_JOB_SCAN_WORKERS` | nonnegative integer | `1` | Maximum large-media byte ranges from one torrent that may be streamed to ClamD simultaneously. Allowed: 1 through 4. |
| `TI_CLAMD_MAX_INFLIGHT_REQUESTS` | nonnegative integer | `4` | Hard application-wide limit for simultaneous ClamD INSTREAM requests across every active torrent. Keep it at or below ClamD MaxThreads. Allowed: 1 through 4. |
| `TI_MAX_CONCURRENT_SCANS` | nonnegative integer | `2` | Default torrent scan slots for a new queue and after a temporary boost ends. Existing slot requests are saved in SQLite. Minimum: 1. |
| `TI_MAX_SCAN_SLOTS` | nonnegative integer | `4` | Maximum slot count the runtime Scan Queue control is permitted to request. Minimum: 1. |
| `TI_MAX_CONCURRENT_LARGE_SCANS` | nonnegative integer | `1` | Maximum number of torrents above the large-job threshold that can scan at the same time. Minimum: 1. |
| `TI_LARGE_SCAN_GIB` | nonnegative integer | `2` | Torrent size in GiB at which the separate large-scan concurrency bound applies. Minimum: 1. |
| `TI_SCAN_SCHEDULER_INTERVAL_SECONDS` | nonnegative integer | `3` | Delay between scheduler attempts to claim pending scan work, in seconds. Minimum: 1. |
| `TI_SCAN_LEASE_SECONDS` | nonnegative integer | `90` | Restart-recovery lease protecting an actively owned scan, in seconds. Minimum: 1. |
| `TI_SCAN_HEARTBEAT_SECONDS` | nonnegative integer | `10` | How frequently an active worker refreshes its durable scan lease, in seconds. Minimum: 1. |
| `TI_SCAN_RETRY_BASE_SECONDS` | nonnegative integer | `30` | Initial delay used by exponential retry after scanner failures, in seconds. Minimum: 1. |
| `TI_SCAN_MAX_FAILURES` | nonnegative integer | `3` | Failure count after which a file/job requires explicit operator retry. Minimum: 1. |
| `TI_SCAN_YIELD_AFTER_FILES` | nonnegative integer | `10` | Number of successfully checkpointed files processed before a worker yields so other queued jobs can progress. Minimum: 1. |
| `TI_PAUSE_CONFIRMATION_TIMEOUT_SECONDS` | nonnegative integer | `30` | Maximum wait for qBittorrent to confirm a torrent is paused before scanning or a destructive action. Minimum: 1. |
| `TI_INFECTED_ACTION` | string | `"hold"` | Action after a verified malware detection. This safety-critical value cannot be changed from the UI. |
| `TI_QUARANTINE_ROOT` | string | `"/quarantine"` | Canonical quarantine boundary used only when the infected-content action is quarantine. |
| `TI_EVENT_DIR` | string | `"/events"` | Writable spool where Torrent Intake atomically emits notifier events. It must be persistent. |
| `TI_POST_PROMOTION_ENABLED` | boolean | `false` | Run the deployment-configured trusted script only after clean scanning, completed final promotion, delay and revalidation. No scripts are queued for historical completed jobs. Scripts have Intake's permissions, not a separate sandbox. |
| `TI_POST_PROMOTION_SCRIPT` | optional string | `unset` | Absolute executable path under /hooks, mounted read-only. Configure in Portainer or settings.json while stopped. Script files are NOT included in portable backups. Never point this at downloaded content. |
| `TI_POST_PROMOTION_COPY_ENABLED` | boolean | `false` | Enable one-time copies for newly promoted torrents whose final parent matches an enabled copy rule. No match means no copy. Originals are retained and collisions are protected. Choose built-in copying OR a custom script; neither is a continuous folder sync. |
| `TI_POST_PROMOTION_COPY_DESTINATION` | optional string | `unset` | Retained for older settings and backups. This global destination is ignored for newly promoted jobs: configure Copy destination rules instead. Previously queued copies keep their pinned destination and layout. |
| `TI_POST_PROMOTION_COPY_RULES` | JSON array | `[]` | Map final-library source roots to existing destinations under /copy-target. The most specific enabled source containing the job's final parent wins; unmatched jobs are not copied. Disabled rules are ignored, so a broader enabled rule can still match. Relative folders are preserved, without a per-job wrapper. Queued jobs retain their saved rule. Maximum 32 rules. |
| `TI_POST_PROMOTION_DELAY_SECONDS` | nonnegative integer | `5` | Minimum delay after verified promotion before checking again and copying or running the script; not a substitute for move verification. Allowed: 0 through 3600. |
| `TI_POST_PROMOTION_TIMEOUT_SECONDS` | nonnegative integer | `7200` | Maximum copy or script runtime, followed by a short shutdown grace period. A timeout does not rescan or move the promoted torrent again. Inspect partial copies before retrying. Allowed: 1 through 604800. |
| `TI_UI_TITLE` | string | `"Torrent Intake"` | Heading displayed at the top of the Torrent Intake interface. |
<!-- END GENERATED APPLICATION ENVIRONMENT -->

The default password is a placeholder, never a usable credential. A saved backup
may contain passwords, private tracker metadata and tokens; its encrypted export
must be protected accordingly. The application does not return connection secrets
to the browser catalog.

### Relationships and structured values

- Definitions warning age must not exceed stale age. The sidecar independently
  applies its own definition-file age limit, which may stop startup earlier.
- Native ceiling is at most 2000 MiB. Initial media window ≤ native ceiling;
  minimum media window ≤ initial window; overlap must be strictly less than the
  minimum window. Only eligible raw-size limits permit adaptive subdivision.
- Per-job media workers ≤ global active ClamD requests ≤ 4. Keep this at or below
  the daemon's `MaxThreads`. Torrent scan slots and byte-window workers are
  separate controls. Lowering neither is required by this deployment example.
- Default and large-job scan slots must not exceed `max_scan_slots`.
  `scan_heartbeat_seconds` must be less than `scan_lease_seconds`.
- Per-attachment allowance ≤ total per-file attachment allowance. Archive entries
  and nested archive copies share their configured totals, depth and reserve.
- `local_overflow_policy` is `queue` or `nas`. `infected_action` is `hold`,
  `quarantine` or `delete`; the default `hold` retains content for review. Delete
  remains available only when explicitly configured. Inspection errors and
  incomplete scans never become verified infection or clean verdicts.
- Built-in copying and trusted custom-script mode are mutually exclusive and
  disabled by default. New copies need an enabled matching rule; the historical
  global destination is not a fallback. Existing queued routes remain pinned.

Named NAS staging values are arrays of records. A marker is an existing readable
file on the intended storage, expressed as a container path. For example:

```json
[{"id":"primary","label":"Primary storage","path":"/downloads/torrent-intake/staging","mount_marker":"/downloads/torrent-intake/.intake-mount"}]
```

`default_nas_staging_id` selects one record. `final_parent_prefixes` is a
comma-separated string of additional absolute roots, **not** a JSON array.
Built-in copy rules use records like this:

```json
[{"source":"/downloads/content","destination":"/copy-target/content","enabled":true}]
```

The destination must exist beneath `/copy-target` and contain the pre-provisioned
`.intake-copy-mount` marker. The most specific enabled source wins. Unmatched
promotions are not copied; a disabled specific rule does not cancel a broader
enabled match. Copies preserve relative payload paths and keep private receipt
state separate. A trusted script instead requires an executable under `/hooks`;
`scripts/after-promotion-copy.sh` invokes the optional native compatibility helper.

## Storage and recovery boundaries

| Container path | Required relationship |
| --- | --- |
| Controller `/app/data` | Private local persistent storage; SQLite, settings, administrator token, restore state and default archive scratch. Never shared with qBittorrent. |
| Controller `/staging-local` | qBittorrent sees the same actual content at `/staging-local`. |
| Controller `/downloads` | qBittorrent sees identical final content and staging at identical paths. |
| Controller `/events` | Persistent event producer directory; share read access with your notifier if used. |
| Controller `/quarantine` | With quarantine action, qBittorrent must also see the same writable directory at `/quarantine`. |
| Both `/run/clamav` | Same private socket directory and compatible numeric ownership. |
| Sidecar `/var/lib/clamav` | Current definitions from one updater, mounted read-only. |
| Controller `/archive-scratch` (optional) | Existing writable separate storage; configure the matching application setting. Unavailable custom scratch does not fall back locally. |
| Controller `/copy-target` (optional) | Existing destination storage, writable by Intake and checked using each destination's marker. |
| Controller `/hooks` (optional) | Trusted operator files, read-only and executable as required. |

All example binds reject missing host paths. An **existing empty mountpoint** can
still exist when NAS is offline: path existence alone does not prove the intended
filesystem is mounted. Verify mounts before starting dependent containers, create
markers only on the intended mounted storage, and keep underlying fallback
directories unwritable to the application. See [storage layout](docs/STORAGE_LAYOUT.md).

A portable backup contains application state, not downloaded content, qBittorrent
state, definitions, host mounts, network definitions, image credentials or Docker
resource settings. Keep the deployed stack and its private values separately.
A restore is staged while paused and drained, applied at restart before SQLite
workers start, and leaves Intake paused for verification. Receiving process
overrides still win over restored settings. Do not run two controllers against
the same state directory or managed torrents.

## Keeping this inventory accurate

After changing an application default or catalog description, run:

```sh
cargo run --example generate_config_reference
cargo test --test configuration_reference
```

The test checks exact generated content, matching stack examples, documented
substitutions, and the absence of active application overrides. The generator
uses Rust and adds no interpreter dependency to the runtime images.
