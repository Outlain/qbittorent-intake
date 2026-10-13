# Storage paths and deployment boundaries

Intake uses container paths. A host may arrange local disks, attached storage or
NAS however it needs, provided the same content appears at the same paths in
Intake and qBittorrent. The application does not create filesystems, mount remote
storage or provision Docker networks.

## A neutral starting layout

| Host example | Container destination | Used by |
| --- | --- | --- |
| `/srv/torrent-intake/data` | `/app/data` | Intake only; local persistent application state |
| `/srv/torrent-intake/staging` | `/staging-local` | Intake and qBittorrent |
| `/srv/torrent-intake/content` | `/downloads` | Intake and qBittorrent |
| `/srv/torrent-intake/events` | `/events` | Intake; optional notifier reader |
| `/srv/torrent-intake/quarantine` | `/quarantine` | Intake and, when quarantine is enabled, qBittorrent |
| `/srv/torrent-intake/socket` | `/run/clamav` | Intake and its dedicated ClamD sidecar |
| `/srv/torrent-intake/definitions` | `/var/lib/clamav` | Sidecar read-only; one separately managed updater writes definitions |
| `/srv/torrent-intake/archive-scratch` | `/archive-scratch` | Optional separate archive scratch for Intake |
| `/srv/torrent-intake/copy-target` | `/copy-target` | Optional post-promotion destination for Intake |
| `/srv/torrent-intake/hooks` | `/hooks` | Optional trusted scripts; Intake mounts read-only |

These are example host paths, not locations Intake creates automatically. Replace
them with provisioned storage. Keep SQLite, settings, tokens and recovery work on
local persistent storage. The `TI_DATA_HOST_DIR` substitution changes the host
source; it does not require changing the default `/app/data` inside the container.

The default NAS staging path is `/downloads/torrent-intake/staging`. A final
category could use `/downloads/content`. It must not point at staging, application
state, quarantine, archive scratch or copy targets. The broad `/downloads` mount
is a simple starting point; separate content mounts also work when their allowed
final roots and qBittorrent paths are configured consistently.

## Existence is not proof of a mounted filesystem

Every bind in the stack uses the long syntax with `create_host_path: false`:

```yaml
volumes:
  - type: bind
    source: /srv/torrent-intake/content
    target: /downloads
    bind:
      create_host_path: false
```

The host source must exist before deployment. This prevents a missing path from
being silently created as a local directory. It cannot detect an existing empty
mountpoint whose intended NAS filesystem is unavailable. Arrange host startup
checks and permissions so writers do not start against an unintended fallback.
For example, inspect the actual mount on the Docker host before deployment:

```sh
findmnt -T /srv/torrent-intake/content -o TARGET,SOURCE,FSTYPE,OPTIONS
```

Use the same bind in qBittorrent. Equivalent-looking directory names on different
hosts or exports are not proof that the bytes are shared. Preserve exact spelling
and case for existing jobs. When replacing a host mount deliberately, stop the
writers and recreate affected containers after verifying the replacement; do not
assume an existing bind automatically follows a remount.

## Ownership and private state

The examples default to numeric UID/GID `10001:10001` for both Intake and ClamD.
Change `INTAKE_UID` and `INTAKE_GID` together if your storage requires another
identity. Give qBittorrent compatible access to the shared content. A display
name inside one container does not establish host ownership or NAS permissions.

Provision the selected local state and socket directories for the chosen numeric
identity. Private state and socket directories should exclude other users;
Intake makes private state files mode `0600` and private state directories `0700`.
Content access can use appropriate groups or ACLs. Do not grant broad write access
to state, hooks or unrelated storage merely to make a permission error disappear.

The socket directory is shared only by Intake and its scanner. The socket itself
is mode `0600`, so both processes must be able to use the same owner identity.
A shared definitions directory is different: the updater writes it, while this
sidecar only reads it. Do not run a second updater on the same definitions.

## Named staging, scratch and copy markers

A named NAS staging record can pin a temporary location and an optional marker:

```json
{"id":"primary","label":"Primary storage","path":"/downloads/torrent-intake/staging","mount_marker":"/downloads/torrent-intake/.intake-mount"}
```

Provision the marker on the intended mounted storage. Intake checks it but does
not create it. Old jobs keep their recorded paths; do not remove or repurpose
those locations while jobs still depend on them.

Archive inspection defaults to `/app/data/archive-scan`. If its temporary expanded
copies should use another disk, enable the `/archive-scratch` bind and set
`archive_scratch_dir` to that container path. An optional
`archive_scratch_mount_marker` must lie inside the configured scratch directory.
The scanner uses a private `archive-scan` child directory and enforces its entry,
byte, depth, deadline and free-space limits. Unavailable custom scratch holds
archive work instead of falling back to the application disk.

Built-in copy rules use a dedicated `/copy-target` mount. Every selected rule
destination requires a readable regular `.intake-copy-mount` file created there
before copying. A simple rule is:

```json
{"source":"/downloads/content","destination":"/copy-target/content","enabled":true}
```

Only new clean promotions matching an enabled rule receive this one-time copy.
Originals stay in place. Existing queued requests retain their pinned route;
changing settings does not silently redirect them. Private records live under
`.intake-copy-state` outside payloads. Existing conflicting destination content is
not overwritten, and a directory being copied may be visible before completion.
Check the copy result before using it. This is not continuous synchronization or
a substitute for an independent backup.

Markers verify expected presence and improve failure handling; they do not
cryptographically identify a NAS/export or replace the host's mount verification.

## Filesystem boundaries and large media

A promotion within one filesystem may be a rename. Moving between local staging
and NAS, between separate filesystems, or between distinct storage datasets can
require a full transfer and temporary duplicate capacity. A shared parent path
or storage pool does not make those operations free.

If placement costs matter, a normal staging directory inside the intended final
filesystem can avoid a cross-filesystem transfer. Keep it isolated from consumers,
register its exact path as named staging, and preserve the same mount/path view
in both applications. The default overflow target remains one explicitly selected
location; Intake does not infer storage policy from a category name.

For large media, scanning streams bounded chunks rather than loading the whole
file into the controller. ClamD still stages its INSTREAM inputs and uses memory
for signatures and parsing. Archive extraction and optional copies add their own
storage work. Size limits and concurrency are separate settings; see the
[configuration reference](../CONFIGURATION.md) and [performance guide](PERFORMANCE.md).

## Planned storage replacement

1. Verify independent backups and destination capacity; seed the replacement
   storage using tools appropriate to that filesystem.
2. Let moves finish, pause and drain Intake, pause affected qBittorrent work, and
   stop other writers. Review queued or interrupted copy requests before moving
   their underlying storage; cancellation removes no payload.
3. Finish and verify the final transfer, permissions and marker files. Retain the
   old storage until rollback is no longer needed.
4. Change host mounts while retaining established container paths. Verify the
   intended filesystem is present and writable, then recreate affected containers.
5. Check qBittorrent content, Intake setup and persisted routes before resuming.
   Changed inode/device/timestamp identities can invalidate scan checkpoints;
   rescanning protects the link between a verdict and its actual bytes.

A backup restore cannot perform these storage steps. Restore application state
only after the receiving host mounts and container paths are ready, and keep the
controller paused until you have verified them.
