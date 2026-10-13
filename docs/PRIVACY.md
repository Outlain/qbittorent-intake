# Privacy and publication

## What belongs in the repository

Publish source, templates, generic examples, documentation, licenses and
synthetic test fixtures. The application does not include analytics or a
telemetry client. Its own outbound HTTP client connects to the configured
qBittorrent service; ClamD uses a local Unix socket. Browser requests use the
application's local endpoints. Configured custom hooks can perform additional
operations and network requests, so review those separately.

qBittorrent's peer/tracker traffic and a separate antivirus-signature updater
are outside the controller's network behavior. Container builds and CI download
packages and toolchains. The browser can open the configured qBittorrent Web UI.

The publication review covers the source tree, image build context, deployment
examples, and decoded synthetic backup fixtures. Examples use generic content
names, placeholder credentials, loopback endpoints and generic `/srv` paths.
No actual deployment credentials, private tracker passkeys, personal host paths
or private service addresses are intentionally included. Synthetic passwords
and passkeys in tests are public test data, never usable deployment credentials.

Public upstream attribution and third-party license authors remain in `NOTICE`,
`THIRD_PARTY_LICENSES.txt` and `tests/fixtures/libarchive/COPYING`. They are
required provenance/licensing material and are not a record of the operator
or their installation.

## Export a fresh repository

Run this from the source root:

```sh
sh scripts/export-source.sh
```

The result is `dist/qbittorent-intake-source.tar.gz`. Extract it into a fresh
directory for the new GitHub repository. The export includes the workflow,
Dockerfiles, lockfile, examples, fixtures and documentation, and excludes the
existing `.git` directory, build outputs and common local state/secret files.
It refuses source symlinks and existing output files. Archive ownership and
file timestamps are normalized, so local account names and edit timestamps
are not carried in tar headers. Source file contents are copied as written;
review any personal changes before publishing an updated export.

Do not use the old checkout's Git history for this clean import: history may
contain deleted code, old examples and author identities. This task does not
rewrite or delete that history. GitHub commits, the repository owner and registry
metadata necessarily identify the account that publishes them; choose those
account settings yourself when creating the repository.

`.gitignore` excludes local state, credentials, `.env` files, logs, databases,
backups and build output. The only `.tibak` exceptions are the explicitly
synthetic compatibility fixtures. `.dockerignore` allows only reviewed build
inputs and excludes common local credential/state names even within source
folders. Neither ignore file can detect a secret pasted into an ordinary source
file; review new changes before publishing.

## Runtime information remains private

Keep the data directory, encrypted backups, passphrases, administrator token,
deployment notes, logs and real environment settings out of Git. Database rows,
original torrent metadata and backups can contain names, paths, credentials and
private tracker tokens. Encryption protects the backup only while its passphrase
remains private. Logs and hook output can include paths and diagnostic data.

The interface assumes a trusted private network for ordinary intake endpoints.
Administrative endpoints also require the local token and same-origin checks.
Use controlled network access; the deployment examples bind the UI to loopback.
The token is retained locally during restore, not imported from another system.

No production data or live service credentials were needed for the validation.
The migration tests use disposable qBittorrent profiles and generated content.
The export is a reviewed source deliverable, not an automatic guarantee about
future edits, dependency releases or existing GitHub account metadata.
