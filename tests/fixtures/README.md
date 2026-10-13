# Reference fixtures

These files contain synthetic test data, never real tracker passkeys or user
credentials.

- `python-backup-vector.tibak` was generated with Python cryptography's
  `Scrypt(N=2**17, r=8, p=1, length=32)` and `AESGCM`, using bytes `0..15` as salt,
  bytes `16..27` as nonce, and the header `b"TI-BACKUP-1\0" + salt + nonce` as AAD.
  Its plaintext is `python-backup-vector.txt`.
- `python-legacy-backup.tibak` was created using this repository's original
  `app.models` and `app.backup.create_backup`, SQLAlchemy 2.0.43, Pydantic Settings
  2.10.1, and cryptography 44.0.2. Its synthetic filenames were later changed to generic
  payload names and the same legacy database was re-exported with the unmodified
  upstream `create_backup` at commit `886d75a14f0d8b5663078a91bae4bd09c1336f94`
  using cryptography 50.0.1. It contains one synthetic paused job, its scan
  run, one clean file checkpoint, and scanner-control state. Later optional
  columns `jobs.custom_tags_json`, `scan_files.ctime_ns/device/inode/scan_method`,
  and `scanner_control.maintenance_*` were removed before export. This tests a
  real Python-produced SQLite archive rather than a Rust roundtrip alone.
- `python-metainfo-vectors.json` records 31 accept/reject decisions from the
  original `app.metainfo.parse_torrent`. Accepted cases include private v1,
  multifile, v2, and hybrid torrents. Rejected cases cover unsafe names,
  symlinks, overlapping paths, malformed file trees, and noncanonical bencode.

All encrypted fixtures use the public test passphrase
`correct horse battery staple`. They are intentionally committed with that
passphrase so tests do not require private infrastructure. The administrator
token is not included in the backup format.

- `python-current-upstream-backup.tibak` was generated on 2026-10-12 by the
  unmodified `app.models` and `app.backup.create_backup` from upstream commit
  `886d75a14f0d8b5663078a91bae4bd09c1336f94` (2026-10-11). The paired JSON file
  records provenance, exact dependency versions, SHA-256, every expected database
  row and setting, and base64-encoded original v1/v2/hybrid torrent metadata.
  Magnet identities come from upstream `parse_torrent`; saved API hashes match
  qBittorrent 4.5.2 (the v2 prefix for v2 and hybrid torrents).
  It includes an infected job with `infected_action=delete`, a clean job awaiting
  promotion, a pending post-promotion script, per-file scan checkpoints, and a
  committed SQLite WAL change. Source paths, usernames, passwords, tags, hashes,
  tracker passkeys and payload bytes are entirely synthetic. The temporary source
  path in saved settings is intentionally rebased by restoration.

The current fixture was created in a disposable Python environment from upstream's
exact requirements (SQLAlchemy 2.0.43, Pydantic 2.11.7, Pydantic Settings 2.10.1,
cryptography 50.0.1). Its generation populated the upstream ORM models, committed
a SQLite WAL update without closing the connection, then called upstream
`create_backup(settings, private_export_directory, public_test_passphrase)`.
Native tests do not regenerate the fixture or require Python. Encryption uses a
fresh random salt and nonce, so regeneration is not byte-for-byte deterministic;
assertions compare the stored expected content and the recorded archive digest.
