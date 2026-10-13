#!/bin/sh
# Linux runner; install cargo/rustc, clamav-daemon, ffmpeg, and libarchive13.
# Uses tiny synthetic signatures, never downloads or changes system databases.
set -eu
workspace=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fixture=$(mktemp -d /tmp/ti-rust-clamd.XXXXXXXX)
clamd_pid=
cleanup() {
    if [ -n "$clamd_pid" ]; then kill "$clamd_pid" 2>/dev/null || true; wait "$clamd_pid" 2>/dev/null || true; fi
    rm -rf -- "$fixture"
}
trap cleanup EXIT HUP INT TERM
mkdir "$fixture/definitions"
printf '%s\n' 'Test.EICAR:0:*:58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a' > "$fixture/definitions/test.ndb"
cat > "$fixture/clamd.conf" <<CONFIG
Foreground yes
LocalSocket $fixture/clamd.sock
LocalSocketMode 600
DatabaseDirectory $fixture/definitions
TemporaryDirectory $fixture
MaxThreads 4
MaxQueue 8
StreamMaxLength 8M
MaxFileSize 8M
MaxScanSize 16M
AlertExceedsMax yes
AlertEncrypted yes
AlertBrokenExecutables yes
AlertBrokenMedia yes
HeuristicScanPrecedence no
CONFIG
clamd --config-file="$fixture/clamd.conf" > "$fixture/clamd.log" 2>&1 &
clamd_pid=$!
attempt=0
while [ ! -S "$fixture/clamd.sock" ]; do
    if ! kill -0 "$clamd_pid" 2>/dev/null; then cat "$fixture/clamd.log"; exit 1; fi
    attempt=$((attempt + 1))
    if [ "$attempt" -gt 60 ]; then cat "$fixture/clamd.log"; exit 1; fi
    sleep 1
done
# Parser-only tests first use an exact attachment marker in the mock daemon.
# Then rerun through real ClamD to verify wire compatibility and EICAR handling.
cargo test --manifest-path "$workspace/Cargo.toml" --test scanner_integration --locked --offline -- --ignored --nocapture --skip real_clamd_native_clean_and_eicar
TI_TEST_CLAMD_SOCKET="$fixture/clamd.sock" cargo test --manifest-path "$workspace/Cargo.toml" --test scanner_integration --locked --offline -- --ignored --nocapture
