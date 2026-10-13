#!/bin/sh
# Run only the transport microbenchmark, in fresh processes for meaningful RSS.
# This deliberately uses a draining mock daemon, not real antivirus signatures.
# No network or production input is used; all files/sockets are temporary.
set -eu
workspace=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
artifacts=$(mktemp /tmp/ti-scanner-benchmark.XXXXXXXX)
trap 'rm -f -- "$artifacts"' EXIT HUP INT TERM
cargo test --manifest-path "$workspace/Cargo.toml" --offline --lib \
    scanning::protocol::tests::attachment_transport_benchmark \
    --no-run --message-format=json > "$artifacts"
binary=$(sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' "$artifacts")
test -n "$binary"
# Bypass cargo when launching each test: a cargo child can inherit cargo's RSS
# high-water mark, hiding the scanner's actual memory requirement.
for mode in legacy direct legacy direct legacy direct; do
    TI_TRANSPORT_BENCH="$mode" "$binary" \
        scanning::protocol::tests::attachment_transport_benchmark \
        --ignored --exact --nocapture
done
