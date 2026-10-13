#!/bin/sh
# Create a clean source tree for a new repository, without this checkout's Git
# history, build outputs, machine ownership metadata, or local runtime state.
set -eu
umask 077
source_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=${1:-"$source_root/dist/qbittorent-intake-source.tar.gz"}
case "$output" in /*) ;; *) output="$PWD/$output" ;; esac
if [ -e "$output" ]; then
    echo "Refusing to overwrite an existing archive: $output" >&2
    exit 1
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
stage="$work/qbittorent-intake"
mkdir "$stage"
cd "$source_root"
# Deliberately enumerate roots: never archive the entire working directory.
for file in Cargo.toml Cargo.lock rust-toolchain.toml \
    Dockerfile Dockerfile.clamd Dockerfile.qbt-tests \
    README.md CONFIGURATION.md LICENSE NOTICE THIRD_PARTY_LICENSES.txt \
    .gitignore .dockerignore .env.example \
    docker-compose.example.yml portainer-stack.example.yml; do
    test -f "$file" && test ! -L "$file"
    cp "$file" "$stage/$file"
done
for tree in src resources templates clamav docs examples scripts tests .github; do
    # Symlinks could import files from outside this reviewed source tree.
    if [ -n "$(find "$tree" -type l -print)" ]; then
        echo "Refusing symlinks in source directory: $tree" >&2
        exit 1
    fi
    find "$tree" -type f -print > "$work/files"
    while IFS= read -r file; do
        # Ignore common editor state, local credentials and build/runtime files.
        case "$file" in
            */.env|*/.env.*|*/admin-token|*/settings.json|*/deployment-notes.txt|\
            *.db|*.db-*|*.sqlite|*.sqlite-*|*.sqlite3|*.sqlite3-*|*.log|\
            *.pem|*.key|*.p12|*.pfx|*/.DS_Store|*/__pycache__/*|\
            */node_modules/*|*/target/*|*/.git/*) continue ;;
            tests/fixtures/python-backup-vector.tibak|\
            tests/fixtures/python-legacy-backup.tibak|\
            tests/fixtures/python-current-upstream-backup.tibak) ;;
            *.tibak) continue ;;
        esac
        mkdir -p "$stage/$(dirname "$file")"
        cp "$file" "$stage/$file"
    done < "$work/files"
done
# Normalize modes and mtimes, then ownership in tar headers. The archive reveals
# neither local account names nor this checkout's path or file-edit timestamps.
find "$stage" -type d -exec chmod 755 {} +
find "$stage" -type f -exec chmod 644 {} +
find "$stage/scripts" -name '*.sh' -exec chmod 755 {} +
find "$stage" -exec env TZ=UTC touch -t 202601010000 {} +
mkdir -p "$(dirname "$output")"
if tar --version 2>/dev/null | head -1 | grep -q 'bsdtar'; then
    COPYFILE_DISABLE=1 tar --format ustar --no-xattrs --no-acls --no-fflags \
        --uid 0 --gid 0 --uname root --gname root -C "$work" \
        -cf "$work/source.tar" qbittorent-intake
else
    tar --format=ustar --owner=0 --group=0 --numeric-owner -C "$work" \
        -cf "$work/source.tar" qbittorent-intake
fi
# gzip's own header otherwise records the export time even when tar times are
# normalized. -n omits both that timestamp and the temporary archive filename.
gzip -n -c "$work/source.tar" > "$output"
printf 'Created %s\n' "$output"
