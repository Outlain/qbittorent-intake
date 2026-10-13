# Building and publishing

This repository builds native Rust programs. The application image contains the
controller, copy helper, FFmpeg, libarchive and rsync for custom hooks. The ClamD
image contains ClamAV and its Rust supervisor. Both run as UID/GID `10001`; neither
image requires Python. Both include `LICENSE`, `NOTICE`,
`THIRD_PARTY_LICENSES.txt` and the Rust standard library's notice under
`/usr/share/doc/torrent-intake/`. Rust `1.90` is the supported minimum and the
Docker build version. `Cargo.lock` is committed and every release build uses
`--locked`.

## Image names and tags

The workflow derives image names from the lowercase GitHub repository name; no
account name is embedded in the project. For a repository named
`OWNER/qbittorent-intake`, the images are:

- `ghcr.io/owner/qbittorent-intake`
- `ghcr.io/owner/qbittorent-intake-clamd`

After all checks pass, a push to `main` publishes `latest` plus a
`sha-<full-commit-hash>` tag for each image. A version tag such as `v1.2.3`
publishes `1.2.3` plus its commit tag. Version tags do not move `latest`.
Both images contain `linux/amd64` and `linux/arm64` variants.

Pull requests and manual workflow runs validate only. Publication uses the
repository's built-in `GITHUB_TOKEN` with package-write permission scoped to the
publish job. Creating this local draft does not create a GitHub repository,
push commits, publish an image, or update any running deployment. Once the
repository is pushed to GitHub, pushes to `main` trigger the configured release
workflow. Ensure Actions is enabled and the repository may publish its packages;
choose package visibility in GHCR after the first publication.

For a new repository, use [`scripts/export-source.sh`](../scripts/export-source.sh)
to create a clean source archive, then extract it into a new folder. The export
omits this checkout's `.git` directory, original commit authors/history, build
outputs and local runtime state. Initialize or upload that extracted folder as
your new repository; do not push this working directory's existing Git history.
The script prepares files locally and never contacts GitHub.

## Release gates

The single workflow `.github/workflows/publish-ghcr.yml` requires:

- Formatting, Clippy, and the Rust suite on Rust `1.90.0`, on native Linux amd64,
  Linux arm64 and macOS runners.
- Real qBittorrent and ClamD integration tests on both Linux architectures.
  Tests use disposable profiles and synthetic antivirus signatures. They do not
  require an external service or download a production signature database.
- Native builds of both container images, nonroot identity checks, installed
  helper checks, and checks that Python is absent. Application startup is also
  tested with a read-only filesystem and dropped capabilities.
- Compose validation and desktop/mobile browser tests against the application
  image. Puppeteer is a development-only test dependency.

GitHub and Docker actions are pinned to verified commits from their official
repositories. Updating a pin should include reviewing the upstream release and
rerunning these checks. QEMU is used to build the published multi-platform
manifest; the functional tests run on native hardware.

## Local validation

From the repository root:

```sh
rustup toolchain install 1.90.0 --profile minimal --component rustfmt --component clippy
cargo +1.90.0 fmt --check
cargo +1.90.0 clippy --all-targets --locked -- -D warnings
cargo +1.90.0 test --locked

GITHUB_OWNER=example docker compose -f docker-compose.example.yml config --quiet
GITHUB_OWNER=example docker compose -f portainer-stack.example.yml config --quiet
docker build -t qbittorent-intake:test .
docker build -f Dockerfile.clamd -t qbittorent-intake-clamd:test .
```

A disposable Linux test image supplies the external scanner tools. Its test
stage includes the development toolchain; the final application image does not.
The qBittorrent extension is also only a test image:

```sh
docker build --target test -t qbittorent-intake:tests .
docker run --rm --network none qbittorent-intake:tests
docker run --rm --network none qbittorent-intake:tests sh scripts/scanner-integration.sh
docker build -f Dockerfile.qbt-tests -t qbittorent-intake:qbt-tests .
docker run --rm --network none qbittorent-intake:qbt-tests
```

For the browser tests, install the version of Puppeteer recorded in the workflow
into a temporary directory, set `NODE_PATH` to that directory's `node_modules`,
and set `CHROME_PATH` to an installed Chrome executable. Then run
`node tests/test_settings_ui.cjs` and `node tests/test_upload_ui.cjs` with
`TI_UI_TEST_IMAGE=qbittorent-intake:test`. Each test creates and removes its own
container and data volume.

## Keeping generated files current

After changing defaults or the settings catalog, regenerate the configuration
reference. After changing `Cargo.lock`, fetch the locked dependencies and
regenerate their notices. Commit the generated files with the source change:

```sh
cargo fetch --locked
cargo run --locked --offline --example generate_config_reference
cargo run --locked --offline --example generate_third_party_licenses
cargo test --locked --test configuration_reference --test dependency_notices
```

The notice generator collects text from cached dependency sources. Its
`--check` mode verifies the committed output without rewriting it:

```sh
cargo run --locked --offline --example generate_third_party_licenses -- --check
```

Deployments remain a separate operator action. Existing volumes, mount paths,
ClamD socket access and antivirus definitions must be configured before starting
containers; see the repository's deployment guide. No automatic updater or
remote deployment step is included in the publishing workflow.
