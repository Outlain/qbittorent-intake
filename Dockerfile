# Build both native runtime programs with the supported minimum Rust version.
FROM rust:1.90-bookworm AS build
WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY resources ./resources
COPY templates ./templates
RUN cp "$(rustc --print sysroot)/share/doc/rust/COPYRIGHT-library.html" \
      /source/rust-standard-library-COPYRIGHT.html \
    && cargo build --release --locked --bin torrent-intake --bin after-promotion-copy

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates ffmpeg rsync libarchive13 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 torrent-intake \
    && useradd --uid 10001 --gid 10001 --create-home torrent-intake \
    && install -d -o 10001 -g 10001 -m 0750 /app/data /events /quarantine
COPY --from=build /source/target/release/torrent-intake /usr/local/bin/torrent-intake
COPY --from=build /source/target/release/after-promotion-copy /usr/local/bin/after-promotion-copy
COPY LICENSE NOTICE THIRD_PARTY_LICENSES.txt /usr/share/doc/torrent-intake/
COPY --from=build /source/rust-standard-library-COPYRIGHT.html /usr/share/doc/torrent-intake/
WORKDIR /app
ENV HOME=/home/torrent-intake
USER 10001:10001
EXPOSE 8000
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=10s --start-period=2m --retries=3 \
    CMD ["torrent-intake", "healthcheck"]
ENTRYPOINT ["torrent-intake"]
CMD ["--host", "0.0.0.0", "--port", "8000"]

# Disposable validation image. Test tooling never enters the runtime above.
FROM build AS test
ENV CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg rsync libarchive13 clamav-daemon && rm -rf /var/lib/apt/lists/*
COPY tests ./tests
COPY scripts ./scripts
COPY examples ./examples
COPY CONFIGURATION.md .env.example docker-compose.example.yml portainer-stack.example.yml ./
COPY THIRD_PARTY_LICENSES.txt ./
RUN cargo test --locked
CMD ["cargo", "test", "--locked", "--offline"]

FROM runtime AS final
