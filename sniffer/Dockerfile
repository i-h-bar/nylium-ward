# Test-only image: builds and runs the real XDP program inside an isolated
# container so it never touches the dev machine's actual network interfaces.
# See docker-compose.yml for how this gets run (privileged, but on a private
# bridge network — never --network host).

FROM rust:1.96-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends zstd \
    && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly --component rust-src --profile minimal

# Prebuilt binary, deliberately NOT `cargo install bpf-linker` — building it
# from source needs an exactly-matching system LLVM, which is precisely the
# toolchain-packaging fragility this container exists to avoid (see
# https://github.com/aya-rs/bpf-linker#installation: "building from source
# ... is not recommended for regular users").
RUN curl -L -o /tmp/bpf-linker.tar.zst \
        https://github.com/aya-rs/bpf-linker/releases/latest/download/bpf-linker-x86_64-unknown-linux-musl.tar.zst \
    && tar --zstd -xf /tmp/bpf-linker.tar.zst -C /usr/local/bin \
    && rm /tmp/bpf-linker.tar.zst

WORKDIR /build
COPY . .
RUN cargo build --release -p mc-sniffer

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/mc-sniffer /usr/local/bin/mc-sniffer
COPY docker/echo_server.py /usr/local/bin/echo_server.py
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["--iface", "eth0"]