# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`sniffer/` is an Aya-based (Rust) eBPF/XDP program meant to sit in front of the Minecraft server (port 25565) and drop traffic that isn't a valid Minecraft handshake. The parent repo (`../`) is the server deployment itself (Helm chart, Cilium, playit tunnel) with its own separate `Taskfile.yaml`. Run sniffer commands from `sniffer/`, not the repo root.

## Commands

```sh
cargo test                                   # unit tests (no root needed)
cargo test -p mc-sniffer-common <test_name>  # single test / filter
cargo clippy --all-targets                   # workspace lints: clippy all+pedantic+nursery+cargo at warn

task run IFACE=<iface>                       # sudo -E cargo run --release -- --iface <iface>; attaches XDP to a real interface
task test:docker                             # Docker integration tests (cd tests && uv run pytest)
cd tests && uv run pytest -k <name>          # single integration test
```

- Building `mc-sniffer` (a default workspace member, so plain `cargo test`/`cargo build` included) runs `mc-sniffer/build.rs`, which cargo-in-cargo builds `mc-sniffer-ebpf` via `aya_build`. That needs a nightly toolchain with `rust-src` and `bpf-linker` on `PATH`. `mc-sniffer-ebpf` is deliberately not a default member, so don't build it directly with the host target.
- `.cargo/config.toml` intentionally sets no `runner`: a runner would apply to `cargo test` too, and the tests don't need root. Only `cargo run` needs root (CAP_BPF/CAP_NET_ADMIN).
- The Docker harness (`Dockerfile`, `docker-compose.yml`) runs the real XDP program on the container's own veth on a private bridge network. `privileged: true` is only there so `bpf()` gets past seccomp. Never switch it to `network_mode: host`. Unit tests passing doesn't mean the verifier will accept the program, so after changing anything in the eBPF path, run `task test:docker`: a rejected program shows the verifier log in `docker compose logs sniffer` instead of `Waiting for Ctrl-C...`.

## Architecture

Three crates (the standard aya template layout):

- **`mc-sniffer-ebpf`**: the `#![no_std]` XDP program (`mc_sniffer`). It chains Ethernet check → `Ipv4Packet::try_parse` → port 25565 filter → `TcpPacket::try_parse` → per-connection verdict. Each step returns `Result<_, xdp_action>`, and the `Err` value *is* the XDP verdict to return. The verdict works like this:
  - Payload-less segments pass.
  - A connection whose first data segment passes `minecraft::check_handshake` is recorded in the `ALLOWED_FLOWS` LRU map and passes from then on. Anything else is dropped.
  - SYN, FIN and RST clear the connection's map entry.
  - Flows are keyed on the full 4-tuple, not the source IP, because behind playit every player arrives from the same agent pod IP.
- **`mc-sniffer`**: userspace loader. It embeds the compiled eBPF object (`include_bytes_aligned!(OUT_DIR/mc-sniffer)`), forwards `aya-log` output to `env_logger` (set `RUST_LOG=info` to see it), attaches to `--iface`, and waits for Ctrl-C.
- **`mc-sniffer-common`**: all parsing logic, shared by both sides. It is `no_std` except under `cfg(test)`, and the `user` feature pulls in `aya` for userspace.

Inside `mc-sniffer-common` there are two parsing layers:

- `ebpf/`: what the kernel program actually uses. Parsers are generic over the `EbpfContext` / `EbpfAction` / `TryParse` traits (`ebpf/traits.rs`), and `ebpf/networking/xdp.rs` implements them for `XdpContext` / `xdp_action::Type`. Packet access goes through `ctx.index::<T>(offset)` → `utils::ptr_at`, which bounds-checks against `data_end` for the verifier, and the `extract!` macro (`macros.rs`) derefs the result. Bounds-check helpers are `#[inline(always)]` because the verifier needs them inlined.
- `networking/`: plain `&[u8]` slice parsers. `net.rs` handles Ethernet/IPv4/TCP, and `parser.rs` handles the Minecraft handshake: VarInt, MC string, `parse_handshake`. These are the reference implementations. The kernel-side handshake check is `ebpf/minecraft.rs`, and it intentionally accepts more than `parse_handshake` does: bytes after the handshake frame and next state 3 are allowed. See its module doc.

Conventions for code that ends up in the eBPF program: `clippy::indexing_slicing`, `unwrap_used`, `expect_used`, and `panic` are warned on outside tests. Use `.get()` with the `checked_slice!` / `try_slice_into!` macros, or `ptr_at`, never raw indexing.

Verifier pitfalls already hit here (comments at each site):
- **Second pointer into a checked header.** Don't take a second `ctx.index` into a header you already checked at a variable offset. LLVM drops the check as redundant and the verifier rejects the load. Read through the checked reference instead (e.g. `TcpFlags::from_header`).
- **Hidden `len` in `ptr_at`.** `ptr_at` hides `len` from LLVM with `read_volatile` so 1-byte bounds checks aren't folded into a form the verifier can't use.
- **Lengths from the wire.** A length read from the packet and used as an offset needs a bitmask clamp in addition to its range check (`ADDRESS_LEN_MASK`).

### Testing eBPF parsers on the host

`ebpf/test_support.rs::FakePacket` builds a *real* `XdpContext` in a unit test. It copies the fixture bytes into memory mapped with `mmap(MAP_32BIT)`, because `xdp_md.data`/`data_end` are `u32` and a normal 64-bit address would be truncated. The buffer is sized exactly to the fixture, so too-short/boundary tests behave like a real packet. This only works on x86-64 Linux. Use `FakePacket::new(&bytes).ctx()` for any new `TryParse` impl test.

`PACKET_EXAMPLES.md` (handshake encoding) and `FRAME_EXAMPLES.md` (a full 71-byte Ethernet+IPv4+TCP+handshake frame) walk through the same byte fixtures the tests use. (Their `src/parser.rs` / `src/net.rs` references now live under `mc-sniffer-common/src/networking/`.)