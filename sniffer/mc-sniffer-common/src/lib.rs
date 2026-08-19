#![cfg_attr(not(test), no_std)]
#![warn(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

// Shared types between mc-sniffer (userspace) and mc-sniffer-ebpf (kernel)
// go here once the XDP program needs to report something back to userspace
// — e.g. a struct describing a dropped/malformed packet, sent up through a
// PerfEventArray or RingBuf map. Empty for now; the toolchain scaffold
// doesn't need it yet.

pub mod net;
pub mod parser;
pub mod macros;
