#![no_std]
#![no_main]
// A panic here isn't a controlled crash like it is in userspace — the
// panic_handler below is just `loop {}`, which hangs the CPU core running
// this program. These lints catch the constructs (slice indexing, .unwrap(),
// .expect(), explicit panic!) that can trigger that before they compile in.
#![warn(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

/// Toolchain scaffold only — always lets traffic through. The next step
/// (once you've reached networking programs in Liz Rice's book) is to
/// actually parse the packet here: the same byte-offset logic already
/// written and tested in `net::parse_ethernet`/`parse_ipv4`/`parse_tcp`
/// (userspace crate), rewritten for the verifier — bounds-checked reads via
/// `ctx.data()`/`ctx.data_end()` and pointer arithmetic instead of slice
/// indexing, no heap, no `Result`-returning helpers with arbitrary control
/// flow — and return `xdp_action::XDP_DROP` for malformed Minecraft-port
/// traffic instead of `XDP_PASS`.
#[xdp]
pub fn mc_sniffer(ctx: XdpContext) -> u32 {
    match try_mc_sniffer(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_mc_sniffer(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");
    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";