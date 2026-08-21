#![no_std]
#![no_main]
#![warn(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use mc_sniffer_common::ebpf::networking::ethernet;
use mc_sniffer_common::ebpf::networking::ipv4::Ipv4Packet;
use mc_sniffer_common::ebpf::networking::tcp::TcpPacket;
use mc_sniffer_common::ebpf::traits::TryParse;
use mc_sniffer_common::ebpf::utils::format_action;

#[xdp]
pub fn mc_sniffer(ctx: XdpContext) -> u32 {
    try_mc_sniffer(ctx).unwrap_or(xdp_action::XDP_ABORTED)
}

fn try_mc_sniffer(ctx: XdpContext) -> Result<u32, ()> {
    info!(&ctx, "Packet received");
    if let Err(action) = ethernet::check_header(&ctx) {
        info!(&ctx, "Ethernet check. Action: {}", format_action(&action));
        return Ok(action);
    }
    let ipv4 = match Ipv4Packet::try_parse(&ctx) {
        Ok(ipv4) => {
            info!(
                &ctx,
                "Parsed IPv4 packet {:i}:{} -> {:i}:{} - size={}",
                ipv4.source_address,
                ipv4.source_port,
                ipv4.destination_address,
                ipv4.destination_port,
                ipv4.total_size,
            );
            ipv4
        }
        Err(action) => {
            info!(&ctx, "Ipv4 check. Action: {}", format_action(&action));
            return Ok(action);
        }
    };

    if ipv4.destination_port != 25565 {
        info!(&ctx, "Skipping none minecraft packet from {:i}:{}", ipv4.source_address, ipv4.source_port);
        return Ok(xdp_action::XDP_PASS);
    }

    let tcp = match TcpPacket::try_parse(&ctx) {
        Ok(tcp) => {
            info!(&ctx, "Parsed TCP packet {} -> {}", tcp.destination_port, tcp.source_port);
            tcp
        },
        Err(action) => {
            info!(&ctx, "TCP check. Action: {}", format_action(&action));
            return Ok(action);
        }
    };

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
