#![no_std]
#![no_main]
#![warn(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::LruHashMap,
    programs::XdpContext,
};
use aya_log_ebpf::{info, warn};
use mc_sniffer_common::ebpf::minecraft::check_handshake;
use mc_sniffer_common::ebpf::networking::ethernet;
use mc_sniffer_common::ebpf::networking::ipv4::Ipv4Packet;
use mc_sniffer_common::ebpf::networking::tcp::TcpPacket;
use mc_sniffer_common::ebpf::traits::TryParse;
use mc_sniffer_common::ebpf::utils::format_action;

const MINECRAFT_PORT: u16 = 25565;

/// One TCP connection, as seen arriving at the server. Keyed on the full
/// 4-tuple rather than the source address alone: behind playit every
/// player arrives from the same agent pod IP, and only the source port
/// tells their connections apart.
#[repr(C)]
#[derive(Clone, Copy)]
struct FlowKey {
    source_address: u32,
    destination_address: u32,
    source_port: u16,
    destination_port: u16,
}

/// Connections whose first data segment was a valid Minecraft handshake.
/// LRU so that connections which vanish without a FIN/RST age out instead
/// of filling the map.
///
/// Sized for headroom over real load (low hundreds of connections at
/// peak), not to it: server-list pings and dead connections take slots
/// too, an evicted player's next packet is dropped (they time out), and
/// the kernel's per-CPU free-slot caching can start evicting before the
/// map is actually full.
#[map]
static ALLOWED_FLOWS: LruHashMap<FlowKey, u8> = LruHashMap::with_max_entries(1024, 0);

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

    if ipv4.destination_port != MINECRAFT_PORT {
        info!(&ctx, "Skipping none minecraft packet from {:i}:{}", ipv4.source_address, ipv4.source_port);
        return Ok(xdp_action::XDP_PASS);
    }

    let tcp = match TcpPacket::try_parse(&ctx) {
        Ok(tcp) => {
            info!(&ctx, "Parsed TCP packet {} -> {}", tcp.source_port, tcp.destination_port);
            tcp
        },
        Err(action) => {
            info!(&ctx, "TCP check. Action: {}", format_action(&action));
            return Ok(action);
        }
    };

    let flow = FlowKey {
        source_address: ipv4.source_address,
        destination_address: ipv4.destination_address,
        source_port: ipv4.source_port,
        destination_port: ipv4.destination_port,
    };

    // A SYN starts a new connection; if this 4-tuple is being reused, the
    // old connection's handshake must not carry over to it.
    if tcp.flags.is_syn() {
        let _ = ALLOWED_FLOWS.remove(&flow);
    }

    let action = if tcp.payload_len == 0 {
        // SYN / ACK / FIN / RST with no data: XDP has to let the TCP
        // handshake complete before any Minecraft bytes can exist, and
        // payload-less segments carry nothing for the server to parse.
        xdp_action::XDP_PASS
    } else if ALLOWED_FLOWS.get_ptr(&flow).is_some() {
        xdp_action::XDP_PASS
    } else if check_handshake(&ctx, tcp.payload_offset, tcp.payload_len).is_ok() {
        if ALLOWED_FLOWS.insert(&flow, &0, 0).is_err() {
            warn!(&ctx, "Failed to remember flow {:i}:{}", flow.source_address, flow.source_port);
        }
        info!(&ctx, "Valid handshake from {:i}:{}", flow.source_address, flow.source_port);
        xdp_action::XDP_PASS
    } else {
        info!(&ctx, "Dropping non-handshake data from {:i}:{}", flow.source_address, flow.source_port);
        xdp_action::XDP_DROP
    };

    // Forget the connection once either side tears it down -- after the
    // verdict, so data riding on the FIN segment itself is still judged.
    if tcp.flags.is_fin() || tcp.flags.is_rst() {
        let _ = ALLOWED_FLOWS.remove(&flow);
    }

    Ok(action)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
