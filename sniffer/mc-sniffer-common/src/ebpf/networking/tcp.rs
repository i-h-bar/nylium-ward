use aya_ebpf::programs::XdpContext;
use crate::networking::net::TcpFlags;

pub struct TcpPacket {
    source_port: u16,
    destination_port: u16,
    flags: TcpFlags
}

impl TryFrom<&XdpContext> for TcpPacket {
    type Error = u32;

    fn try_from(ctx: &XdpContext) -> Result<Self, Self::Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::test_support::FakePacket;
    use aya_ebpf::bindings::xdp_action;

    // Same Ethernet+IPv4+TCP bytes as ipv4.rs's VALID_FRAME (and net.rs's
    // LOCALHOST_LOGIN_FRAME) -- source port 54321, destination port 25565,
    // PSH+ACK, TCP header at the usual EthHdr::LEN + Ipv4Hdr::LEN offset
    // this codebase already assumes elsewhere (see Ipv4Packet::try_from's
    // own TCP source-port read).
    #[rustfmt::skip]
    const VALID_FRAME: [u8; 71] = [
        // Ethernet header (14 bytes)
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // destination MAC
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // source MAC
        0x08, 0x00,                         // Ethertype: IPv4
        // IPv4 header (20 bytes, IHL = 5, no options)
        0x45, 0x00,             // version 4, IHL 5; DSCP/ECN unused
        0x00, 0x39,             // Total Length = 57 (20 + 20 + 17)
        0x12, 0x34,             // Identification (arbitrary)
        0x00, 0x00,             // Flags/Fragment offset (none)
        0x40, 0x06,             // TTL 64, Protocol 6 (TCP)
        0x00, 0x00,             // Header checksum (not validated)
        0x0A, 0x00, 0x01, 0x04, // source 10.0.1.4
        0x0A, 0x2B, 0xFF, 0x41, // destination 10.43.255.65
        // TCP header (20 bytes, data offset = 5, no options)
        0xD4, 0x31,             // source port 54321
        0x63, 0xDD,             // destination port 25565
        0x00, 0x00, 0x00, 0x01, // sequence number (arbitrary)
        0x00, 0x00, 0x00, 0x01, // ack number (arbitrary)
        0x50, 0x18,             // data offset 5, flags PSH+ACK
        0x20, 0x00,             // window size (arbitrary)
        0x00, 0x00,             // checksum (not validated)
        0x00, 0x00,             // urgent pointer (unused)
        // TCP payload: full Minecraft handshake wire bytes (length-prefix
        // included) -- same 17 bytes as PACKET_EXAMPLES.md's Example 1.
        0x10, 0x00, 0x81, 0x06, 0x09,
        b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't',
        0x63, 0xDD, 0x02,
    ];

    // `TcpPacket` doesn't derive `Debug`, so `.unwrap_err()` (which needs
    // the whole `Result`, Ok side included, to be `Debug` for its panic
    // message) isn't usable -- same reasoning as ipv4.rs's assert_dropped.
    fn assert_rejected(result: Result<TcpPacket, u32>, expected: u32) {
        match result {
            Err(action) => assert_eq!(action, expected),
            Ok(_) => panic!("expected the packet to be rejected, but it parsed successfully"),
        }
    }

    #[test]
    fn reads_ports_and_flags() {
        let mut pkt = FakePacket::new(&VALID_FRAME);
        let tcp = TcpPacket::try_from(&pkt.ctx())
            .expect("should parse a valid TCP header");
        assert_eq!(tcp.source_port, 54321);
        assert_eq!(tcp.destination_port, 25565);
        // Flags byte 0x18 = 0b0001_1000 = PSH (0x08) + ACK (0x10).
        assert!(!tcp.flags.is_syn());
        assert!(tcp.flags.is_ack());
        assert!(!tcp.flags.is_fin());
        assert!(!tcp.flags.is_rst());
        assert!(tcp.flags.is_psh());
    }

    #[test]
    fn syn_flag_is_read_correctly() {
        // A bare SYN (connection open, no data yet) -- flags byte 0x02.
        let mut frame = VALID_FRAME;
        frame[14 + 20 + 13] = 0x02; // TCP header's flags byte
        let mut pkt = FakePacket::new(&frame);
        let tcp = TcpPacket::try_from(&pkt.ctx())
            .expect("should parse a valid TCP header");
        assert!(tcp.flags.is_syn());
        assert!(!tcp.flags.is_ack());
        assert!(!tcp.flags.is_fin());
        assert!(!tcp.flags.is_rst());
        assert!(!tcp.flags.is_psh());
    }

    #[test]
    fn too_short_is_rejected() {
        // Ethernet (14) + IPv4 (20) with no TCP header at all -- one byte
        // short of the fixed 20-byte TCP header even starting to fit.
        let mut pkt = FakePacket::new(&VALID_FRAME[..34 + 19]);
        // NOTE: adjust the expected action below to match whatever
        // TcpPacket::try_from actually returns for a too-short buffer
        // (XDP_ABORTED if it comes from a ptr_at/index! bounds failure,
        // matching ethernet.rs's too_short_is_aborted and
        // Ipv4Packet::try_from's own use of ptr_at).
        assert_rejected(TcpPacket::try_from(&pkt.ctx()), xdp_action::XDP_ABORTED);
    }

    #[test]
    fn rejects_undersized_header_even_when_data_offset_claims_it_fits() {
        // data offset 0 -> header_len would compute to 0, which must not
        // bypass the real 20-byte minimum TCP header size (a legitimate
        // segment can't have a data offset below 5) -- mirrors net.rs's
        // parse_tcp test of the same name.
        //
        // NOTE: only meaningful once TcpPacket::try_from actually computes
        // and validates a data-offset-derived header length the way
        // net.rs::parse_tcp does; adjust the expected action to match your
        // design (XDP_DROP, matching how Ipv4Packet::try_from treats its
        // own semantic validation failures, is the closest existing
        // convention in this crate).
        let mut frame = VALID_FRAME;
        frame[14 + 20 + 12] = 0x00; // data offset 0, flags cleared
        let mut pkt = FakePacket::new(&frame);
        assert_rejected(TcpPacket::try_from(&pkt.ctx()), xdp_action::XDP_DROP);
    }
}