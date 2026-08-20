use aya_ebpf::bindings::xdp_action;
use aya_ebpf::programs::XdpContext;
use network_types::eth::EthHdr;
use network_types::ip::{IpError, IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;
use crate::ebpf::utils::ptr_at;
use crate::{extract, index};

pub struct Ipv4Packet(u32, u16, usize);

impl Ipv4Packet {
    pub fn addr(&self) -> u32 {
        self.0
    }

    pub fn port(&self) -> u16 {
        self.1
    }

    pub fn len(&self) -> usize {
        self.2
    }
}

impl TryFrom<&XdpContext> for Ipv4Packet {
    type Error = u32;

    fn try_from(ctx: &XdpContext) -> Result<Self, Self::Error> {
        let ipv4hdr: *const Ipv4Hdr = index!(ctx[EthHdr::LEN]);
        if extract!(ipv4hdr).version() != 4 {
            return Err(xdp_action::XDP_DROP);
        }

        let source_addr = u32::from_be_bytes(extract!(ipv4hdr).src_addr);
        let proto = extract!(ipv4hdr).proto()
            .map_err(|IpError::InvalidProto(_proto)| xdp_action::XDP_DROP)?;

        let source_port = match proto {
            IpProto::Tcp => {
                let tcphdr: *const TcpHdr = index!(ctx[EthHdr::LEN + Ipv4Hdr::LEN]);
                u16::from_be_bytes(extract!(tcphdr).source)
            }
            IpProto::Udp => return Err(xdp_action::XDP_DROP), // Udp not allowed in this context
            _ => return Err(xdp_action::XDP_DROP),
        };

        let total_len = u16::from_be_bytes( extract!(ipv4hdr).tot_len) as usize;
        if total_len < Ipv4Hdr::LEN {
            return Err(xdp_action::XDP_DROP);
        }

        let start = ctx.data();
        let end = ctx.data_end();

        if total_len >= 1500 {
            return Err(xdp_action::XDP_DROP);
        }

        if start + EthHdr::LEN + total_len > end {
            return Err(xdp_action::XDP_DROP);
        }

        Ok(Self(source_addr, source_port, total_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::test_support::FakePacket;

    // Same Ethernet+IPv4+TCP bytes as net.rs's LOCALHOST_LOGIN_FRAME /
    // parser.rs's fixtures -- 10.0.1.4:54321 -> 10.43.255.65:25565,
    // PSH+ACK, IPv4 Total Length 57 (20 IP header + 20 TCP header + 17
    // payload), carrying a full Minecraft handshake wire payload.
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

    // `Ipv4Packet` doesn't derive `Debug`, so `.unwrap_err()` (which needs
    // the whole `Result`, Ok side included, to be `Debug` for its panic
    // message) isn't usable here -- this sidesteps that without touching
    // the struct's derives.
    fn assert_dropped(result: Result<Ipv4Packet, u32>) {
        match result {
            Err(action) => assert_eq!(action, xdp_action::XDP_DROP),
            Ok(_) => panic!("expected the packet to be dropped, but it parsed successfully"),
        }
    }

    #[test]
    fn succeeds_and_reads_addr_port_len() {
        let mut pkt = FakePacket::new(&VALID_FRAME);
        let ipv4 = Ipv4Packet::try_from(&pkt.ctx())
            .expect("should parse a valid IPv4+TCP packet");
        assert_eq!(ipv4.addr(), u32::from_be_bytes([10, 0, 1, 4]));
        assert_eq!(ipv4.port(), 54321); // TCP source port
        assert_eq!(ipv4.len(), 57); // IPv4 Total Length
    }

    #[test]
    fn tolerates_trailing_ethernet_padding() {
        // Same frame, with 6 bytes of trailing zero padding appended, as if
        // padded out to Ethernet's 64-byte minimum frame size. Total Length
        // in the header is unchanged, so this must still parse successfully
        // -- matching net.rs's parse_ipv4, which explicitly tolerates this
        // (see its own trims_trailing_ethernet_padding test).
        let mut frame = VALID_FRAME.to_vec();
        frame.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        let mut pkt = FakePacket::new(&frame);
        assert!(Ipv4Packet::try_from(&pkt.ctx()).is_ok());
    }

    #[test]
    fn rejects_non_tcp_protocol() {
        let mut frame = VALID_FRAME;
        frame[14 + 9] = 17; // protocol field, offset 9 into the IP header; 17 = UDP
        let mut pkt = FakePacket::new(&frame);
        assert_dropped(Ipv4Packet::try_from(&pkt.ctx()));
    }

    #[test]
    fn rejects_non_v4_version() {
        // KNOWN GAP vs net.rs::parse_ipv4: Ipv4Packet::try_from doesn't
        // check the version nibble at all right now, so this documents the
        // intended behavior rather than something already implemented --
        // it's expected to fail until a version check is added.
        let mut frame = VALID_FRAME;
        frame[14] = 0x65; // version 6 (IHL nibble left as 5, doesn't matter)
        let mut pkt = FakePacket::new(&frame);
        assert_dropped(Ipv4Packet::try_from(&pkt.ctx()));
    }

    #[test]
    fn rejects_total_length_greater_than_packet_len() {
        // Total Length field (IP header offset 2-3): claim 200 bytes even
        // though only 57 actually arrived. Must not read/slice past the
        // real buffer.
        let mut frame = VALID_FRAME;
        frame[14 + 2] = 0x00;
        frame[14 + 3] = 0xC8;
        let mut pkt = FakePacket::new(&frame);
        assert_dropped(Ipv4Packet::try_from(&pkt.ctx()));
    }

    #[test]
    fn rejects_total_length_smaller_than_ip_header() {
        // Total Length field: claim only 10 bytes, smaller than the 20-byte
        // IPv4 header it's attached to.
        let mut frame = VALID_FRAME;
        frame[14 + 2] = 0x00;
        frame[14 + 3] = 0x0A;
        let mut pkt = FakePacket::new(&frame);
        assert_dropped(Ipv4Packet::try_from(&pkt.ctx()));
    }
}