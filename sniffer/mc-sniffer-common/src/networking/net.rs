use crate::{checked_slice, try_slice_into};

pub const ETHERTYPE_IPV4: u16 = 0x0800;

/// The one IP protocol number this crate looks for (UDP is 17, ICMP is 1,
/// etc. — all out of scope).
pub const IP_PROTOCOL_TCP: u8 = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame<'a> {
    pub ethertype: u16,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Header {
    pub protocol: u8,
    pub source: [u8; 4],
    pub destination: [u8; 4],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Packet<'a> {
    pub header: Ipv4Header,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags(u8);

const FIN_BIT: u8 = 0b0000_0001;
const SYN_BIT: u8 = 0b0000_0010;
const RST_BIT: u8 = 0b0000_0100;
const PSH_BIT: u8 = 0b0000_1000;
const ACK_BIT: u8 = 0b0001_0000;

impl From<&u8> for TcpFlags {
    fn from(flag: &u8) -> Self {
        Self(*flag)
    }
}

impl TcpFlags {
    #[must_use]
    pub const fn is_fin(&self) -> bool {
        (self.0 & FIN_BIT) != 0
    }
    #[must_use]
    pub const fn is_syn(&self) -> bool {
        (self.0 & SYN_BIT) != 0
    }
    #[must_use]
    pub const fn is_rst(&self) -> bool {
        (self.0 & RST_BIT) != 0
    }
    #[must_use]
    pub const fn is_psh(&self) -> bool {
        (self.0 & PSH_BIT) != 0
    }

    #[must_use]
    pub const fn is_ack(&self) -> bool {
        (self.0 & ACK_BIT) != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub flags: TcpFlags,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetError {
    TooShort,
    UnsupportedEthertype(u16),
    UnsupportedIpVersion(u8),
    UnsupportedIpProtocol(u8),
}

/// Parses the fixed 14-byte Ethernet header and hands back everything after
/// it as `payload`.
///
/// # Errors
/// Returns [`NetError::TooShort`] if `frame` is under 14 bytes.
pub fn parse_ethernet(frame: &[u8]) -> Result<EthernetFrame<'_>, NetError> {
    let ethertype = u16::from_be_bytes(try_slice_into!(frame[12..14], NetError::TooShort));

    Ok(EthernetFrame {
        ethertype,
        payload: checked_slice!(frame[14..], NetError::TooShort),
    })
}

/// Parses the variable-length IPv4 header (header length computed from the
/// IHL nibble) and trims `payload` to the header's own Total Length field.
///
/// # Errors
/// Returns [`NetError::TooShort`] if `packet` is under 20 bytes, if the
/// IHL-derived header length is longer than `packet` itself, or if the
/// header's Total Length field is smaller than the header or larger than
/// `packet`'s actual length. Returns [`NetError::UnsupportedIpVersion`] if
/// the version nibble isn't `4`, or [`NetError::UnsupportedIpProtocol`] if
/// the protocol byte isn't [`IP_PROTOCOL_TCP`].
pub fn parse_ipv4(packet: &[u8]) -> Result<Ipv4Packet<'_>, NetError> {
    if packet.is_empty() || packet.len() < 20 {
        return Err(NetError::TooShort);
    }

    let first_byte = checked_slice!(packet[0], NetError::TooShort);
    let ip_version = first_byte >> 4;
    if ip_version != 4 {
        return Err(NetError::UnsupportedIpVersion(ip_version));
    }

    let header_len = ((first_byte & 0x0F) * 4) as usize;
    let &protocol = checked_slice!(packet[9], NetError::TooShort);
    if protocol != IP_PROTOCOL_TCP {
        return Err(NetError::UnsupportedIpProtocol(protocol));
    }

    let total_len = u16::from_be_bytes(try_slice_into!(packet[2..4], NetError::TooShort)) as usize;
    let source: [u8; 4] = try_slice_into!(packet[12..16], NetError::TooShort);
    let destination: [u8; 4] = try_slice_into!(packet[16..20], NetError::TooShort);

    let header = Ipv4Header {
        protocol,
        source,
        destination,
    };

    Ok(Ipv4Packet {
        header,
        payload: checked_slice!(packet[header_len..total_len], NetError::TooShort),
    })
}

/// Parses the variable-length TCP header (header length computed from the
/// data-offset nibble) and hands back everything after it as `payload`.
///
/// # Errors
/// Returns [`NetError::TooShort`] if `segment` is under 20 bytes, or if the
/// data-offset-derived header length is either longer than `segment` itself
/// or shorter than the real 20-byte minimum.
pub fn parse_tcp(segment: &[u8]) -> Result<TcpSegment<'_>, NetError> {
    let header_byte = checked_slice!(segment[12], NetError::TooShort);
    let header_len = ((header_byte >> 4) * 4) as usize;

    if segment.len() < header_len || header_len < 20 {
        return Err(NetError::TooShort);
    }

    let source_port = u16::from_be_bytes(try_slice_into!(segment[..2], NetError::TooShort));
    let destination_port = u16::from_be_bytes(try_slice_into!(segment[2..4], NetError::TooShort));

    Ok(TcpSegment {
        source_port,
        destination_port,
        flags: checked_slice!(segment[13], NetError::TooShort).into(),
        payload: checked_slice!(segment[header_len..], NetError::TooShort),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real, hand-encoded Ethernet+IPv4+TCP frame carrying the same
    // "localhost:25565, next_state=Login" Minecraft handshake used in
    // parser.rs's `handshake_localhost_login` test. See FRAME_EXAMPLES.md
    // for the byte-by-byte breakdown of every field below.
    #[rustfmt::skip]
    const LOCALHOST_LOGIN_FRAME: [u8; 71] = [
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
        // included) — same 17 bytes as PACKET_EXAMPLES.md's Example 1.
        0x10, 0x00, 0x81, 0x06, 0x09,
        b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't',
        0x63, 0xDD, 0x02,
    ];

    mod parse_ethernet {
        use super::*;

        #[test]
        fn reads_ipv4_ethertype_and_payload() {
            let frame = parse_ethernet(&LOCALHOST_LOGIN_FRAME).unwrap();
            assert_eq!(frame.ethertype, ETHERTYPE_IPV4);
            assert_eq!(frame.payload, &LOCALHOST_LOGIN_FRAME[14..]);
        }

        #[test]
        fn reports_non_ipv4_ethertype() {
            // 0x0806 = ARP. This crate doesn't reject it here — parse_ethernet
            // just reports what it found.
            let mut frame = LOCALHOST_LOGIN_FRAME;
            frame[12] = 0x08;
            frame[13] = 0x06;
            assert_eq!(parse_ethernet(&frame).unwrap().ethertype, 0x0806);
        }

        #[test]
        fn too_short() {
            let buf = [0u8; 13]; // one byte short of the fixed 14-byte header
            assert_eq!(parse_ethernet(&buf), Err(NetError::TooShort));
        }

        #[test]
        fn exact_minimum_length_succeeds() {
            // Exactly 14 bytes — the fixed header with no payload at all.
            let mut buf = [0u8; 14];
            buf[12] = 0x08;
            buf[13] = 0x00;
            let frame = parse_ethernet(&buf).unwrap();
            assert_eq!(frame.ethertype, ETHERTYPE_IPV4);
            assert!(frame.payload.is_empty());
        }

        #[test]
        fn one_byte_over_minimum_succeeds() {
            // 15 bytes — the fixed header plus a single byte of payload.
            let mut buf = [0u8; 15];
            buf[12] = 0x08;
            buf[13] = 0x00;
            buf[14] = 0xAB;
            let frame = parse_ethernet(&buf).unwrap();
            assert_eq!(frame.ethertype, ETHERTYPE_IPV4);
            assert_eq!(frame.payload, &[0xAB]);
        }
    }

    mod parse_ipv4 {
        use super::*;

        #[test]
        fn reads_header_and_trims_payload_to_total_length() {
            let eth = parse_ethernet(&LOCALHOST_LOGIN_FRAME).unwrap();
            let ip = super::super::parse_ipv4(eth.payload).unwrap();
            assert_eq!(ip.header.protocol, IP_PROTOCOL_TCP);
            assert_eq!(ip.header.source, [10, 0, 1, 4]);
            assert_eq!(ip.header.destination, [10, 43, 255, 65]);
            // Total Length (57) - header_len (20) = 37 bytes of payload.
            assert_eq!(ip.payload.len(), 37);
        }

        #[test]
        fn trims_trailing_ethernet_padding() {
            // Same frame, but with 6 bytes of trailing zero padding appended —
            // as if this were a small packet padded out to Ethernet's 64-byte
            // minimum frame size. Total Length in the header is unchanged, so
            // the padding must NOT show up in `payload`.
            let mut padded = LOCALHOST_LOGIN_FRAME.to_vec();
            padded.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            let eth = parse_ethernet(&padded).unwrap();
            let ip = super::super::parse_ipv4(eth.payload).unwrap();
            assert_eq!(ip.payload.len(), 37); // same as the unpadded case
        }

        #[test]
        fn rejects_non_tcp_protocol() {
            let mut frame = LOCALHOST_LOGIN_FRAME;
            frame[14 + 9] = 17; // protocol field, offset 9 into the IP header; 17 = UDP
            let eth = parse_ethernet(&frame).unwrap();
            assert_eq!(
                super::super::parse_ipv4(eth.payload),
                Err(NetError::UnsupportedIpProtocol(17))
            );
        }

        #[test]
        fn rejects_non_v4_version() {
            let mut frame = LOCALHOST_LOGIN_FRAME;
            frame[14] = 0x65; // version 6 (IHL nibble left as 5, doesn't matter)
            let eth = parse_ethernet(&frame).unwrap();
            assert_eq!(
                super::super::parse_ipv4(eth.payload),
                Err(NetError::UnsupportedIpVersion(6))
            );
        }

        #[test]
        fn rejects_total_length_greater_than_packet_len() {
            // Total Length field (IP header offset 2-3): claim 200 bytes even
            // though only 57 actually arrived. Must not read/slice past the
            // real buffer.
            let mut frame = LOCALHOST_LOGIN_FRAME;
            frame[14 + 2] = 0x00;
            frame[14 + 3] = 0xC8;
            let eth = parse_ethernet(&frame).unwrap();
            assert_eq!(
                super::super::parse_ipv4(eth.payload),
                Err(NetError::TooShort)
            );
        }

        #[test]
        fn rejects_total_length_less_than_header_len() {
            // Total Length field: claim only 10 bytes, smaller than the
            // 20-byte header it's attached to. A packet can't be shorter
            // than its own (fixed-size, no-options) header.
            let mut frame = LOCALHOST_LOGIN_FRAME;
            frame[14 + 2] = 0x00;
            frame[14 + 3] = 0x0A;
            let eth = parse_ethernet(&frame).unwrap();
            assert!(matches!(
                super::super::parse_ipv4(eth.payload),
                Err(NetError::TooShort)
            ));
        }

        #[test]
        fn rejects_undersized_packet_even_when_ihl_claims_it_fits() {
            // version 4, IHL 0 -> header_len computes to 0, which must not
            // bypass the real 20-byte minimum IPv4 header size. Without that
            // floor, reading the fixed-offset protocol/source/destination
            // fields below would panic instead of returning an error.
            let buf = [0x40u8; 15];
            assert_eq!(super::super::parse_ipv4(&buf), Err(NetError::TooShort));
        }
    }

    mod parse_tcp {
        use super::*;

        #[test]
        fn reads_ports_flags_and_payload() {
            let eth = parse_ethernet(&LOCALHOST_LOGIN_FRAME).unwrap();
            let ip = super::super::parse_ipv4(eth.payload).unwrap();
            let tcp = super::super::parse_tcp(ip.payload).unwrap();
            assert_eq!(tcp.source_port, 54321);
            assert_eq!(tcp.destination_port, 25565);
            // Flags byte 0x18 = 0b0001_1000 = PSH (0x08) + ACK (0x10).
            assert!(!tcp.flags.is_syn());
            assert!(tcp.flags.is_ack());
            assert!(!tcp.flags.is_fin());
            assert!(!tcp.flags.is_rst());
            assert!(tcp.flags.is_psh());
            // This is the same 17-byte full-wire Minecraft packet used in
            // parser.rs's handshake_localhost_login test.
            assert_eq!(tcp.payload.len(), 17);
            assert_eq!(tcp.payload[0], 0x10); // outer Minecraft length-prefix VarInt
        }

        #[test]
        fn syn_has_no_payload() {
            // A bare SYN (connection open, no data yet) — flags byte 0x02, and
            // in this example nothing follows the 20-byte fixed header.
            #[rustfmt::skip]
            let syn_segment: [u8; 20] = [
                0xD4, 0x31, 0x63, 0xDD,             // ports
                0x00, 0x00, 0x00, 0x00,             // sequence number
                0x00, 0x00, 0x00, 0x00,             // ack number (unused on a SYN)
                0x50, 0x02,                          // data offset 5, flags SYN
                0x20, 0x00, 0x00, 0x00, 0x00, 0x00, // window, checksum, urgent
            ];
            let tcp = super::super::parse_tcp(&syn_segment).unwrap();
            assert!(tcp.flags.is_syn());
            assert!(!tcp.flags.is_ack());
            assert!(!tcp.flags.is_fin());
            assert!(!tcp.flags.is_rst());
            assert!(!tcp.flags.is_psh());
            assert!(tcp.payload.is_empty());
        }

        #[test]
        fn too_short() {
            let buf = [0u8; 19]; // one byte short of the fixed 20-byte minimum
            assert_eq!(super::super::parse_tcp(&buf), Err(NetError::TooShort));
        }

        #[test]
        fn rejects_undersized_header_even_when_data_offset_claims_it_fits() {
            // data offset 0 -> header_len computes to 0, which must not
            // bypass the real 20-byte minimum TCP header size (a legitimate
            // segment can't have a data offset below 5). Without that floor,
            // the header bytes (ports, flags, etc.) would leak into
            // `payload` instead of this returning an error.
            #[rustfmt::skip]
            let segment: [u8; 20] = [
                0xD4, 0x31, 0x63, 0xDD,             // ports
                0x00, 0x00, 0x00, 0x00,             // sequence number
                0x00, 0x00, 0x00, 0x00,             // ack number
                0x00, 0x02,                          // data offset 0, flags SYN
                0x20, 0x00, 0x00, 0x00, 0x00, 0x00, // window, checksum, urgent
            ];
            assert_eq!(super::super::parse_tcp(&segment), Err(NetError::TooShort));
        }
    }
}
