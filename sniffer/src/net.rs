//! Walks a raw captured frame down through Ethernet, IPv4, and TCP framing to
//! get to the one thing the rest of this crate actually cares about: a TCP
//! payload, and which 4-tuple it belongs to. This is the same kind of
//! byte-offset header-walking you'll do again (with far fewer conveniences)
//! if this ever becomes an eBPF program — no `pnet`/libpcap equivalent exists
//! there, so it's worth learning to do by hand now.
//!
//! See `../FRAME_EXAMPLES.md` for a real, byte-by-byte worked example — a
//! full Ethernet+IPv4+TCP frame carrying one of the same Minecraft handshake
//! payloads from `PACKET_EXAMPLES.md`, so you can trace a packet all the way
//! from the wire down to what `parse_handshake` already knows how to read.
//!
//! ## Scope decisions worth knowing up front
//! - **IPv4 only.** This pod's cluster networking is IPv4-only already (see
//!   the playit-hardening design doc's note on this host having no IPv6
//!   route) — IPv6 support is a deliberate non-goal, not an oversight.
//! - **TCP only.** Nothing else this sniffer cares about (Minecraft traffic)
//!   runs over anything else.
//! - **Checksums are not validated.** A bad IP/TCP checksum means "corrupted
//!   in transit," which is a different concern from "not a valid Minecraft
//!   packet" — out of scope here.
//! - **`parse_handshake` still needs help before you can call it.** This
//!   module gets you the TCP payload. `parse_handshake` expects the packet
//!   *body* — packet ID onward, with the outer Minecraft length-prefix VarInt
//!   already stripped. Stripping that prefix and deciding *which* payload
//!   bytes are "the first packet of a new connection" is flow-tracking logic
//!   for the next segment (the capture loop in `main.rs`), not this module.

/// The one Ethertype value this crate looks for — everything else (ARP,
/// IPv6, VLAN tags, ...) is out of scope and reported as
/// `NetError::UnsupportedEthertype`.
pub const ETHERTYPE_IPV4: u16 = 0x0800;

/// The one IP protocol number this crate looks for (UDP is 17, ICMP is 1,
/// etc. — all out of scope).
pub const IP_PROTOCOL_TCP: u8 = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame<'a> {
    pub ethertype: u16,
    /// Everything after the 14-byte Ethernet header — handed to `parse_ipv4`.
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
    /// The IP payload, trimmed to the header's own Total Length field — see
    /// `parse_ipv4`'s doc comment for why that trimming matters.
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub flags: TcpFlags,
    /// Everything after the TCP header — this is what eventually reaches
    /// `parse_handshake` (once the flow-tracking loop decides it's worth
    /// looking at, and strips the Minecraft length-prefix VarInt).
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetError {
    /// The buffer was shorter than the header currently being read needs —
    /// carries what was actually needed, for whichever header hit it.
    TooShort { needed: usize, got: usize },
    /// Not an Ethertype this crate handles (see `ETHERTYPE_IPV4`).
    UnsupportedEthertype(u16),
    /// The IP version nibble wasn't 4.
    UnsupportedIpVersion(u8),
    /// Not a protocol this crate handles (see `IP_PROTOCOL_TCP`).
    UnsupportedIpProtocol(u8),
}

/// Parses the fixed 14-byte Ethernet header: 6 bytes destination MAC, 6 bytes
/// source MAC (both ignored — nothing here needs them), then a 2-byte
/// Ethertype, big-endian, at offset 12. Everything from offset 14 onward is
/// the payload — for `ETHERTYPE_IPV4`, that's an IPv4 packet.
///
/// # Your task
/// Check there are at least 14 bytes. Read the 2-byte Ethertype at offset 12
/// (`u16::from_be_bytes`). Return the struct with `payload` set to
/// `&frame[14..]`. This function does **not** reject non-IPv4 Ethertypes
/// itself — it just reports what it found; `ethertype != ETHERTYPE_IPV4` is
/// the caller's problem (the capture loop, later) to filter on or not.
pub fn parse_ethernet(frame: &[u8]) -> Result<EthernetFrame<'_>, NetError> {
    todo!("read the Ethertype at offset 12, return the struct with payload = &frame[14..]")
}

/// Parses an IPv4 header — which, unlike Ethernet's fixed 14 bytes, has a
/// **variable length**: the low 4 bits of the very first byte are the IHL
/// (Internet Header Length), a count of 32-bit *words*, not bytes. Almost
/// always `5` (20 bytes, no options), but never assume that — always compute
/// `header_len = ihl * 4` and use it.
///
/// Other fields you need, all fixed-offset regardless of IHL:
/// - byte 0, high nibble: IP version — reject anything that isn't `4`
/// - bytes 2-3: **Total Length**, big-endian — the whole IP packet's length
///   (header + payload) *as sent*, which may well be less than
///   `packet.len()`: Ethernet frames have a 64-byte minimum size, so a small
///   IP packet can arrive with trailing zero-padding you must NOT treat as
///   payload. Use Total Length to trim the payload's end, not `packet.len()`.
/// - byte 9: protocol number (see `IP_PROTOCOL_TCP`)
/// - bytes 12-15: source address
/// - bytes 16-19: destination address
///
/// # Your task
/// Validate version == 4 and compute `header_len` from the IHL nibble
/// (`NetError::TooShort` if `packet.len() < header_len`). Read Total Length;
/// if it's less than `header_len` or greater than `packet.len()`, that's also
/// `NetError::TooShort` (a packet can't claim to be bigger than what actually
/// arrived). Slice `payload` as `&packet[header_len..total_length]`. Read
/// protocol, source, destination at their fixed offsets above.
pub fn parse_ipv4(packet: &[u8]) -> Result<Ipv4Packet<'_>, NetError> {
    todo!("compute header_len from the IHL nibble, trim payload to Total Length, read the fixed-offset fields")
}

/// Parses a TCP header — which, like IPv4, has a **variable length**: the
/// top 4 bits of byte 12 are the Data Offset, a count of 32-bit words (same
/// idea as IPv4's IHL, different field name). `header_len = data_offset * 4`.
///
/// Fixed-offset fields:
/// - bytes 0-1: source port, big-endian
/// - bytes 2-3: destination port, big-endian
/// - byte 12, high nibble: data offset (as above)
/// - byte 13: flags — one bit each, low to high: `FIN=0x01, SYN=0x02,
///   RST=0x04, PSH=0x08, ACK=0x10` (URG/ECE/CWR exist too but nothing here
///   needs them)
///
/// # Your task
/// Compute `header_len` from byte 12's high nibble; `NetError::TooShort` if
/// `segment.len() < header_len` (this also covers the "segment is shorter
/// than the fixed 20-byte minimum" case, since `header_len` is always
/// `>= 20`). Read the two ports. Read byte 13 and mask out each flag bit into
/// `TcpFlags`. `payload` is `&segment[header_len..]`.
pub fn parse_tcp(segment: &[u8]) -> Result<TcpSegment<'_>, NetError> {
    todo!("compute header_len from the data-offset nibble, read ports + flags, slice the payload")
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

    // ---- parse_ethernet -----------------------------------------------------

    #[test]
    fn ethernet_reads_ipv4_ethertype_and_payload() {
        let frame = parse_ethernet(&LOCALHOST_LOGIN_FRAME).unwrap();
        assert_eq!(frame.ethertype, ETHERTYPE_IPV4);
        assert_eq!(frame.payload, &LOCALHOST_LOGIN_FRAME[14..]);
    }

    #[test]
    fn ethernet_reports_non_ipv4_ethertype() {
        // 0x0806 = ARP. This crate doesn't reject it here — parse_ethernet
        // just reports what it found.
        let mut frame = LOCALHOST_LOGIN_FRAME;
        frame[12] = 0x08;
        frame[13] = 0x06;
        assert_eq!(parse_ethernet(&frame).unwrap().ethertype, 0x0806);
    }

    #[test]
    fn ethernet_too_short() {
        let buf = [0u8; 13]; // one byte short of the fixed 14-byte header
        assert_eq!(
            parse_ethernet(&buf),
            Err(NetError::TooShort { needed: 14, got: 13 })
        );
    }

    // ---- parse_ipv4 -----------------------------------------------------

    #[test]
    fn ipv4_reads_header_and_trims_payload_to_total_length() {
        let eth = parse_ethernet(&LOCALHOST_LOGIN_FRAME).unwrap();
        let ip = parse_ipv4(eth.payload).unwrap();
        assert_eq!(ip.header.protocol, IP_PROTOCOL_TCP);
        assert_eq!(ip.header.source, [10, 0, 1, 4]);
        assert_eq!(ip.header.destination, [10, 43, 255, 65]);
        // Total Length (57) - header_len (20) = 37 bytes of payload.
        assert_eq!(ip.payload.len(), 37);
    }

    #[test]
    fn ipv4_trims_trailing_ethernet_padding() {
        // Same frame, but with 6 bytes of trailing zero padding appended —
        // as if this were a small packet padded out to Ethernet's 64-byte
        // minimum frame size. Total Length in the header is unchanged, so
        // the padding must NOT show up in `payload`.
        let mut padded = LOCALHOST_LOGIN_FRAME.to_vec();
        padded.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        let eth = parse_ethernet(&padded).unwrap();
        let ip = parse_ipv4(eth.payload).unwrap();
        assert_eq!(ip.payload.len(), 37); // same as the unpadded case
    }

    #[test]
    fn ipv4_rejects_non_tcp_protocol() {
        let mut frame = LOCALHOST_LOGIN_FRAME;
        frame[14 + 9] = 17; // protocol field, offset 9 into the IP header; 17 = UDP
        let eth = parse_ethernet(&frame).unwrap();
        assert_eq!(parse_ipv4(eth.payload), Err(NetError::UnsupportedIpProtocol(17)));
    }

    #[test]
    fn ipv4_rejects_non_v4_version() {
        let mut frame = LOCALHOST_LOGIN_FRAME;
        frame[14] = 0x65; // version 6 (IHL nibble left as 5, doesn't matter)
        let eth = parse_ethernet(&frame).unwrap();
        assert_eq!(parse_ipv4(eth.payload), Err(NetError::UnsupportedIpVersion(6)));
    }

    // ---- parse_tcp -----------------------------------------------------

    #[test]
    fn tcp_reads_ports_flags_and_payload() {
        let eth = parse_ethernet(&LOCALHOST_LOGIN_FRAME).unwrap();
        let ip = parse_ipv4(eth.payload).unwrap();
        let tcp = parse_tcp(ip.payload).unwrap();
        assert_eq!(tcp.source_port, 54321);
        assert_eq!(tcp.destination_port, 25565);
        assert_eq!(
            tcp.flags,
            TcpFlags { syn: false, ack: true, fin: false, rst: false, psh: true }
        );
        // This is the same 17-byte full-wire Minecraft packet used in
        // parser.rs's handshake_localhost_login test.
        assert_eq!(tcp.payload.len(), 17);
        assert_eq!(tcp.payload[0], 0x10); // outer Minecraft length-prefix VarInt
    }

    #[test]
    fn tcp_syn_has_no_payload() {
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
        let tcp = parse_tcp(&syn_segment).unwrap();
        assert_eq!(
            tcp.flags,
            TcpFlags { syn: true, ack: false, fin: false, rst: false, psh: false }
        );
        assert!(tcp.payload.is_empty());
    }

    #[test]
    fn tcp_too_short() {
        let buf = [0u8; 19]; // one byte short of the fixed 20-byte minimum
        assert_eq!(
            parse_tcp(&buf),
            Err(NetError::TooShort { needed: 20, got: 19 })
        );
    }
}