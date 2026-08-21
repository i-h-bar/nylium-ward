use crate::extract;
use aya_ebpf::bindings::xdp_action;
use network_types::eth::{EthHdr, EtherType};
use crate::ebpf::traits::{EbpfAction, EbpfContext};

/// Checks that `ctx` carries a well-formed Ethernet header, and that its
/// Ethertype is IPv4 -- the only traffic this crate cares about.
///
/// # Errors
/// Returns [`xdp_action::XDP_ABORTED`] if the Ethernet header itself doesn't
/// fit in the packet. Returns [`xdp_action::XDP_PASS`] if the header is
/// well-formed but the Ethertype isn't IPv4 -- this isn't corrupted, just
/// uninteresting traffic (ARP, IPv6, ...) that should be passed through
/// untouched rather than dropped.
pub fn check_header<C: EbpfContext>(ctx: &C) -> Result<(), C::Action> {
    let eth_hdr: *const EthHdr = ctx.index(0)?;
    match extract!(eth_hdr).ether_type() {
        Ok(EtherType::Ipv4) => Ok(()),
        _ => Err(C::Action::ok()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::test_support::FakePacket;

    // Same 14-byte Ethernet header shape used throughout this crate's other
    // fixtures (net.rs, parser.rs) -- destination/source MAC, then
    // Ethertype IPv4.
    #[rustfmt::skip]
    const MIN_ETH_FRAME: [u8; 14] = [
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // destination MAC
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // source MAC
        0x08, 0x00,                         // Ethertype: IPv4
    ];

    #[test]
    fn accepts_ipv4_ethertype() {
        let mut pkt = FakePacket::new(&MIN_ETH_FRAME);
        assert_eq!(check_header(&pkt.ctx()), Ok(()));
    }

    #[test]
    fn passes_through_non_ipv4_ethertype() {
        // 0x0806 = ARP. Not corrupted -- a perfectly valid Ethernet header,
        // just not carrying IPv4 -- so this must come back as Err(XDP_PASS),
        // not XDP_DROP (this is the exact ARP-logged-as-"corrupted" bug
        // found and fixed earlier: check_header must not conflate "valid
        // header, uninteresting ethertype" with "couldn't parse this at
        // all").
        let mut frame = MIN_ETH_FRAME;
        frame[12] = 0x08;
        frame[13] = 0x06;
        let mut pkt = FakePacket::new(&frame);
        assert_eq!(check_header(&pkt.ctx()), Err(xdp_action::XDP_PASS));
    }

    #[test]
    fn too_short_is_aborted() {
        let mut pkt = FakePacket::new(&[0u8; 13]); // one byte short of the fixed 14-byte header
        assert_eq!(check_header(&pkt.ctx()), Err(xdp_action::XDP_ABORTED));
    }

    #[test]
    fn exact_minimum_length_succeeds() {
        let mut pkt = FakePacket::new(&MIN_ETH_FRAME); // exactly 14 bytes
        assert_eq!(check_header(&pkt.ctx()), Ok(()));
    }

    #[test]
    fn one_byte_over_minimum_succeeds() {
        let mut frame = MIN_ETH_FRAME.to_vec();
        frame.push(0xAB);
        let mut pkt = FakePacket::new(&frame);
        assert_eq!(check_header(&pkt.ctx()), Ok(()));
    }
}
