//! Minecraft handshake validation straight off packet memory -- the
//! eBPF-side counterpart of [`crate::networking::parser::parse_handshake`].
//!
//! The slice-based parser can't run in the kernel as-is: the verifier won't
//! accept a `&[u8]` over packet memory, so every byte here is read through
//! a bounds-checked [`EbpfContext::index`], every loop has a fixed upper
//! bound, and every length taken from the wire is capped before it's used
//! as an offset.
//!
//! It also differs from `parse_handshake` on purpose in what it accepts:
//! - it starts at the length-prefix `VarInt` (the raw TCP payload), not the
//!   packet ID;
//! - bytes *after* the handshake frame are fine -- real clients send
//!   Handshake + Login Start / Status Request in the same segment;
//! - next state 3 (Transfer, 1.20.5+) is accepted alongside 1 and 2;
//! - the server address is length-checked but not UTF-8 validated (the
//!   server itself does that).

use crate::ebpf::traits::{EbpfAction, EbpfContext};
use crate::extract;

const MAX_VARINT_BYTES: usize = 5;
const CONTINUE_BIT: u8 = 0b1000_0000;
const SEGMENT_BIT: u8 = 0b0111_1111;

/// Vanilla reads the server address as `String(255)`: at most 255 chars,
/// i.e. at most 255 * 3 bytes of UTF-8 on the wire.
pub const MAX_SERVER_ADDRESS_BYTES: u32 = 255 * 3;

/// Largest possible handshake body: packet ID (1) + protocol version (up to
/// 5) + address length (2, for anything <= 765) + address + port (2) + next
/// state (1).
pub const MAX_HANDSHAKE_LEN: u32 = 1 + 5 + 2 + MAX_SERVER_ADDRESS_BYTES + 2 + 1;

/// Smallest all-ones mask covering [`MAX_SERVER_ADDRESS_BYTES`] -- see its
/// use in [`check_handshake`].
const ADDRESS_LEN_MASK: usize = 0x3FF;
const _: () = assert!(MAX_SERVER_ADDRESS_BYTES as usize <= ADDRESS_LEN_MASK);

/// Reads one byte at `offset`, mapping an out-of-bounds read to a drop --
/// running off the end of the packet here means a truncated handshake, not
/// a corrupted context.
#[allow(clippy::inline_always)] // Needed for eBPF verifier
#[inline(always)]
fn byte_at<C: EbpfContext>(ctx: &C, offset: usize) -> Result<u8, C::Action> {
    let ptr = ctx.index::<u8>(offset).map_err(|_| C::Action::drop())?;
    Ok(*extract!(ptr))
}

/// Reads a `VarInt` at `offset`, returning its raw 32 bits (negative values
/// come out as huge `u32`s, which every caller's upper-bound check then
/// rejects) and how many bytes it took.
#[allow(clippy::inline_always)] // Needed for eBPF verifier
#[inline(always)]
fn read_varint<C: EbpfContext>(ctx: &C, offset: usize) -> Result<(u32, usize), C::Action> {
    let mut value = 0u32;
    for i in 0..MAX_VARINT_BYTES {
        let byte = byte_at(ctx, offset + i)?;
        value |= u32::from(byte & SEGMENT_BIT) << (7 * i);
        if byte & CONTINUE_BIT == 0 {
            return Ok((value, i + 1));
        }
    }
    Err(C::Action::drop())
}

/// Checks that the TCP payload at `offset` (`len` bytes, as declared by the
/// IP/TCP headers) *starts with* one complete, well-formed Minecraft
/// handshake frame.
///
/// # Errors
/// Returns `C::Action`'s drop action if the payload isn't a handshake: a
/// zero/oversized/truncated frame length, a packet ID other than `0`, an
/// oversized server address, a next state outside `1..=3`, or fields that
/// don't add up to exactly the declared frame length.
#[allow(clippy::inline_always)] // Needed for eBPF verifier
#[inline(always)]
pub fn check_handshake<C: EbpfContext>(
    ctx: &C,
    offset: usize,
    len: usize,
) -> Result<(), C::Action> {
    let (frame_len, prefix_len) = read_varint(ctx, offset)?;
    if frame_len == 0 || frame_len > MAX_HANDSHAKE_LEN {
        return Err(C::Action::drop());
    }
    let frame_len = frame_len as usize;
    if prefix_len + frame_len > len {
        return Err(C::Action::drop());
    }

    let body = offset + prefix_len;
    let mut pos = 0;

    let (packet_id, n) = read_varint(ctx, body + pos)?;
    if packet_id != 0 {
        return Err(C::Action::drop());
    }
    pos += n;

    let (_protocol_version, n) = read_varint(ctx, body + pos)?;
    pos += n;

    let (address_len, n) = read_varint(ctx, body + pos)?;
    if address_len > MAX_SERVER_ADDRESS_BYTES {
        return Err(C::Action::drop());
    }
    // The mask is a no-op for any length that passed the check above, but
    // LLVM may test a different copy of `address_len` than the one it adds
    // here, leaving the verifier with no upper bound on the offset (and
    // rejecting every read after it). An AND is a bound it always tracks.
    pos += n + (address_len as usize & ADDRESS_LEN_MASK);

    // Server port: any value is fine, it just has to be there.
    byte_at(ctx, body + pos + 1)?;
    pos += 2;

    let (next_state, n) = read_varint(ctx, body + pos)?;
    if !(1..=3).contains(&next_state) {
        return Err(C::Action::drop());
    }
    pos += n;

    if pos != frame_len {
        return Err(C::Action::drop());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::networking::tcp::TcpPacket;
    use crate::ebpf::test_support::{FakePacket, tcp_frame};
    use crate::ebpf::traits::TryParse;
    use aya_ebpf::bindings::xdp_action;

    /// Runs `check_handshake` over `payload` exactly the way the XDP
    /// program does: wrapped in real headers, bounds taken from
    /// `TcpPacket::try_parse`.
    fn check_frame(frame: &[u8]) -> Result<(), u32> {
        let mut pkt = FakePacket::new(frame);
        let ctx = pkt.ctx();
        let Ok(tcp) = TcpPacket::try_parse(&ctx) else {
            panic!("fixture's own headers should parse");
        };
        check_handshake(&ctx, tcp.payload_offset, tcp.payload_len)
    }

    fn check(payload: &[u8]) -> Result<(), u32> {
        check_frame(&tcp_frame(payload))
    }

    // PACKET_EXAMPLES.md's examples, length prefix included.
    fn localhost_login() -> Vec<u8> {
        let mut p = vec![0x10, 0x00, 0x81, 0x06, 0x09];
        p.extend_from_slice(b"localhost");
        p.extend_from_slice(&[0x63, 0xDD, 0x02]);
        p
    }

    fn domain_status() -> Vec<u8> {
        let mut p = vec![0x17, 0x00, 0x81, 0x06, 0x10];
        p.extend_from_slice(b"play.example.com");
        p.extend_from_slice(&[0x63, 0xDD, 0x01]);
        p
    }

    /// Builds a handshake with an arbitrary address and next state, length
    /// prefix computed to match.
    fn handshake(address: &[u8], next_state: u8) -> Vec<u8> {
        let mut body = vec![0x00, 0x81, 0x06]; // packet ID 0, protocol 769
        let mut addr_len = u32::try_from(address.len()).unwrap();
        loop {
            let byte = u8::try_from(addr_len & 0x7F).unwrap();
            addr_len >>= 7;
            if addr_len == 0 {
                body.push(byte);
                break;
            }
            body.push(byte | 0x80);
        }
        body.extend_from_slice(address);
        body.extend_from_slice(&[0x63, 0xDD, next_state]);
        let body_len = u16::try_from(body.len()).unwrap();
        let mut p = if body_len < 0x80 {
            vec![u8::try_from(body_len).unwrap()]
        } else {
            vec![
                u8::try_from(body_len & 0x7F).unwrap() | 0x80,
                u8::try_from(body_len >> 7).unwrap(),
            ]
        };
        p.extend_from_slice(&body);
        p
    }

    const DROP: Result<(), u32> = Err(xdp_action::XDP_DROP);

    #[test]
    fn accepts_login_handshake() {
        assert_eq!(check(&localhost_login()), Ok(()));
    }

    #[test]
    fn accepts_status_handshake() {
        assert_eq!(check(&domain_status()), Ok(()));
    }

    #[test]
    fn accepts_transfer_next_state() {
        assert_eq!(check(&handshake(b"localhost", 3)), Ok(()));
    }

    #[test]
    fn accepts_trailing_login_start_in_same_segment() {
        // Handshake immediately followed by a Login Start frame -- what a
        // real client's first data segment usually looks like.
        let mut p = localhost_login();
        p.extend_from_slice(&[0x07, 0x00, 0x05, b'S', b't', b'e', b'v', b'e']);
        assert_eq!(check(&p), Ok(()));
    }

    #[test]
    fn accepts_max_length_address() {
        let address = vec![b'a'; MAX_SERVER_ADDRESS_BYTES as usize];
        assert_eq!(check(&handshake(&address, 2)), Ok(()));
    }

    #[test]
    fn rejects_address_one_byte_too_long() {
        let address = vec![b'a'; MAX_SERVER_ADDRESS_BYTES as usize + 1];
        assert_eq!(check(&handshake(&address, 2)), DROP);
    }

    #[test]
    fn rejects_http() {
        assert_eq!(check(b"GET / HTTP/1.1\r\n"), DROP);
    }

    #[test]
    fn rejects_wrong_packet_id() {
        let mut p = localhost_login();
        p[1] = 0x01;
        assert_eq!(check(&p), DROP);
    }

    #[test]
    fn rejects_invalid_next_state() {
        assert_eq!(check(&handshake(b"localhost", 0)), DROP);
        assert_eq!(check(&handshake(b"localhost", 4)), DROP);
    }

    #[test]
    fn rejects_zero_frame_length() {
        assert_eq!(check(&[0x00, 0x00]), DROP);
    }

    #[test]
    fn rejects_frame_longer_than_payload() {
        // Declares 17 bytes of body but only 16 arrived -- a handshake
        // split across segments is treated as invalid.
        let p = localhost_login();
        assert_eq!(check(&p[..p.len() - 1]), DROP);
    }

    #[test]
    fn rejects_frame_length_disagreeing_with_fields() {
        // Prefix claims one byte more than the fields actually take; the
        // extra byte is supplied so the frame itself isn't truncated.
        let mut p = localhost_login();
        p[0] += 1;
        p.push(0x00);
        assert_eq!(check(&p), DROP);
    }

    #[test]
    fn rejects_frame_length_shorter_than_fields() {
        let mut p = localhost_login();
        p[0] -= 1;
        assert_eq!(check(&p), DROP);
    }

    #[test]
    fn rejects_oversized_frame_length() {
        // 0xFF 0x7F = 16383, far over MAX_HANDSHAKE_LEN.
        let mut p = vec![0xFF, 0x7F];
        p.extend_from_slice(&localhost_login()[1..]);
        assert_eq!(check(&p), DROP);
    }

    #[test]
    fn rejects_overlong_varint() {
        // Six continuation bytes for the protocol version.
        let mut p = vec![0x0F, 0x00, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80];
        p.extend_from_slice(&[0x00, 0x63, 0xDD, 0x02, 0, 0, 0, 0]);
        assert_eq!(check(&p), DROP);
    }

    #[test]
    fn rejects_negative_address_length() {
        // Address length VarInt = -1 (0xFF 0xFF 0xFF 0xFF 0x0F).
        let p = [
            0x0B, 0x00, 0x81, 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x63, 0xDD, 0x02,
        ];
        assert_eq!(check(&p), DROP);
    }

    #[test]
    fn rejects_empty_payload() {
        assert_eq!(check(&[]), DROP);
    }

    #[test]
    fn padding_never_completes_a_truncated_frame() {
        // Truncated handshake, then trailing Ethernet padding that happens
        // to supply the missing byte: the declared payload length, not the
        // physical buffer, must bound the frame.
        let p = localhost_login();
        let mut frame = tcp_frame(&p[..p.len() - 1]);
        frame.push(0x02);
        assert_eq!(check_frame(&frame), DROP);
    }
}
