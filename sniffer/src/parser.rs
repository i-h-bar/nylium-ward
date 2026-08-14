use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub protocol_version: i32,
    pub server_address: String,
    pub server_port: u16,
    pub next_state: NextState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextState {
    Status,
    Login,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    UnexpectedEof,
    VarIntTooLong,
    WrongPacketId(i32),
    InvalidUtf8,
    InvalidNextState(i32),
    NegativeLength(i32),
    InvalidPort(Vec<u8>),
    TrailingBytes(usize),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::UnexpectedEof => write!(f, "ran out of bytes mid-field"),
            ParseError::VarIntTooLong => write!(f, "VarInt longer than 5 bytes"),
            ParseError::WrongPacketId(id) => write!(f, "expected packet ID 0x00, got {id:#x}"),
            ParseError::InvalidUtf8 => write!(f, "server address bytes weren't valid UTF-8"),
            ParseError::InvalidNextState(n) => write!(f, "next_state {n} is neither 1 nor 2"),
            ParseError::NegativeLength(n) => write!(f, "length {n} is negative"),
            ParseError::InvalidPort(port) => write!(f, "invalid port {port:?}"),
            ParseError::TrailingBytes(len) => write!(f, "{len} trailing bytes in packet"),
        }
    }
}

const MAX_VARINT_BYTES: usize = 5;
const CONTINUE_BIT: u8 = 0b10000000;
const SEGMENT_BIT: u8 = 0b0111_1111;

pub fn read_varint(buf: &[u8]) -> Result<(i32, usize), ParseError> {
    let mut num: i32 = 0;
    let mut bytes_consumed = 0;
    let mut cont: bool = true;
    for (i, byte) in buf.iter().take(5).enumerate() {
        num |= ((byte & SEGMENT_BIT) as i32) << (i * 7);
        cont = byte & CONTINUE_BIT != 0;

        if !cont {
            bytes_consumed = i + 1;
            break;
        }

        if i == MAX_VARINT_BYTES - 1 {
            return Err(ParseError::VarIntTooLong);
        }
    }

    if cont {
        return Err(ParseError::UnexpectedEof);
    }

    Ok((num, bytes_consumed))
}

pub fn read_mc_string(buf: &[u8]) -> Result<(String, usize), ParseError> {
    let (len, consumed) = read_varint(buf)?;
    let len = usize::try_from(len).map_err(|_| ParseError::NegativeLength(len))?;
    let total = len + consumed;
    if buf.len() < total {
        return Err(ParseError::UnexpectedEof);
    }

    Ok((
        String::from_utf8(buf[consumed..len + 1].into()).map_err(|_| ParseError::InvalidUtf8)?,
        total,
    ))
}

pub fn parse_handshake(buf: &[u8]) -> Result<Handshake, ParseError> {
    let mut total = 0;
    let (pid, consumed) = read_varint(buf)?;
    total += consumed;
    if pid != 0 {
        return Err(ParseError::WrongPacketId(pid));
    }

    let (protov, consumed) = read_varint(&buf[total..])?;
    total += consumed;

    let (server_addr, consumed) = read_mc_string(&buf[total..])?;
    total += consumed;

    let required_len = total + 2;
    if buf.len() < required_len {
        return Err(ParseError::UnexpectedEof);
    }
    let port_buf = &buf[total..required_len];
    let server_port: u16 = u16::from_be_bytes(
        port_buf
            .try_into()
            .map_err(|_| ParseError::InvalidPort(port_buf.to_vec()))?,
    );
    total = required_len;

    let (next_state_num, consumed) = read_varint(&buf[total..])?;
    total += consumed;
    if buf.len() > total {
        return Err(ParseError::TrailingBytes(buf.len() - total));
    }

    let next_state = match next_state_num {
        1 => NextState::Status,
        2 => NextState::Login,
        value => return Err(ParseError::InvalidNextState(value)),
    };

    Ok(Handshake {
        protocol_version: protov,
        server_address: server_addr,
        server_port,
        next_state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- read_varint ------------------------------------------------------

    #[test]
    fn varint_single_byte() {
        assert_eq!(read_varint(&[0x00]), Ok((0, 1)));
        assert_eq!(read_varint(&[0x02]), Ok((2, 1)));
    }

    #[test]
    fn varint_two_bytes() {
        // 769 — see the worked example in read_varint's doc comment.
        assert_eq!(read_varint(&[0x81, 0x06]), Ok((769, 2)));
    }

    #[test]
    fn varint_stops_before_trailing_bytes() {
        // Only the VarInt itself should be consumed — trailing bytes belong
        // to whatever field comes next and must be left alone.
        assert_eq!(read_varint(&[0x02, 0xAA, 0xBB]), Ok((2, 1)));
    }

    #[test]
    fn varint_max_five_bytes_is_valid() {
        // The canonical "-1 as a 32-bit VarInt" encoding — all 32 bits set,
        // encoded as exactly 5 bytes. This is the largest legal VarInt.
        assert_eq!(read_varint(&[0xFF, 0xFF, 0xFF, 0xFF, 0x0F]), Ok((-1, 5)));
    }

    #[test]
    fn varint_last_byte_extra_bits_are_truncated_not_rejected() {
        // Bytes 0-3 place bits 0..28 of the result (4 * 7 = 28 bits). That
        // only leaves 4 bits of room in a 32-bit value for byte 4 — but nothing
        // stops a byte 4 from having all 7 low bits set anyway. Checked
        // against the official Java decoder (minecraft.wiki's reference
        // pseudocode): it does `value |= (currentByte & SEGMENT_BITS) << 28`
        // with no check that only 4 of those 7 bits matter — the top 3 just
        // shift past bit 31 and fall off silently. So this isn't a bug to fix;
        // it's real (if surprising) protocol behavior, and this test pins it
        // down so nobody "fixes" it into rejecting these bytes later.
        //
        // buf: four "continuation set, zero payload" bytes, then a
        // terminating byte of 0x7F — the maximum possible value, i.e. the
        // case most likely to lose bits.
        let buf = [0x80, 0x80, 0x80, 0x80, 0x7F];
        assert_eq!(read_varint(&buf), Ok((-268435456, 5)));
    }

    #[test]
    fn varint_six_bytes_is_too_long() {
        assert_eq!(
            read_varint(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            Err(ParseError::VarIntTooLong)
        );
    }

    #[test]
    fn varint_truncated_is_eof() {
        // Continuation bit set, then nothing.
        assert_eq!(read_varint(&[0x81]), Err(ParseError::UnexpectedEof));
        assert_eq!(read_varint(&[]), Err(ParseError::UnexpectedEof));
    }

    // ---- read_mc_string -----------------------------------------------------

    #[test]
    fn string_localhost() {
        let buf = [
            0x09, // length = 9
            b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't',
        ];
        assert_eq!(read_mc_string(&buf), Ok(("localhost".to_string(), 10)));
    }

    #[test]
    fn string_stops_before_trailing_bytes() {
        let buf = [0x02, b'h', b'i', 0xAA, 0xBB];
        assert_eq!(read_mc_string(&buf), Ok(("hi".to_string(), 3)));
    }

    #[test]
    fn string_truncated_is_eof() {
        let buf = [0x05, b'h', b'i']; // says 5 bytes, only 2 present
        assert_eq!(read_mc_string(&buf), Err(ParseError::UnexpectedEof));
    }

    #[test]
    fn string_invalid_utf8() {
        let buf = [0x01, 0xFF]; // 0xFF alone is never valid UTF-8
        assert_eq!(read_mc_string(&buf), Err(ParseError::InvalidUtf8));
    }

    #[test]
    fn string_negative_length_is_rejected() {
        // The canonical 5-byte VarInt encoding of -1 (see read_varint's own
        // `varint_max_five_bytes_is_valid` test) used as a length prefix. A
        // byte count can never legitimately be negative, so this must come
        // back as a clean error rather than `-1 as usize` wrapping into
        // `usize::MAX` and blowing up (or worse, silently misbehaving) a few
        // lines later.
        let buf = [0xFF, 0xFF, 0xFF, 0xFF, 0x0F];
        assert_eq!(read_mc_string(&buf), Err(ParseError::NegativeLength(-1)));
    }

    // ---- parse_handshake ----------------------------------------------------
    //
    // These byte arrays are real, hand-encoded Handshake packet *bodies*
    // (packet ID onward, length-prefix already stripped) — see
    // PACKET_EXAMPLES.md for the annotated breakdown of both.

    #[test]
    fn handshake_localhost_login() {
        #[rustfmt::skip]
        let buf: [u8; 16] = [
            0x00,             // packet ID
            0x81, 0x06,       // protocol version 769
            0x09,             // server address length = 9
            b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't',
            0x63, 0xDD,       // port 25565, big-endian
            0x02,             // next_state = 2 (Login)
        ];
        assert_eq!(
            parse_handshake(&buf),
            Ok(Handshake {
                protocol_version: 769,
                server_address: "localhost".to_string(),
                server_port: 25565,
                next_state: NextState::Login,
            })
        );
    }

    #[test]
    fn handshake_trailing_bytes_rejected() {
        // The same valid localhost/Login packet as handshake_localhost_login,
        // with 3 extra bytes tacked on the end. All five fields still parse
        // fine on their own — this only shows up if something checks that
        // the whole buffer got consumed, which is exactly what a client
        // padding garbage after a syntactically-valid handshake would look
        // like on the wire.
        #[rustfmt::skip]
        let buf: [u8; 19] = [
            0x00,             // packet ID
            0x81, 0x06,       // protocol version 769
            0x09,             // server address length = 9
            b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't',
            0x63, 0xDD,       // port 25565, big-endian
            0x02,             // next_state = 2 (Login)
            0xAA, 0xBB, 0xCC, // trailing garbage — not part of any field
        ];
        assert_eq!(parse_handshake(&buf), Err(ParseError::TrailingBytes(3)));
    }

    #[test]
    fn handshake_domain_status() {
        #[rustfmt::skip]
        let buf: [u8; 23] = [
            0x00,             // packet ID
            0x81, 0x06,       // protocol version 769
            0x10,             // server address length = 16
            b'p', b'l', b'a', b'y', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
            0x63, 0xDD,       // port 25565, big-endian
            0x01,             // next_state = 1 (Status)
        ];
        assert_eq!(
            parse_handshake(&buf),
            Ok(Handshake {
                protocol_version: 769,
                server_address: "play.example.com".to_string(),
                server_port: 25565,
                next_state: NextState::Status,
            })
        );
    }

    #[test]
    fn handshake_wrong_packet_id() {
        let buf = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(parse_handshake(&buf), Err(ParseError::WrongPacketId(1)));
    }

    #[test]
    fn handshake_invalid_next_state() {
        #[rustfmt::skip]
        let buf: [u8; 16] = [
            0x00,
            0x81, 0x06,
            0x09,
            b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't',
            0x63, 0xDD,
            0x05, // invalid — neither 1 nor 2
        ];
        assert_eq!(parse_handshake(&buf), Err(ParseError::InvalidNextState(5)));
    }

    #[test]
    fn handshake_truncated() {
        let buf = [0x00, 0x81, 0x06, 0x09, b'l', b'o']; // string cut short
        assert_eq!(parse_handshake(&buf), Err(ParseError::UnexpectedEof));
    }

    #[test]
    fn handshake_truncated_before_port_is_eof_not_panic() {
        // pid=0, protocol_version=0 (1 byte), address="a" (2 bytes: length +
        // 1 char) — then only 1 byte left, not the 2 the port field needs.
        // The bounds check ahead of the port read currently checks
        // `buf.len() < total` instead of `buf.len() < total + 2`, so this
        // buffer slips past it and panics on `buf[total..total + 2]` instead
        // of returning a clean UnexpectedEof.
        let buf = [0x00, 0x00, 0x01, b'a', 0xFF];
        assert_eq!(parse_handshake(&buf), Err(ParseError::UnexpectedEof));
    }

    #[test]
    fn not_minecraft_at_all() {
        // What a plain HTTP request looks like if something probes port
        // 25565 with it. 'G' = 0x47 — top bit clear, so it reads fine as a
        // one-byte VarInt (71), it's just the wrong packet ID.
        let buf = b"GET / HTTP/1.1\r\n";
        assert_eq!(parse_handshake(buf), Err(ParseError::WrongPacketId(71)));
    }
}
