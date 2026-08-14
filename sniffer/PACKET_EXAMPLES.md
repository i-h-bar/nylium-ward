# Minecraft Handshake Packet — Worked Examples

Real, hand-encoded packets to check your `src/parser.rs` implementation against
by hand, before trusting the test suite. All three appear as test fixtures in
`src/parser.rs` too — these are the same bytes, just laid out so you can follow
the encoding yourself.

## Framing: length-prefix vs. body

Every Minecraft packet on the wire is:

```
[VarInt: length of everything after this field] [packet ID] [packet fields...]
```

`parse_handshake` in this crate only ever sees the **body** — packet ID
onward, with the outer length VarInt already stripped. That stripping is a
job for the capture loop we'll write later, not the parser. The "full wire
bytes" rows below include the length prefix so you can see the whole picture;
the "body" rows are what actually goes into `parse_handshake`.

## Example 1 — `localhost:25565`, next_state = Login

A client connecting to `localhost` to actually join the game.

| Field | Type | Value | Bytes |
|---|---|---|---|
| packet length | VarInt | 16 | `10` |
| packet ID | VarInt | 0 | `00` |
| protocol version | VarInt | 769 | `81 06` |
| server address | String | `"localhost"` | `09` `6c 6f 63 61 6c 68 6f 73 74` |
| server port | u16 (big-endian) | 25565 | `63 dd` |
| next state | VarInt | 2 (Login) | `02` |

Full wire bytes (17 total):
```
10 00 81 06 09 6c 6f 63 61 6c 68 6f 73 74 63 dd 02
```

Body only, i.e. what `parse_handshake` receives (16 bytes):
```
00 81 06 09 6c 6f 63 61 6c 68 6f 73 74 63 dd 02
```

**Decoding `81 06` (protocol version) by hand:**
```
0x81 = 1000_0001   top bit set -> more bytes follow; low 7 bits = 000_0001 = 1
0x06 = 0000_0110   top bit clear -> last byte;        low 7 bits = 000_0110 = 6
value = 1 | (6 << 7) = 1 + 768 = 769
```

## Example 2 — `play.example.com:25565`, next_state = Status

A client (or a server-list ping) checking the server's MOTD/player count
before deciding whether to actually join — same protocol version, a longer
domain instead of `localhost`, `next_state = 1`.

| Field | Type | Value | Bytes |
|---|---|---|---|
| packet length | VarInt | 23 | `17` |
| packet ID | VarInt | 0 | `00` |
| protocol version | VarInt | 769 | `81 06` |
| server address | String | `"play.example.com"` (16 bytes) | `10` `70 6c 61 79 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d` |
| server port | u16 (big-endian) | 25565 | `63 dd` |
| next state | VarInt | 1 (Status) | `01` |

Full wire bytes (24 total):
```
17 00 81 06 10 70 6c 61 79 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d 63 dd 01
```

Body only (23 bytes):
```
00 81 06 10 70 6c 61 79 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d 63 dd 01
```

Note the string length byte is `0x10` (16, one byte — still under the 128
single-byte VarInt ceiling) even though the string itself is longer than
Example 1's. It only takes a second VarInt byte once the length reaches 128.

## Example 3 — not Minecraft at all

What shows up if something (a port scanner, a misconfigured health check, a
curious `nc`) sends a plain HTTP request at port 25565 instead of a real
client connecting:

```
GET / HTTP/1.1\r\n
```

As bytes, the first one is `'G'` = `0x47` = `0100_0111`. Its top bit is
*clear*, so `read_varint` happily reads it as a complete, valid, one-byte
VarInt — value `71`. It's a well-formed VarInt, just the wrong one:
`parse_handshake` should reject it with `WrongPacketId(71)`, not a parse
failure. This is the case the sniffer is actually watching for in
production — the *bytes* were syntactically fine, they just weren't a
Minecraft handshake.

## A note on the protocol version

`769` here is a real Minecraft Java Edition protocol version (1.21.4), but
the parser doesn't need to recognize or validate *which* version it is —
any VarInt is structurally legal in that field. Treat it as an opaque number
to report, not something to range-check.