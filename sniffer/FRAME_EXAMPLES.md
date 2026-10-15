# Ethernet + IPv4 + TCP Frame — Worked Example

A real, hand-encoded frame carrying the same `localhost:25565` Minecraft
handshake from `PACKET_EXAMPLES.md`'s Example 1 — so you can trace one packet
all the way from the wire down to a `Handshake` struct. This is the same 71
bytes as `LOCALHOST_LOGIN_FRAME` in `src/net.rs`'s tests.

## Layered breakdown

```
[ Ethernet header: 14 bytes, fixed  ]
[ IPv4 header: 20 bytes (IHL=5)     ]  <- variable length, computed from IHL
[ TCP header: 20 bytes (offset=5)   ]  <- variable length, computed from data offset
[ TCP payload: 17 bytes             ]  <- a full Minecraft packet (length-prefix included)
```

Total: 14 + 20 + 20 + 17 = 71 bytes.

### Ethernet header (offset 0, 14 bytes)

| Field | Bytes | Value |
|---|---|---|
| destination MAC | `02 00 00 00 00 01` | (unused by this crate) |
| source MAC | `02 00 00 00 00 02` | (unused by this crate) |
| Ethertype | `08 00` | `0x0800` = IPv4 |

Fixed size — no variable-length concept at this layer. Everything from byte
14 onward is the IPv4 packet.

### IPv4 header (offset 14, 20 bytes here — but *not always* 20)

| Field | Bytes | Value |
|---|---|---|
| version + IHL | `45` | version `4`, IHL `5` (5 × 4 = 20-byte header, no options) |
| DSCP/ECN | `00` | unused |
| Total Length | `00 39` | 57 (20 header + 20 TCP header + 17 payload) |
| Identification | `12 34` | arbitrary |
| Flags/Fragment offset | `00 00` | none |
| TTL | `40` | 64 |
| Protocol | `06` | TCP |
| Header checksum | `00 00` | not validated by this crate |
| Source address | `0A 00 01 04` | `10.0.1.4` |
| Destination address | `0A 2B FF 41` | `10.43.255.65` — the pinned `minecraft` Service ClusterIP from `chart/values.yaml` |

**The IHL nibble matters.** `0x45`'s low nibble is `5`, meaning a 20-byte
header (5 × 4). A real packet with IP options would have a higher IHL and a
longer header — `parse_ipv4` has to compute this, never assume 20.

**Total Length trims trailing Ethernet padding.** Ethernet frames have a
64-byte minimum size; a small IP packet arriving inside one can have extra
zero bytes tacked on the end that are *not* part of the IP payload. This
frame's Total Length (57) exactly matches its real content, so there's no
padding here — but `net.rs`'s `ipv4_trims_trailing_ethernet_padding` test
adds 6 padding bytes and checks they don't leak into the parsed payload.

### TCP header (offset 34, 20 bytes here — but *not always* 20)

| Field | Bytes | Value |
|---|---|---|
| source port | `D4 31` | 54321 (client's ephemeral port) |
| destination port | `63 DD` | 25565 |
| sequence number | `00 00 00 01` | arbitrary |
| ack number | `00 00 00 01` | arbitrary |
| data offset + reserved + NS | `50` | data offset `5` (20-byte header, no options) |
| flags | `18` | `0b0001_1000` = PSH (`0x08`) + ACK (`0x10`) |
| window size | `20 00` | arbitrary |
| checksum | `00 00` | not validated by this crate |
| urgent pointer | `00 00` | unused |

**Data offset is TCP's version of IHL** — same idea (a word count in the top
nibble of a byte), different field name, same reason `parse_tcp` can't assume
a fixed 20-byte header either.

**Flags, one bit each in byte 13:**

```
bit:   7   6   5   4   3   2   1   0
flag: CWR ECE URG ACK PSH RST SYN FIN
```

`0x18` = `0001_1000` → bit 4 (ACK) and bit 3 (PSH) set, everything else
clear. A PSH+ACK carrying data right after the three-way handshake completes
is exactly what a real Minecraft client's handshake packet looks like on the
wire.

### TCP payload (offset 54, 17 bytes)

```
10 00 81 06 09 6c 6f 63 61 6c 68 6f 73 74 63 dd 02
```

This is the *exact* 17-byte sequence from `PACKET_EXAMPLES.md`'s Example 1 —
outer length-prefix VarInt (`10`) included. `parse_tcp` hands you these bytes
as-is; stripping that length-prefix and handing the remaining 16-byte body to
`parse_handshake` is flow-tracking-loop work, not `net.rs`'s job.