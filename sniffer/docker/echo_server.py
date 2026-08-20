#!/usr/bin/env python3
"""Minimal stub TCP listener for integration tests: echoes back whatever
bytes it receives on port 25565.

This exists because XDP can only make a PASS/DROP call using what a bare
SYN carries -- there's no payload yet at that point. Real Minecraft-
handshake validation has to happen on the first data-carrying packet, which
arrives *after* the TCP handshake already completed -- so "did connect()
succeed" can't tell a valid handshake from garbage; both complete the
handshake identically. Whether the *data* actually got echoed back is the
signal that can: DROP means this process never sees those bytes at all.

Runs inside the sniffer container (backgrounded by entrypoint.sh) so it
sits behind the same XDP hook mc-sniffer is attached to.
"""

import socket


def main() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 25565))
    server.listen(8)
    while True:
        conn, _ = server.accept()
        try:
            conn.settimeout(5)
            data = conn.recv(4096)
            if data:
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()


if __name__ == "__main__":
    main()