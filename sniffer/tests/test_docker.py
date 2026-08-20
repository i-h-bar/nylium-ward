"""Integration tests for the Docker test harness (../Dockerfile,
../docker-compose.yml): builds and starts the sniffer + probe containers on
their own isolated bridge network, and sends real Minecraft-handshake-shaped
probes (plus one deliberately-not-Minecraft one) at the sniffer container.

Why there are two different kinds of assertion in here: XDP can only make a
PASS/DROP call using what a bare SYN carries -- there's no payload yet at
that point. Real Minecraft-handshake validation has to happen on the first
data-carrying packet, which arrives *after* the TCP handshake already
completed. So "did connect() succeed" can't distinguish a valid handshake
from garbage -- both complete the handshake identically. Whether the
*payload* actually reaches something listening behind the hook is the
signal that can, which is what the stub echo listener (docker/echo_server.py,
backgrounded by docker/entrypoint.sh inside the sniffer container) is for.

- assert_probe_observed / the "*_observed" tests: just "did the XDP hook see
  this frame at all" (via the "Packet received" log line). Cheap, and
  true today since mc-sniffer-ebpf is still the placeholder that passes and
  logs everything unconditionally.
- probe_and_capture_echo / the "*_delivered" / "*_is_dropped" tests: the
  actually substantive ones. test_non_minecraft_traffic_is_dropped is the
  real target -- it currently FAILS, because nothing is dropped yet.
  Implementing real handshake validation in mc-sniffer-ebpf (parse the
  payload the way parser.rs::parse_handshake does, XDP_DROP on failure) is
  what turns it green.
"""

import subprocess
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args, cwd=REPO_ROOT, check=check, capture_output=True, text=True
    )


def sniffer_logs() -> str:
    return run("docker", "compose", "logs", "sniffer").stdout


def packet_log_count() -> int:
    return sniffer_logs().count("Packet received")


@pytest.fixture(scope="session")
def sniffer_stack():
    run("docker", "compose", "up", "--build", "-d")
    try:
        for _ in range(30):
            if "Waiting for Ctrl-C" in sniffer_logs():
                break
            time.sleep(1)
        else:
            pytest.fail(f"sniffer never reached ready state within 30s:\n{sniffer_logs()}")
        yield
    finally:
        run("docker", "compose", "down", check=False)


def send_probe(payload: bytes) -> None:
    """Sends `payload` from the probe container to sniffer:25565 and
    discards whatever happens next -- only useful for the log-based
    "was this even observed" checks below."""
    probe_code = (
        "import socket\n"
        f"buf = {payload!r}\n"
        "try:\n"
        "    s = socket.create_connection(('sniffer', 25565), timeout=2)\n"
        "    s.send(buf)\n"
        "    s.close()\n"
        "except OSError:\n"
        "    pass\n"
    )
    run("docker", "compose", "exec", "-T", "probe", "python3", "-c", probe_code)


def assert_probe_observed(payload: bytes) -> None:
    before = packet_log_count()
    send_probe(payload)
    time.sleep(1)
    after = packet_log_count()
    assert after > before, f"XDP hook never logged this probe (count stayed at {before})"


def probe_and_capture_echo(payload: bytes, *, timeout: float = 3.0) -> bytes:
    """Sends `payload` from the probe container to sniffer:25565 and
    returns whatever bytes the stub echo listener sent back -- empty if the
    connection failed, or nothing arrived within `timeout`. See this
    module's docstring for why this (not connect() success/failure) is the
    real PASS/DROP signal."""
    probe_code = (
        "import socket, sys\n"
        f"buf = {payload!r}\n"
        "try:\n"
        "    s = socket.create_connection(('sniffer', 25565), timeout=2)\n"
        "    s.send(buf)\n"
        f"    s.settimeout({timeout})\n"
        "    reply = s.recv(4096)\n"
        "    s.close()\n"
        "except OSError:\n"
        "    reply = b''\n"
        "sys.stdout.write(reply.hex())\n"
    )
    result = run("docker", "compose", "exec", "-T", "probe", "python3", "-c", probe_code)
    return bytes.fromhex(result.stdout.strip())


# Same three scenarios PACKET_EXAMPLES.md and parser.rs's own unit tests
# use -- full wire bytes (length-prefix included), since nothing in the
# eBPF program strips it yet.

EXAMPLE_1_LOCALHOST_LOGIN = bytes.fromhex("1000810609") + b"localhost" + bytes.fromhex("63dd02")
EXAMPLE_2_DOMAIN_STATUS = (
    bytes.fromhex("1700810610") + b"play.example.com" + bytes.fromhex("63dd01")
)
EXAMPLE_3_NOT_MINECRAFT = b"GET / HTTP/1.1\r\n"


def test_localhost_login_handshake_observed(sniffer_stack):
    assert_probe_observed(EXAMPLE_1_LOCALHOST_LOGIN)


def test_domain_status_handshake_observed(sniffer_stack):
    assert_probe_observed(EXAMPLE_2_DOMAIN_STATUS)


def test_not_minecraft_traffic_observed(sniffer_stack):
    assert_probe_observed(EXAMPLE_3_NOT_MINECRAFT)


def test_valid_handshake_data_is_delivered(sniffer_stack):
    """A syntactically valid handshake's bytes should reach whatever's
    listening behind the sniffer. True today (the placeholder passes
    everything) and must keep being true once real filtering lands."""
    echo = probe_and_capture_echo(EXAMPLE_1_LOCALHOST_LOGIN)
    assert echo == EXAMPLE_1_LOCALHOST_LOGIN


def test_non_minecraft_traffic_is_dropped(sniffer_stack):
    """PACKET_EXAMPLES.md's Example 3 -- a plain HTTP request hitting port
    25565 -- is exactly the "wrong packet ID, not actually Minecraft" case
    this whole sniffer exists to catch. Its bytes should never reach
    anything listening behind the hook.

    This is the real target: it currently FAILS, because mc-sniffer-ebpf is
    still the placeholder that passes everything through unconditionally.
    Implement real handshake validation there (parse the payload the way
    parser.rs::parse_handshake does, XDP_DROP on failure) to turn this
    green.
    """
    echo = probe_and_capture_echo(EXAMPLE_3_NOT_MINECRAFT)
    assert echo == b"", f"garbage payload was NOT dropped -- got echoed back: {echo!r}"