#!/bin/sh
# Backgrounds the stub echo listener (see echo_server.py), then execs the
# real program as the foreground process so container lifecycle/signals
# still map to it correctly.
set -e
python3 /usr/local/bin/echo_server.py &
exec mc-sniffer "$@"