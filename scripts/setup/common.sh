#!/usr/bin/env bash
# Shared helpers sourced by every per-target setup script.

log_info()  { printf '\033[1;34m[setup]\033[0m %s\n' "$*"; }
log_warn()  { printf '\033[1;33m[setup]\033[0m %s\n' "$*" >&2; }
log_error() { printf '\033[1;31m[setup]\033[0m %s\n' "$*" >&2; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

require_sudo() {
  if [ "$(id -u)" -ne 0 ] && ! has_cmd sudo; then
    log_error "Root privileges are required to install packages, and sudo is not available."
    exit 1
  fi
}