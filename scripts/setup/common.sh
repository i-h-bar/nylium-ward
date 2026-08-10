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

is_wsl() {
  [ -n "${WSL_DISTRO_NAME:-}" ] || grep -qi microsoft /proc/version 2>/dev/null
}

check_wsl_systemd() {
  if is_wsl && [ ! -d /run/systemd/system ]; then
    log_warn "Running under WSL without systemd enabled — k3s needs systemd to manage its service."
    log_warn "Add this to /etc/wsl.conf, then run 'wsl --shutdown' from Windows and reopen this distro:"
    log_warn "  [boot]"
    log_warn "  systemd=true"
    read -r -p "Continue anyway? [y/N] " wsl_confirm
    case "$wsl_confirm" in
      [yY]|[yY][eE][sS]) ;;
      *) log_info "Aborted."; exit 0 ;;
    esac
  fi
}