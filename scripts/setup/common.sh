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

confirm() {
  # Usage: confirm "prompt text" — returns 0 for yes, 1 for no/anything else.
  local prompt="$1" reply
  read -r -p "$prompt [y/N] " reply
  case "$reply" in
    [yY]|[yY][eE][sS]) return 0 ;;
    *) return 1 ;;
  esac
}

# k3s reads this file on every start — fresh install or a plain restart of an
# already-running service — so writing it here (rather than passing
# INSTALL_K3S_EXEC only at first-install time) handles both cases identically.
K3S_CONFIG_FILE="/etc/rancher/k3s/config.yaml"

k3s_config_has_cilium_settings() {
  [ -f "$K3S_CONFIG_FILE" ] \
    && grep -q '^flannel-backend: *"\?none"\?' "$K3S_CONFIG_FILE" \
    && grep -q '^disable-network-policy: *true' "$K3S_CONFIG_FILE"
}

write_k3s_cilium_config() {
  if [ "${DRY_RUN:-0}" = "1" ]; then
    log_info "[dry-run] would write $K3S_CONFIG_FILE: flannel-backend: none, disable-network-policy: true"
    return
  fi
  sudo mkdir -p "$(dirname "$K3S_CONFIG_FILE")"
  printf 'flannel-backend: "none"\ndisable-network-policy: true\n' | sudo tee "$K3S_CONFIG_FILE" >/dev/null
}

install_k3s() {
  if has_cmd k3s; then
    if k3s_config_has_cilium_settings; then
      log_info "k3s already installed and configured for Cilium, skipping ($(k3s --version | head -n1))"
    else
      log_warn "k3s is already installed on this machine WITHOUT the flannel-disable config Cilium needs."
      log_warn "Applying it restarts the k3s service and is CLUSTER-WIDE — it affects every workload"
      log_warn "already running here (e.g. another repo's pods), not just this one."
      if ! confirm "Reconfigure this k3s installation's CNI for Cilium now?"; then
        log_error "Declined. Aborting — Cilium and this chart's CiliumNetworkPolicy resources cannot work without this change."
        exit 1
      fi
      write_k3s_cilium_config
      if [ "${DRY_RUN:-0}" = "1" ]; then
        log_info "[dry-run] would run: sudo systemctl restart k3s"
      else
        log_info "Restarting k3s..."
        sudo systemctl restart k3s
      fi
    fi
  else
    write_k3s_cilium_config
    log_info "Installing k3s..."
    if [ "${DRY_RUN:-0}" = "1" ]; then
      log_info "[dry-run] would run: curl -sfL https://get.k3s.io | sh -"
    else
      curl -sfL https://get.k3s.io | sh -
    fi
  fi

  # k3s.yaml is root-only by default; copy it into the invoking user's
  # kubeconfig so `kubectl`/`helm` work without sudo.
  local target_user target_home
  target_user="${SUDO_USER:-$USER}"
  target_home="$(getent passwd "$target_user" | cut -d: -f6)"

  if [ "${DRY_RUN:-0}" = "1" ]; then
    log_info "[dry-run] would copy /etc/rancher/k3s/k3s.yaml to $target_home/.kube/config"
  else
    mkdir -p "$target_home/.kube"
    sudo cp /etc/rancher/k3s/k3s.yaml "$target_home/.kube/config"
    sudo chown "$target_user":"$target_user" "$target_home/.kube/config"
    chmod 600 "$target_home/.kube/config"
    log_info "kubeconfig written to $target_home/.kube/config"
  fi

  if ! has_cmd kubectl; then
    if [ "${DRY_RUN:-0}" = "1" ]; then
      log_info "[dry-run] would run: sudo ln -sf /usr/local/bin/k3s /usr/local/bin/kubectl"
    else
      sudo ln -sf /usr/local/bin/k3s /usr/local/bin/kubectl
      log_info "Linked kubectl -> k3s"
    fi
  fi
}

# Version pinned in Taskfile.yaml (CILIUM_VERSION var) — this function just
# fails loudly if the DaemonSet/operator never come up healthy. Shells out to
# `task cilium:up` (rather than duplicating the helm commands here) so there's
# one definition of the Cilium install, not two — this requires install_task
# to have already run, which is why setup.sh calls these in that order.
_COMMON_SH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

install_cilium() {
  if [ "${DRY_RUN:-0}" = "1" ]; then
    log_info "[dry-run] would run: task cilium:up"
    return
  fi
  log_info "Installing Cilium..."
  ( cd "$_COMMON_SH_DIR/../.." && task cilium:up )
}