#!/usr/bin/env bash
# Installs the tools this repo needs: k3s (Kubernetes), Helm, and Task.
#
# Usage:
#   ./scripts/setup.sh              # auto-detect the target from /etc/os-release
#   ./scripts/setup.sh debian       # force a specific target (debian, arch)
#
# To add support for another OS, drop a scripts/setup/<target>.sh defining
# install_prereqs, install_k3s, install_helm, and install_task, then extend
# detect_target below.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=setup/common.sh
source "$SCRIPT_DIR/setup/common.sh"

detect_target() {
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case " ${ID:-} ${ID_LIKE:-} " in
      *" debian "*|*" ubuntu "*) echo "debian" ;;
      *" arch "*|*" cachyos "*) echo "arch" ;;
      *) echo "unsupported" ;;
    esac
  else
    echo "unsupported"
  fi
}

TARGET="${1:-$(detect_target)}"
TARGET_SCRIPT="$SCRIPT_DIR/setup/$TARGET.sh"

if [ ! -f "$TARGET_SCRIPT" ]; then
  supported="$(cd "$SCRIPT_DIR/setup" && ls -- *.sh | grep -v '^common\.sh$' | sed 's/\.sh$//' | tr '\n' ' ')"
  log_error "No setup support for target '$TARGET'. Supported targets: $supported"
  exit 1
fi

require_sudo
check_wsl_systemd

log_info "Setting up for target: $TARGET"
log_info "This will install: k3s (Kubernetes, incl. kubectl), Helm, Cilium (CNI), and Task."
read -r -p "Continue? [y/N] " confirm
case "$confirm" in
  [yY]|[yY][eE][sS]) ;;
  *) log_info "Aborted."; exit 0 ;;
esac

# shellcheck source=/dev/null
source "$TARGET_SCRIPT"

install_prereqs
install_k3s
install_helm
install_task
install_cilium

log_info "Done. Verify with:"
log_info "  kubectl version --client && helm version --short && task --version"