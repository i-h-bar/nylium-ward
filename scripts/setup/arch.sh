#!/usr/bin/env bash
# Arch-based target (Arch Linux, CachyOS, etc.): installs k3s (which provides
# kubectl), Helm, and Task. Sourced by scripts/setup.sh — expects common.sh
# already sourced.

install_prereqs() {
  log_info "Installing base dependencies (curl, ca-certificates)..."
  sudo pacman -Sy --needed --noconfirm curl ca-certificates
}

install_k3s() {
  if has_cmd k3s; then
    log_info "k3s already installed, skipping ($(k3s --version | head -n1))"
  else
    log_info "Installing k3s..."
    curl -sfL https://get.k3s.io | sh -
  fi

  # k3s.yaml is root-only by default; copy it into the invoking user's
  # kubeconfig so `kubectl`/`helm` work without sudo.
  local target_user target_home
  target_user="${SUDO_USER:-$USER}"
  target_home="$(getent passwd "$target_user" | cut -d: -f6)"

  mkdir -p "$target_home/.kube"
  sudo cp /etc/rancher/k3s/k3s.yaml "$target_home/.kube/config"
  sudo chown "$target_user":"$target_user" "$target_home/.kube/config"
  chmod 600 "$target_home/.kube/config"
  log_info "kubeconfig written to $target_home/.kube/config"

  if ! has_cmd kubectl; then
    sudo ln -sf /usr/local/bin/k3s /usr/local/bin/kubectl
    log_info "Linked kubectl -> k3s"
  fi
}

install_helm() {
  if has_cmd helm; then
    log_info "helm already installed, skipping ($(helm version --short))"
    return
  fi

  log_info "Installing helm..."
  sudo pacman -S --needed --noconfirm helm
}

install_task() {
  if has_cmd task; then
    log_info "task already installed, skipping ($(task --version))"
    return
  fi

  log_info "Installing task..."
  sudo pacman -S --needed --noconfirm go-task
}