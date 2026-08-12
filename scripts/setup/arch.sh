#!/usr/bin/env bash
# Arch-based target (Arch Linux, CachyOS, etc.): installs Helm and Task. k3s
# and Cilium install via common.sh (install_k3s/install_cilium), shared
# across every target. Sourced by scripts/setup.sh — expects common.sh
# already sourced.

install_prereqs() {
  log_info "Installing base dependencies (curl, ca-certificates)..."
  sudo pacman -Sy --needed --noconfirm curl ca-certificates
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