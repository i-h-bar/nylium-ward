#!/usr/bin/env bash
# Debian/Ubuntu target: installs k3s (which provides kubectl), Helm, and Task.
# Sourced by scripts/setup.sh — expects common.sh already sourced.

install_prereqs() {
  log_info "Installing base dependencies (curl, gpg, ca-certificates)..."
  sudo apt-get update
  sudo apt-get install -y curl gpg ca-certificates apt-transport-https
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
  local key_id="DDF78C3E6EBB2D2CC223C95C62BA89D07698DBC6"
  local key_file
  key_file="$(mktemp)"

  curl -fsSL https://packages.buildkite.com/helm-linux/helm-debian/gpgkey > "$key_file"

  if [ "$(gpg --show-keys --with-colons "$key_file" | awk -F: '$1 == "fpr" {print $10}' | head -n1)" != "$key_id" ]; then
    log_error "Helm apt key fingerprint mismatch — refusing to trust it."
    rm -f "$key_file"
    exit 1
  fi

  gpg --dearmor < "$key_file" | sudo tee /usr/share/keyrings/helm.gpg >/dev/null
  rm -f "$key_file"
  echo "deb [signed-by=/usr/share/keyrings/helm.gpg] https://packages.buildkite.com/helm-linux/helm-debian/any/ any main" \
    | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list >/dev/null
  sudo apt-get update
  sudo apt-get install -y helm
}

install_task() {
  if has_cmd task; then
    log_info "task already installed, skipping ($(task --version))"
    return
  fi

  log_info "Installing task..."
  curl -1sLf 'https://dl.cloudsmith.io/public/task/task/setup.deb.sh' | sudo -E bash
  sudo apt-get install -y task
}