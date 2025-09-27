#!/usr/bin/env bash
set -euo pipefail

# --- Helpers ---
log() { printf "\n\033[1;32m[+] %s\033[0m\n" "$*"; }
warn() { printf "\n\033[1;33m[!] %s\033[0m\n" "$*"; }
err()  { printf "\n\033[1;31m[✗] %s\033[0m\n" "$*"; }
has()  { command -v "$1" >/dev/null 2>&1; }

ensure_path_line() {
  local line="$1"; local rc="$HOME/.bashrc"
  grep -qxF "$line" "$rc" 2>/dev/null || echo "$line" >> "$rc"
}

require_sudo() {
  if [[ $EUID -ne 0 ]]; then
    sudo -v || { err "This script needs sudo permission at times."; exit 1; }
  fi
}

update_apt_once() {
  if [[ -z "${APT_UPDATED:-}" ]]; then
    require_sudo
    sudo apt-get update -y
    APT_UPDATED=1
  fi
}

# --- Ensure common PATHs for user-installed tools ---
log "Ensuring ~/.local/bin and ~/.cargo/bin are on PATH"
ensure_path_line 'export PATH="$HOME/.local/bin:$PATH"'
ensure_path_line 'export PATH="$HOME/.cargo/bin:$PATH"'
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

# --- Docker + Compose (plugin) ---
ensure_docker() {
  if has docker && docker --version >/dev/null 2>&1; then
    log "docker already installed: $(docker --version | head -n1)"
  else
    log "Installing Docker Engine from Docker’s official repo"
    require_sudo
    sudo apt-get remove -y docker docker-engine docker.io containerd runc || true
    update_apt_once
    sudo apt-get install -y ca-certificates curl gnupg
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
      | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
    sudo apt-get update -y
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    sudo systemctl enable --now docker
    log "Adding $USER to docker group (log out/in to take effect)"
    sudo usermod -aG docker "$USER" || true
  fi

  if docker compose version >/dev/null 2>&1; then
    log "docker compose available: $(docker compose version | head -n1)"
  else
    warn "docker compose not found; installing plugin"
    require_sudo
    sudo apt-get install -y docker-compose-plugin
  fi
}

# --- NVIDIA Container Toolkit for Docker (GPU support) ---
ensure_nvidia_container_toolkit() {
  if has nvidia-smi; then
    log "NVIDIA driver detected: $(nvidia-smi --query-gpu=name,driver_version --format=csv,noheader | head -n1)"
  else
    warn "nvidia-smi not found. Install NVIDIA drivers for GPU access inside containers."
  fi

  if has nvidia-ctk && dpkg -l | grep -q '^ii\s\+nvidia-container-toolkit'; then
    log "nvidia-container-toolkit already installed"
  else
    log "Installing NVIDIA Container Toolkit repo & package"
    require_sudo
    update_apt_once
    sudo apt-get install -y curl gpg
    curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
      | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
    curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
      | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#' \
      | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list >/dev/null
    sudo apt-get update -y
    sudo apt-get install -y nvidia-container-toolkit
  fi

  log "Configuring Docker runtime with nvidia-ctk"
  require_sudo
  sudo nvidia-ctk runtime configure --runtime=docker
  sudo systemctl restart docker
  log "Docker restarted with NVIDIA runtime support"
}

# --- Python + pip + pipx ---
ensure_python_stack() {
  if has python3; then
    log "python3 already installed: $(python3 --version)"
  else
    log "Installing python3"
    update_apt_once; sudo apt-get install -y python3
  fi

  if has pip3; then
    log "pip already installed: $(pip3 --version)"
  else
    log "Installing python3-pip"
    update_apt_once; sudo apt-get install -y python3-pip
  fi

  if has pipx; then
    log "pipx already installed: $(pipx --version)"
  else
    log "Installing pipx"
    update_apt_once; sudo apt-get install -y pipx
    python3 -m pipx ensurepath || true
  fi
}

# --- Make `python` resolve to python3 ---
ensure_python_alias() {
  if has python; then
    log "python already present: $(python --version 2>&1 || true)"
    return
  fi
  log "Ensuring 'python' points to python3"
  require_sudo
  update_apt_once
  if apt-cache show python-is-python3 >/dev/null 2>&1; then
    sudo apt-get install -y python-is-python3
  else
    if [[ -x /usr/bin/python3 ]]; then
      sudo ln -sf /usr/bin/python3 /usr/local/bin/python
      log "Created /usr/local/bin/python -> /usr/bin/python3"
    else
      err "python3 not found at /usr/bin/python3; cannot create alias."
    fi
  fi
}

# --- Node.js (npm + npx) via NodeSource ---
ensure_node() {
  if has npm; then
    log "npm already installed: $(npm -v)"
  else
    log "Installing Node.js (NodeSource, LTS 22.x)"
    require_sudo
    update_apt_once
    sudo apt-get install -y ca-certificates curl
    curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
    sudo apt-get install -y nodejs
  fi

  if has npx; then
    log "npx available: $(npx --version)"
  else
    warn "npx not found; ensuring npm is present"
    require_sudo; sudo apt-get install -y npm
  fi
}

# --- uv (Astral) + uvx ---
ensure_uv() {
  if has uv && has uvx; then
    log "uv/uvx already installed: $(uv --version)"
  else
    log "Installing uv (Astral)"
    curl -LsSf https://astral.sh/uv/install.sh | sh
  fi
}

# --- Git ---
ensure_git() {
  if has git; then
    log "git already installed: $(git --version)"
  else
    log "Installing git"
    update_apt_once
    require_sudo
    sudo apt-get install -y git
  fi
}

# --- GitHub CLI (gh) ---
ensure_github_cli() {
  if has gh; then
    log "gh already installed: $(gh --version | head -n1)"
    return
  fi

  log "Installing GitHub CLI (gh) from official APT repo"
  require_sudo
  update_apt_once
  sudo apt-get install -y curl gpg || true
  sudo install -m 0755 -d /etc/apt/keyrings
  if curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
      | sudo tee /etc/apt/keyrings/githubcli-archive-keyring.gpg >/dev/null; then
    sudo chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
      | sudo tee /etc/apt/sources.list.d/github-cli.list >/dev/null
    sudo apt-get update -y || true
    if sudo apt-get install -y gh; then
      log "gh installed: $(gh --version | head -n1)"
      return
    fi
  fi

  warn "Falling back to Snap install for gh"
  if sudo snap install gh --classic; then
    log "gh installed via Snap: $(gh --version | head -n1)"
  else
    err "Failed to install gh via APT and Snap."
    return 1
  fi
}

# --- PostgreSQL client (psql) ---
ensure_psql() {
  if has psql; then
    log "psql already installed: $(psql --version | head -n1)"
  else
    log "Installing PostgreSQL client (psql)"
    update_apt_once
    require_sudo
    # Generic client metapackage; pulls current default client (Ubuntu 24.04 → 16)
    sudo apt-get install -y postgresql-client
  fi
}

# --- Supabase CLI (.deb from latest GitHub release) ---
ensure_supabase() {
  if has supabase; then
    log "supabase already installed: $(supabase --version)"
    return
  fi
  log "Installing Supabase CLI from latest GitHub .deb"
  local arch; arch="$(dpkg --print-architecture)"
  local gh_api="https://api.github.com/repos/supabase/cli/releases/latest"
  local url
  url="$(curl -fsSL "$gh_api" \
    | grep -Eo 'https://[^"]+supabase_[0-9.+-]+_linux_'"$arch"'\.deb' \
    | head -n1 || true)"
  if [[ -z "$url" ]]; then
    err "Could not resolve Supabase .deb for arch '$arch'. See releases: https://github.com/supabase/cli/releases"
    return 1
  fi
  local tmpdeb="/tmp/$(basename "$url")"
  curl -fL "$url" -o "$tmpdeb"
  require_sudo
  sudo dpkg -i "$tmpdeb" || { warn "Fixing deps with apt -f install"; sudo apt-get -f install -y; }
  rm -f "$tmpdeb"
  log "Supabase installed: $(supabase --version)"
}

# --- Stripe CLI (Linux tarball from latest GitHub release) ---
ensure_stripe() {
  if has stripe; then
    log "stripe already installed: $(stripe version | head -n1)"
    return
  fi
  log "Installing Stripe CLI from latest GitHub tarball"
  local arch uname_arch url version tgz tmpdir bindir
  uname_arch="$(uname -m)"
  case "$uname_arch" in
    x86_64|amd64) arch="x86_64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) err "Unsupported CPU arch: $uname_arch"; return 1 ;;
  esac
  version="$(curl -fsSL https://api.github.com/repos/stripe/stripe-cli/releases/latest | grep -Eo '"tag_name":\s*"v[^"]+' | sed 's/"tag_name":\s*"v//')"
  if [[ -z "$version" ]]; then
    err "Could not determine latest Stripe CLI version."
    return 1
  fi
  tgz="stripe_${version}_linux_${arch}.tar.gz"
  url="https://github.com/stripe/stripe-cli/releases/download/v${version}/${tgz}"
  tmpdir="$(mktemp -d)"
  curl -fL "$url" -o "$tmpdir/$tgz"
  tar -xzf "$tmpdir/$tgz" -C "$tmpdir"
  bindir="$HOME/.local/bin"
  mkdir -p "$bindir"
  install -m 0755 "$tmpdir/stripe" "$bindir/stripe"
  rm -rf "$tmpdir"
  log "Stripe installed: $(stripe version | head -n1)"
}

# --- Run all ---
ensure_docker
ensure_nvidia_container_toolkit
ensure_python_stack
ensure_python_alias
ensure_node
ensure_uv
ensure_git
ensure_github_cli
ensure_psql
ensure_supabase
ensure_stripe

# --- Versions summary ---
printf "\n\033[1;34m=== Versions Summary ===\033[0m\n"
{ docker --version || true; }
{ docker compose version || true; }
{ python --version || true; }
{ python3 --version || true; }
{ pip3 --version || true; }
{ pipx --version || true; }
{ node -v || true; }
{ npm -v || true; }
{ npx --version || true; }
{ uv --version || true; }
{ uvx --version || true; }
{ git --version || true; }
{ gh --version || true; }
{ psql --version || true; }
{ supabase --version || true; }
{ stripe version || true; }

printf "\nNote: If you were just added to the 'docker' group, log out/in (or reboot) before using Docker without sudo.\n"
printf "GPU test (optional): docker run --rm --gpus all nvidia/cuda:12.6.2-base-ubuntu24.04 nvidia-smi\n"
