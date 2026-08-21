#!/usr/bin/env bash
# falk installer
#
#   curl -fsSL https://raw.githubusercontent.com/svarm-dev/falk/main/install.sh | bash
#
# The GitHub blob URL (/blob/main/install.sh) is HTML and will not run.
# Pass flags after bash -s -- :
#
#   curl -fsSL ... | bash -s -- --version v0.1.0
#   curl -fsSL ... | bash -s -- --install-dir /usr/local/bin
set -euo pipefail

REPO="${FALK_REPO:-svarm-dev/falk}"
BIN_NAME="falk"
DEFAULT_BIN_DIR="${HOME}/.local/bin"
GITHUB_RELEASES="https://github.com/${REPO}/releases"
GIT_URL="https://github.com/${REPO}.git"

VERSION="${FALK_VERSION:-latest}"
BIN_DIR="${FALK_INSTALL_DIR:-${DEFAULT_BIN_DIR}}"

if [ -n "${NO_COLOR+x}" ] || [ ! -t 1 ]; then
  GREEN='' YELLOW='' BLUE='' RED='' BOLD='' DIM='' NC=''
else
  GREEN='\033[0;32m'
  YELLOW='\033[0;33m'
  BLUE='\033[0;34m'
  RED='\033[0;31m'
  BOLD='\033[1m'
  DIM='\033[2m'
  NC='\033[0m'
fi

print_step() { printf '%b▸%b %s\n' "${BLUE}" "${NC}" "$1"; }
print_success() { printf '%b✓%b %s\n' "${GREEN}" "${NC}" "$1"; }
print_warn() { printf '%b!%b %s\n' "${YELLOW}" "${NC}" "$1"; }
print_error() { printf '%b✗%b %s\n' "${RED}" "${NC}" "$1" >&2; }

die() {
  print_error "$1"
  exit 1
}

usage() {
  cat <<EOF
Install ${BIN_NAME} to ${BIN_DIR}

Usage: install.sh [options]

Options:
  -v, --version VERSION     Release tag to install (e.g. v0.1.0). Default: latest
  -b, --install-dir DIR     Directory for the falk binary. Default: ~/.local/bin
                            Also accepted as FALK_INSTALL_DIR.
      --from-source         Skip prebuilt binaries and build with Cargo
  -h, --help                Show this help

Environment:
  FALK_REPO           GitHub owner/name (default: svarm-dev/falk)
  FALK_VERSION        Same as --version
  FALK_INSTALL_DIR    Same as --install-dir
EOF
}

FROM_SOURCE=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    -v | --version)
      [ "$#" -ge 2 ] || die "--version requires a value"
      VERSION="$2"
      shift 2
      ;;
    --version=*)
      VERSION="${1#*=}"
      shift
      ;;
    -b | --install-dir)
      [ "$#" -ge 2 ] || die "--install-dir requires a value"
      BIN_DIR="$2"
      shift 2
      ;;
    --install-dir=*)
      BIN_DIR="${1#*=}"
      shift
      ;;
    --from-source)
      FROM_SOURCE=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      die "Unknown option: $1 (see --help)"
      ;;
  esac
done

# Accept 0.1.0 or v0.1.0; release tags are v-prefixed.
normalize_tag() {
  local v="$1"
  case "$v" in
    latest | "") printf 'latest\n' ;;
    v*) printf '%s\n' "$v" ;;
    *) printf 'v%s\n' "$v" ;;
  esac
}

VERSION="$(normalize_tag "${VERSION}")"

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

download_optional() {
  local url="$1" dest="$2"
  if need_cmd curl; then
    curl --proto '=https' --tlsv1.2 -fsSL -o "$dest" "$url"
  elif need_cmd wget; then
    wget -qO "$dest" "$url"
  else
    return 1
  fi
}

detect_target() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "${os}" in
    Linux) os="unknown-linux-gnu" ;;
    Darwin) os="apple-darwin" ;;
    *)
      die "Unsupported operating system: ${os}. falk requires Linux or macOS."
      ;;
  esac

  case "${arch}" in
    x86_64 | amd64) arch="x86_64" ;;
    arm64 | aarch64) arch="aarch64" ;;
    *)
      die "Unsupported architecture: ${arch}. falk ships x86_64 and aarch64 binaries."
      ;;
  esac

  printf '%s-%s\n' "${arch}" "${os}"
}

sha256_file() {
  local file="$1"
  if need_cmd sha256sum; then
    sha256sum "${file}" | awk '{print $1}'
  elif need_cmd shasum; then
    shasum -a 256 "${file}" | awk '{print $1}'
  else
    print_warn "No sha256sum/shasum; skipping checksum verification"
    return 1
  fi
}

verify_checksum() {
  local archive="$1" sums="$2"
  local expected actual base
  base="$(basename "${archive}")"
  expected="$(awk -v f="${base}" '$2 == f || $2 == "*"f { print $1; exit }' "${sums}")"
  if [ -z "${expected}" ]; then
    expected="$(awk 'NF { print $1; exit }' "${sums}")"
  fi
  [ -n "${expected}" ] || {
    print_warn "Checksum file did not contain ${base}"
    return 1
  }
  actual="$(sha256_file "${archive}")" || return 0
  if [ "${expected}" != "${actual}" ]; then
    die "Checksum mismatch for ${base}
  expected: ${expected}
  actual:   ${actual}"
  fi
  print_success "Checksum verified"
}

in_path() {
  local dir="$1"
  case ":${PATH}:" in
    *":${dir}:"*) return 0 ;;
    *) return 1 ;;
  esac
}

print_path_help() {
  local current_shell
  current_shell="$(basename "${SHELL:-}")"
  printf '\n%bNext step%b  add %s to PATH:\n\n' "${BOLD}" "${NC}" "${BIN_DIR}"
  case "${current_shell}" in
    fish)
      printf '  %bfish_add_path %s%b\n' "${BLUE}" "${BIN_DIR}" "${NC}"
      printf '  %b# or: echo '\''fish_add_path %s'\'' >> ~/.config/fish/config.fish%b\n' "${DIM}" "${BIN_DIR}" "${NC}"
      ;;
    zsh)
      printf '  %becho '\''export PATH="%s:$PATH"'\'' >> ~/.zshrc && source ~/.zshrc%b\n' "${BLUE}" "${BIN_DIR}" "${NC}"
      ;;
    *)
      printf '  %becho '\''export PATH="%s:$PATH"'\'' >> ~/.bashrc && source ~/.bashrc%b\n' "${BLUE}" "${BIN_DIR}" "${NC}"
      ;;
  esac
  printf '\n'
}

install_binary() {
  local src="$1"
  mkdir -p "${BIN_DIR}"
  chmod 755 "${src}"
  if need_cmd install; then
    install -m 755 "${src}" "${BIN_DIR}/${BIN_NAME}"
  else
    cp "${src}" "${BIN_DIR}/${BIN_NAME}"
    chmod 755 "${BIN_DIR}/${BIN_NAME}"
  fi
}

TMPDIR_INSTALL=""
cleanup() {
  if [ -n "${TMPDIR_INSTALL}" ] && [ -d "${TMPDIR_INSTALL}" ]; then
    rm -rf "${TMPDIR_INSTALL}"
  fi
}
trap cleanup EXIT

install_from_release() {
  local target archive_name url sums_url archive sums extracted
  target="$(detect_target)"
  archive_name="${BIN_NAME}-${target}.tar.gz"

  if [ "${VERSION}" = "latest" ]; then
    url="${GITHUB_RELEASES}/latest/download/${archive_name}"
    sums_url="${GITHUB_RELEASES}/latest/download/${archive_name}.sha256"
  else
    url="${GITHUB_RELEASES}/download/${VERSION}/${archive_name}"
    sums_url="${GITHUB_RELEASES}/download/${VERSION}/${archive_name}.sha256"
  fi

  print_step "Looking for ${archive_name} (${VERSION})"
  TMPDIR_INSTALL="$(mktemp -d "${TMPDIR:-/tmp}/falk-install.XXXXXX")"
  archive="${TMPDIR_INSTALL}/${archive_name}"
  sums="${TMPDIR_INSTALL}/${archive_name}.sha256"

  print_step "Downloading ${url}"
  if ! download_optional "${url}" "${archive}"; then
    cleanup
    TMPDIR_INSTALL=""
    return 1
  fi

  if download_optional "${sums_url}" "${sums}"; then
    verify_checksum "${archive}" "${sums}"
  else
    print_warn "No checksum published for this asset; continuing without verification"
  fi

  print_step "Extracting"
  tar -xzf "${archive}" -C "${TMPDIR_INSTALL}"

  extracted=""
  for candidate in "${TMPDIR_INSTALL}/${BIN_NAME}" "${TMPDIR_INSTALL}"/*/"${BIN_NAME}"; do
    if [ -f "${candidate}" ]; then
      extracted="${candidate}"
      break
    fi
  done
  [ -n "${extracted}" ] || die "Archive did not contain ${BIN_NAME}"

  install_binary "${extracted}"
  print_success "Installed ${BIN_DIR}/${BIN_NAME}"
  return 0
}

install_from_cargo() {
  local tmp_root cargo_args
  need_cmd cargo || die "No prebuilt binary for this platform, and cargo is not installed.
Install Rust from https://rustup.rs and rerun, or download a release from:
  ${GITHUB_RELEASES}"
  need_cmd git || die "git is required to build falk from source"

  print_step "Building from source with Cargo (this may take a few minutes)"
  cleanup
  TMPDIR_INSTALL="$(mktemp -d "${TMPDIR:-/tmp}/falk-install.XXXXXX")"
  tmp_root="${TMPDIR_INSTALL}/cargo-root"
  mkdir -p "${tmp_root}"

  cargo_args=(install --git "${GIT_URL}" falk-cli --locked --force --root "${tmp_root}")
  if [ "${VERSION}" != "latest" ]; then
    cargo_args+=(--tag "${VERSION}")
  fi

  cargo "${cargo_args[@]}"
  [ -f "${tmp_root}/bin/${BIN_NAME}" ] || die "cargo install did not produce ${BIN_NAME}"
  install_binary "${tmp_root}/bin/${BIN_NAME}"
  print_success "Installed ${BIN_DIR}/${BIN_NAME} from source"
}

printf '\n%bfalk installer%b\n\n' "${BOLD}" "${NC}"

if [ "${FROM_SOURCE}" -eq 1 ]; then
  install_from_cargo
elif install_from_release; then
  :
else
  print_warn "No prebuilt binary for this platform/version; falling back to source"
  install_from_cargo
fi

if [ -x "${BIN_DIR}/${BIN_NAME}" ]; then
  print_step "Checking ${BIN_NAME} --version"
  "${BIN_DIR}/${BIN_NAME}" --version || print_warn "binary installed but --version failed"
fi

printf '\n%b✨ Installation complete%b\n\n' "${BOLD}${GREEN}" "${NC}"
printf '  %b%s -- claude%b\n' "${BOLD}" "${BIN_NAME}" "${NC}"
printf '  %b%s --hard-limit 2.50 -- aider%b\n' "${DIM}" "${BIN_NAME}" "${NC}"

if ! in_path "${BIN_DIR}"; then
  print_path_help
else
  printf '\n'
fi
