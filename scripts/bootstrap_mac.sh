#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

ASSUME_YES=0
for arg in "$@"; do
  case "${arg}" in
    -y|--yes)
      ASSUME_YES=1
      ;;
    -h|--help)
      echo "Usage: bash scripts/bootstrap_mac.sh [--yes]"
      echo ""
      echo "Creates .venv, installs Python/HStego dependencies, checks Homebrew packages,"
      echo "and optionally installs ardrive-cli if npm is available."
      exit 0
      ;;
    *)
      echo "Unknown option: ${arg}" >&2
      exit 1
      ;;
  esac
done

step() {
  printf '\n==> %s\n' "$1"
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 is required but was not found." >&2
    return 1
  fi
}

ask_yes() {
  local prompt="$1"
  if [[ "${ASSUME_YES}" -eq 1 ]]; then
    return 0
  fi
  read -r -p "${prompt} [y/N] " reply
  [[ "${reply}" == "y" || "${reply}" == "Y" || "${reply}" == "yes" || "${reply}" == "YES" ]]
}

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This bootstrap script is macOS-only. Use the README Ubuntu steps on Linux." >&2
  exit 1
fi

step "Checking macOS toolchain"
need_cmd xcode-select
if ! xcode-select -p >/dev/null 2>&1; then
  echo "Xcode Command Line Tools are missing. Run: xcode-select --install" >&2
  exit 1
fi

need_cmd brew

step "Installing Homebrew packages"
brew install python@3.12 age jpeg

PYTHON_BIN="$(brew --prefix python@3.12)/bin/python3.12"
if [[ ! -x "${PYTHON_BIN}" ]]; then
  echo "python3.12 was not found at ${PYTHON_BIN}" >&2
  exit 1
fi

step "Creating project virtual environment"
if [[ ! -d ".venv" ]]; then
  "${PYTHON_BIN}" -m venv .venv
else
  echo ".venv already exists; reusing it."
fi

# shellcheck source=/dev/null
source .venv/bin/activate

step "Installing Python dependencies"
python -m pip install --upgrade pip
python -m pip install imageio numpy scipy pycryptodome numba Pillow

step "Installing HStego native extension"
bash scripts/install_hstego_mac.sh

step "Checking ArDrive CLI"
if command -v ardrive >/dev/null 2>&1; then
  ardrive --version || true
else
  echo "ardrive-cli is not installed."
  if command -v npm >/dev/null 2>&1 && ask_yes "Install ardrive-cli globally with npm now?"; then
    npm install -g ardrive-cli
  else
    echo "Install later with: npm install -g ardrive-cli"
  fi
fi

step "Running doctor"
python cli/confess.py doctor

cat <<'EOF'

Bootstrap complete.

Next:
  source .venv/bin/activate
  python cli/confess.py doctor
EOF
