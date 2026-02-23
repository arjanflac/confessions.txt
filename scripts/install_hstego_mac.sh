#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${VIRTUAL_ENV:-}" ]]; then
  echo "Activate a virtual environment first (source .venv/bin/activate)."
  exit 1
fi

PY_VER="$(python -c 'import sys; print(".".join(map(str, sys.version_info[:2])))' 2>/dev/null || true)"
if [[ -z "${PY_VER}" ]]; then
  echo "Python not found in this shell."
  exit 1
fi
case "${PY_VER}" in
  3.11|3.12) ;;
  *)
    echo "Python ${PY_VER} detected. Use Python 3.11 or 3.12 to build HStego."
    echo "Example: $(brew --prefix python@3.12 2>/dev/null)/bin/python3.12 -m venv .venv"
    exit 1
    ;;
esac

ARCH="$(uname -m)"
USE_SSE2NEON=0
if [[ "${ARCH}" == "arm64" ]]; then
  USE_SSE2NEON=1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "git not found. Install Xcode Command Line Tools: xcode-select --install"
  exit 1
fi

if ! command -v xcode-select >/dev/null 2>&1; then
  echo "xcode-select not found. Install Xcode Command Line Tools: xcode-select --install"
  exit 1
fi

if ! xcode-select -p >/dev/null 2>&1; then
  echo "Xcode Command Line Tools not installed."
  echo "Run: xcode-select --install"
  exit 1
fi

if ! command -v xcrun >/dev/null 2>&1; then
  echo "xcrun not found. Install Xcode Command Line Tools: xcode-select --install"
  exit 1
fi

SDKROOT="$(xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
if [[ -z "${SDKROOT}" || ! -f "${SDKROOT}/usr/include/c++/v1/cstdio" ]]; then
  # Fallback: try the Xcode.app SDK if installed.
  XCODE_SDK_DIR="/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs"
  if [[ -d "${XCODE_SDK_DIR}" ]]; then
    SDKROOT="$(ls -1 "${XCODE_SDK_DIR}"/MacOSX*.sdk 2>/dev/null | sort -V | tail -n 1)"
  fi
fi

CXX_INCLUDE_DIR=""
if [[ -n "${SDKROOT}" && -f "${SDKROOT}/usr/include/c++/v1/cstdio" ]]; then
  CXX_INCLUDE_DIR="${SDKROOT}/usr/include/c++/v1"
elif [[ -f "/Library/Developer/CommandLineTools/usr/include/c++/v1/cstdio" ]]; then
  CXX_INCLUDE_DIR="/Library/Developer/CommandLineTools/usr/include/c++/v1"
fi

if [[ -z "${SDKROOT}" || -z "${CXX_INCLUDE_DIR}" ]]; then
  echo "C++ headers not found."
  echo "Try one of the following, then re-run this script:"
  echo "  xcode-select --install"
  echo "  sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer"
  echo "If CLT is already installed, reinstall it:"
  echo "  sudo rm -rf /Library/Developer/CommandLineTools"
  echo "  xcode-select --install"
  exit 1
fi

if ! command -v brew >/dev/null 2>&1; then
  echo "Homebrew not found. Install Homebrew, then run: brew install jpeg"
  exit 1
fi

BREW_JPEG_PREFIX="$(brew --prefix jpeg 2>/dev/null || true)"
if [[ -z "${BREW_JPEG_PREFIX}" || ! -f "${BREW_JPEG_PREFIX}/include/jpeglib.h" ]]; then
  echo "libjpeg headers not found. Run: brew install jpeg"
  exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

git clone --depth 1 --branch v0.5 https://github.com/daniellerch/hstego.git "${TMP_DIR}/hstego"

# On Apple Silicon, HStego's STC code uses x86 SSE intrinsics.
# Use sse2neon to translate SSE intrinsics to NEON for arm64 builds.
if [[ "${USE_SSE2NEON}" -eq 1 ]]; then
  if ! command -v curl >/dev/null 2>&1; then
    echo "curl not found. Install curl and retry."
    exit 1
  fi
  SSE2NEON_COMMIT="f1bc16e4b107f368a6098edd0d423803657837bd"
  SSE2NEON_URL="https://raw.githubusercontent.com/DLTcollab/sse2neon/${SSE2NEON_COMMIT}/sse2neon.h"
  curl -L --fail --silent --show-error "${SSE2NEON_URL}" -o "${TMP_DIR}/hstego/src/sse2neon.h"

  perl -0pi -e 's/#include <emmintrin.h>/#if defined(__aarch64__) || defined(__arm64__) || defined(__ARM_NEON__)\n#include "sse2neon.h"\n#else\n#include <emmintrin.h>\n#endif/s' "${TMP_DIR}/hstego/src/stc_embed_c.cpp"
  perl -0pi -e 's/#include <xmmintrin.h>/#if defined(__aarch64__) || defined(__arm64__) || defined(__ARM_NEON__)\n#include "sse2neon.h"\n#else\n#include <xmmintrin.h>\n#endif/s' "${TMP_DIR}/hstego/src/stc_ml_c.cpp"
  # sse_mathfun.h includes x86 headers; strip them and prepend a sse2neon guard.
  SSE_MATHFUN="${TMP_DIR}/hstego/src/sse_mathfun.h" \
  python - <<'PY'
import os
from pathlib import Path
p = Path(os.environ["SSE_MATHFUN"])
data = p.read_bytes().decode("utf-8", errors="ignore").replace("\r\n", "\n")
lines = [ln for ln in data.split("\n") if "xmmintrin.h" not in ln and "emmintrin.h" not in ln]
clean = "\n".join(lines)
header = """#if defined(__aarch64__) || defined(__arm64__) || defined(__ARM_NEON__)
#include "sse2neon.h"
#else
#include <xmmintrin.h>
#include <emmintrin.h>
#endif
"""
p.write_text(header + clean)
PY
fi

# HStego's JPEG extension includes jpegint.h, which Homebrew does not install.
# Removing this include fixes the build on macOS with Homebrew libjpeg.
sed -i '' '/jpegint.h/d' "${TMP_DIR}/hstego/src/jpeg_toolbox_extension.c"

# libjpeg does not expose jround_up in public headers on macOS.
# Define it locally if missing.
awk '
  /#include <Python.h>/ && !done {
    print;
    print "#ifndef jround_up";
    print "#define jround_up(a,b) ((((a) + (b) - 1) / (b)) * (b))";
    print "#endif";
    done=1;
    next
  }
  { print }
' "${TMP_DIR}/hstego/src/jpeg_toolbox_extension.c" > "${TMP_DIR}/hstego/src/jpeg_toolbox_extension.c.tmp"
mv "${TMP_DIR}/hstego/src/jpeg_toolbox_extension.c.tmp" "${TMP_DIR}/hstego/src/jpeg_toolbox_extension.c"

CFLAGS="-I${BREW_JPEG_PREFIX}/include" \
CPPFLAGS="-I${BREW_JPEG_PREFIX}/include -isysroot ${SDKROOT}" \
CXXFLAGS="-isysroot ${SDKROOT} -I${CXX_INCLUDE_DIR}" \
LDFLAGS="-L${BREW_JPEG_PREFIX}/lib" \
python -m pip install "${TMP_DIR}/hstego"

echo "HStego install complete."
