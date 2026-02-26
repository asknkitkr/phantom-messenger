#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# Phantom Messenger — Universal Setup & Run Script
#
# Usage:
#   chmod +x run.sh
#   ./run.sh              # Set up everything and launch the app
#   ./run.sh --test       # Set up and run tests only (don't launch)
#   ./run.sh --install    # Set up only (don't launch or test)
#   ./run.sh --clean      # Remove existing data (database, keys) and start fresh
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Colour

info()  { echo -e "${CYAN}[ℹ]${NC} $*"; }
ok()    { echo -e "${GREEN}[✔]${NC} $*"; }
warn()  { echo -e "${YELLOW}[⚠]${NC} $*"; }
fail()  { echo -e "${RED}[✖]${NC} $*"; exit 1; }

# ── Parse arguments ──────────────────────────────────────────────────
MODE="run"   # run | test | install
CLEAN=false
for arg in "$@"; do
    case "$arg" in
        --test)    MODE="test" ;;
        --install) MODE="install" ;;
        --clean)   CLEAN=true ;;
        --help|-h)
            echo "Usage: ./run.sh [--test | --install | --clean | --help]"
            echo ""
            echo "  (default)   Set up and launch Phantom Messenger"
            echo "  --test      Set up and run tests only"
            echo "  --install   Set up only (install deps, create venv)"
            echo "  --clean     Remove existing data and start fresh"
            echo "  --help      Show this help message"
            exit 0
            ;;
        *) warn "Unknown argument: $arg (ignored)" ;;
    esac
done

# ── Resolve project root (directory containing this script) ──────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║        ${CYAN}Phantom Messenger${NC}${BOLD} — Setup & Run          ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: Detect OS & Package Manager ──────────────────────────────
info "Detecting operating system …"

OS="$(uname -s)"
DISTRO=""
PKG_MGR=""

case "$OS" in
    Darwin)
        OS="macOS"
        if command -v brew &>/dev/null; then
            PKG_MGR="brew"
        fi
        ;;
    Linux)
        OS="Linux"
        if [ -f /etc/os-release ]; then
            DISTRO="$(. /etc/os-release && echo "$ID")"
        fi
        if command -v apt-get &>/dev/null; then
            PKG_MGR="apt"
        elif command -v dnf &>/dev/null; then
            PKG_MGR="dnf"
        elif command -v pacman &>/dev/null; then
            PKG_MGR="pacman"
        fi
        ;;
    MINGW*|MSYS*|CYGWIN*)
        OS="Windows"
        warn "Windows detected via Git Bash / MSYS2."
        warn "Please install Python 3.11+, libsodium, and sqlcipher manually."
        ;;
    *)
        fail "Unsupported operating system: $OS"
        ;;
esac

ok "OS: ${BOLD}$OS${NC}${DISTRO:+ ($DISTRO)}  |  Package manager: ${PKG_MGR:-none detected}"

# ── Step 1b: Clean existing data if requested ────────────────────────
if [ "$CLEAN" = true ]; then
    # Determine the platform-specific data directory
    case "$OS" in
        macOS)   APP_DATA_DIR="$HOME/Library/Application Support/PhantomMessenger" ;;
        Windows) APP_DATA_DIR="${APPDATA:-$HOME/AppData/Roaming}/PhantomMessenger" ;;
        *)       APP_DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/PhantomMessenger" ;;
    esac

    if [ -d "$APP_DATA_DIR" ]; then
        warn "Removing existing data directory: $APP_DATA_DIR"
        rm -rf "$APP_DATA_DIR"
        ok "Data directory removed. You will create a fresh identity on next launch."
    else
        info "No existing data directory found — nothing to clean."
    fi
fi

# ── Step 2: Install System Dependencies ──────────────────────────────
install_system_deps() {
    info "Installing system dependencies …"

    case "$PKG_MGR" in
        brew)
            # Ensure Homebrew is available
            if ! command -v brew &>/dev/null; then
                warn "Homebrew not found. Installing Homebrew …"
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew update --quiet
            brew install python@3 libsodium sqlcipher 2>/dev/null || true
            ok "System dependencies installed via Homebrew."
            ;;
        apt)
            info "Updating package lists (may require sudo) …"
            sudo apt-get update -qq
            sudo apt-get install -y -qq \
                python3 python3-pip python3-venv \
                libsodium-dev libsqlcipher-dev build-essential
            ok "System dependencies installed via apt."
            ;;
        dnf)
            sudo dnf install -y \
                python3 python3-pip python3-devel \
                libsodium-devel sqlcipher-devel gcc
            ok "System dependencies installed via dnf."
            ;;
        pacman)
            sudo pacman -Sy --noconfirm --needed \
                python python-pip libsodium sqlcipher base-devel
            ok "System dependencies installed via pacman."
            ;;
        *)
            warn "No supported package manager found."
            warn "Please manually install: Python 3.11+, libsodium, sqlcipher"
            ;;
    esac
}

# ── Step 3: Check Python Version ─────────────────────────────────────
find_python() {
    # Search common paths — include Homebrew locations explicitly
    local candidates=(
        /opt/homebrew/bin/python3
        /usr/local/bin/python3
        python3.13 python3.12 python3.11 python3 python
    )
    for cmd in "${candidates[@]}"; do
        if command -v "$cmd" &>/dev/null; then
            local ver
            ver="$("$cmd" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+')"
            local major minor
            major="$(echo "$ver" | cut -d. -f1)"
            minor="$(echo "$ver" | cut -d. -f2)"
            if [ "$major" -ge 3 ] && [ "$minor" -ge 11 ]; then
                # Verify the installation actually works (catches broken uv/pyenv installs)
                if "$cmd" -c "import sys, os, venv" 2>/dev/null; then
                    PYTHON="$cmd"
                    return 0
                else
                    warn "Python at $(command -v "$cmd") ($ver) is broken — skipping."
                fi
            fi
        fi
    done
    return 1
}

check_python() {
    info "Checking for Python 3.11+ …"
    if find_python; then
        ok "Found: $($PYTHON --version) → $(command -v "$PYTHON")"
    else
        warn "Python 3.11+ not found. Attempting to install via system package manager …"
        install_system_deps
        if find_python; then
            ok "Found after install: $($PYTHON --version)"
        else
            fail "Python 3.11+ is required but could not be found or installed.\n    Please install Python 3.11+ manually: https://www.python.org/downloads/"
        fi
    fi
}

PYTHON=""
check_python

# ── Step 4: Install System Libraries (if not already done) ───────────
# Check if libsodium is available (needed by PyNaCl)
check_native_libs() {
    local need_install=false

    # Quick check: try importing the Python packages to see if native libs exist
    if ! "$PYTHON" -c "import ctypes.util; assert ctypes.util.find_library('sodium')" 2>/dev/null; then
        warn "libsodium not found on the system."
        need_install=true
    fi

    if [ "$need_install" = true ]; then
        install_system_deps
    else
        ok "System libraries (libsodium) detected."
    fi
}

check_native_libs

# ── Step 5: Create Virtual Environment ───────────────────────────────
VENV_DIR="$SCRIPT_DIR/.venv"

RECREATE_VENV=false

if [ -d "$VENV_DIR" ] && [ -f "$VENV_DIR/bin/activate" ]; then
    # Check if the existing venv uses Python 3.11+
    if [ -f "$VENV_DIR/bin/python3" ]; then
        VENV_PY_VER="$("$VENV_DIR/bin/python3" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+')"
        VENV_MAJOR="$(echo "$VENV_PY_VER" | cut -d. -f1)"
        VENV_MINOR="$(echo "$VENV_PY_VER" | cut -d. -f2)"
        if [ "$VENV_MAJOR" -ge 3 ] && [ "$VENV_MINOR" -ge 11 ]; then
            info "Virtual environment already exists at ${BOLD}.venv/${NC} (Python $VENV_PY_VER)"
        else
            warn "Existing .venv uses Python $VENV_PY_VER (need 3.11+). Recreating …"
            RECREATE_VENV=true
        fi
    else
        warn "Existing .venv is broken (no python3 binary). Recreating …"
        RECREATE_VENV=true
    fi
else
    RECREATE_VENV=true
fi

if [ "$RECREATE_VENV" = true ]; then
    rm -rf "$VENV_DIR"
    info "Creating virtual environment with $($PYTHON --version) …"
    # Use --without-pip to avoid ensurepip failures on some systems
    "$PYTHON" -m venv --without-pip "$VENV_DIR"
    ok "Virtual environment created at ${BOLD}.venv/${NC}"
fi

# Activate
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
# Switch to the venv's own Python (not the system one)
PYTHON="$VENV_DIR/bin/python3"
ok "Virtual environment activated ($($PYTHON --version))."

# ── Step 6: Upgrade pip & Install Project ────────────────────────────
# Bootstrap pip if it's not available in the venv
if ! "$PYTHON" -m pip --version &>/dev/null; then
    info "Bootstrapping pip (ensurepip not available) …"
    curl -sSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
    "$PYTHON" /tmp/get-pip.py --quiet
    rm -f /tmp/get-pip.py
    ok "pip bootstrapped."
else
    info "Upgrading pip …"
    "$PYTHON" -m pip install --upgrade pip --quiet
fi

info "Installing Phantom Messenger and dependencies …"
"$PYTHON" -m pip install -e ".[dev]" --quiet
ok "All Python dependencies installed."

# ── Step 7: Run Tests (if requested or default run) ──────────────────
if [ "$MODE" = "test" ]; then
    echo ""
    info "Running test suite …"
    echo "─────────────────────────────────────────────"
    "$PYTHON" -m pytest tests/ -v
    echo "─────────────────────────────────────────────"
    ok "Tests complete."
    echo ""
    exit 0
fi

# ── Step 8: Launch Application ───────────────────────────────────────
if [ "$MODE" = "install" ]; then
    echo ""
    ok "Setup complete! To launch Phantom Messenger:"
    echo ""
    echo "    source .venv/bin/activate"
    echo "    python -m messenger"
    echo ""
    exit 0
fi

echo ""
ok "Setup complete — launching Phantom Messenger …"
echo ""
"$PYTHON" -m messenger
