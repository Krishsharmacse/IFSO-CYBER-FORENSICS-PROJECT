#!/usr/bin/env bash
# ============================================================
#  CyberX Forensics Platform — Linux/macOS Setup Script
#  Run: chmod +x setup_linux.sh && ./setup_linux.sh
# ============================================================

set -e

echo "============================================================"
echo "  CyberX Forensics Platform - Linux/macOS Setup"
echo "============================================================"
echo

# ── Detect OS ─────────────────────────────────────────────────
OS="$(uname -s)"
PKG_MGR=""
if [ "$OS" = "Linux" ]; then
    if command -v apt-get &>/dev/null; then
        PKG_MGR="apt"
    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
    elif command -v pacman &>/dev/null; then
        PKG_MGR="pacman"
    fi
elif [ "$OS" = "Darwin" ]; then
    PKG_MGR="brew"
fi

echo "OS        : $OS"
echo "Pkg Mgr   : ${PKG_MGR:-unknown}"
echo

# ── Python check ──────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 not found. Please install Python 3.10+."
    exit 1
fi
PYTHON_VER=$(python3 --version)
echo "[OK] $PYTHON_VER"

# ── Node.js check ─────────────────────────────────────────────
if ! command -v node &>/dev/null; then
    echo "[ERROR] Node.js not found. Please install from https://nodejs.org/"
    exit 1
fi
NODE_VER=$(node --version)
echo "[OK] Node.js $NODE_VER"
echo

# ── Backend venv ──────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[1/5] Setting up Python virtual environment..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo "      Created .venv"
else
    echo "      .venv already exists, skipping."
fi

# shellcheck disable=SC1091
source .venv/bin/activate

echo "[2/5] Installing Python dependencies..."
pip install --upgrade pip --quiet
pip install \
    fastapi uvicorn sqlalchemy python-dotenv \
    yara-python joblib pandas scikit-learn numpy \
    requests paramiko pyzipper pikepdf \
    eml-parser python-evtx \
    impacket whois \
    androguard \
    --quiet
echo "      Python packages installed."
echo

# ── Frontend ──────────────────────────────────────────────────
echo "[3/5] Installing frontend Node.js dependencies..."
cd frontend
npm install --silent
cd ..
echo "      Frontend packages installed."
echo

# ── System packages / External tools ─────────────────────────
echo "[4/5] Checking external tools..."
echo

check_tool() {
    local name="$1"
    local cmd="$2"
    local apt_pkg="$3"
    local brew_pkg="$4"

    if command -v "$cmd" &>/dev/null; then
        echo "  [OK]      $name"
    else
        echo "  [MISSING] $name"
        if [ "$PKG_MGR" = "apt" ] && [ -n "$apt_pkg" ]; then
            echo "            Install: sudo apt install $apt_pkg"
        elif [ "$PKG_MGR" = "brew" ] && [ -n "$brew_pkg" ]; then
            echo "            Install: brew install $brew_pkg"
        fi
    fi
}

check_tool "exiftool"            "exiftool"   "libimage-exiftool-perl" "exiftool"
check_tool "tshark"              "tshark"     "tshark"                 "wireshark"
check_tool "John the Ripper"     "john"       "john"                   "john"
check_tool "steghide"            "steghide"   "steghide"               "steghide"
check_tool "SleuthKit (mmls)"    "mmls"       "sleuthkit"              "sleuthkit"
check_tool "SleuthKit (fls)"     "fls"        "sleuthkit"              "sleuthkit"
check_tool "SleuthKit (mactime)" "mactime"    "sleuthkit"              "sleuthkit"

# Volatility (pip installed)
if python3 -c "import volatility3" &>/dev/null 2>&1 || command -v vol &>/dev/null; then
    echo "  [OK]      Volatility3"
else
    echo "  [MISSING] Volatility3 — Install: pip install volatility3"
fi

# Ghidra (bundled)
GHIDRA_FOUND=false
for d in plugins/ghidra_*/; do
    if [ -f "${d}support/analyzeHeadless" ]; then
        GHIDRA_FOUND=true
        break
    fi
done
if $GHIDRA_FOUND; then
    echo "  [OK]      Ghidra (plugins folder)"
else
    echo "  [MISSING] Ghidra — Download: https://ghidra-sre.org"
    echo "            Extract to plugins/ghidra_X.Y.Z_PUBLIC/"
fi

# MobSF
if curl -s --max-time 2 http://localhost:8008 &>/dev/null; then
    echo "  [OK]      MobSF (running at localhost:8008)"
else
    echo "  [INFO]    MobSF not detected — start it separately if needed"
    echo "            Run: cd plugins/Mobile-Security-Framework-MobSF && ./setup.sh && ./run.sh"
fi

echo
echo "[5/5] Checking .env file..."
if [ ! -f "backend/.env" ]; then
    if [ -f "backend/.env.example" ]; then
        cp "backend/.env.example" "backend/.env"
        echo "  Created backend/.env from .env.example"
    else
        touch "backend/.env"
        echo "  Created empty backend/.env (add your API keys)"
    fi
else
    echo "  backend/.env already exists."
fi

echo
echo "============================================================"
echo "  Setup complete!"
echo
echo "  Quick start:"
echo "    Backend : cd backend && uv run --with uvicorn uvicorn main:app --reload"
echo "    Frontend: cd frontend && npm run dev"
echo
echo "  OR use the convenience script:"
echo "    chmod +x run_linux.sh && ./run_linux.sh"
echo "============================================================"
