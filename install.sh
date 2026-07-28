#!/bin/bash
# ============================================
#  FirmwareX Installer for Linux
#  Firmware Analysis Tool v1.0.0
#  Supports: Ubuntu, Kali Linux, Debian, macOS
# ============================================

set -e

# ── Colors ───────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

# ── Banner ───────────────────────────────────────────────
echo ""
echo -e "${CYAN}  ╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}  ║                                                   ║${NC}"
echo -e "${CYAN}  ║   ${WHITE}FirmwareX${CYAN} — Firmware Analysis Tool              ║${NC}"
echo -e "${CYAN}  ║   Linux Installer v1.0.0                          ║${NC}"
echo -e "${CYAN}  ║                                                   ║${NC}"
echo -e "${CYAN}  ╚═══════════════════════════════════════════════════╝${NC}"
echo ""

# ── Parse arguments ──────────────────────────────────────
FULL_INSTALL=false
for arg in "$@"; do
    case $arg in
        --full)
            FULL_INSTALL=true
            shift
            ;;
        --help|-h)
            echo "  Usage: ./install.sh [OPTIONS]"
            echo ""
            echo "  Options:"
            echo "    --full    Install extra tools (binwalk, radare2)"
            echo "    --help    Show this help message"
            echo ""
            exit 0
            ;;
    esac
done

# ── Detect distro ────────────────────────────────────────
DISTRO="unknown"
PKG_MANAGER="apt"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO="$ID"
    echo -e "  [${CYAN}*${NC}] Detected: ${YELLOW}$PRETTY_NAME${NC}"
elif [ -f /etc/lsb-release ]; then
    . /etc/lsb-release
    DISTRO="$DISTRIB_ID"
    echo -e "  [${CYAN}*${NC}] Detected: ${YELLOW}$DISTRIB_DESCRIPTION${NC}"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    DISTRO="macos"
    PKG_MANAGER="brew"
    echo -e "  [${CYAN}*${NC}] Detected: ${YELLOW}macOS${NC}"
else
    echo -e "  [${YELLOW}!${NC}] Could not detect distribution"
fi

echo ""

# ── Check / Install Node.js ──────────────────────────────
echo -e "  [${CYAN}*${NC}] Checking prerequisites..."
echo ""

if command -v node &> /dev/null; then
    NODE_VER=$(node -v)
    NPM_VER=$(npm -v 2>/dev/null || echo "not found")
    echo -e "  [${GREEN}+${NC}] Node.js $NODE_VER found"
    echo -e "  [${GREEN}+${NC}] npm v$NPM_VER found"
else
    echo -e "  [${YELLOW}!${NC}] Node.js is NOT installed"
    echo ""
    
    if [[ "$DISTRO" == "ubuntu" || "$DISTRO" == "debian" || "$DISTRO" == "kali" ]]; then
        echo -e "  [${CYAN}*${NC}] Installing Node.js via apt..."
        echo ""
        
        # Try NodeSource repo for latest LTS
        if command -v curl &> /dev/null; then
            echo -e "  [${CYAN}*${NC}] Adding NodeSource repository..."
            curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - 2>/dev/null || true
        fi
        
        sudo apt-get update -qq
        sudo apt-get install -y nodejs npm 2>/dev/null || sudo apt-get install -y nodejs 2>/dev/null
        
        if command -v node &> /dev/null; then
            echo -e "  [${GREEN}+${NC}] Node.js $(node -v) installed"
        else
            echo -e "  [${RED}!${NC}] Failed to install Node.js via apt"
            echo ""
            echo -e "  ${YELLOW}Install manually using nvm:${NC}"
            echo -e "    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash"
            echo -e "    source ~/.bashrc"
            echo -e "    nvm install 20"
            echo ""
            exit 1
        fi
    elif [[ "$DISTRO" == "macos" ]]; then
        if command -v brew &> /dev/null; then
            echo -e "  [${CYAN}*${NC}] Installing Node.js via Homebrew..."
            brew install node
        else
            echo -e "  [${RED}!${NC}] Please install Node.js from https://nodejs.org/"
            exit 1
        fi
    else
        echo -e "  [${RED}!${NC}] Please install Node.js 18+ manually:"
        echo -e "    ${CYAN}https://nodejs.org/${NC}"
        echo -e "    or use nvm: ${CYAN}curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash${NC}"
        exit 1
    fi
fi

echo ""

# ── Install optional Linux tools ─────────────────────────
if [[ "$DISTRO" == "ubuntu" || "$DISTRO" == "debian" || "$DISTRO" == "kali" ]]; then
    echo -e "  [${CYAN}*${NC}] Installing optional analysis tools..."
    echo ""
    
    # Core tools (lightweight)
    CORE_TOOLS="binutils file"
    
    for tool in $CORE_TOOLS; do
        if dpkg -l | grep -q " $tool "; then
            echo -e "  [${GREEN}+${NC}] $tool already installed"
        else
            echo -e "  [${CYAN}*${NC}] Installing $tool..."
            sudo apt-get install -y $tool 2>/dev/null && \
                echo -e "  [${GREEN}+${NC}] $tool installed" || \
                echo -e "  [${YELLOW}!${NC}] $tool installation skipped"
        fi
    done
    
    # Full install extras
    if [ "$FULL_INSTALL" = true ]; then
        echo ""
        echo -e "  [${CYAN}*${NC}] Full install mode — installing extra tools..."
        echo ""
        
        EXTRA_TOOLS="binwalk squashfs-tools"
        
        for tool in $EXTRA_TOOLS; do
            if command -v $tool &> /dev/null; then
                echo -e "  [${GREEN}+${NC}] $tool already installed"
            else
                echo -e "  [${CYAN}*${NC}] Installing $tool..."
                sudo apt-get install -y $tool 2>/dev/null && \
                    echo -e "  [${GREEN}+${NC}] $tool installed" || \
                    echo -e "  [${YELLOW}!${NC}] $tool installation skipped"
            fi
        done
        
        # Radare2
        if command -v r2 &> /dev/null; then
            echo -e "  [${GREEN}+${NC}] radare2 already installed"
        else
            echo -e "  [${CYAN}*${NC}] Installing radare2..."
            sudo apt-get install -y radare2 2>/dev/null && \
                echo -e "  [${GREEN}+${NC}] radare2 installed" || \
                echo -e "  [${YELLOW}!${NC}] radare2 installation skipped (install from https://rada.re/n/)"
        fi
    fi
    echo ""
fi

# ── Install npm dependencies ─────────────────────────────
echo -e "  [${CYAN}*${NC}] Installing npm dependencies..."
echo ""

npm install --no-audit --no-fund 2>&1 | while read line; do
    echo -e "    ${GRAY}$line${NC}"
done

echo ""
echo -e "  [${GREEN}+${NC}] Dependencies installed successfully"
echo ""

# ── Setup library files ──────────────────────────────────
echo -e "  [${CYAN}*${NC}] Setting up client-side libraries..."

mkdir -p public/lib

# Copy fflate
if [ -f "node_modules/fflate/umd/index.js" ]; then
    cp node_modules/fflate/umd/index.js public/lib/fflate.min.js
    echo -e "  [${GREEN}+${NC}] fflate library copied"
elif [ -f "node_modules/fflate/dist/fflate.umd.js" ]; then
    cp node_modules/fflate/dist/fflate.umd.js public/lib/fflate.min.js
    echo -e "  [${GREEN}+${NC}] fflate library copied (alt path)"
else
    echo -e "  [${YELLOW}!${NC}] fflate UMD build not found"
fi

# Copy JSZip
if [ -f "node_modules/jszip/dist/jszip.min.js" ]; then
    cp node_modules/jszip/dist/jszip.min.js public/lib/jszip.min.js
    echo -e "  [${GREEN}+${NC}] JSZip library copied"
else
    echo -e "  [${YELLOW}!${NC}] JSZip not found"
fi

echo ""

# ── Make CLI executable ──────────────────────────────────
if [ -f "cli.js" ]; then
    chmod +x cli.js
    echo -e "  [${GREEN}+${NC}] CLI tool made executable"
fi

echo ""

# ── Verify installation ─────────────────────────────────
echo -e "  [${CYAN}*${NC}] Verifying installation..."

node -e "try{require('./modules/file-detector');console.log('  [\x1b[32m+\x1b[0m] Modules: OK')}catch(e){console.log('  [\x1b[33m!\x1b[0m] Modules: '+e.message)}"
node -e "try{require('express');console.log('  [\x1b[32m+\x1b[0m] Express: OK')}catch(e){console.log('  [\x1b[33m!\x1b[0m] Express: '+e.message)}"
node -e "try{require('chalk');console.log('  [\x1b[32m+\x1b[0m] Chalk: OK')}catch(e){console.log('  [\x1b[33m!\x1b[0m] Chalk: '+e.message)}"
node -e "try{require('commander');console.log('  [\x1b[32m+\x1b[0m] Commander: OK')}catch(e){console.log('  [\x1b[33m!\x1b[0m] Commander: '+e.message)}"

echo ""

# ── Optional native tools info ───────────────────────────
echo -e "  [${CYAN}*${NC}] Native tool status:"
command -v strings &> /dev/null && echo -e "  [${GREEN}+${NC}] strings: available" || echo -e "  [${GRAY}-${NC}] strings: not installed (apt install binutils)"
command -v readelf &> /dev/null && echo -e "  [${GREEN}+${NC}] readelf: available" || echo -e "  [${GRAY}-${NC}] readelf: not installed (apt install binutils)"
command -v objdump &> /dev/null && echo -e "  [${GREEN}+${NC}] objdump: available" || echo -e "  [${GRAY}-${NC}] objdump: not installed (apt install binutils)"
command -v file    &> /dev/null && echo -e "  [${GREEN}+${NC}] file: available"    || echo -e "  [${GRAY}-${NC}] file: not installed (apt install file)"
command -v binwalk &> /dev/null && echo -e "  [${GREEN}+${NC}] binwalk: available" || echo -e "  [${GRAY}-${NC}] binwalk: not installed (./install.sh --full)"
command -v r2      &> /dev/null && echo -e "  [${GREEN}+${NC}] radare2: available" || echo -e "  [${GRAY}-${NC}] radare2: not installed (./install.sh --full)"

echo ""

# ── Success ──────────────────────────────────────────────
echo -e "  ${GREEN}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "  ${GREEN}║         Installation Complete!                    ║${NC}"
echo -e "  ${GREEN}╚═══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${WHITE}Start Web UI:${NC}"
echo -e "    ${CYAN}npm start${NC}"
echo -e "    ${GRAY}(Opens http://localhost:3000 in your browser)${NC}"
echo ""
echo -e "  ${WHITE}CLI Usage:${NC}"
echo -e "    ${CYAN}node cli.js --help${NC}"
echo -e "    ${CYAN}node cli.js detect firmware.bin${NC}"
echo -e "    ${CYAN}node cli.js analyze firmware.bin${NC}"
echo -e "    ${CYAN}node cli.js entropy firmware.bin${NC}"
echo -e "    ${CYAN}node cli.js strings firmware.bin${NC}"
echo -e "    ${CYAN}node cli.js hexdump firmware.bin${NC}"
echo -e "    ${CYAN}node cli.js decrypt firmware.enc --method xor --key \"FF\"${NC}"
echo -e "    ${CYAN}node cli.js disasm firmware.elf --auto${NC}"
echo -e "    ${CYAN}node cli.js extract firmware.zip --output ./extracted${NC}"
echo -e "    ${CYAN}node cli.js info firmware.elf --sections${NC}"
echo -e "    ${CYAN}node cli.js convert firmware.hex${NC}"
echo -e "    ${CYAN}node cli.js security firmware.bin${NC}"
echo ""
echo -e "  ${GRAY}For full install with extra tools: ./install.sh --full${NC}"
echo ""
