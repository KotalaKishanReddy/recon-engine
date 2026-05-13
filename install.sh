#!/usr/bin/env bash
# install.sh — ReconEngine one-shot installer
# Works on: Linux, WSL, Kali, macOS
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/KotalaKishanReddy/recon-engine/main/install.sh | bash
# OR:
#   wget -qO- https://raw.githubusercontent.com/KotalaKishanReddy/recon-engine/main/install.sh | bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

REPO="https://github.com/KotalaKishanReddy/recon-engine.git"
DIR="recon-engine"

echo -e "\n${CYAN}[*] ReconEngine Installer${NC}"
echo -e "${CYAN}==========================${NC}"

# ── 1. System deps check ─────────────────────────────────────────────────────
echo -e "\n${YELLOW}[1/5] Checking system dependencies...${NC}"

for cmd in git python3 pip3 go; do
    if command -v $cmd &>/dev/null; then
        echo -e "  ${GREEN}[+]${NC} $cmd found"
    else
        echo -e "  ${RED}[!] $cmd not found.${NC}"
        case $cmd in
            git)     echo "      Install: sudo apt install git -y" ;;
            python3) echo "      Install: sudo apt install python3 python3-pip -y" ;;
            pip3)    echo "      Install: sudo apt install python3-pip -y" ;;
            go)      echo "      Install: https://go.dev/dl/  (or: sudo apt install golang-go)" ;;
        esac
        exit 1
    fi
done
echo -e "${GREEN}[+] All system deps present.${NC}"

# ── 2. Clone repo ────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[2/5] Cloning ReconEngine...${NC}"
if [ -d "$DIR" ]; then
    echo -e "  ${YELLOW}[~] Folder '$DIR' already exists — pulling latest instead.${NC}"
    cd "$DIR"
    git pull origin main
else
    git clone "$REPO"
    cd "$DIR"
fi
echo -e "${GREEN}[+] Repo ready at: $(pwd)${NC}"

# ── 3. Python deps ───────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[3/5] Installing Python dependencies...${NC}"
pip3 install -r requirements.txt --upgrade -q
echo -e "${GREEN}[+] Python deps installed.${NC}"

# ── 4. Go tools ──────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[4/5] Installing Go tools...${NC}"

GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/d3mondev/puredns/v2@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/sensepost/gowitness@latest"
    "github.com/ffuf/ffuf/v2@latest"
)

for tool in "${GO_TOOLS[@]}"; do
    name=$(basename "${tool%%@*}")
    printf "  -> %-20s" "$name"
    go install "$tool" 2>/dev/null && echo -e "${GREEN}[done]${NC}" || echo -e "${RED}[failed]${NC}"
done
echo -e "${GREEN}[+] Go tools installed.${NC}"

# ── 5. Nuclei templates ───────────────────────────────────────────────────────
echo -e "\n${YELLOW}[5/5] Downloading Nuclei templates...${NC}"
if command -v nuclei &>/dev/null; then
    nuclei -update-templates -silent && echo -e "${GREEN}[+] Nuclei templates ready.${NC}" || echo -e "${YELLOW}[~] Template download skipped.${NC}"
else
    echo -e "${YELLOW}[~] nuclei not in PATH yet — run: nuclei -update-templates${NC}"
fi

# ── Make update.sh executable ─────────────────────────────────────────────────
chmod +x update.sh

echo -e "\n${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  ReconEngine installed successfully!     ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo -e "\n  Start a scan:"
echo -e "  ${GREEN}python3 main.py --csv your_scope.csv --profile fast${NC}"
echo -e "\n  Future updates:"
echo -e "  ${GREEN}./update.sh${NC}\n"
