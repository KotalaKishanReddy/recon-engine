#!/usr/bin/env bash
# update.sh — ReconEngine universal updater
# Works on: Linux, WSL, macOS, Kali
#
# First time setup:
#   chmod +x update.sh
#   ./update.sh
#
# After that, just run:
#   ./update.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "\n${CYAN}[*] ReconEngine Updater${NC}"
echo -e "${CYAN}========================${NC}"

# ── 1. Pull latest code ───────────────────────────────────────────────────────
echo -e "\n${YELLOW}[1/4] Pulling latest code from GitHub...${NC}"
git pull origin main || { echo -e "${RED}[!] git pull failed. Check internet or SSH auth.${NC}"; exit 1; }
echo -e "${GREEN}[+] Repo updated.${NC}"

# ── 2. Python deps ────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[2/4] Updating Python dependencies...${NC}"
if command -v pip3 &>/dev/null; then
    pip3 install -r requirements.txt --upgrade -q
elif command -v pip &>/dev/null; then
    pip install -r requirements.txt --upgrade -q
else
    echo -e "${RED}[!] pip not found. Install Python first.${NC}"; exit 1
fi
echo -e "${GREEN}[+] Python deps updated.${NC}"

# ── 3. Go tools ───────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[3/4] Updating Go tools...${NC}"
if ! command -v go &>/dev/null; then
    echo -e "${RED}[!] Go not found. Install from https://go.dev/dl/${NC}"
    exit 1
fi

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
echo -e "${GREEN}[+] Go tools updated.${NC}"

# ── 4. Nuclei templates ───────────────────────────────────────────────────────
echo -e "\n${YELLOW}[4/4] Updating Nuclei templates...${NC}"
if command -v nuclei &>/dev/null; then
    nuclei -update-templates -silent && echo -e "${GREEN}[+] Nuclei templates updated.${NC}" || echo -e "${YELLOW}[~] Template update skipped (no internet?).${NC}"
else
    echo -e "${YELLOW}[~] nuclei not in PATH yet, skipping templates.${NC}"
fi

echo -e "\n${CYAN}[+] ReconEngine is fully up to date.${NC}"
echo -e "    Run: ${GREEN}python3 main.py --csv your_scope.csv --profile fast${NC}\n"
