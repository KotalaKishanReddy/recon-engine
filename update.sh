#!/usr/bin/env bash
# update.sh — ReconEngine one-shot updater
# Works on: Linux, WSL, Kali, macOS
#
# Run from inside the recon-engine folder:
#   ./update.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

VENV=".venv"

echo -e "\n${CYAN}[*] ReconEngine Updater${NC}"
echo -e "${CYAN}========================${NC}"

# ── 1. Pull latest code ───────────────────────────────────────────────────────
echo -e "\n${YELLOW}[1/4] Pulling latest code from GitHub...${NC}"
git pull origin main || { echo -e "${RED}[!] git pull failed.${NC}"; exit 1; }
echo -e "${GREEN}[+] Repo updated.${NC}"

# ── 2. Python deps (via venv) ────────────────────────────────────────────────
echo -e "\n${YELLOW}[2/4] Updating Python dependencies...${NC}"
if [ ! -d "$VENV" ]; then
    python3 -m venv "$VENV"
    echo -e "  ${GREEN}[+] Created .venv${NC}"
fi
"$VENV/bin/pip" install -r requirements.txt --upgrade -q
echo -e "${GREEN}[+] Python deps updated.${NC}"

# ── 3. Go tools ──────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[3/4] Updating Go tools...${NC}"
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

# ── 4. Nuclei templates ──────────────────────────────────────────────────────
echo -e "\n${YELLOW}[4/4] Updating Nuclei templates...${NC}"
if command -v nuclei &>/dev/null; then
    nuclei -update-templates -silent && echo -e "${GREEN}[+] Templates updated.${NC}" || echo -e "${YELLOW}[~] Skipped.${NC}"
else
    echo -e "${YELLOW}[~] nuclei not in PATH. Run: nuclei -update-templates${NC}"
fi

echo -e "\n${CYAN}[+] ReconEngine is fully up to date.${NC}"
echo -e "    Run: ${GREEN}./run.sh --csv your_scope.csv --profile fast${NC}\n"
