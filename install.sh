#!/usr/bin/env bash
# install.sh — ReconEngine one-shot installer
# Works on: Linux, WSL, Kali, macOS
#
# Usage (from anywhere):
#   curl -fsSL https://raw.githubusercontent.com/KotalaKishanReddy/recon-engine/main/install.sh | bash
# OR (if already cloned):
#   bash install.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

REPO="https://github.com/KotalaKishanReddy/recon-engine.git"
VENV=".venv"

# Always work from the directory this script lives in
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "\n${CYAN}[*] ReconEngine Installer${NC}"
echo -e "${CYAN}==========================${NC}"
echo -e "  Working dir: ${SCRIPT_DIR}"

# ── 1. System deps check ────────────────────────────────────────────────────
echo -e "\n${YELLOW}[1/5] Checking system dependencies...${NC}"
for cmd in git python3 go; do
    if command -v $cmd &>/dev/null; then
        echo -e "  ${GREEN}[+]${NC} $cmd found"
    else
        echo -e "  ${RED}[!] $cmd not found.${NC}"
        case $cmd in
            git)     echo "      Fix: sudo apt install git -y" ;;
            python3) echo "      Fix: sudo apt install python3 python3-venv -y" ;;
            go)      echo "      Fix: https://go.dev/dl/ OR sudo apt install golang-go" ;;
        esac
        exit 1
    fi
done
echo -e "${GREEN}[+] All system deps present.${NC}"

# ── 2. Clone or update repo ──────────────────────────────────────────────────
echo -e "\n${YELLOW}[2/5] Checking repo...${NC}"
# If requirements.txt exists here, we ARE inside the repo already
if [ -f "requirements.txt" ]; then
    echo -e "  ${GREEN}[+] Already inside repo at: ${SCRIPT_DIR}${NC}"
    git pull origin main
else
    # Running via curl pipe or from outside — clone fresh
    if [ -d "recon-engine" ]; then
        echo -e "  ${YELLOW}[~] recon-engine/ exists — pulling latest.${NC}"
        cd recon-engine
        git pull origin main
    else
        git clone "$REPO"
        cd recon-engine
    fi
fi
echo -e "${GREEN}[+] Repo ready at: $(pwd)${NC}"

# ── 3. Python venv + deps ────────────────────────────────────────────────────
echo -e "\n${YELLOW}[3/5] Setting up Python virtualenv + dependencies...${NC}"
if [ ! -d "$VENV" ]; then
    python3 -m venv "$VENV"
    echo -e "  ${GREEN}[+] .venv created${NC}"
else
    echo -e "  ${YELLOW}[~] .venv exists, reusing.${NC}"
fi
"$VENV/bin/pip" install --upgrade pip -q
"$VENV/bin/pip" install -r requirements.txt -q
echo -e "${GREEN}[+] Python deps installed.${NC}"

# Write run.sh launcher
cat > run.sh << 'EOF'
#!/usr/bin/env bash
cd "$(dirname "$0")"
.venv/bin/python3 main.py "$@"
EOF
chmod +x run.sh
echo -e "  ${GREEN}[+] run.sh created${NC}"

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

# ── 5. Nuclei templates ──────────────────────────────────────────────────────
echo -e "\n${YELLOW}[5/5] Downloading Nuclei templates...${NC}"
if command -v nuclei &>/dev/null; then
    nuclei -update-templates -silent && echo -e "${GREEN}[+] Templates ready.${NC}" || echo -e "${YELLOW}[~] Skipped.${NC}"
else
    echo -e "${YELLOW}[~] nuclei not in PATH yet. After install run:${NC}"
    echo -e "    ${YELLOW}echo 'export PATH=\$PATH:\$HOME/go/bin' >> ~/.bashrc && source ~/.bashrc${NC}"
    echo -e "    ${YELLOW}nuclei -update-templates${NC}"
fi

chmod +x update.sh 2>/dev/null || true

echo -e "\n${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  ReconEngine installed successfully!     ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo -e "\n  Start a scan:"
echo -e "  ${GREEN}./run.sh --csv your_scope.csv --profile fast${NC}"
echo -e "\n  Future updates:"
echo -e "  ${GREEN}./update.sh${NC}\n"
