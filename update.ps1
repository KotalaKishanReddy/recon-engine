# update.ps1 — ReconEngine one-shot updater
# Run from inside the recon-engine folder:
#   .\update.ps1
# On first run if blocked: Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

$ErrorActionPreference = "Stop"

Write-Host "`n[*] ReconEngine Updater" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan

# 1. Pull latest repo changes
Write-Host "`n[1/3] Pulling latest code from GitHub..." -ForegroundColor Yellow
git pull origin main
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] git pull failed. Check your internet or auth." -ForegroundColor Red
    exit 1
}
Write-Host "[+] Repo updated." -ForegroundColor Green

# 2. Update Python dependencies
Write-Host "`n[2/3] Updating Python dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt --upgrade --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] pip install failed." -ForegroundColor Red
    exit 1
}
Write-Host "[+] Python deps updated." -ForegroundColor Green

# 3. Update all Go tools
Write-Host "`n[3/3] Updating Go tools..." -ForegroundColor Yellow
$goTools = @(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "github.com/d3mondev/puredns/v2@latest",
    "github.com/tomnomnom/waybackurls@latest",
    "github.com/tomnomnom/gf@latest",
    "github.com/sensepost/gowitness@latest",
    "github.com/ffuf/ffuf/v2@latest"
)
foreach ($tool in $goTools) {
    $name = $tool.Split("/")[-1].Split("@")[0]
    Write-Host "  -> $name" -NoNewline
    go install $tool 2>$null
    Write-Host " [done]" -ForegroundColor Green
}

Write-Host "`n[+] ReconEngine is up to date." -ForegroundColor Cyan
Write-Host "    Run: python main.py --csv your_scope.csv --profile fast`n" -ForegroundColor White
