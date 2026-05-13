# 🔍 ReconEngine

> **Automated bug bounty recon orchestrator.**  
> For authorized security research only.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Version](https://img.shields.io/badge/reporter-v2.0-green)
![License](https://img.shields.io/badge/license-private-red)

---

## What it does

Three-phase recon pipeline that runs all standard tools in sequence,
aggregates and scores findings, and produces a single downloadable
`.md` report ready to paste into HackerOne, Notion, or Obsidian.

```
Phase 1 ─ Passive     subfinder + amass + crt.sh + Shodan
Phase 2 ─ Active      puredns → httpx → nmap → wafw00f → gowitness
Phase 3 ─ Vuln        nuclei → gf → ffuf → paramspider → waybackurls → JS secrets
```

---

## Quick Start

```bash
# Install Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/d3mondev/puredns/v2@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
go install github.com/sensepost/gowitness@latest
pip install -r requirements.txt

# Run (fast profile)
python main.py --csv scope.csv --profile fast

# Run (deep profile — screenshots + nuclei)
python main.py --csv scope.csv --profile deep

# View run history
python main.py --history
```

---

## Output

Every run produces:

```
output/{run_id}/
  ├── report_{run_id}.html          interactive dashboard
  ├── report_{run_id}.md            ← full-data markdown (HackerOne / Notion ready)
  ├── passive/passive_results.json
  ├── active/active_results.json
  ├── vuln/vuln_results.json
  ├── vuln/waybackurls.txt
  └── active/screenshots/           (deep profile only)
```

---

## Markdown Report — 18 Sections

| # | Section | What’s inside |
|---|---------|---------------|
| 1 | Pipeline Health | Per-tool ✅/🔴/⚠️ status + auto-diagnosis |
| 2 | Executive Summary | KPI table + top 5 findings + DNS coverage % |
| 3 | HVT Spotlight | Auto-detected juicy internal tooling subdomains |
| 4 | Takeover Candidates | CNAME/name-pattern takeover analysis |
| 5 | Domain Attack Surface | Per-domain scoring table |
| 6 | All Findings | Full table + detailed block + H1 draft per finding |
| 7 | Passive Recon | All subdomains (collapsible) + crt.sh + Shodan |
| 8 | Active — Live Hosts | httpx results: status, title, tech, WAF |
| 9 | Active — Nmap | Port/service table + interesting ports |
| 10 | Nuclei Findings | Template, severity, matched URL, description |
| 11 | JS Secret Leaks | Type, host, file, redacted snippet |
| 12 | Wayback — Historical URLs | Juicy paths + juicy-param URLs from archive |
| 13 | Parameter Surface | Injection candidates + param frequency table |
| 14 | GF Pattern Matches | XSS/SQLi/RCE/LFI/SSRF URL lists |
| 15 | Directory Fuzzing | ffuf hits with status + length |
| 16 | WAF & Tech Fingerprint | Per-host WAF + tech stack |
| 17 | Screenshot Index | Gowitness PNG listing |
| 18 | Raw Score Breakdown | All findings ranked by score with ASCII bar |

---

## Profiles

| Profile | Passive | Active | Vuln | Screenshots | Rate |
|---------|---------|--------|------|-------------|------|
| `fast` | ✅ | ✅ | ❌ | ❌ | 50 req/s |
| `deep` | ✅ | ✅ | ✅ | ✅ | 30 req/s |
| `stealth` | ✅ | ❌ | ❌ | ❌ | 10 req/s |

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md).
