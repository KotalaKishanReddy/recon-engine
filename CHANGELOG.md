# Changelog

All notable changes to ReconEngine are documented here.

---

## [v2.0] — 2026-05-13

### Reporter (`reporter/markdown_reporter.py`)
- **STR-01** Pipeline Health section — per-tool row table with ✅/🔴/⚠️ status and
  auto-diagnosis block when active phase returns 0 live hosts
- **STR-02** Subdomain Takeover Candidates — CNAME record scan + name-pattern
  matching against 24 known-vulnerable services (S3, GitHub Pages, Heroku, Azure,
  Netlify, Vercel, Fastly …)
- **STR-03** High-Value Target Spotlight — keyword-based auto-detection of 32
  internal tooling subdomains (jenkins, argocd, vault, grafana, metabase, n8n,
  sonarqube …) with per-tool probe tips and curl cheatsheet
- **STR-04** DNS Resolve Coverage metric in Executive Summary
  (puredns resolved N/440)
- **STR-05** HackerOne-ready collapsible draft block per finding —
  Title, Severity, Steps to Reproduce, Impact, Remediation pre-filled
- **STR-06** Screenshot Index section listing all gowitness PNGs with
  filename and full path
- **STR-07** Wayback Machine / Historical URL Analysis section — reads
  `vuln/waybackurls.txt`, breaks down file extensions, surfaces juicy
  historical paths and juicy-param URLs
- **STR-08** Parameter Surface section — unified view of paramspider_urls
  + params_found; juicy injection candidates highlighted; top param
  frequency table with risk labels
- TOC updated to 18 sections
- Reporter version stamped in header and footer

### Active Recon (`modules/active/active_recon.py`)
- **DNS-01** puredns pre-filter stage — validates subdomain DNS resolution
  before feeding to httpx; eliminates `440 subs → 0 live hosts` silent failure
- **HTTP-01** httpx hardened for WAF evasion: `-random-agent -retries 2
  -threads 10 -timeout 15 -rate-limit 50`
- `dns_resolved` count added to `active_results` output for STR-04
- Bundled fallback resolver list (Quad9 + CF + Google, 10 entries)

### Config (`config.yaml`)
- `rate_limit` lowered: fast=50 (was 150), deep=30 (was 50)
- `puredns` added to tools section
- `dns_resolve_timeout` added per profile

---

## [v1.0] — 2026-05-12

### Initial Release
- Full 3-phase pipeline: passive → active → vuln
- Passive: subfinder, amass, crt.sh, Shodan
- Active: httpx, nmap, wafw00f, gowitness
- Vuln: nuclei, gf, ffuf, paramspider, waybackurls, JS secret scanner
- Aggregator + scorer with priority labels
- HTML report generator
- Markdown report generator (all 14 sections)
- SQLite run history + diff (new findings detection)
- Multi-profile: fast / deep / stealth
- HackerOne CSV scope parser
