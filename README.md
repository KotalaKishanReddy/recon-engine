# ReconEngine 🎯

Automated Bug Bounty Recon Pipeline — drop in a HackerOne/Bugcrowd CSV, get a prioritized HTML report out.

## Features
- 📥 Parses HackerOne & Bugcrowd scope CSVs automatically
- 🔍 Passive recon: subfinder, amass, crt.sh, theHarvester
- ⚡ Active probing: httpx, nmap, wafw00f, gowitness screenshots
- 🧠 Vuln scanning: nuclei, paramspider, gf patterns
- 📊 Priority-scored HTML dashboard report (Critical → Low)
- 🐳 Docker-ready (Kali Linux base with all tools pre-installed)
- ⚙️ 3 scan profiles: fast / deep / stealth

## Usage

### Local
```bash
pip install -r requirements.txt
python main.py --csv hackerone_scope.csv
python main.py --csv scope.csv --profile deep --run-id tesla_audit
```

### Docker
```bash
docker compose -f docker/docker-compose.yml build
docker compose -f docker/docker-compose.yml run recon-engine \
  --csv /app/output/scope.csv --profile deep
```

## Scan Profiles

| Profile | Passive | Active | Vuln Scan | Screenshots |
|---------|---------|--------|-----------|-------------|
| `fast` | ✅ | ✅ | ❌ | ❌ |
| `deep` | ✅ | ✅ | ✅ | ✅ |
| `stealth` | ✅ | ❌ | ❌ | ❌ |

## Project Structure

```
recon-engine/
├── main.py                  ← CLI entrypoint
├── config.yaml              ← Tool paths, API keys, profiles, scoring
├── requirements.txt
├── parser/
│   └── csv_parser.py        ← H1/Bugcrowd CSV → normalized targets
├── modules/
│   ├── passive/passive_recon.py   ← subfinder, amass, crt.sh, theHarvester
│   ├── active/active_recon.py     ← httpx, nmap, wafw00f, gowitness
│   └── vuln/vuln_scan.py          ← nuclei, paramspider, gf
├── aggregator/
│   └── scorer.py            ← Dedup + priority scoring
├── reporter/
│   └── reporter.py          ← Self-contained HTML dashboard
└── docker/
    ├── Dockerfile
    └── docker-compose.yml
```

## Output

Every scan produces:
- `output/{run_id}/report_{run_id}.html` — open in browser, filter by severity
- `output/{run_id}/aggregated_results.json` — raw findings for scripting
- Per-tool raw output files in `passive/`, `active/`, `vuln/` subdirs

## API Keys (optional but recommended)

Add to `config.yaml` for wider passive coverage:
- [Shodan](https://shodan.io)
- [SecurityTrails](https://securitytrails.com)
- [Chaos (ProjectDiscovery)](https://chaos.projectdiscovery.io)
- [VirusTotal](https://virustotal.com)

## Legal

> ⚠️ For **authorized bug bounty use only**. Always verify targets are in-scope before running active or vuln scan phases. Use `--profile stealth` for first contact with any new program.
