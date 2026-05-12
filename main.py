#!/usr/bin/env python3
"""
ReconEngine — main.py
Usage: python main.py --csv scope.csv [--profile fast|deep|stealth] [--run-id myrun]

Pipeline:
  1. Parse CSV -> extract scope
  2. Passive recon (subfinder, amass, crt.sh, theHarvester)
  3. Active recon (httpx, nmap, wafw00f, gowitness)
  4. Vulnerability scan (nuclei, paramspider, gf)
  5. Score & aggregate
  6. Generate HTML report
"""
import asyncio
import argparse
import json
import sys
import yaml
import shutil
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))
from parser.csv_parser             import parse_csv, print_summary
from modules.passive.passive_recon import run_passive
from modules.active.active_recon   import run_active
from modules.vuln.vuln_scan        import run_vuln
from aggregator.scorer             import score_and_aggregate
from reporter.reporter             import generate_report

BANNER = """
  ____                        _____             _
 |  _ \\  ___  ___ ___  _ __  | ____|_ __   __ _(_)_ __   ___
 | |_) |/ _ \\/ __/ _ \\| '_ \\ |  _| | '_ \\ / _` | | '_ \\ / _ \\
 |  _ <  __/ (_| (_) | | | || |___| | | | (_| | | | | |  __/
 |_| \\_\\___|\\___\\___/|_| |_||_____|_| |_|\\__, |_|_| |_|\\___|
                                              |___/
  Bug Bounty Recon Automation — For authorized use only.
"""


def load_config(path="config.yaml"):
    cfg = Path(path)
    if not cfg.exists():
        print(f"[!] {path} not found. Using defaults.")
        return {}
    with open(cfg) as f:
        return yaml.safe_load(f) or {}


def check_tools(config):
    tools = config.get("tools", {})
    for name, binary in tools.items():
        found = shutil.which(binary) is not None
        print(f"  [{'OK' if found else 'MISSING'}] {name:<15} ({binary})")


def get_profile(config, name):
    profiles = config.get("profiles", {})
    default  = config.get("default_profile", "fast")
    return profiles.get(name, profiles.get(default, {
        "passive": True, "active": True, "vuln": False,
        "screenshots": False, "threads": 20, "rate_limit": 150,
    }))


async def run_pipeline(args, config):
    print(BANNER)
    run_id       = args.run_id or datetime.now().strftime("%Y%m%d_%H%M%S")
    profile_name = args.profile or config.get("default_profile", "fast")
    profile      = get_profile(config, profile_name)

    print(f"[*] Run ID  : {run_id}")
    print(f"[*] CSV     : {args.csv}")
    print(f"[*] Profile : {profile_name}")

    out_dir = Path(config.get("output_dir", "./output")) / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] Output  : {out_dir}\n")

    print("[*] Tool availability:")
    check_tools(config)
    print()

    # ── Step 1: Parse ────────────────────────────────────────
    print("=" * 50 + "\n  STEP 1: Parsing scope CSV\n" + "=" * 50)
    targets     = parse_csv(args.csv)
    print_summary(targets)
    web_targets = [t for t in targets if not t.skip and t.eligible_for_bounty]
    if not web_targets:
        print("[!] No web targets found. Exiting."); return
    apex_domains = list(dict.fromkeys(t.apex_domain for t in web_targets))
    print(f"[*] Apex domains: {apex_domains}\n")
    (out_dir / "scope.json").write_text(json.dumps([t.to_dict() for t in web_targets], indent=2))

    # ── Step 2: Passive ──────────────────────────────────────
    print("=" * 50 + "\n  STEP 2: Passive Reconnaissance\n" + "=" * 50)
    if profile.get("passive", True):
        passive_results = await run_passive(apex_domains, out_dir, config)
        total = sum(len(d.get("subdomains", [])) for d in passive_results.values())
        print(f"\n  Done. Subdomains found: {total}\n")
    else:
        passive_results = {d: {"domain": d, "subdomains": [d], "emails": []} for d in apex_domains}
        print("  Skipped.\n")

    # ── Step 3: Active ───────────────────────────────────────
    print("=" * 50 + "\n  STEP 3: Active Reconnaissance\n" + "=" * 50)
    if profile.get("active", True):
        active_results = await run_active(passive_results, out_dir, config, profile)
        print(f"\n  Done. Live hosts: {active_results.get('live_count', 0)}\n")
    else:
        active_results = {"live_hosts": [], "live_count": 0, "waf_detection": {}, "nmap": {}}
        print("  Skipped.\n")

    # ── Step 4: Vuln ─────────────────────────────────────────
    print("=" * 50 + "\n  STEP 4: Vulnerability Scanning\n" + "=" * 50)
    if profile.get("vuln", False):
        vuln_results = await run_vuln(active_results, passive_results, out_dir, config)
        print(f"\n  Done. Nuclei findings: {vuln_results.get('nuclei_count', 0)}\n")
    else:
        vuln_results = {"nuclei_findings": [], "nuclei_count": 0, "param_urls": {}, "gf_patterns": {}}
        print("  Skipped (use --profile deep to enable).\n")

    # ── Step 5: Score ────────────────────────────────────────
    print("=" * 50 + "\n  STEP 5: Scoring & Aggregation\n" + "=" * 50)
    aggregated = score_and_aggregate(passive_results, active_results, vuln_results, config, out_dir)

    # ── Step 6: Report ───────────────────────────────────────
    print("\n" + "=" * 50 + "\n  STEP 6: Generating Report\n" + "=" * 50)
    report_path = generate_report(aggregated, passive_results, active_results, run_id, profile_name, out_dir)

    print("\n" + "=" * 50 + "\n  SCAN COMPLETE\n" + "=" * 50)
    by_sev = aggregated.get("by_severity", {})
    print(f"  Critical : {by_sev.get('critical', 0)}")
    print(f"  High     : {by_sev.get('high', 0)}")
    print(f"  Medium   : {by_sev.get('medium', 0)}")
    print(f"  Low      : {by_sev.get('low', 0)}")
    print(f"  Report   : {report_path}\n")
    for domain, sig in sorted(
        aggregated.get("domain_signals", {}).items(),
        key=lambda x: -x[1].get("interest_score", 0)
    ):
        print(f"    {sig.get('priority', '')} -- {domain}")


def main():
    p = argparse.ArgumentParser(description="ReconEngine -- Automated Bug Bounty Recon Pipeline")
    p.add_argument("--csv",     required=True)
    p.add_argument("--profile", default=None,          help="fast | deep | stealth")
    p.add_argument("--run-id",  default=None)
    p.add_argument("--config",  default="config.yaml")
    args = p.parse_args()
    asyncio.run(run_pipeline(args, load_config(args.config)))


if __name__ == "__main__":
    main()
