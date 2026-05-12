"""
main.py — ReconEngine CLI
Usage:
    python main.py --csv samples/hackerone_sample_scope.csv --profile fast
    python main.py --csv scope.csv --profile deep
    python main.py --csv scope.csv --profile stealth
    python main.py --history          # show last 10 runs

Fix B-08: calls db.set_db_path(out_root) so the history DB follows --output.
Fix B-01: imports parse_scope_csv (the wrapper that now exists in csv_parser).
Timeout overhaul: _active_profile injected into config so passive/vuln modules
                  can look up their own profile timeouts.
"""
import argparse
import asyncio
import hashlib
import json
import sys
import time
from datetime import datetime
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))
from parser.csv_parser  import parse_scope_csv          # B-01 fix
from modules.passive    import run_passive
from modules.active     import run_active
from modules.vuln       import run_vuln_scan
from aggregator         import score_and_aggregate
from reporter           import generate_report
from db                 import save_run, diff_findings, get_run_history, set_db_path  # B-08 fix

BANNER = r"""
  ____                      _____             _
 |  _ \ ___  ___ ___  _ __ | ____|_ __   __ _(_)_ __   ___
 | |_) / _ \/ __/ _ \| '_ \|  _| | '_ \ / _` | | '_ \ / _ \
 |  _ <  __/ (_| (_) | | | | |___| | | | (_| | | | | |  __/
 |_| \_\___|\___\___/|_| |_|_____|_| |_|\__, |_|_| |_|\___|
                                         |___/
  Bug Bounty Recon Orchestrator  |  For authorized use only
"""


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def scope_hash(targets: dict) -> str:
    raw = json.dumps(targets, sort_keys=True)
    return hashlib.md5(raw.encode()).hexdigest()[:8]


def fmt_elapsed(seconds: float) -> str:
    """Human-readable elapsed time: 4m 32s."""
    m, s = divmod(int(seconds), 60)
    return f"{m}m {s}s" if m else f"{s}s"


def print_summary(
    aggregated: dict, new_findings: list, run_id: str, out_dir: Path, total_elapsed: float
) -> None:
    by_sev = aggregated.get("by_severity", {})
    print("\n" + "=" * 62)
    print(f"  Run ID      : {run_id}")
    print(f"  Output      : {out_dir}")
    print(f"  Wall time   : {fmt_elapsed(total_elapsed)}")
    print(f"  Total       : {aggregated.get('total_findings', 0)} findings")
    print(f"  NEW         : {len(new_findings)} new since last scan")
    sev_str = "  ".join(f"{k.upper()}: {v}" for k, v in by_sev.items() if v)
    if sev_str:
        print(f"  {sev_str}")
    print("=" * 62)
    for domain, sig in aggregated.get("domain_signals", {}).items():
        p    = sig.get("priority", "")
        icon = "\U0001f534" if "HIGH" in p else "\U0001f7e1" if "MEDIUM" in p else "\U0001f7e2"
        print(f"  {icon}  {domain:<35} score={sig.get('interest_score', 0):<6} {p}")
    print("=" * 62 + "\n")


async def main() -> None:
    print(BANNER)
    parser = argparse.ArgumentParser(description="ReconEngine — Bug Bounty Recon Orchestrator")
    parser.add_argument("--csv",     help="Path to HackerOne/Bugcrowd scope CSV")
    parser.add_argument("--profile", default="fast", choices=["fast", "deep", "stealth"],
                        help="Scan profile (default: fast)")
    parser.add_argument("--config",  default="config.yaml", help="Config file path")
    parser.add_argument("--output",  default="",            help="Custom output directory")
    parser.add_argument("--history", action="store_true",   help="Show last 10 run history")
    args = parser.parse_args()

    # B-08 + B-04 (history): resolve output root BEFORE needing the DB
    out_root = Path(args.output) if args.output else Path("./output")
    set_db_path(str(out_root))   # DB follows --output

    # --history: does NOT need config.yaml
    if args.history:
        rows = get_run_history(10)
        if not rows:
            print("No runs in history yet.")
        for r in rows:
            s = r["summary"]
            print(
                f"  [{r['created_at'][:16]}]  {r['run_id']}  "
                f"profile={r['profile']}  "
                f"findings={s.get('total_findings', 0)}  "
                f"critical={s.get('by_severity', {}).get('critical', 0)}"
            )
        return

    if not args.csv:
        parser.print_help()
        sys.exit(1)

    config = load_config(args.config)

    # Inject active profile name so sub-modules can read their timeouts
    config["_active_profile"] = args.profile

    run_id  = datetime.now().strftime("%Y%m%d_%H%M%S")
    profile = config["profiles"].get(args.profile, config["profiles"]["fast"])

    # B-01 fix: parse_scope_csv now actually exists and returns a dict
    targets = parse_scope_csv(Path(args.csv))
    domains = targets.get("domains", [])

    if not domains:
        print("[!] No valid in-scope domains found in CSV. Check format.")
        sys.exit(1)

    run_dir = out_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    set_db_path(str(out_root))   # set again after out_root is fully resolved

    print(f"[*] Domains in scope  : {domains}")
    print(f"[*] Profile           : {args.profile}")
    print(f"[*] Output directory  : {run_dir}")
    print(f"[*] Run ID            : {run_id}\n")

    t0_total = time.monotonic()

    # ── Phase 1: Passive ──────────────────────────────────────────────────────
    t0 = time.monotonic()
    print("[Phase 1/3] Passive Recon ...")
    passive_results = await run_passive(domains, run_dir, config)
    print(f"[Phase 1/3] complete in {fmt_elapsed(time.monotonic()-t0)}\n")

    # ── Phase 2: Active ───────────────────────────────────────────────────────
    t0 = time.monotonic()
    print("[Phase 2/3] Active Recon ...")
    active_results = await run_active(passive_results, run_dir, config, profile)
    print(f"[Phase 2/3] complete in {fmt_elapsed(time.monotonic()-t0)}\n")

    # ── Phase 3: Vuln Scan ────────────────────────────────────────────────────
    t0 = time.monotonic()
    print("[Phase 3/3] Vuln Scan ...")
    vuln_results = await run_vuln_scan(passive_results, active_results, run_dir, config, profile)
    print(f"[Phase 3/3] complete in {fmt_elapsed(time.monotonic()-t0)}\n")

    # ── Aggregate + Diff ──────────────────────────────────────────────────────
    print("[*] Aggregating & scoring ...")
    aggregated = score_and_aggregate(
        passive_results, active_results, vuln_results, config, run_dir
    )
    new_findings, findings_with_flags = diff_findings(run_id, aggregated.get("findings", []))
    aggregated["findings"] = findings_with_flags

    # ── Persist run ───────────────────────────────────────────────────────────
    save_run(run_id, args.profile, scope_hash(targets), {
        "total_findings": aggregated.get("total_findings", 0),
        "by_severity":    aggregated.get("by_severity", {}),
        "new_findings":   len(new_findings),
        "live_hosts":     active_results.get("live_count", 0),
    })

    # ── Report ────────────────────────────────────────────────────────────────
    print("[*] Generating report ...")
    report_path = generate_report(
        aggregated, passive_results, active_results, run_id, args.profile, run_dir
    )

    total_elapsed = time.monotonic() - t0_total
    print_summary(aggregated, new_findings, run_id, run_dir, total_elapsed)
    print(f"  \U0001f4c4 Report      : {report_path}")
    print(f"  \u23f1  Total time  : {fmt_elapsed(total_elapsed)}")

    if new_findings:
        print(f"\n  \U0001f6a8 {len(new_findings)} NEW findings since last run:")
        for f in new_findings[:5]:
            print(
                f"     [{f.get('severity','?').upper():8}] "
                f"{f.get('title','')[:55]}  ({f.get('host','')})"
            )
        if len(new_findings) > 5:
            print(f"     ... and {len(new_findings)-5} more. See report.")


if __name__ == "__main__":
    asyncio.run(main())
