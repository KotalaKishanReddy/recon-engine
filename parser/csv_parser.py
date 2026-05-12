"""
csv_parser.py
Parses HackerOne / Bugcrowd scope CSV exports into normalized target objects.

Fix B-01: Added parse_scope_csv() wrapper that main.py imports.
"""
import csv
import re
import json
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any

ASSET_TYPES = {
    "wildcard": r"^\*\.[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$",
    "domain":   r"^(?!https?://)[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$",
    "url":      r"^https?://",
    "ip":       r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$",
    "android":  r"(android|com\.[a-z])",
    "ios":      r"(ios|apple\.com)",
    "cidr":     r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$",
}

SKIP_TYPES = {"android", "ios", "other"}

H1_ASSET_COL  = ["asset_identifier", "asset identifier", "identifier", "scope", "target"]
H1_TYPE_COL   = ["asset_type", "asset type", "type"]
H1_REWARD_COL = ["eligible_for_bounty", "bounty", "in_scope"]
H1_INSTR_COL  = ["instruction", "notes", "description"]


@dataclass
class Target:
    raw: str
    asset_type: str
    apex_domain: str
    in_scope: bool = True
    eligible_for_bounty: bool = True
    notes: str = ""
    source_row: int = 0
    skip: bool = False

    def to_dict(self) -> Dict:
        return asdict(self)


def _find_col(headers: List[str], candidates: List[str]) -> Optional[str]:
    h_lower = {h.lower().strip(): h for h in headers}
    for c in candidates:
        if c.lower() in h_lower:
            return h_lower[c.lower()]
    return None


def _infer_type(value: str) -> str:
    for t, pattern in ASSET_TYPES.items():
        if re.search(pattern, value, re.IGNORECASE):
            return t
    return "unknown"


def _extract_apex(raw: str, asset_type: str) -> str:
    raw = raw.strip().lower()
    if asset_type == "wildcard":
        return raw.lstrip("*.")
    if asset_type == "url":
        match = re.search(r"https?://([^/?]+)", raw)
        return match.group(1) if match else raw
    if asset_type in ("domain", "unknown"):
        return raw
    return raw


def parse_csv(filepath: str) -> List[Target]:
    """Core parser — returns List[Target]."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"CSV not found: {filepath}")

    targets: List[Target] = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames or []

        asset_col  = _find_col(headers, H1_ASSET_COL)
        type_col   = _find_col(headers, H1_TYPE_COL)
        reward_col = _find_col(headers, H1_REWARD_COL)
        instr_col  = _find_col(headers, H1_INSTR_COL)

        if not asset_col:
            raise ValueError(
                f"Cannot find asset column. Headers: {headers}\nExpected one of: {H1_ASSET_COL}"
            )

        for i, row in enumerate(reader, start=2):
            raw = row.get(asset_col, "").strip()
            if not raw:
                continue

            if type_col and row.get(type_col, "").strip():
                raw_type = row[type_col].strip().lower()
                type_map = {
                    "url": "url", "domain": "domain", "wildcard": "wildcard",
                    "ip_address": "ip", "cidr": "cidr",
                    "android": "android", "ios": "ios",
                    "other": "unknown", "hardware": "unknown",
                }
                asset_type = type_map.get(raw_type, _infer_type(raw))
            else:
                asset_type = _infer_type(raw)

            eligible = True
            if reward_col:
                val = row.get(reward_col, "true").strip().lower()
                eligible = val in ("true", "yes", "1", "")

            notes = row.get(instr_col, "").strip() if instr_col else ""
            apex  = _extract_apex(raw, asset_type)
            skip  = asset_type in SKIP_TYPES

            targets.append(Target(
                raw=raw, asset_type=asset_type, apex_domain=apex,
                eligible_for_bounty=eligible, notes=notes, source_row=i, skip=skip,
            ))
    return targets


def print_summary(targets: List[Target]) -> None:
    total    = len(targets)
    skipped  = sum(1 for t in targets if t.skip)
    web_tgts = [t for t in targets if not t.skip]
    types: Dict[str, int] = {}
    for t in web_tgts:
        types[t.asset_type] = types.get(t.asset_type, 0) + 1
    print(f"\n{'─'*50}")
    print(f"  CSV Parse Summary")
    print(f"{'─'*50}")
    print(f"  Total rows       : {total}")
    print(f"  Skipped (non-web): {skipped}")
    print(f"  Web targets      : {len(web_tgts)}")
    for t, c in sorted(types.items()):
        print(f"    {t:<12}: {c}")
    print(f"{'─'*50}\n")


def parse_scope_csv(filepath) -> Dict[str, Any]:
    """
    B-01 fix: wrapper called by main.py.
    Accepts str or Path. Returns:
        {
          'domains':  [apex domain strings, deduplicated, sorted],
          'targets':  [serialised Target dicts],
          'skipped':  [serialised Target dicts for non-web assets],
        }
    """
    targets = parse_csv(str(filepath))
    print_summary(targets)
    domains = sorted({t.apex_domain for t in targets
                      if not t.skip and t.apex_domain and t.eligible_for_bounty})
    skipped = [t.to_dict() for t in targets if t.skip]
    return {
        "domains": domains,
        "targets": [t.to_dict() for t in targets],
        "skipped": skipped,
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python csv_parser.py <scope.csv>")
        sys.exit(1)
    result = parse_scope_csv(sys.argv[1])
    print(f"Apex domains: {result['domains']}")
