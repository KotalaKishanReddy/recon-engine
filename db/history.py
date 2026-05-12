"""
history.py
SQLite-backed run history for delta/diff mode.
Detects NEW findings that didn't exist in previous scans.

Fix applied (B-08):
  DB_PATH is no longer hardcoded to ./output/.
  main.py calls set_db_path(out_root) so the DB follows the --output flag.
  This prevents history loss when the user points to a different output dir.
"""
import sqlite3
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Tuple
from datetime import datetime

# Default — overridden by main.py via set_db_path() before any DB call
DB_PATH = Path("./output/recon_history.db")


def set_db_path(output_dir: str) -> None:
    """
    B-08 FIX: Point the DB to the active output directory.
    Call this in main.py as soon as out_root is resolved.
    """
    global DB_PATH
    DB_PATH = Path(output_dir) / "recon_history.db"


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""CREATE TABLE IF NOT EXISTS runs (
        run_id TEXT PRIMARY KEY,
        created_at TEXT,
        profile TEXT,
        scope_hash TEXT,
        summary TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS findings (
        fingerprint TEXT PRIMARY KEY,
        run_id TEXT,
        first_seen TEXT,
        last_seen TEXT,
        category TEXT,
        severity TEXT,
        host TEXT,
        title TEXT,
        url TEXT,
        score INTEGER
    )""")
    conn.commit()
    return conn


def _fingerprint(finding: Dict) -> str:
    key = f"{finding.get('category')}|{finding.get('host')}|{finding.get('title', '')[:60]}"
    return hashlib.sha1(key.encode()).hexdigest()


def save_run(run_id: str, profile: str, scope_hash: str, summary: Dict) -> None:
    conn = _connect()
    conn.execute(
        "INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?)",
        (run_id, datetime.utcnow().isoformat(), profile, scope_hash, json.dumps(summary))
    )
    conn.commit()
    conn.close()


def diff_findings(run_id: str, findings: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """
    Returns (new_findings, all_findings_with_is_new_flag)
    New = fingerprint not seen in any previous run.
    """
    conn    = _connect()
    now     = datetime.utcnow().isoformat()
    new     = []
    updated = []

    for f in findings:
        fp     = _fingerprint(f)
        row    = conn.execute("SELECT first_seen FROM findings WHERE fingerprint=?", (fp,)).fetchone()
        is_new = row is None
        if is_new:
            conn.execute(
                "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?)",
                (fp, run_id, now, now,
                 f.get("category"), f.get("severity"),
                 f.get("host"), f.get("title"), f.get("url"), f.get("score", 0))
            )
            new.append(f)
        else:
            conn.execute("UPDATE findings SET last_seen=?, run_id=? WHERE fingerprint=?", (now, run_id, fp))
        updated.append({**f, "is_new": is_new})

    conn.commit()
    conn.close()
    print(f"  [diff] {len(new)} NEW findings out of {len(findings)} total")
    return new, updated


def get_run_history(limit: int = 10) -> List[Dict]:
    conn = _connect()
    rows = conn.execute(
        "SELECT run_id, created_at, profile, summary FROM runs ORDER BY created_at DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [{"run_id": r[0], "created_at": r[1], "profile": r[2], "summary": json.loads(r[3])} for r in rows]
