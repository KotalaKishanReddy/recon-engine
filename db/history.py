"""
history.py
SQLite-backed run history for delta/diff mode.
Detects NEW findings that didn't exist in previous scans.

Fix B-08: DB_PATH is no longer hardcoded. set_db_path() lets main.py
          point the DB to the same root as --output so it follows the
          user's output directory and survives output dir migrations.
"""
import sqlite3
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Tuple
from datetime import datetime

# Default — overridden by set_db_path() called from main.py
DB_PATH = Path("./output/recon_history.db")


def set_db_path(output_root: str) -> None:
    """
    B-08 fix: called by main.py after resolving out_root so the DB
    lives alongside all other run artefacts, not always in ./output/.
    """
    global DB_PATH
    DB_PATH = Path(output_root) / "recon_history.db"


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""CREATE TABLE IF NOT EXISTS runs (
        run_id     TEXT PRIMARY KEY,
        created_at TEXT,
        profile    TEXT,
        scope_hash TEXT,
        summary    TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS findings (
        fingerprint TEXT PRIMARY KEY,
        run_id      TEXT,
        first_seen  TEXT,
        last_seen   TEXT,
        category    TEXT,
        severity    TEXT,
        host        TEXT,
        title       TEXT,
        url         TEXT,
        score       INTEGER
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
    Returns (new_findings, all_findings_with_is_new_flag).
    New = fingerprint not seen in any previous run.
    """
    conn    = _connect()
    now     = datetime.utcnow().isoformat()
    new:     List[Dict] = []
    updated: List[Dict] = []

    for f in findings:
        fp    = _fingerprint(f)
        row   = conn.execute(
            "SELECT first_seen FROM findings WHERE fingerprint=?", (fp,)
        ).fetchone()
        is_new = row is None
        if is_new:
            conn.execute(
                "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?)",
                (fp, run_id, now, now,
                 f.get("category"), f.get("severity"),
                 f.get("host"),    f.get("title"), f.get("url"), f.get("score", 0))
            )
            new.append(f)
        else:
            conn.execute(
                "UPDATE findings SET last_seen=?, run_id=? WHERE fingerprint=?",
                (now, run_id, fp)
            )
        updated.append({**f, "is_new": is_new})

    conn.commit()
    conn.close()
    print(f"  [diff] {len(new)} NEW / {len(findings)} total findings")
    return new, updated


def get_run_history(limit: int = 10) -> List[Dict]:
    conn = _connect()
    rows = conn.execute(
        "SELECT run_id, created_at, profile, summary "
        "FROM runs ORDER BY created_at DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [
        {"run_id": r[0], "created_at": r[1], "profile": r[2], "summary": json.loads(r[3])}
        for r in rows
    ]
