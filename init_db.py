"""
PTaaS — Database Initialization & Access Layer  (v5.1 — synchronized)
=======================================================================
Thread-safe SQLite connection with Write-Ahead Logging.

Signature contract (must match server.py call-sites exactly):
  insert_scan(domain, selected_tools, risk_level="INFO", status="PENDING", raw_results=None) -> int
  update_scan(scan_id, status, risk_level, raw_results, duration_sec) -> None
  fetch_history(limit=50, offset=0) -> list[dict]
  fetch_scan_by_id(scan_id) -> dict | None
  db_save_webhook(webhook_url, platform) -> None
  db_get_webhook() -> dict | None          ← always returns plain dict, never sqlite3.Row
"""

import sqlite3
import json
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).parent / "ptaas.db"


# ── Connection factory ────────────────────────────────────────────────────────

def _get_connection() -> sqlite3.Connection:
    """
    Opens a WAL-mode SQLite connection.
    row_factory=sqlite3.Row lets us call dict(row) safely everywhere.
    check_same_thread=False is safe here because every call opens+closes
    its own connection (no shared state between threads).
    """
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


# ── Schema ────────────────────────────────────────────────────────────────────

def init_db() -> None:
    """
    Creates all tables and indexes if they don't exist.
    Idempotent — safe to call on every startup.
    """
    conn = _get_connection()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            domain         TEXT    NOT NULL,
            selected_tools TEXT    NOT NULL DEFAULT '[]',
            risk_level     TEXT    NOT NULL DEFAULT 'INFO',
            status         TEXT    NOT NULL DEFAULT 'PENDING',
            raw_results    TEXT    NOT NULL DEFAULT '{}',
            duration_sec   REAL             DEFAULT 0.0,
            timestamp      TEXT             DEFAULT (datetime('now','localtime'))
        )
    """)

    c.execute("""
        CREATE INDEX IF NOT EXISTS idx_scans_ts
        ON scans (timestamp DESC)
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS webhook_config (
            id          INTEGER PRIMARY KEY,
            webhook_url TEXT    NOT NULL,
            platform    TEXT    NOT NULL DEFAULT 'slack',
            updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)

    conn.commit()
    conn.close()
    print(f"[DB] Schema ready at: {DB_PATH}")


# ── Scan CRUD ─────────────────────────────────────────────────────────────────

def insert_scan(
    domain: str,
    selected_tools: list,
    risk_level: str = "INFO",
    status: str = "PENDING",
    raw_results: Optional[dict] = None,
) -> int:
    """
    Inserts a new scan row and returns its integer primary-key ID.
    selected_tools is stored as a JSON array string.
    """
    conn = _get_connection()
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO scans (domain, selected_tools, risk_level, status, raw_results)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            domain,
            json.dumps(selected_tools),
            risk_level,
            status,
            json.dumps(raw_results if raw_results is not None else {}),
        ),
    )
    scan_id: int = c.lastrowid          # ← correct attribute (not lastrow_id)
    conn.commit()
    conn.close()
    return scan_id


def update_scan(
    scan_id: int,
    status: str,
    risk_level: str,
    raw_results: dict,
    duration_sec: float,
) -> None:
    """
    Overwrites status, risk, results, and duration for an existing scan row.
    Called both mid-pipeline (status=RUNNING) and on completion/error.
    """
    conn = _get_connection()
    conn.execute(
        """
        UPDATE scans
           SET status       = ?,
               risk_level   = ?,
               raw_results  = ?,
               duration_sec = ?
         WHERE id = ?
        """,
        (status, risk_level, json.dumps(raw_results), round(duration_sec, 3), scan_id),
    )
    conn.commit()
    conn.close()


def fetch_history(limit: int = 50, offset: int = 0) -> list:
    """
    Returns paginated scan rows as plain dicts, newest-first.
    selected_tools is returned as a parsed list (not raw JSON string).
    """
    conn = _get_connection()
    rows = conn.execute(
        """
        SELECT id, domain, selected_tools, risk_level, status,
               duration_sec, timestamp
          FROM scans
         ORDER BY id DESC
         LIMIT ? OFFSET ?
        """,
        (limit, offset),
    ).fetchall()
    conn.close()

    result = []
    for r in rows:
        d = dict(r)
        # Safely parse the stored JSON array back to a Python list
        try:
            d["selected_tools"] = json.loads(d["selected_tools"] or "[]")
        except (json.JSONDecodeError, TypeError):
            d["selected_tools"] = []
        result.append(d)
    return result


def fetch_scan_by_id(scan_id: int) -> Optional[dict]:
    """
    Returns a single scan row as a plain dict, or None if not found.
    raw_results is returned as a parsed dict (not raw JSON string).
    selected_tools is returned as a parsed list.
    """
    conn = _get_connection()
    row = conn.execute(
        "SELECT * FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    conn.close()

    if row is None:
        return None

    d = dict(row)   # sqlite3.Row → plain dict; safe for cfg["key"] access

    # Parse JSON blobs back to native Python types
    try:
        d["raw_results"] = json.loads(d["raw_results"] or "{}")
    except (json.JSONDecodeError, TypeError):
        d["raw_results"] = {}

    try:
        d["selected_tools"] = json.loads(d["selected_tools"] or "[]")
    except (json.JSONDecodeError, TypeError):
        d["selected_tools"] = []

    return d


# ── Webhook config ────────────────────────────────────────────────────────────

def db_save_webhook(webhook_url: str, platform: str) -> None:
    """Upserts the single webhook configuration row."""
    conn = _get_connection()
    conn.execute("DELETE FROM webhook_config")
    conn.execute(
        """
        INSERT INTO webhook_config (id, webhook_url, platform, updated_at)
        VALUES (1, ?, ?, datetime('now'))
        """,
        (webhook_url, platform),
    )
    conn.commit()
    conn.close()


def db_get_webhook() -> Optional[dict]:
    """
    Returns the webhook config as a plain dict with keys
    'webhook_url' and 'platform', or None if not configured.
    Always returns dict — never a bare sqlite3.Row.
    """
    conn = _get_connection()
    row = conn.execute(
        "SELECT webhook_url, platform FROM webhook_config WHERE id = 1"
    ).fetchone()
    conn.close()
    return dict(row) if row else None   # dict() converts sqlite3.Row safely


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    print("[DB] All tables ready. Launch backend: python server.py")