"""
Resurface SQLite database layer

Lightweight persistence using Python's built-in sqlite3.
No ORM needed — we keep it fast and simple.
"""
import os
import json
import sqlite3
from pathlib import Path
from datetime import datetime
from contextlib import contextmanager

try:
    from loguru import logger
except ImportError:
    import logging as logger


# Default database path (relative to project root)
DEFAULT_DB_PATH = "data/resurface.db"


def _get_db_path(db_path: str = None) -> str:
    """Resolve database path, creating parent dirs if needed."""
    if db_path is None:
        # Walk up from this file to find project root
        project_root = Path(__file__).parent.parent
        db_path = str(project_root / DEFAULT_DB_PATH)
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    return db_path


@contextmanager
def get_connection(db_path: str = None):
    """Context manager for database connections with WAL mode."""
    path = _get_db_path(db_path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ──────────────────────────────────────────────
#  Schema / Init
# ──────────────────────────────────────────────

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS reports (
    id              INTEGER PRIMARY KEY,
    title           TEXT NOT NULL,
    severity        TEXT,
    weakness        TEXT,
    team            TEXT,
    platform        TEXT DEFAULT 'hackerone',
    disclosed_at    TEXT,
    scraped_at      TEXT,
    raw_json        TEXT,
    visibility      TEXT
);

CREATE TABLE IF NOT EXISTS parsed_reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id       INTEGER NOT NULL,
    vuln_type       TEXT,
    target_url      TEXT,
    target_domain   TEXT,
    replay_method   TEXT DEFAULT 'http',
    requires_auth   INTEGER DEFAULT 0,
    confidence      REAL DEFAULT 0.0,
    steps_json      TEXT,
    parsed_at       TEXT,
    FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS replay_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id       INTEGER NOT NULL,
    result          TEXT CHECK(result IN ('vulnerable','fixed','partial','inconclusive','error')),
    confidence      REAL DEFAULT 0.0,
    target_url      TEXT,
    llm_analysis    TEXT,
    evidence_json   TEXT,
    duration_seconds REAL DEFAULT 0.0,
    replayed_at     TEXT,
    FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_parsed_report_id ON parsed_reports(report_id);
CREATE INDEX IF NOT EXISTS idx_results_report_id ON replay_results(report_id);
CREATE INDEX IF NOT EXISTS idx_results_result ON replay_results(result);
CREATE INDEX IF NOT EXISTS idx_reports_severity ON reports(severity);
CREATE INDEX IF NOT EXISTS idx_reports_team ON reports(team);
"""


def init_db(db_path: str = None) -> str:
    """
    Initialize the database schema. Idempotent — safe to call repeatedly.
    Returns the resolved database file path.
    """
    path = _get_db_path(db_path)
    with get_connection(path) as conn:
        conn.executescript(SCHEMA_SQL)
    logger.info(f"Database initialized at {path}")
    return path


# ──────────────────────────────────────────────
#  Reports CRUD
# ──────────────────────────────────────────────

def save_report(report: dict, db_path: str = None) -> int:
    """
    Upsert a scraped report into the reports table.
    Accepts the raw JSON dict as-is from the scraper.
    Returns the report id.
    """
    report_id = report.get("id")
    if not report_id:
        raise ValueError("Report dict must contain an 'id' field")

    title = report.get("title", "Unknown")
    severity = report.get("severity_rating", report.get("severity", ""))
    weakness_obj = report.get("weakness") or {}
    weakness = weakness_obj.get("name", "") if isinstance(weakness_obj, dict) else str(weakness_obj)
    team_obj = report.get("team") or {}
    team = team_obj.get("handle", "") if isinstance(team_obj, dict) else str(team_obj)
    platform = report.get("platform", "hackerone")
    disclosed_at = report.get("disclosed_at", "")
    visibility = report.get("visibility", "")
    raw_json = json.dumps(report, default=str)
    now = datetime.utcnow().isoformat()

    with get_connection(db_path) as conn:
        conn.execute("""
            INSERT INTO reports (id, title, severity, weakness, team, platform,
                                 disclosed_at, scraped_at, raw_json, visibility)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                title=excluded.title,
                severity=excluded.severity,
                weakness=excluded.weakness,
                team=excluded.team,
                platform=excluded.platform,
                disclosed_at=excluded.disclosed_at,
                scraped_at=excluded.scraped_at,
                raw_json=excluded.raw_json,
                visibility=excluded.visibility
        """, (report_id, title, severity, weakness, team, platform,
              disclosed_at, now, raw_json, visibility))
    return report_id


def save_parsed(parsed: dict, db_path: str = None) -> int:
    """
    Save a parsed report. If a parsed entry for the same report_id exists,
    replace it (delete old + insert new).
    Returns the new row id.
    """
    report_id = parsed.get("report_id")
    if not report_id:
        raise ValueError("parsed dict must contain 'report_id'")

    vuln_type = parsed.get("vuln_type", "unknown")
    if hasattr(vuln_type, "value"):
        vuln_type = vuln_type.value
    target_url = parsed.get("target_url", "")
    target_domain = parsed.get("target_domain", "")
    replay_method = parsed.get("replay_method", "http")
    if hasattr(replay_method, "value"):
        replay_method = replay_method.value
    requires_auth = 1 if parsed.get("requires_auth") else 0
    confidence = parsed.get("confidence", 0.0)

    # Serialize steps
    steps = parsed.get("steps", [])
    if steps and hasattr(steps[0], "__dict__"):
        steps = [s.__dict__ if hasattr(s, "__dict__") else s for s in steps]
    steps_json = json.dumps(steps, default=str)

    parsed_at = parsed.get("parsed_at")
    if isinstance(parsed_at, datetime):
        parsed_at = parsed_at.isoformat()
    elif not parsed_at:
        parsed_at = datetime.utcnow().isoformat()

    with get_connection(db_path) as conn:
        # Remove previous parsed entries for this report
        conn.execute("DELETE FROM parsed_reports WHERE report_id = ?", (report_id,))
        cursor = conn.execute("""
            INSERT INTO parsed_reports
                (report_id, vuln_type, target_url, target_domain, replay_method,
                 requires_auth, confidence, steps_json, parsed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (report_id, vuln_type, target_url, target_domain, replay_method,
              requires_auth, confidence, steps_json, parsed_at))
    return cursor.lastrowid


def save_result(result: dict, db_path: str = None) -> int:
    """
    Save a replay result. Allows multiple results per report (different targets/runs).
    Returns the new row id.
    """
    report_id = result.get("report_id")
    if not report_id:
        raise ValueError("result dict must contain 'report_id'")

    status = result.get("result", "error")
    if hasattr(status, "value"):
        status = status.value
    confidence = result.get("confidence", 0.0)
    target_url = result.get("target_url", result.get("target", ""))
    llm_analysis = result.get("llm_analysis", result.get("analysis", ""))

    evidence = result.get("evidence", result.get("evidence_json", []))
    if isinstance(evidence, list) and evidence and hasattr(evidence[0], "__dict__"):
        evidence = [e.__dict__ for e in evidence]
    evidence_json = json.dumps(evidence, default=str) if not isinstance(evidence, str) else evidence

    duration = result.get("duration_seconds", 0.0)
    replayed_at = result.get("replayed_at")
    if isinstance(replayed_at, datetime):
        replayed_at = replayed_at.isoformat()
    elif not replayed_at:
        replayed_at = datetime.utcnow().isoformat()

    with get_connection(db_path) as conn:
        cursor = conn.execute("""
            INSERT INTO replay_results
                (report_id, result, confidence, target_url, llm_analysis,
                 evidence_json, duration_seconds, replayed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (report_id, status, confidence, target_url, llm_analysis,
              evidence_json, duration, replayed_at))
    return cursor.lastrowid


# ──────────────────────────────────────────────
#  Queries
# ──────────────────────────────────────────────

def get_report(report_id: int, db_path: str = None) -> dict | None:
    """Fetch a single report with its parsed info and latest result."""
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
        if not row:
            return None
        report = dict(row)

        parsed = conn.execute(
            "SELECT * FROM parsed_reports WHERE report_id = ? ORDER BY parsed_at DESC LIMIT 1",
            (report_id,)
        ).fetchone()
        report["parsed"] = dict(parsed) if parsed else None

        results = conn.execute(
            "SELECT * FROM replay_results WHERE report_id = ? ORDER BY replayed_at DESC",
            (report_id,)
        ).fetchall()
        report["results"] = [dict(r) for r in results]

    return report


def get_all_reports(db_path: str = None, limit: int = None,
                    severity: str = None, team: str = None) -> list[dict]:
    """Fetch all reports with optional filters."""
    query = "SELECT * FROM reports WHERE 1=1"
    params = []

    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if team:
        query += " AND team = ?"
        params.append(team)

    query += " ORDER BY id DESC"
    if limit:
        query += " LIMIT ?"
        params.append(limit)

    with get_connection(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def get_all_results(db_path: str = None) -> list[dict]:
    """Fetch all replay results joined with report metadata."""
    query = """
        SELECT
            rr.*,
            r.title,
            r.severity,
            r.weakness,
            r.team,
            r.platform,
            pr.vuln_type,
            pr.replay_method,
            pr.requires_auth
        FROM replay_results rr
        JOIN reports r ON rr.report_id = r.id
        LEFT JOIN parsed_reports pr ON rr.report_id = pr.report_id
        ORDER BY rr.replayed_at DESC
    """
    with get_connection(db_path) as conn:
        rows = conn.execute(query).fetchall()
    return [dict(r) for r in rows]


def get_stats(db_path: str = None) -> dict:
    """
    Aggregate statistics across the whole database.
    Returns a dict with counts, breakdowns, and distributions.
    """
    stats = {}
    with get_connection(db_path) as conn:
        # Total reports
        stats["total_reports"] = conn.execute(
            "SELECT COUNT(*) FROM reports"
        ).fetchone()[0]

        # Parsed count
        stats["parsed_count"] = conn.execute(
            "SELECT COUNT(DISTINCT report_id) FROM parsed_reports"
        ).fetchone()[0]

        # Total replays
        stats["total_replays"] = conn.execute(
            "SELECT COUNT(*) FROM replay_results"
        ).fetchone()[0]

        # Result breakdown
        result_rows = conn.execute("""
            SELECT result, COUNT(*) as cnt
            FROM replay_results
            GROUP BY result
            ORDER BY cnt DESC
        """).fetchall()
        stats["result_breakdown"] = {r["result"]: r["cnt"] for r in result_rows}

        # Severity distribution
        sev_rows = conn.execute("""
            SELECT severity, COUNT(*) as cnt
            FROM reports
            WHERE severity IS NOT NULL AND severity != ''
            GROUP BY severity
            ORDER BY cnt DESC
        """).fetchall()
        stats["severity_distribution"] = {r["severity"]: r["cnt"] for r in sev_rows}

        # Vuln type distribution
        vtype_rows = conn.execute("""
            SELECT vuln_type, COUNT(*) as cnt
            FROM parsed_reports
            WHERE vuln_type IS NOT NULL
            GROUP BY vuln_type
            ORDER BY cnt DESC
        """).fetchall()
        stats["vuln_type_distribution"] = {r["vuln_type"]: r["cnt"] for r in vtype_rows}

        # Top programs/teams
        team_rows = conn.execute("""
            SELECT team, COUNT(*) as cnt
            FROM reports
            WHERE team IS NOT NULL AND team != ''
            GROUP BY team
            ORDER BY cnt DESC
            LIMIT 15
        """).fetchall()
        stats["top_teams"] = {r["team"]: r["cnt"] for r in team_rows}

        # Average confidence by result
        conf_rows = conn.execute("""
            SELECT result, AVG(confidence) as avg_conf
            FROM replay_results
            GROUP BY result
        """).fetchall()
        stats["avg_confidence"] = {r["result"]: round(r["avg_conf"], 3) for r in conf_rows}

        # Average replay duration
        dur = conn.execute(
            "SELECT AVG(duration_seconds) FROM replay_results"
        ).fetchone()[0]
        stats["avg_duration_seconds"] = round(dur, 2) if dur else 0.0

    return stats
