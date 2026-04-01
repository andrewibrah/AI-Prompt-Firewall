"""
Audit Logger — SQLite-backed decision logging.
==============================================
Every firewall verdict gets logged with full metadata:
- Request ID, timestamp, prompt text (truncated)
- Verdict (allow/block/flag)
- Every detection layer's result
- Confidence scores, matched patterns, categories

Schema is append-only. Designed for the React dashboard to query.
"""

import json
from pathlib import Path

try:
    import aiosqlite
except ImportError:  # pragma: no cover - exercised only in misconfigured runtimes
    aiosqlite = None

from models import FirewallVerdict

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id      TEXT NOT NULL UNIQUE,
    timestamp       TEXT NOT NULL,
    prompt          TEXT NOT NULL,
    prompt_length   INTEGER NOT NULL,
    verdict         TEXT NOT NULL,
    primary_category TEXT NOT NULL,
    highest_confidence REAL NOT NULL,
    blocked_by      TEXT,
    scan_results    TEXT NOT NULL,
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_verdict ON audit_log(verdict);
CREATE INDEX IF NOT EXISTS idx_audit_category ON audit_log(primary_category);
"""

INSERT_SQL = """
INSERT OR IGNORE INTO audit_log
    (request_id, timestamp, prompt, prompt_length, verdict,
     primary_category, highest_confidence, blocked_by, scan_results)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


class AuditLogger:
    """Async SQLite audit logger for all firewall decisions."""

    def __init__(self, db_path: str = "./data/audit.db"):
        self.db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def init_db(self) -> None:
        """Create tables if they don't exist."""
        if aiosqlite is None:
            raise RuntimeError(
                "aiosqlite is not installed in the Python interpreter running the app. "
                "Use '.venv/bin/python -m uvicorn api.server:app --reload --port 8000' "
                "or install project dependencies in that interpreter."
            )
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self.db_path)
        await self._db.executescript(CREATE_TABLE_SQL)
        await self._db.commit()

    async def close(self) -> None:
        if self._db:
            await self._db.close()

    async def log(self, verdict: FirewallVerdict) -> None:
        """Insert a verdict record."""
        if not self._db:
            return

        scan_json = json.dumps(
            [r.model_dump(mode="json") for r in verdict.scan_results],
            default=str,
        )

        await self._db.execute(INSERT_SQL, (
            verdict.request_id,
            verdict.timestamp.isoformat(),
            verdict.prompt[:2000],  # Truncate for storage
            len(verdict.prompt),
            verdict.verdict.value,
            verdict.primary_category.value,
            verdict.highest_confidence,
            verdict.blocked_by.value if verdict.blocked_by else None,
            scan_json,
        ))
        await self._db.commit()

    async def get_recent(self, limit: int = 100) -> list[dict]:
        """Fetch recent audit entries for the dashboard."""
        if not self._db:
            return []
        cursor = await self._db.execute(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        columns = [desc[0] for desc in cursor.description]
        rows = await cursor.fetchall()
        results = []
        for row in rows:
            entry = dict(zip(columns, row))
            entry["scan_results"] = json.loads(entry["scan_results"])
            results.append(entry)
        return results

    async def get_stats(self) -> dict:
        """Aggregated statistics for dashboard widgets."""
        if not self._db:
            return {}

        stats = {}

        # Total counts by verdict
        cursor = await self._db.execute(
            "SELECT verdict, COUNT(*) as count FROM audit_log GROUP BY verdict"
        )
        stats["verdict_counts"] = dict(await cursor.fetchall())

        # Counts by category
        cursor = await self._db.execute(
            "SELECT primary_category, COUNT(*) as count FROM audit_log "
            "WHERE verdict != 'allow' GROUP BY primary_category ORDER BY count DESC"
        )
        stats["category_counts"] = dict(await cursor.fetchall())

        # Counts by detection layer
        cursor = await self._db.execute(
            "SELECT blocked_by, COUNT(*) as count FROM audit_log "
            "WHERE blocked_by IS NOT NULL GROUP BY blocked_by ORDER BY count DESC"
        )
        stats["layer_counts"] = dict(await cursor.fetchall())

        # Average confidence for blocks
        cursor = await self._db.execute(
            "SELECT AVG(highest_confidence) FROM audit_log WHERE verdict = 'block'"
        )
        row = await cursor.fetchone()
        stats["avg_block_confidence"] = round(row[0], 4) if row[0] else 0.0

        # Total requests
        cursor = await self._db.execute("SELECT COUNT(*) FROM audit_log")
        stats["total_requests"] = (await cursor.fetchone())[0]

        # Requests last 24h
        cursor = await self._db.execute(
            "SELECT COUNT(*) FROM audit_log WHERE timestamp > datetime('now', '-1 day')"
        )
        stats["last_24h"] = (await cursor.fetchone())[0]

        # Confidence distribution (for histogram)
        cursor = await self._db.execute(
            "SELECT ROUND(highest_confidence, 1) as bucket, COUNT(*) as count "
            "FROM audit_log WHERE verdict != 'allow' "
            "GROUP BY bucket ORDER BY bucket"
        )
        stats["confidence_distribution"] = dict(await cursor.fetchall())

        # Recent blocks timeline (last 7 days, by hour)
        cursor = await self._db.execute(
            "SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour, COUNT(*) as count "
            "FROM audit_log WHERE verdict = 'block' "
            "AND timestamp > datetime('now', '-7 days') "
            "GROUP BY hour ORDER BY hour"
        )
        stats["block_timeline"] = [
            {"hour": row[0], "count": row[1]} for row in await cursor.fetchall()
        ]

        return stats
