"""Optional PostgreSQL event journal for authenticated GUI activity."""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

log = logging.getLogger("vedette.activity")


class ActivityJournal:
    def __init__(self, dsn: str | None):
        self.dsn = dsn or ""

    @property
    def enabled(self):
        return bool(self.dsn)

    def _connect(self):
        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError("Install psycopg[binary] to enable PostgreSQL activity tracking") from exc
        return psycopg.connect(self.dsn)

    def initialize(self):
        if not self.enabled:
            return
        with self._connect() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS vedette_activity (
                id BIGSERIAL PRIMARY KEY,
                occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                actor TEXT NOT NULL DEFAULT 'unknown',
                action TEXT NOT NULL,
                resource TEXT NOT NULL DEFAULT '',
                status INTEGER,
                details JSONB NOT NULL DEFAULT '{}'::jsonb
            )""")
            conn.execute("CREATE INDEX IF NOT EXISTS vedette_activity_time_idx ON vedette_activity (occurred_at DESC)")

    def record(self, actor, action, resource="", status=None, details=None):
        if not self.enabled:
            return
        try:
            with self._connect() as conn:
                conn.execute("INSERT INTO vedette_activity (actor, action, resource, status, details) VALUES (%s,%s,%s,%s,%s::jsonb)",
                             (actor or "unknown", action, resource, status,
                              json.dumps(details or {})))
        except Exception:
            log.exception("Could not write PostgreSQL activity event")

    def recent(self, limit=100):
        if not self.enabled:
            return []
        with self._connect() as conn:
            rows = conn.execute("SELECT id, occurred_at, actor, action, resource, status, details FROM vedette_activity ORDER BY id DESC LIMIT %s", (limit,)).fetchall()
        return [{"id": r[0], "occurred_at": r[1].astimezone(timezone.utc).isoformat(),
                 "actor": r[2], "action": r[3], "resource": r[4],
                 "status": r[5], "details": r[6]} for r in rows]


def from_environment():
    return ActivityJournal(os.environ.get("DATABASE_URL") or os.environ.get("VEDETTE_DATABASE_URL"))
