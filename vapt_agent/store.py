"""SQLite persistence for `Assessment` objects across process restarts (FS-1).

Before this, `api.ASSESSMENTS` was a plain in-memory dict: the audit log and raw tool outputs
already survived a restart (append-only file, per-assessment `raw/` directory on disk), but the
assessment index itself -- plan, findings, approvals, events -- did not. This closes that gap
without introducing a new service dependency: one file, `data/assessments.db`, written with the
stdlib's `sqlite3`, mirroring how `accounts.py` already persists accounts.

Design choice: store each assessment as one row holding its full JSON serialization (Pydantic's
own `model_dump_json`), not a normalized relational schema. An Assessment's shape (nested plan
steps, findings, approvals, events) changes as the project grows, and a single JSON blob round-
trips through `Assessment.model_validate_json` with zero migration code -- the schema IS the
Pydantic model, which is already the single source of truth everywhere else in this codebase.
The tradeoff (no server-side SQL queries over individual fields) is fine at this scale: the API
layer already does all its filtering in Python over the in-memory dict, same as before.
"""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from .models import Assessment, now


class AssessmentStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS assessments ("
            " id TEXT PRIMARY KEY,"
            " created_at TEXT NOT NULL,"
            " updated_at TEXT NOT NULL,"
            " data TEXT NOT NULL"
            ")"
        )
        self._conn.commit()

    def save(self, a: Assessment) -> None:
        """Insert or fully overwrite -- an Assessment is never partially updated; the API layer
        always has the whole in-memory object and just re-saves it after each mutation."""
        data = a.model_dump_json()
        with self._lock:
            self._conn.execute(
                "INSERT INTO assessments (id, created_at, updated_at, data) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET updated_at = excluded.updated_at, data = excluded.data",
                (a.id, a.created, now(), data),
            )
            self._conn.commit()

    def load_all(self) -> dict[str, Assessment]:
        """Called once at startup to repopulate the in-memory index. Oldest first, so iteration
        order after a restart matches the order assessments were originally created in."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT data FROM assessments ORDER BY created_at ASC"
            ).fetchall()
        out: dict[str, Assessment] = {}
        for (data,) in rows:
            a = Assessment.model_validate_json(data)
            out[a.id] = a
        return out

    def delete(self, assessment_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM assessments WHERE id = ?", (assessment_id,))
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
