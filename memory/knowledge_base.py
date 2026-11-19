"""Long-term memory: one SQLite file shared by every user of the app.

* recommendations - fixes produced by the model (or imported), with engineer feedback
* topic_labels    - OS / application labels decided by the model or a person

A liked or unrated recommendation is reused for the same finding on the same OS,
so the model is only called once per unique finding. A disliked one is never reused.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import pandas as pd

import settings

_SCHEMA = """
CREATE TABLE IF NOT EXISTS recommendations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    check_type    TEXT NOT NULL,
    finding_key   TEXT NOT NULL,
    os_family     TEXT NOT NULL DEFAULT '',
    application   TEXT NOT NULL DEFAULT '',
    content       TEXT NOT NULL,
    model         TEXT NOT NULL DEFAULT '',
    source        TEXT NOT NULL DEFAULT 'model',
    feedback      TEXT,
    feedback_note TEXT,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rec_lookup ON recommendations (check_type, finding_key, os_family);
CREATE TABLE IF NOT EXISTS topic_labels (
    title      TEXT PRIMARY KEY,
    topic      TEXT NOT NULL,
    source     TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class KnowledgeBase:
    def __init__(self, path: Path | None = None):
        self.path = Path(path or settings.KB_FILE)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript(_SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        finally:
            db.close()

    # ---- recommendations --------------------------------------------------------
    def find_recommendation(self, check_type: str, finding_key: str, os_family: str = "") -> dict[str, Any] | None:
        """Newest reusable answer for this finding: liked first, never a disliked one."""
        with self._connect() as db:
            row = db.execute(
                """SELECT * FROM recommendations
                   WHERE check_type = ? AND finding_key = ? AND os_family = ?
                     AND (feedback IS NULL OR feedback != 'dislike')
                   ORDER BY (feedback = 'like') DESC, id DESC LIMIT 1""",
                (check_type, finding_key, os_family),
            ).fetchone()
        return self._row(row) if row else None

    def save_recommendation(self, check_type: str, finding_key: str, os_family: str, application: str,
                            content: dict[str, Any], model: str, source: str = "model") -> int:
        with self._connect() as db:
            cursor = db.execute(
                """INSERT INTO recommendations
                   (check_type, finding_key, os_family, application, content, model, source, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (check_type, finding_key, os_family, application, json.dumps(content, ensure_ascii=False),
                 model, source, _now()),
            )
            return int(cursor.lastrowid)

    def set_feedback(self, recommendation_id: int, feedback: str | None, note: str = "") -> None:
        with self._connect() as db:
            db.execute("UPDATE recommendations SET feedback = ?, feedback_note = ? WHERE id = ?",
                       (feedback, note, recommendation_id))

    def recommendations(self) -> pd.DataFrame:
        with self._connect() as db:
            return pd.read_sql_query(
                """SELECT id, check_type, finding_key, os_family, application, model, source, feedback, created_at
                   FROM recommendations ORDER BY id DESC""", db)

    @staticmethod
    def _row(row: sqlite3.Row) -> dict[str, Any]:
        record = dict(row)
        record["content"] = json.loads(record["content"])
        return record

    # ---- topic labels -----------------------------------------------------------
    def topic_labels(self) -> dict[str, str]:
        with self._connect() as db:
            return {row["title"]: row["topic"] for row in db.execute("SELECT title, topic FROM topic_labels")}

    def save_topic_labels(self, labels: dict[str, str], source: str) -> None:
        with self._connect() as db:
            db.executemany(
                "INSERT OR REPLACE INTO topic_labels (title, topic, source, created_at) VALUES (?, ?, ?, ?)",
                [(title, topic, source, _now()) for title, topic in labels.items()],
            )

    # ---- migration from the old per-application CSV files -------------------------
    def import_legacy_csv(self, csv_path: Path) -> int:
        """Import an old '<application>_KB.csv' file. Returns the number of new rows."""
        application = csv_path.stem.removesuffix("_KB")
        frame = pd.read_csv(csv_path)
        added = 0
        for _, row in frame.iterrows():
            title = str(row.get("Title", "")).strip()
            if not title or self.find_recommendation("vulnerability", title, ""):
                continue
            content = {"summary": f"Imported from the previous knowledge base ({csv_path.name}).",
                       "steps": [{"title": "Recommended solution", "detail": str(row.get("Recommended Solution", "")),
                                  "commands": []}]}
            record_id = self.save_recommendation("vulnerability", title, "", application, content, "", "legacy import")
            feedback = str(row.get("Feedback", "")).strip().lower()
            if feedback in ("like", "dislike"):
                self.set_feedback(record_id, feedback)
            added += 1
        return added
