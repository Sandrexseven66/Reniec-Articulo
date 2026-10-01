import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import settings


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def connect():
    connection = sqlite3.connect(settings.database_path)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def init_db() -> None:
    with connect() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            credential_id TEXT UNIQUE NOT NULL,
            payload TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            signature TEXT NOT NULL,
            qr_payload TEXT NOT NULL,
            qr_version INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'VALID',
            issued_at TEXT NOT NULL,
            expires_at TEXT
        );
        CREATE TABLE IF NOT EXISTS verification_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            verification_id TEXT UNIQUE NOT NULL,
            credential_id TEXT,
            result TEXT NOT NULL,
            signature_valid INTEGER NOT NULL,
            integrity_valid INTEGER NOT NULL,
            offline INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            synced INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS revocations (
            credential_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            reason TEXT,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS experiments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scenario TEXT NOT NULL,
            attack TEXT NOT NULL,
            result TEXT NOT NULL,
            execution_time REAL NOT NULL,
            metrics TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        ''' )


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row else None


def json_value(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
