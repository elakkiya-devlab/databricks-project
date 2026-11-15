import hashlib
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from backend.models.asset import utcnow


class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS assets(id TEXT PRIMARY KEY, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS actions(id TEXT PRIMARY KEY, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS overlays(id TEXT PRIMARY KEY, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS audits(id INTEGER PRIMARY KEY, body TEXT NOT NULL,
                    previous_hash TEXT NOT NULL, hash TEXT NOT NULL);
            """)

    @contextmanager
    def connect(self, write=True):
        connection = sqlite3.connect(self.path, timeout=30)
        try:
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def event(self, actor, operation, target="", outcome="ok", connection=None):
        if connection is None:
            with self.connect() as opened:
                return self.event(actor, operation, target, outcome, opened)
        previous = connection.execute("SELECT hash FROM audits ORDER BY id DESC LIMIT 1").fetchone()
        previous = previous[0] if previous else "0" * 64
        body = json.dumps(dict(at=utcnow().isoformat(), actor=actor, operation=operation,
                               target=target, outcome=outcome), sort_keys=True)
        digest = hashlib.sha256((previous + body).encode()).hexdigest()
        connection.execute("INSERT INTO audits(body,previous_hash,hash) VALUES(?,?,?)", (body, previous, digest))

    def rows(self, table):
        if table not in {"assets", "runs", "actions", "overlays", "audits"}:
            raise ValueError("Invalid table")
        with self.connect(write=False) as connection:
            return [json.loads(row[0]) for row in connection.execute(f"SELECT body FROM {table} ORDER BY rowid")]

    def get(self, table, identity):
        if table not in {"assets", "actions"}:
            raise ValueError("Invalid table")
        with self.connect(write=False) as connection:
            row = connection.execute(f"SELECT body FROM {table} WHERE id=?", (identity,)).fetchone()
            if not row:
                raise KeyError(identity)
            return json.loads(row[0])

    def verify_audit(self):
        with self.connect(write=False) as connection:
            previous = "0" * 64
            for body, claimed_previous, digest in connection.execute(
                    "SELECT body,previous_hash,hash FROM audits ORDER BY id"):
                if claimed_previous != previous or hashlib.sha256((previous + body).encode()).hexdigest() != digest:
                    return False
                previous = digest
        return True