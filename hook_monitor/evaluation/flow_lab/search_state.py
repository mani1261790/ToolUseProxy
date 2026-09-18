"""Private single-controller journal, separate from both runtime and trial DBs."""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import sqlite3

from .models import canonical
from .preflight import LabError


APPLICATION_ID = 0x54555053


class SearchJournal:
    def __init__(self, directory: Path):
        self.directory = directory.absolute()
        if any(p.is_symlink() for p in (self.directory, *self.directory.parents)):
            raise LabError("unsafe_search_storage")
        self.directory.mkdir(mode=0o700, exist_ok=True)
        allowed = {"search.sqlite3", "search.sqlite3-journal", "controller.lock", "trials"}
        if any(p.name not in allowed or p.is_symlink() for p in self.directory.iterdir()):
            raise LabError("unrelated_search_storage")
        self.database = self.directory / "search.sqlite3"
        if self.database.exists() and self.database.stat().st_nlink != 1:
            raise LabError("unsafe_search_storage")
        existed = self.database.exists()
        self.db = sqlite3.connect(self.database, timeout=5, isolation_level=None)
        try:
            if existed and self.db.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID:
                raise LabError("search_schema_mismatch")
            if existed and self.db.execute("PRAGMA user_version").fetchone()[0] != 1:
                raise LabError("search_schema_mismatch")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY, value TEXT)")
            self.db.execute(f"PRAGMA application_id={APPLICATION_ID}")
            self.db.execute("PRAGMA user_version=1")
            os.chmod(self.database, 0o600)
        except BaseException:
            self.db.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.db.close()

    @contextmanager
    def lease(self):
        path = self.directory / "controller.lock"
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            if os.fstat(fd).st_nlink != 1:
                raise LabError("unsafe_search_storage")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise LabError("search_already_running") from None
            yield
        finally:
            os.close(fd)

    def read(self) -> dict | None:
        row = self.db.execute("SELECT value FROM state WHERE id=1").fetchone()
        if row is None:
            return None
        if not isinstance(row[0], str) or len(row[0]) > 1024 * 1024:
            raise LabError("invalid_search_state")
        try:
            value = json.loads(row[0])
        except ValueError:
            raise LabError("invalid_search_state") from None
        if not isinstance(value, dict):
            raise LabError("invalid_search_state")
        return value

    def write(self, value: dict) -> None:
        encoded = canonical(value)
        if len(encoded) > 1024 * 1024:
            raise LabError("search_state_limit")
        self.db.execute("INSERT OR REPLACE INTO state VALUES (1, ?)", (encoded,))

    def storage_size(self) -> int:
        total = 0
        for directory in (self.directory, self.directory / "trials"):
            if not directory.exists():
                continue
            if directory.is_symlink():
                raise LabError("unsafe_search_storage")
            for entry in directory.iterdir():
                if entry.is_symlink():
                    raise LabError("unsafe_search_storage")
                if entry.is_file():
                    total += entry.stat().st_size
        return total
