"""GitHub synchronization runs outside Hooks; all failures use closed codes."""

from __future__ import annotations

import fcntl
import json
import os
import re
import sqlite3
import subprocess
from pathlib import Path

from hook_monitor.runtime.pilot_issue import parse_proposal, proposal_document, validate_document
from hook_monitor.runtime.pilot_outbox import enqueue_comparisons


class SyncFailure(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class GitHubClient:
    def _run(self, args: list[str], *, data: dict | None = None, ambiguous: bool = False):
        command = ["gh", *args]
        if data is not None:
            command.extend(["--input", "-"])
        try:
            result = subprocess.run(command, input=None if data is None else json.dumps(data),
                                    capture_output=True, text=True, timeout=20, check=False)
        except FileNotFoundError as error:
            raise SyncFailure("missing_cli") from error
        except (OSError, subprocess.TimeoutExpired) as error:
            raise SyncFailure("ambiguous" if ambiguous else "network") from error
        if result.returncode != 0:
            if not ambiguous and "gh auth login" in result.stderr:
                raise SyncFailure("unauthenticated")
            raise SyncFailure("ambiguous" if ambiguous else "network")
        try:
            return json.loads(result.stdout)
        except ValueError as error:
            raise SyncFailure("ambiguous" if ambiguous else "invalid") from error

    def authenticate(self):
        self._run(["api", "user"])

    def _pages(self, endpoint: str):
        rows = []
        separator = "&" if "?" in endpoint else "?"
        for page in range(1, 11):
            result = self._run(["api", f"{endpoint}{separator}per_page=100&page={page}"])
            if not isinstance(result, list) or any(not isinstance(item, dict) for item in result):
                raise SyncFailure("invalid")
            rows.extend(result)
            if len(result) < 100:
                return rows
        # Never assume an issue is absent after a truncated listing.
        raise SyncFailure("invalid")

    def issues(self, repository: str):
        return [item for item in self._pages(f"repos/{repository}/issues?state=all")
                if "pull_request" not in item]

    def comments(self, repository: str, number: int):
        return self._pages(f"repos/{repository}/issues/{number}/comments")

    def create(self, repository: str, title: str, body: str):
        return self._run(["api", "--method", "POST", f"repos/{repository}/issues"],
                         data={"title": title, "body": body}, ambiguous=True)

    def reopen(self, repository: str, number: int):
        return self._run(["api", "--method", "PATCH", f"repos/{repository}/issues/{number}"],
                         data={"state": "open"})

    def comment(self, repository: str, number: int, body: str):
        return self._run(["api", "--method", "POST", f"repos/{repository}/issues/{number}/comments"],
                         data={"body": body}, ambiguous=True)


def _number(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 1_000_000_000:
        raise SyncFailure("invalid")
    return value


def sync_pending(path: Path, *, repository: str, client=None, limit: int = 20) -> dict:
    if not isinstance(repository, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", repository
    ):
        raise SyncFailure("unconfigured")
    if not 1 <= limit <= 100:
        raise ValueError("sync limit must be between 1 and 100")
    client = client or GitHubClient()
    lock_path = path.parent / (path.name + ".pilot-sync.lock")
    descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"status": "busy", "sent": 0}
        enqueue_comparisons(path)
        with sqlite3.connect(path.resolve().as_uri() + "?mode=rw", uri=True, timeout=1) as conn:
            conn.row_factory = sqlite3.Row
            pending = conn.execute("SELECT * FROM pilot_issue_outbox WHERE state = 'pending' "
                                   "ORDER BY rowid LIMIT ?", (limit,)).fetchall()
        if not pending:
            return {"status": "ok", "sent": 0}
        try:
            client.authenticate()
            issues = client.issues(repository)
        except SyncFailure as error:
            _set_error(path, [row["delivery_key"] for row in pending], error.code)
            return {"status": "pending", "sent": 0, "error": error.code}
        sent = 0
        for row in pending:
            try:
                item = parse_proposal(json.loads(row["proposal_json"]))
                if item.delivery_key != row["delivery_key"] or item.problem_key != row["problem_key"]:
                    raise SyncFailure("invalid")
                title, body = proposal_document(item)
                validate_document(item, title=title, body=body)
                with sqlite3.connect(path) as conn:
                    binding = conn.execute("SELECT repository, issue_number FROM pilot_issue_bindings "
                                           "WHERE problem_key = ?", (item.problem_key,)).fetchone()
                if binding is not None and binding[0] != repository:
                    raise SyncFailure("unconfigured")
                problem_marker = f"<!-- tooluseproxy-problem:{item.problem_key} -->"
                delivery_marker = f"<!-- tooluseproxy-delivery:{item.delivery_key} -->"
                matches = [issue for issue in issues if problem_marker in (issue.get("body") or "")]
                if len(matches) > 1:
                    raise SyncFailure("ambiguous")
                if matches:
                    issue = matches[0]
                    number = _number(issue.get("number"))
                    if binding is not None and binding[1] != number:
                        raise SyncFailure("ambiguous")
                    comments = client.comments(repository, number)
                    delivered = delivery_marker in (issue.get("body") or "") or any(
                        delivery_marker in (comment.get("body") or "") for comment in comments)
                    if not delivered:
                        if row["last_error"] == "ambiguous":
                            # The previous write may still be completing. Only
                            # reconcile; never repeat an uncertain POST.
                            continue
                        if issue.get("state") == "closed":
                            client.reopen(repository, number)
                            issue["state"] = "open"
                        _set_error(path, [row["delivery_key"]], "ambiguous")
                        client.comment(repository, number, body)
                else:
                    if binding is not None:
                        raise SyncFailure("ambiguous")
                    if row["last_error"] == "ambiguous":
                        continue
                    _set_error(path, [row["delivery_key"]], "ambiguous")
                    issue = client.create(repository, title, body)
                    number = _number(issue.get("number"))
                    issues.append({"number": number, "state": "open", "body": body})
                with sqlite3.connect(path) as conn:
                    binding = conn.execute("SELECT repository, issue_number FROM pilot_issue_bindings "
                                           "WHERE problem_key = ?", (item.problem_key,)).fetchone()
                    if binding is not None and binding != (repository, number):
                        raise SyncFailure("ambiguous")
                    conn.execute("INSERT OR IGNORE INTO pilot_issue_bindings VALUES (?,?,?)",
                                 (item.problem_key, repository, number))
                    conn.execute("UPDATE pilot_issue_outbox SET state='sent', issue_number=?, last_error=NULL "
                                 "WHERE delivery_key=?", (number, item.delivery_key))
                sent += 1
            except SyncFailure as error:
                _set_error(path, [row["delivery_key"]], error.code)
            except (ValueError, TypeError, KeyError):
                _set_error(path, [row["delivery_key"]], "invalid")
        with sqlite3.connect(path) as conn:
            remaining = conn.execute("SELECT COUNT(*) FROM pilot_issue_outbox WHERE state='pending'").fetchone()[0]
        return {"status": "pending" if remaining else "ok", "sent": sent, "remaining": remaining}


def _set_error(path: Path, keys: list[str], code: str) -> None:
    with sqlite3.connect(path) as conn:
        # Preserve uncertain-write state until remote reconciliation succeeds.
        conn.executemany("UPDATE pilot_issue_outbox SET last_error = CASE WHEN last_error = 'ambiguous' "
                         "THEN last_error ELSE ? END WHERE delivery_key = ?", ((code, key) for key in keys))
