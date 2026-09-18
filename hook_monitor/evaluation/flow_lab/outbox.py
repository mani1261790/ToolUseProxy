"""Durable synthetic-only outbox. Unknown writes are reconciled, never retried."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
import fcntl
import json
import os
from pathlib import Path
import re
import sqlite3

from tooluseproxy.pilot_worker import GitHubClient, SyncFailure
from .models import canonical
from .preflight import LabError
from .proposal import document, parse_proposal

APPLICATION_ID = 0x5455504F


def number(value):
    if type(value) is not int or not 1 <= value <= 1000000000:
        raise SyncFailure('invalid')
    return value


def marker_present(value, marker):
    return isinstance(value, str) and marker in value.splitlines()


class Outbox:
    def __init__(self, directory: Path, repository: str):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', repository):
            raise LabError('invalid_issue_repository')
        self.directory = directory.absolute()
        if any(p.is_symlink() for p in (self.directory, *self.directory.parents)):
            raise LabError('unsafe_issue_outbox')
        self.directory.mkdir(mode=0o700, exist_ok=True)
        allowed = {'outbox.sqlite3', 'outbox.sqlite3-journal', 'sync.lock'}
        if any(p.name not in allowed or p.is_symlink() or p.stat().st_nlink != 1
               for p in self.directory.iterdir()):
            raise LabError('unrelated_issue_outbox')
        path = self.directory / 'outbox.sqlite3'
        existed = path.exists()
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.repository = repository
        try:
            if existed and (self.db.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID
                            or self.db.execute('PRAGMA user_version').fetchone()[0] != 1):
                raise LabError('issue_outbox_schema_mismatch')
            self.db.executescript('''
                PRAGMA synchronous=FULL;
                CREATE TABLE IF NOT EXISTS destination(id INTEGER PRIMARY KEY CHECK(id=1), repository TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS proposals(
                    delivery TEXT PRIMARY KEY, problem TEXT NOT NULL, payload TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending','in_flight','sent','rejected')),
                    issue INTEGER, error TEXT);
                CREATE TABLE IF NOT EXISTS bindings(problem TEXT PRIMARY KEY, issue INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS scan_cursor(id INTEGER PRIMARY KEY CHECK(id=1), position INTEGER NOT NULL);
                INSERT OR IGNORE INTO scan_cursor VALUES (1,0);
            ''')
            self.db.execute(f'PRAGMA application_id={APPLICATION_ID}')
            self.db.execute('PRAGMA user_version=1')
            self.db.execute('INSERT OR IGNORE INTO destination VALUES (1,?)', (repository,))
            row = self.db.execute('SELECT repository FROM destination WHERE id=1').fetchone()
            if row and row[0] != repository:
                raise LabError('issue_destination_mismatch')
            os.chmod(path, 0o600)
        except BaseException:
            self.db.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.db.close()

    @contextmanager
    def lease(self):
        fd = os.open(self.directory / 'sync.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            if os.fstat(fd).st_nlink != 1:
                raise LabError('unsafe_issue_outbox')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise LabError('issue_sync_busy') from None
            yield
        finally:
            os.close(fd)

    def enqueue(self, item):
        document(item)
        payload = canonical(asdict(item))
        row = self.db.execute('SELECT payload FROM proposals WHERE delivery=?', (item.delivery_key,)).fetchone()
        if row and row[0] != payload:
            raise LabError('immutable_issue_proposal')
        return self.db.execute('INSERT OR IGNORE INTO proposals VALUES (?,?,?,\'pending\',NULL,NULL)',
                               (item.delivery_key, item.problem_key, payload)).rowcount

    def bind(self, problem, issue):
        from .proposal import checked_hex
        checked_hex(problem)
        number(issue)
        with self.lease():
            self._bind(problem, issue)

    def _bind(self, problem, issue):
        previous = self.db.execute('SELECT issue FROM bindings WHERE problem=?', (problem,)).fetchone()
        if previous and previous[0] != issue:
            raise SyncFailure('ambiguous')
        self.db.execute('INSERT OR IGNORE INTO bindings VALUES (?,?)', (problem, issue))

    def summary(self):
        return {row[0]: row[1] for row in self.db.execute('SELECT state,count(*) FROM proposals GROUP BY state')}

    def report(self, sent=0, error=None):
        states = self.summary()
        result = {'status': 'pending' if any(k != 'sent' and v for k, v in states.items()) else 'ok',
                  'sent': sent, 'states': states}
        if error:
            result['error'] = error
        return result

    def sync(self, *, client=None, limit=20):
        if type(limit) is not int or not 1 <= limit <= 20:
            raise LabError('invalid_issue_sync_limit')
        client = client or GitHubClient()
        sent = 0
        with self.lease():
            cursor = self.db.execute('SELECT position FROM scan_cursor WHERE id=1').fetchone()[0]
            rows = self.db.execute(
                "SELECT rowid AS queue_id,* FROM proposals WHERE state IN ('pending','in_flight') "
                "ORDER BY CASE WHEN rowid>? THEN 0 ELSE 1 END,rowid LIMIT ?", (cursor, limit)
            ).fetchall()
            if rows:
                # A permanently unknown write must not starve unrelated later problems.
                self.db.execute('UPDATE scan_cursor SET position=? WHERE id=1', (rows[-1]['queue_id'],))
            if not rows:
                return self.report()
            try:
                client.authenticate()
                issues = client.issues(self.repository)
            except SyncFailure as exc:
                return self.report(error=exc.code)
            for row in rows:
                try:
                    item = parse_proposal(json.loads(row['payload']))
                    title, body = document(item)
                    if row['delivery'] != item.delivery_key or row['problem'] != item.problem_key:
                        raise LabError('invalid_synthetic_proposal')
                    problem_marker = f'<!-- tooluseproxy-lab-problem:{item.problem_key} -->'
                    delivery_marker = f'<!-- tooluseproxy-lab-delivery:{item.delivery_key} -->'
                    matches = [i for i in issues if marker_present(i.get('body'), problem_marker)]
                    bound = self.db.execute('SELECT issue FROM bindings WHERE problem=?', (item.problem_key,)).fetchone()
                    if bound:
                        if any(number(i.get('number')) != bound[0] for i in matches):
                            raise SyncFailure('ambiguous')
                        matches = [i for i in issues if i.get('number') == bound[0]]
                        if not matches:
                            raise SyncFailure('ambiguous')
                    if len(matches) > 1:
                        raise SyncFailure('ambiguous')
                    issue = matches[0] if matches else None
                    delivered = False
                    if issue:
                        issue_number = number(issue.get('number'))
                        comments = client.comments(self.repository, issue_number)
                        delivered = marker_present(issue.get('body'), delivery_marker) or any(
                            marker_present(c.get('body'), delivery_marker) for c in comments)
                    if not delivered:
                        if row['state'] == 'in_flight' or self.db.execute(
                            "SELECT 1 FROM proposals WHERE problem=? AND state='in_flight'", (item.problem_key,)
                        ).fetchone():
                            continue
                        # Durable intent precedes POST, including timeouts and process interruption.
                        self.db.execute("UPDATE proposals SET state='in_flight',error=NULL WHERE delivery=?", (item.delivery_key,))
                        if issue:
                            response = client.comment(self.repository, issue_number, body)
                            if not isinstance(response, dict):
                                raise SyncFailure('ambiguous')
                            if type(response.get('id')) is not int or not 1 <= response['id'] < 2**63:
                                raise SyncFailure('ambiguous')
                        else:
                            response = client.create(self.repository, title, body)
                            if not isinstance(response, dict):
                                raise SyncFailure('ambiguous')
                            issue_number = number(response.get('number'))
                            issues.append(response)
                        if not marker_present(response.get('body'), delivery_marker):
                            raise SyncFailure('ambiguous')
                    self.db.execute('BEGIN IMMEDIATE')
                    try:
                        self._bind(item.problem_key, issue_number)
                        self.db.execute("UPDATE proposals SET state='sent',issue=?,error=NULL WHERE delivery=?", (issue_number, item.delivery_key))
                        self.db.execute('COMMIT')
                    except BaseException:
                        self.db.execute('ROLLBACK')
                        raise
                    sent += 1
                except (LabError, ValueError, TypeError, KeyError):
                    self.db.execute("UPDATE proposals SET state=CASE WHEN state='in_flight' THEN state ELSE 'rejected' END,error='invalid' WHERE delivery=?", (row['delivery'],))
                except SyncFailure as exc:
                    code = exc.code if exc.code in {'ambiguous','invalid','network','unauthenticated','missing_cli'} else 'invalid'
                    self.db.execute('UPDATE proposals SET error=? WHERE delivery=?', (code, row['delivery']))
        return self.report(sent)
