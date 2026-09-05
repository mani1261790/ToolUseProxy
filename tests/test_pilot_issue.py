from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
import tempfile
import unittest
import os
import fcntl
import io
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

from hook_monitor.runtime.pilot_models import ProblemSymptom, ToolFamily
from hook_monitor.runtime.pilot_issue import proposals_for_comparison, proposal_document, validate_document
from hook_monitor.runtime.pilot_outbox import (
    enqueue_comparisons, start_pending_worker, configure_sync, sync_configuration,
)
from hook_monitor.runtime.storage import EventStore
from tooluseproxy.pilot_worker import SyncFailure, sync_pending
from tooluseproxy.cli import main
from hook_monitor.runtime.workspace import resolve_workspace


class FakeGitHub:
    def __init__(self):
        self.items, self.replies = [], {}
        self.creates, self.posts, self.reopens = 0, 0, 0
        self.auth_error = None
        self.uncertain = False
        self.effect = True

    def authenticate(self):
        if self.auth_error:
            raise SyncFailure(self.auth_error)

    def issues(self, repository):
        return copy.deepcopy(self.items)

    def comments(self, repository, number):
        return copy.deepcopy(self.replies.get(number, []))

    def create(self, repository, title, body):
        self.creates += 1
        item = {"number": len(self.items) + 1, "state": "open", "body": body, "title": title}
        if self.effect:
            self.items.append(item)
        if self.uncertain:
            raise SyncFailure("ambiguous")
        return copy.deepcopy(item)

    def reopen(self, repository, number):
        self.reopens += 1
        self.items[number - 1]["state"] = "open"

    def comment(self, repository, number, body):
        self.posts += 1
        self.replies.setdefault(number, []).append({"body": body})
        if self.uncertain:
            raise SyncFailure("ambiguous")


class PilotIssueTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "events.db"
        EventStore(self.path).initialize()
        self.client = FakeGitHub()
        symptoms = {str(item): 0 for item in ProblemSymptom}
        symptoms["miss_candidate"] = 1
        self.report = {
            "comparison": {"detector_version": "pilot-v1-" + "a" * 48,
                           "observation_count": 40, "project_count": 2},
            "problem_groups": [{"cause": "unidentified", "reason_code": "public_flow_absent",
                                "tool_family": "shell", "problem_count": 1,
                                "project_count": 1, "symptom": symptoms}],
            "coverage": {"unknown_task_count": 0, "projects_without_task_records": 0,
                         "unmatched_by_family": {str(item): 0 for item in ToolFamily}},
            "limitations": {"recording_gap_count_unknown": False},
        }

    def add_comparison(self, index):
        identifier = hashlib.sha256(str(index).encode()).hexdigest()
        with sqlite3.connect(self.path) as conn:
            conn.execute("INSERT INTO pilot_comparisons VALUES (?,?,?,?,?)", (
                identifier, self.report["comparison"]["detector_version"], index,
                json.dumps(self.report), "2026-09-05T00:00:00Z"))
        return identifier

    def sync(self):
        return sync_pending(self.path, repository="synthetic/product", client=self.client)

    def test_template_rejects_changed_body_and_arbitrary_versions(self):
        item = proposals_for_comparison("a" * 64, self.report)[0]
        title, body = proposal_document(item)
        validate_document(item, title=title, body=body)
        for extra in ("/private/project", "https://private.invalid", "private project name"):
            with self.assertRaises(ValueError):
                validate_document(item, title=title, body=body + extra)
        self.report["comparison"]["detector_version"] = "private-project"
        with self.assertRaises(ValueError):
            proposals_for_comparison("a" * 64, self.report)

    def test_create_append_reopen_and_replay(self):
        self.add_comparison(1)
        self.assertEqual(1, enqueue_comparisons(self.path))
        self.assertEqual(0, enqueue_comparisons(self.path))
        self.assertEqual(1, self.sync()["sent"])
        self.assertEqual(0, self.sync()["sent"])
        self.add_comparison(2)
        self.client.items[0]["state"] = "closed"
        self.assertEqual(1, self.sync()["sent"])
        self.assertEqual((1, 1, 1), (self.client.creates, self.client.posts, self.client.reopens))
        self.report["problem_groups"][0]["cause"] = "externality"
        self.add_comparison(3)
        self.assertEqual(1, self.sync()["sent"])
        self.assertEqual(2, self.client.creates)

    def test_uncertain_success_is_reconciled_without_duplicate_post(self):
        self.add_comparison(1)
        self.client.uncertain = True
        self.assertEqual("pending", self.sync()["status"])
        self.client.uncertain = False
        self.assertEqual(1, self.sync()["sent"])
        self.assertEqual(1, self.client.creates)
        self.add_comparison(2)
        self.client.uncertain = True
        self.assertEqual("pending", self.sync()["status"])
        self.client.uncertain = False
        self.assertEqual(1, self.sync()["sent"])
        self.assertEqual(1, self.client.posts)

    def test_uncertain_absence_is_not_reposted_blindly(self):
        self.add_comparison(1)
        self.client.uncertain, self.client.effect = True, False
        self.sync()
        self.client.uncertain, self.client.effect = False, True
        self.assertEqual("pending", self.sync()["status"])
        self.assertEqual(1, self.client.creates)

    def test_missing_auth_preserves_pending_and_later_retries(self):
        self.add_comparison(1)
        self.client.auth_error = "unauthenticated"
        self.assertEqual("unauthenticated", self.sync()["error"])
        self.assertEqual(0, self.client.creates)
        self.client.auth_error = None
        self.assertEqual(1, self.sync()["sent"])

    def test_unknown_coverage_and_recording_gaps_also_make_proposals(self):
        self.report["coverage"]["unknown_task_count"] = 1
        self.report["limitations"]["recording_gap_count_unknown"] = True
        items = proposals_for_comparison("a" * 64, self.report)
        self.assertEqual({"detection", "coverage", "recording_gap"}, {item.kind for item in items})
        for item in items:
            self.assertNotIn(str(self.path.parent), proposal_document(item)[1])

    def test_automatic_worker_is_opt_in_and_does_not_wait(self):
        self.add_comparison(1)
        enqueue_comparisons(self.path)
        environment = {"TOOLUSEPROXY_PILOT_ISSUE_SYNC": "0",
                       "TOOLUSEPROXY_PILOT_ISSUE_REPOSITORY": "synthetic/product"}
        with patch.dict(os.environ, environment), patch("subprocess.Popen") as process:
            self.assertFalse(start_pending_worker(self.path, workspace_root=self.path.parent))
            process.assert_not_called()
        environment["TOOLUSEPROXY_PILOT_ISSUE_SYNC"] = "1"
        with patch.dict(os.environ, environment), patch("subprocess.Popen") as process:
            self.assertTrue(start_pending_worker(self.path, workspace_root=self.path.parent))
            self.assertTrue(process.call_args.kwargs["start_new_session"])
            process.return_value.wait.assert_not_called()
            process.return_value.communicate.assert_not_called()

    def test_simultaneous_worker_is_skipped_without_remote_write(self):
        self.add_comparison(1)
        lock = self.path.parent / (self.path.name + ".pilot-sync.lock")
        with lock.open("w") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual("busy", self.sync()["status"])
        self.assertEqual(0, self.client.creates)
        self.assertEqual(1, self.sync()["sent"])

    def test_existing_binding_cannot_be_redirected_to_another_repository(self):
        self.add_comparison(1)
        self.sync()
        self.add_comparison(2)
        result = sync_pending(self.path, repository="different/product", client=self.client)
        self.assertEqual("pending", result["status"])
        self.assertEqual(0, self.client.posts)
        self.assertEqual(1, self.client.creates)

    def test_invalid_comparison_is_skipped_without_stalling_other_proposals(self):
        self.report["comparison"]["detector_version"] = "private-project"
        bad = self.add_comparison(1)
        self.report["comparison"]["detector_version"] = "pilot-v1-" + "a" * 48
        self.add_comparison(2)
        self.assertEqual(1, self.sync()["sent"])
        with sqlite3.connect(self.path) as conn:
            self.assertEqual("rejected", conn.execute("SELECT state FROM pilot_issue_preparations "
                                                      "WHERE comparison_id=?", (bad,)).fetchone()[0])
        self.assertNotIn("private-project", self.client.items[0]["body"])

    def test_schema_ten_upgrade_preserves_comparisons(self):
        self.add_comparison(1)
        with sqlite3.connect(self.path) as conn:
            for name in ("pilot_issue_outbox", "pilot_issue_bindings", "pilot_issue_preparations", "pilot_issue_config"):
                conn.execute(f"DROP TABLE {name}")
            conn.execute("PRAGMA user_version = 10")
        EventStore(self.path).initialize()
        self.assertEqual(1, self.sync()["sent"])

    def test_cli_sync_and_outbox_use_only_the_fake_transport(self):
        root = self.path.parent
        EventStore(self.path).register_workspace(resolve_workspace(str(root), str(root)))
        self.add_comparison(1)
        with patch("tooluseproxy.pilot_worker.GitHubClient", return_value=self.client), \
             patch("sys.stdout", new_callable=io.StringIO) as output:
            status = main(["pilot", "sync", "--repository", "synthetic/product",
                           "--db", str(self.path), "--workspace", str(root)])
        self.assertEqual(0, status)
        self.assertNotIn(str(root), output.getvalue())
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            status = main(["pilot", "outbox", "--db", str(self.path), "--workspace", str(root)])
        self.assertEqual(0, status)
        result = json.loads(output.getvalue())
        self.assertEqual("sent", result["outbox"][0]["state"])
        self.assertEqual(1, result["preparations"]["prepared"])

    def test_sync_setting_persists_without_desktop_environment_variables(self):
        environment = {key: value for key, value in os.environ.items()
                       if key not in {"TOOLUSEPROXY_PILOT_ISSUE_SYNC", "TOOLUSEPROXY_PILOT_ISSUE_REPOSITORY"}}
        with patch.dict(os.environ, environment, clear=True):
            self.assertEqual(("", False), sync_configuration(self.path))
            configure_sync(self.path, repository="synthetic/product", enabled=True)
            self.assertEqual(("synthetic/product", True), sync_configuration(self.path))
            configure_sync(self.path, repository="synthetic/product", enabled=False)
            self.assertEqual(("synthetic/product", False), sync_configuration(self.path))

    def test_source_entrypoint_starts_worker_from_unrelated_directory_without_network(self):
        root = self.path.parent
        EventStore(self.path).register_workspace(resolve_workspace(str(root), str(root)))
        # Empty outbox returns before authentication or network access.
        environment = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
        entrypoint = Path(__file__).resolve().parents[1] / "tooluseproxy_plugin.py"
        result = subprocess.run([sys.executable, str(entrypoint), "pilot", "sync",
                                 "--db", str(self.path), "--workspace", str(root),
                                 "--repository", "synthetic/product"],
                                cwd=root, env=environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(0, json.loads(result.stdout)["sent"])
