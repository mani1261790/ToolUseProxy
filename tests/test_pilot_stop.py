from __future__ import annotations

import hashlib
import json
import io
import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from hook_monitor.runtime.parser import normalize_event
from hook_monitor.runtime.pilot_coverage import read_task_coverage
from hook_monitor.runtime.pilot_stop import compare_on_stop, list_comparisons
from hook_monitor.runtime.pilot_storage import store_pilot_observation
from hook_monitor.runtime.storage import EventStore
from hook_monitor.runtime.runner import run_hook
from hook_monitor.runtime.workspace import resolve_workspace
from tests import test_pilot_aggregate as fixtures


class PilotStopTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "events.db"
        EventStore(self.path).initialize()
        self.event = normalize_event("stop", {"session_id": "synthetic-session",
                                    "turn_id": "one", "cwd": str(self.root)},
                                     workspace_root=str(self.root))

    def add(self, project, start, end):
        for index in range(start, end):
            item = fixtures.PilotAggregateTest()._observation(project, index)
            store_pilot_observation(self.path, replace(
                item, event_ref_sha256=hashlib.sha256(item.observation_id.encode()).hexdigest(),
                detector_version="pilot-v1-" + "a" * 48))

    def compare(self):
        return compare_on_stop(self.path, event=self.event, codex_home=self.root / "codex")

    def test_initial_and_subsequent_rounds_skip_low_use_and_retries(self):
        self.add(1, 0, 20)
        self.add(2, 0, 19)
        self.add(3, 0, 1)
        self.assertEqual((), self.compare())
        self.add(2, 19, 20)
        self.assertEqual(1, len(self.compare()))
        self.assertEqual((), self.compare())
        self.add(1, 20, 40)
        self.assertEqual((), self.compare())
        self.add(2, 20, 40)
        self.assertEqual(1, len(self.compare()))
        reports = list_comparisons(self.path)
        self.assertEqual([1, 2], [item["report"]["comparison"]["round"] for item in reports])
        self.assertNotIn(str(self.root), json.dumps(reports))
        self.assertNotIn("ws_v1_", json.dumps(reports))

    def test_simultaneous_stops_do_not_duplicate(self):
        self.add(1, 0, 20)
        self.add(2, 0, 20)
        def attempt(_):
            try:
                return self.compare()
            except sqlite3.OperationalError as error:
                # Stop deliberately does not wait indefinitely for another
                # writer. Its next invocation retries the still-unclaimed round.
                self.assertEqual(sqlite3.SQLITE_BUSY, error.sqlite_errorcode)
                return ()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, range(2)))
        results.append(self.compare())
        self.assertEqual(1, sum(map(len, results)))
        self.assertEqual(1, len(list_comparisons(self.path)))

    def test_real_stop_path_and_comparison_failure_leave_hook_output_unchanged(self):
        EventStore(self.path).register_workspace(resolve_workspace(str(self.root), str(self.root)))
        self.add(1, 0, 20)
        self.add(2, 0, 20)
        payload = {"session_id": "session", "turn_id": "stop-1", "cwd": str(self.root)}
        def invoke():
            stdin = type("Input", (), {"buffer": io.BytesIO(json.dumps(payload).encode())})()
            with patch("sys.stdin", stdin), patch("sys.stdout", new_callable=io.StringIO) as output, \
                 patch("sys.stderr", new_callable=io.StringIO) as error, \
                 patch.dict(os.environ, {"TOOLUSEPROXY_PILOT_RECORDING": "1",
                                          "TOOLUSEPROXY_PILOT_ISSUE_SYNC": "0",
                                          "TOOLUSEPROXY_STOP_POLICY": "0",
                                          "TOOLUSEPROXY_WORKSPACE_ROOT": str(self.root)}):
                code = run_hook("stop", db_path=self.path, allow_schema_migration=False)
            return code, output.getvalue(), error.getvalue()
        self.assertEqual((0, "", ""), invoke())
        self.assertEqual(1, len(list_comparisons(self.path)))
        with patch("hook_monitor.runtime.pilot_stop.compare_on_stop",
                   side_effect=sqlite3.OperationalError("artificial failure")):
            failed = invoke()
        self.assertEqual((0, ""), failed[:2])
        self.assertIn("比較を完了できません", failed[2])

    def test_project_aliases_do_not_shift_when_another_project_arrives(self):
        self.add(2, 0, 20)
        self.add(3, 0, 20)
        self.compare()
        before = list_comparisons(self.path)[0]
        self.add(1, 0, 40)
        self.add(2, 20, 40)
        self.add(3, 20, 40)
        self.compare()
        after = list_comparisons(self.path)
        self.assertEqual(before, after[0])
        self.assertEqual(3, after[1]["report"]["comparison"]["project_count"])
        with sqlite3.connect(self.path) as conn:
            self.assertEqual("ws_v1_2" + "0" * 63, conn.execute(
                "SELECT workspace_id FROM pilot_project_aliases WHERE alias_number = 1").fetchone()[0])

    def test_failed_comparison_rolls_back_position_and_retries(self):
        self.add(1, 0, 20)
        self.add(2, 0, 20)
        with patch("hook_monitor.runtime.pilot_stop.build_pilot_comparisons",
                   side_effect=ValueError("artificial comparison failure")):
            with self.assertRaises(ValueError):
                self.compare()
        with sqlite3.connect(self.path) as conn:
            self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM pilot_comparisons").fetchone()[0])
            self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM pilot_coverage_snapshots").fetchone()[0])
        self.assertEqual(1, len(self.compare()))

    def test_schema_nine_migration_keeps_feedback_data(self):
        self.add(1, 0, 20)
        with sqlite3.connect(self.path) as conn:
            for name in ("pilot_comparisons", "pilot_project_aliases", "pilot_coverage_snapshots"):
                conn.execute(f"DROP TABLE {name}")
            conn.execute("PRAGMA user_version = 9")
        EventStore(self.path).initialize()
        self.add(2, 0, 20)
        self.assertEqual(1, len(self.compare()))


class PilotCoverageTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "codex"
        (self.home / "sessions").mkdir(parents=True)
        self.path = self.home / "sessions" / "synthetic.jsonl"
        self.records = [{"type": "session_meta", "payload": {"id": "session", "cwd": str(self.root)}}]

    def read(self, *, hashes=None):
        self.path.write_text("\n".join(json.dumps(item) for item in self.records) + "\n")
        return read_task_coverage(self.path, session_id="session", workspace_root=self.root,
                                  codex_home=self.home, hook_call_hashes=hashes or set())

    def test_only_types_counts_and_unknowns_survive(self):
        for name, identifier in (("functions.exec_command", "one"), ("functions.write_stdin", "two")):
            self.records.append({"type": "response_item", "payload": {
                "type": "function_call", "name": name, "call_id": identifier,
                "arguments": "synthetic-private-input-do-not-copy",}})
        self.records.append({"type": "response_item", "payload": {
            "type": "web_search_call", "id": "three", "action": {"query": "private-query"}}})
        result = self.read(hashes={hashlib.sha256(b"one").hexdigest()})
        self.assertEqual("known", result["status"])
        self.assertEqual(3, result["observed_calls"])
        self.assertEqual(2, result["hook_unmatched"])
        self.assertEqual(1, result["unmatched_by_family"]["continuation"])
        self.assertEqual(1, result["unmatched_by_family"]["hosted"])
        serialized = json.dumps(result)
        for excluded in ("private", "session", str(self.root), "arguments", "call_id"):
            self.assertNotIn(excluded, serialized)

    def test_other_project_or_unparsed_nested_tools_are_unknown(self):
        self.records[0]["payload"]["cwd"] = "/synthetic-other-project"
        self.assertEqual("unknown", self.read()["status"])
        self.records[0]["payload"]["cwd"] = str(self.root)
        self.records.append({"type": "response_item", "payload": {
            "type": "custom_tool_call", "name": "exec", "call_id": "nested", "input": "private code"}})
        result = self.read()
        self.assertEqual("unsupported", result["reason"])
        self.assertIsNone(result["observed_calls"])

    def test_missing_and_oversized_input_are_not_zero(self):
        result = read_task_coverage(None, session_id="session", workspace_root=self.root,
                                   codex_home=self.home, hook_call_hashes=set())
        self.assertIsNone(result["observed_calls"])
        self.records.append({"type": "response_item", "payload": {"type": "message", "text": "x" * 140000}})
        self.assertEqual("limit", self.read()["reason"])
