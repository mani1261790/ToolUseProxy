from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from hook_monitor.analysis.source_index import load_sources_and_chunks
from hook_monitor.analysis.adapters.registry import run_adapters
from hook_monitor.analysis.graph import (
    build_artifact_flow_edges,
    build_source_binding_edges,
)
from hook_monitor.runtime.ids import make_event_id, make_source_chunk_id
from hook_monitor.runtime.models import (
    FlowEdge,
    LineageAssignment,
    ProtectedSource,
    ResourceSnapshot,
    SourceChunk,
    StoredPolicyDecision,
)
from hook_monitor.runtime.operations import extract_tool_operations
from hook_monitor.runtime.parser import build_artifacts, build_fragments, normalize_event
from hook_monitor.runtime.source_config import load_protected_sources
from hook_monitor.runtime.storage import EventStore
from hook_monitor.runtime.workspace import make_workspace_id, resolve_workspace


class WorkspaceIdentityTest(unittest.TestCase):
    def test_runtime_derived_tables_require_workspace_primary_keys(self) -> None:
        expected = {
            "information_flow_edges": ("workspace_id", "edge_id"),
            "information_flow_edge_scopes": (
                "workspace_id",
                "session_id",
                "edge_id",
            ),
            "resource_versions": ("workspace_id", "node_id"),
            "sink_candidates": ("workspace_id", "node_id"),
            "analysis_cursors": ("workspace_id", "session_id"),
            "fragment_shingles": (
                "workspace_id",
                "session_id",
                "fragment_id",
                "shingle",
            ),
            "fragment_exact_index": (
                "workspace_id",
                "session_id",
                "fragment_id",
            ),
            "runtime_lineage_state": (
                "workspace_id",
                "session_id",
                "source_node_kind",
                "source_node_id",
                "node_kind",
                "node_id",
            ),
            "runtime_source_binding_edges": (
                "workspace_id",
                "session_id",
                "edge_id",
            ),
            "workspace_analysis_state": ("workspace_id", "key"),
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            db_path = Path(temporary_directory) / "events.db"
            EventStore(db_path).initialize()
            with sqlite3.connect(db_path) as connection:
                for table, expected_key in expected.items():
                    with self.subTest(table=table):
                        rows = connection.execute(
                            f"PRAGMA table_info({table})"
                        ).fetchall()
                        actual_key = tuple(
                            row[1]
                            for row in sorted(
                                (row for row in rows if row[5]),
                                key=lambda row: row[5],
                            )
                        )
                        workspace_column = next(
                            row for row in rows if row[1] == "workspace_id"
                        )
                        self.assertEqual(expected_key, actual_key)
                        self.assertEqual(1, workspace_column[3])

    def test_cwd_identity_is_stable_across_lexical_variants(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "workspace"
            root.mkdir()

            direct = resolve_workspace(str(root))
            dotted = resolve_workspace(f"{root}/.")

        self.assertTrue(direct.ready)
        self.assertEqual(direct, dotted)
        self.assertTrue(direct.workspace_id.startswith("ws_v1_"))
        self.assertEqual(
            make_workspace_id(direct.canonical_root or ""),
            direct.workspace_id,
        )

    def test_parent_symlink_alias_has_same_identity_but_root_symlink_is_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            real_parent = base / "real"
            workspace = real_parent / "workspace"
            workspace.mkdir(parents=True)
            parent_alias = base / "parent-alias"
            parent_alias.symlink_to(real_parent, target_is_directory=True)
            root_alias = base / "root-alias"
            root_alias.symlink_to(workspace, target_is_directory=True)

            direct = resolve_workspace(str(workspace))
            through_parent_alias = resolve_workspace(
                str(parent_alias / "workspace")
            )
            through_root_alias = resolve_workspace(str(root_alias))

        self.assertTrue(direct.ready)
        self.assertEqual(direct.workspace_id, through_parent_alias.workspace_id)
        self.assertEqual(direct.canonical_root, through_parent_alias.canonical_root)
        self.assertEqual("workspace_root_symlink", through_root_alias.status)
        self.assertIsNone(through_root_alias.workspace_id)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin case alias behavior")
    def test_case_alias_has_same_physical_identity(self) -> None:
        canonical = Path(__file__).resolve().parents[1]
        alias = Path(str(canonical).swapcase())
        if not alias.exists() or alias.stat() != canonical.stat():
            self.skipTest("workspace filesystem is case-sensitive")

        direct = resolve_workspace(str(canonical))
        through_case_alias = resolve_workspace(str(alias))

        self.assertEqual(direct.workspace_id, through_case_alias.workspace_id)
        self.assertEqual(direct.canonical_root, through_case_alias.canonical_root)

    def test_explicit_root_tracks_nested_cwd_and_rejects_outside_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            root = base / "workspace"
            nested = root / "packages" / "app"
            outside = base / "outside"
            nested.mkdir(parents=True)
            outside.mkdir()

            resolved = resolve_workspace(str(nested), str(root))
            rejected = resolve_workspace(str(outside), str(root))

        self.assertTrue(resolved.ready)
        self.assertEqual(str(root.resolve()), resolved.canonical_root)
        self.assertEqual(str(nested.resolve()), resolved.execution_cwd)
        self.assertEqual("configured_root", resolved.discovered_by)
        self.assertEqual("execution_cwd_outside_workspace", rejected.status)
        self.assertIsNone(rejected.workspace_id)

    def test_invalid_explicit_root_never_falls_back_to_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cwd = Path(temporary_directory)
            empty = resolve_workspace(str(cwd), "")
            relative = resolve_workspace(str(cwd), "relative/root")
            missing = resolve_workspace(str(cwd), str(cwd / "missing"))

        self.assertEqual("workspace_root_empty", empty.status)
        self.assertEqual("workspace_root_not_absolute", relative.status)
        self.assertEqual("workspace_root_path_missing", missing.status)
        self.assertTrue(
            all(
                workspace.workspace_id is None
                for workspace in (empty, relative, missing)
            )
        )

    def test_invalid_cwd_and_root_errors_are_unresolved_without_raising(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            regular_file = base / "file.txt"
            regular_file.write_text("not a directory", encoding="utf-8")

            cases = (
                (resolve_workspace(None), "execution_cwd_missing"),
                (resolve_workspace("relative"), "workspace_root_not_absolute"),
                (
                    resolve_workspace(str(regular_file)),
                    "workspace_root_not_directory",
                ),
                (
                    resolve_workspace(f"{base}/embedded\0nul"),
                    "workspace_root_io_error",
                ),
            )

        for workspace, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(expected, workspace.status)
                self.assertIsNone(workspace.workspace_id)

    def test_event_id_is_salted_by_explicit_workspace_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "workspace"
            nested = root / "nested"
            nested.mkdir(parents=True)
            payload = {
                "session_id": "session-workspace",
                "turn_id": "turn-workspace",
                "tool_use_id": "tool-workspace",
                "tool_name": "Bash",
                "cwd": str(nested),
                "tool_input": {"command": "printf ok"},
            }

            root_scoped = normalize_event(
                "pre_tool_use",
                payload,
                workspace_root=str(root),
            )
            nested_scoped = normalize_event(
                "pre_tool_use",
                payload,
                workspace_root=str(nested),
            )
            repeated = normalize_event(
                "pre_tool_use",
                payload,
                workspace_root=f"{root}/.",
            )
            default_scoped = normalize_event("pre_tool_use", payload)

        self.assertNotEqual(root_scoped.workspace_id, nested_scoped.workspace_id)
        self.assertNotEqual(root_scoped.event_id, nested_scoped.event_id)
        self.assertEqual(root_scoped.event_id, repeated.event_id)
        self.assertEqual(
            root_scoped.workspace_id,
            root_scoped.workspace_namespace_id,
        )
        self.assertEqual(
            make_event_id("pre_tool_use", payload),
            default_scoped.event_id,
        )

    def test_invalid_configured_roots_have_stable_distinct_namespaces(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cwd = Path(temporary_directory) / "cwd"
            cwd.mkdir()
            payload = {
                "session_id": "session-invalid-root",
                "turn_id": "turn-invalid-root",
                "tool_use_id": "tool-invalid-root",
                "tool_name": "Bash",
                "cwd": str(cwd),
                "tool_input": {"command": "printf ok"},
            }
            unset = normalize_event("pre_tool_use", payload)
            empty = normalize_event("pre_tool_use", payload, workspace_root="")
            missing_a = normalize_event(
                "pre_tool_use",
                payload,
                workspace_root=str(cwd / "missing-a"),
            )
            repeated_a = normalize_event(
                "pre_tool_use",
                payload,
                workspace_root=str(cwd / "missing-a"),
            )
            missing_b = normalize_event(
                "pre_tool_use",
                payload,
                workspace_root=str(cwd / "missing-b"),
            )

        self.assertIsNone(unset.workspace_namespace_id)
        self.assertEqual(missing_a.workspace_namespace_id, repeated_a.workspace_namespace_id)
        self.assertEqual(missing_a.event_id, repeated_a.event_id)
        self.assertEqual(4, len({unset.event_id, empty.event_id, missing_a.event_id, missing_b.event_id}))
        self.assertTrue((empty.workspace_namespace_id or "").startswith("ws_cfg_v1_"))
        self.assertNotEqual(missing_a.workspace_namespace_id, missing_b.workspace_namespace_id)

    def test_runner_uses_configured_workspace_root_for_nested_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "workspace"
            nested = root / "packages" / "app"
            nested.mkdir(parents=True)
            db_path = Path(temporary_directory) / "events.db"
            EventStore(db_path).initialize()
            EventStore(db_path).register_workspace(resolve_workspace(str(root)))
            payload = {
                "session_id": "session-runner-workspace",
                "turn_id": "turn-runner-workspace",
                "tool_use_id": "tool-runner-workspace",
                "tool_name": "Bash",
                "cwd": str(nested),
                "tool_input": {"command": "printf ok"},
            }
            environment = os.environ.copy()
            environment.update(
                {
                    "TOOLUSEPROXY_DB_PATH": str(db_path),
                    "TOOLUSEPROXY_PRE_TOOL_POLICY": "0",
                    "TOOLUSEPROXY_WORKSPACE_ROOT": str(root),
                }
            )

            result = subprocess.run(
                [sys.executable, str(Path(__file__).resolve().parents[1] / "hooks" / "monitor_pre_tool.py")],
                input=json.dumps(payload),
                text=True,
                capture_output=True,
                cwd=nested,
                env=environment,
                check=False,
            )
            with sqlite3.connect(db_path) as connection:
                row = connection.execute(
                    """
                    SELECT
                        workspace_id,
                        workspace_root,
                        workspace_execution_cwd,
                        workspace_status,
                        workspace_source,
                        workspace_namespace_id
                    FROM events
                    """
                ).fetchone()

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(make_workspace_id(str(root.resolve())), row[0])
        self.assertEqual(str(root.resolve()), row[1])
        self.assertEqual(str(nested.resolve()), row[2])
        self.assertEqual("ready", row[3])
        self.assertEqual("configured_root", row[4])
        self.assertEqual(row[0], row[5])

    def test_global_root_variable_does_not_enable_an_unconfigured_project(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cwd = Path(temporary_directory) / "cwd"
            cwd.mkdir()
            missing_root = Path(temporary_directory) / "missing-root"
            db_path = Path(temporary_directory) / "events.db"
            EventStore(db_path).initialize()
            command = """*** Begin Patch
*** Add File: target.txt
+content
*** End Patch"""
            base_payload = {
                "session_id": "session-unresolved-runner",
                "turn_id": "turn-unresolved-runner",
                "tool_use_id": "tool-unresolved-runner",
                "tool_name": "apply_patch",
                "cwd": str(cwd),
                "tool_input": {"command": command},
            }
            environment = os.environ.copy()
            environment.update(
                {
                    "TOOLUSEPROXY_DB_PATH": str(db_path),
                    "TOOLUSEPROXY_WORKSPACE_ROOT": str(missing_root),
                }
            )
            hook_root = Path(__file__).resolve().parents[1] / "hooks"
            pre = subprocess.run(
                [sys.executable, str(hook_root / "monitor_pre_tool.py")],
                input=json.dumps(base_payload),
                text=True,
                capture_output=True,
                cwd=cwd,
                env=environment,
                check=False,
            )
            post = subprocess.run(
                [sys.executable, str(hook_root / "monitor_post_tool.py")],
                input=json.dumps(
                    {
                        **base_payload,
                        "tool_response": {"exit_code": 0},
                    }
                ),
                text=True,
                capture_output=True,
                cwd=cwd,
                env=environment,
                check=False,
            )
            with sqlite3.connect(db_path) as connection:
                event_rows = connection.execute(
                    """
                    SELECT workspace_status, workspace_namespace_id, payload_json
                    FROM events
                    ORDER BY sequence_no
                    """
                ).fetchall()
                operation = connection.execute(
                    "SELECT outcome, outcome_evidence FROM tool_operations"
                ).fetchone()
                outcome_count = connection.execute(
                    "SELECT COUNT(*) FROM tool_operation_outcomes"
                ).fetchone()[0]
                snapshot_count = connection.execute(
                    "SELECT COUNT(*) FROM resource_snapshots"
                ).fetchone()[0]

        self.assertEqual(0, pre.returncode, pre.stderr)
        self.assertEqual(0, post.returncode, post.stderr)
        self.assertEqual("", pre.stdout)
        self.assertEqual("", post.stdout)
        self.assertEqual([], event_rows)
        self.assertIsNone(operation)
        self.assertEqual(0, outcome_count)
        self.assertEqual(0, snapshot_count)

    def test_record_persists_workspace_and_rejects_forged_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "workspace"
            root.mkdir()
            store = EventStore(Path(temporary_directory) / "events.db")
            store.initialize()
            event = normalize_event(
                "pre_tool_use",
                {
                    "session_id": "session-record",
                    "turn_id": "turn-record",
                    "tool_use_id": "tool-record",
                    "tool_name": "Bash",
                    "cwd": str(root),
                    "tool_input": {"command": "printf ok"},
                },
            )
            artifacts = build_artifacts(event)
            store.record(event, artifacts, build_fragments(artifacts))

            stored = store.get_event_workspace_context(event.event_id)
            with sqlite3.connect(store.db_path) as connection:
                workspace_count = connection.execute(
                    "SELECT COUNT(*) FROM workspaces"
                ).fetchone()[0]
                raw_payload = connection.execute(
                    "SELECT payload_json FROM events WHERE event_id = ?",
                    (event.event_id,),
                ).fetchone()[0]

            forged_workspace_id = "ws_v1_bad"
            forged = replace(
                event,
                event_id=make_event_id(
                    event.phase,
                    event.raw_payload,
                    workspace_namespace_id=None,
                ),
                workspace_id=forged_workspace_id,
            )
            with self.assertRaisesRegex(ValueError, "workspace id"):
                store.record(forged, artifacts, build_fragments(artifacts))

            mismatched_context = replace(
                event,
                workspace_lexical_root=str(root.parent),
            )
            with self.assertRaisesRegex(ValueError, "filesystem state"):
                store.record(
                    mismatched_context,
                    artifacts,
                    build_fragments(artifacts),
                )

            with sqlite3.connect(store.db_path) as connection:
                event_count_after_rejections = connection.execute(
                    "SELECT COUNT(*) FROM events"
                ).fetchone()[0]

        self.assertTrue(stored.ready)
        self.assertEqual(event.workspace_id, stored.workspace_id)
        self.assertEqual(1, workspace_count)
        self.assertEqual(event.raw_payload, json.loads(raw_payload))
        self.assertEqual(1, event_count_after_rejections)

    def test_same_session_and_tool_use_in_two_roots_do_not_replace_events(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            roots = (base / "workspace-a", base / "workspace-b")
            for root in roots:
                root.mkdir()
            store = EventStore(base / "events.db")
            store.initialize()
            events = []
            for root in roots:
                event = normalize_event(
                    "pre_tool_use",
                    {
                        "session_id": "shared-session",
                        "turn_id": "shared-turn",
                        "tool_use_id": "shared-tool-use",
                        "tool_name": "Bash",
                        "cwd": str(root),
                        "tool_input": {"command": "printf ok"},
                    },
                )
                artifacts = build_artifacts(event)
                store.record(event, artifacts, build_fragments(artifacts))
                events.append(event)
            with sqlite3.connect(store.db_path) as connection:
                event_count = connection.execute(
                    "SELECT COUNT(*) FROM events"
                ).fetchone()[0]
                workspace_count = connection.execute(
                    "SELECT COUNT(*) FROM workspaces"
                ).fetchone()[0]

        self.assertNotEqual(events[0].workspace_id, events[1].workspace_id)
        self.assertNotEqual(events[0].event_id, events[1].event_id)
        self.assertEqual(2, event_count)
        self.assertEqual(2, workspace_count)

    def test_unresolved_event_is_recorded_without_workspace_registry_row(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = EventStore(Path(temporary_directory) / "events.db")
            store.initialize()
            event = normalize_event(
                "stop",
                {
                    "session_id": "session-unresolved",
                    "turn_id": "turn-unresolved",
                    "cwd": str(Path(temporary_directory) / "missing"),
                    "last_assistant_message": "safe response",
                },
            )
            artifacts = build_artifacts(event)
            store.record(event, artifacts, build_fragments(artifacts))

            stored = store.get_event_workspace_context(event.event_id)
            with sqlite3.connect(store.db_path) as connection:
                workspace_count = connection.execute(
                    "SELECT COUNT(*) FROM workspaces"
                ).fetchone()[0]

        self.assertEqual("workspace_root_path_missing", stored.status)
        self.assertIsNone(stored.workspace_id)
        self.assertEqual(0, workspace_count)

    def test_legacy_event_workspace_backfill_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "legacy-workspace"
            root.mkdir()
            db_path = Path(temporary_directory) / "events.db"
            with sqlite3.connect(db_path) as connection:
                connection.execute(
                    """
                    CREATE TABLE events (
                        event_id TEXT PRIMARY KEY,
                        phase TEXT NOT NULL,
                        session_id TEXT,
                        turn_id TEXT,
                        tool_use_id TEXT,
                        tool_name TEXT,
                        cwd TEXT,
                        model TEXT,
                        permission_mode TEXT,
                        transcript_path TEXT,
                        payload_json TEXT NOT NULL,
                        recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                connection.execute(
                    """
                    INSERT INTO events (
                        event_id,
                        phase,
                        session_id,
                        cwd,
                        payload_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "legacy-event",
                        "pre_tool_use",
                        "legacy-session",
                        str(root),
                        "{}",
                    ),
                )

            store = EventStore(db_path)
            store.initialize()
            first = store.get_event_workspace_context("legacy-event")
            store.initialize()
            second = store.get_event_workspace_context("legacy-event")
            with sqlite3.connect(db_path) as connection:
                workspace_count = connection.execute(
                    "SELECT COUNT(*) FROM workspaces"
                ).fetchone()[0]
                marker_count = connection.execute(
                    """
                    SELECT COUNT(*) FROM analysis_state
                    WHERE key = 'migration.workspace_identity.v1'
                    """
                ).fetchone()[0]
                indexes = {
                    row[1]
                    for row in connection.execute("PRAGMA index_list(events)")
                }

        self.assertTrue(first.ready)
        self.assertEqual("legacy_cwd", first.discovered_by)
        self.assertEqual(first, second)
        self.assertEqual(1, workspace_count)
        self.assertEqual(1, marker_count)
        self.assertIn("idx_events_workspace_session_sequence", indexes)

    def test_initialize_backfills_legacy_row_inserted_after_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "legacy-workspace"
            root.mkdir()
            db_path = Path(temporary_directory) / "events.db"
            store = EventStore(db_path)
            store.initialize()
            with sqlite3.connect(db_path) as connection:
                connection.execute(
                    """
                    INSERT INTO events (
                        event_id,
                        phase,
                        session_id,
                        cwd,
                        payload_json,
                        sequence_no
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "late-legacy-event",
                        "pre_tool_use",
                        "legacy-session",
                        str(root),
                        "{}",
                        1,
                    ),
                )

            store.initialize()
            workspace = store.get_event_workspace_context("late-legacy-event")

        self.assertTrue(workspace.ready)
        self.assertEqual("legacy_cwd", workspace.discovered_by)

    def test_initialize_serializes_concurrent_first_migration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            db_path = Path(temporary_directory) / "events.db"

            def initialize_store(_: int) -> None:
                EventStore(db_path).initialize()

            with ThreadPoolExecutor(max_workers=8) as executor:
                list(executor.map(initialize_store, range(8)))

            with sqlite3.connect(db_path) as connection:
                event_columns = [
                    row[1] for row in connection.execute("PRAGMA table_info(events)")
                ]
                marker_count = connection.execute(
                    """
                    SELECT COUNT(*) FROM analysis_state
                    WHERE key = 'migration.workspace_identity.v1'
                    """
                ).fetchone()[0]

        self.assertEqual(len(event_columns), len(set(event_columns)))
        self.assertEqual(1, marker_count)

    def test_workspace_source_catalogs_coexist_and_replace_independently(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            store = EventStore(base / "events.db")
            store.initialize()
            catalogs = {}
            for label in ("a", "b"):
                root = base / f"workspace-{label}"
                root.mkdir()
                (root / "secret.txt").write_text(
                    f"secret {label}",
                    encoding="utf-8",
                )
                (root / "protected_sources.json").write_text(
                    json.dumps(
                        {
                            "sources": [
                                {
                                    "id": "shared-secret",
                                    "path": "secret.txt",
                                    "type": "text",
                                    "sensitivity": "confidential",
                                    "policy_tags": ["no_external"],
                                }
                            ]
                        }
                    ),
                    encoding="utf-8",
                )
                event = normalize_event(
                    "pre_tool_use",
                    {
                        "session_id": f"session-{label}",
                        "tool_use_id": f"tool-{label}",
                        "tool_name": "Read",
                        "cwd": str(root),
                        "tool_input": {"path": "secret.txt"},
                    },
                )
                artifacts = build_artifacts(event)
                store.record(event, artifacts, build_fragments(artifacts))
                assert event.workspace_id is not None
                sources, chunks = load_sources_and_chunks(
                    root,
                    workspace_id=event.workspace_id,
                )
                store.replace_sources_for_workspace(
                    event.workspace_id,
                    sources,
                    chunks,
                )
                catalogs[label] = (event.workspace_id, sources, chunks)

            workspace_a, sources_a, chunks_a = catalogs["a"]
            workspace_b, sources_b, chunks_b = catalogs["b"]

            self.assertNotEqual(sources_a[0].source_id, sources_b[0].source_id)
            self.assertNotEqual(chunks_a[0].chunk_id, chunks_b[0].chunk_id)
            self.assertEqual("shared-secret", sources_a[0].source_key)
            self.assertEqual(sources_a, store.list_protected_sources_for_workspace(workspace_a))
            self.assertEqual(chunks_b, store.list_source_chunks_for_workspace(workspace_b))

            forged_a_chunk = replace(
                chunks_a[0],
                chunk_id=chunks_b[0].chunk_id,
            )
            with self.assertRaisesRegex(ValueError, "chunk id does not match"):
                store.replace_sources_for_workspace(
                    workspace_a,
                    sources_a,
                    [forged_a_chunk],
                )
            self.assertEqual(
                chunks_b,
                store.list_source_chunks_for_workspace(workspace_b),
            )

            forged_legacy_source = replace(
                sources_a[0],
                workspace_id=None,
                source_key=None,
            )
            forged_legacy_chunk = replace(chunks_a[0], workspace_id=None)
            with self.assertRaisesRegex(ValueError, "belongs to a workspace"):
                store.upsert_sources(
                    [forged_legacy_source],
                    [forged_legacy_chunk],
                )
            detached_legacy_chunk = replace(
                chunks_a[0],
                chunk_id="legacy-chunk-with-new-id",
                workspace_id=None,
            )
            with self.assertRaisesRegex(ValueError, "references a workspace"):
                store.upsert_sources([], [detached_legacy_chunk])
            self.assertEqual(
                sources_a,
                store.list_protected_sources_for_workspace(workspace_a),
            )
            self.assertEqual(
                chunks_b,
                store.list_source_chunks_for_workspace(workspace_b),
            )

            store.replace_sources_for_workspace(workspace_a, [], [])

            self.assertEqual([], store.list_protected_sources_for_workspace(workspace_a))
            self.assertEqual(sources_b, store.list_protected_sources_for_workspace(workspace_b))

    def test_workspace_source_catalog_rejects_mismatch_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "workspace"
            root.mkdir()
            (root / "secret.txt").write_text("secret", encoding="utf-8")
            (root / "protected_sources.json").write_text(
                json.dumps(
                    {
                        "sources": [
                            {
                                "id": "secret",
                                "path": "secret.txt",
                                "type": "text",
                                "sensitivity": "confidential",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            store = EventStore(Path(temporary_directory) / "events.db")
            store.initialize()
            event = normalize_event(
                "pre_tool_use",
                {
                    "session_id": "source-catalog-session",
                    "tool_use_id": "source-catalog-tool",
                    "tool_name": "Read",
                    "cwd": str(root),
                    "tool_input": {"path": "secret.txt"},
                },
            )
            artifacts = build_artifacts(event)
            store.record(event, artifacts, build_fragments(artifacts))
            assert event.workspace_id is not None
            sources, chunks = load_sources_and_chunks(
                root,
                workspace_id=event.workspace_id,
            )
            store.replace_sources_for_workspace(event.workspace_id, sources, chunks)
            forged_chunk = replace(
                chunks[0],
                source_id="protected_source_v1_forged",
            )

            with self.assertRaisesRegex(ValueError, "does not belong"):
                store.replace_sources_for_workspace(
                    event.workspace_id,
                    sources,
                    [forged_chunk],
                )
            with self.assertRaisesRegex(ValueError, "workspace does not match"):
                store.replace_sources_for_workspace(
                    "ws_v1_other",
                    sources,
                    chunks,
                )
            outside = root.parent / "outside.txt"
            outside.write_text("outside", encoding="utf-8")
            forged_path = replace(sources[0], path="../outside.txt")
            with self.assertRaisesRegex(ValueError, "inside workspace"):
                store.replace_sources_for_workspace(
                    event.workspace_id,
                    [forged_path],
                    chunks,
                )

            self.assertEqual(
                sources,
                store.list_protected_sources_for_workspace(event.workspace_id),
            )
            self.assertEqual(
                chunks,
                store.list_source_chunks_for_workspace(event.workspace_id),
            )

    def test_legacy_sources_are_not_visible_in_workspace_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = EventStore(Path(temporary_directory) / "events.db")
            store.initialize()
            source = ProtectedSource(
                source_id="legacy-source",
                path="legacy.txt",
                source_type="text",
                sensitivity="confidential",
                policy_tags=(),
            )
            chunk = SourceChunk(
                chunk_id="legacy-source:0:hash",
                source_id=source.source_id,
                ordinal=0,
                text="legacy",
                normalized_text="legacy",
                text_hash="hash",
                shingle_fingerprint="[]",
                token_count=1,
            )
            store.upsert_sources([source], [chunk])

            self.assertEqual([source], store.list_protected_sources())
            self.assertEqual([], store.list_protected_sources_for_workspace("ws_v1_any"))
            self.assertEqual([], store.list_source_chunks_for_workspace("ws_v1_any"))

    def test_legacy_source_schema_is_quarantined_during_migration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            db_path = Path(temporary_directory) / "events.db"
            with sqlite3.connect(db_path) as connection:
                connection.execute(
                    """
                    CREATE TABLE protected_sources (
                        source_id TEXT PRIMARY KEY,
                        path TEXT NOT NULL,
                        source_type TEXT NOT NULL,
                        sensitivity TEXT NOT NULL,
                        policy_tags_json TEXT NOT NULL,
                        recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE source_chunks (
                        chunk_id TEXT PRIMARY KEY,
                        source_id TEXT NOT NULL,
                        ordinal INTEGER NOT NULL,
                        text TEXT NOT NULL,
                        normalized_text TEXT NOT NULL,
                        text_hash TEXT NOT NULL,
                        shingle_fingerprint TEXT NOT NULL,
                        token_count INTEGER NOT NULL,
                        recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                connection.execute(
                    """
                    INSERT INTO protected_sources (
                        source_id,
                        path,
                        source_type,
                        sensitivity,
                        policy_tags_json
                    ) VALUES ('legacy', 'legacy.txt', 'text', 'confidential', '[]')
                    """
                )
                connection.execute(
                    """
                    INSERT INTO source_chunks (
                        chunk_id,
                        source_id,
                        ordinal,
                        text,
                        normalized_text,
                        text_hash,
                        shingle_fingerprint,
                        token_count
                    ) VALUES ('legacy:0:hash', 'legacy', 0, 'legacy', 'legacy', 'hash', '[]', 1)
                    """
                )

            store = EventStore(db_path)
            store.initialize()
            legacy_source = store.list_protected_sources()[0]
            legacy_chunk = store.list_source_chunks()[0]
            scoped_sources = store.list_protected_sources_for_workspace("ws_v1_any")

        self.assertIsNone(legacy_source.workspace_id)
        self.assertIsNone(legacy_source.source_key)
        self.assertIsNone(legacy_chunk.workspace_id)
        self.assertEqual([], scoped_sources)

    def test_legacy_derived_resource_and_sink_rows_are_rebuilt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            db_path = Path(temporary_directory) / "events.db"
            with sqlite3.connect(db_path) as connection:
                connection.execute(
                    """
                    CREATE TABLE resource_versions (
                        node_id TEXT PRIMARY KEY,
                        path TEXT NOT NULL,
                        content_hash TEXT,
                        sequence_no INTEGER NOT NULL,
                        session_id TEXT,
                        origin_tool_use_id TEXT,
                        recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                connection.execute(
                    """
                    INSERT INTO resource_versions (
                        node_id,
                        path,
                        content_hash,
                        sequence_no,
                        session_id,
                        origin_tool_use_id
                    ) VALUES ('legacy-resource', '/legacy.txt', 'hash', 1, 's', 't')
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE sink_candidates (
                        node_id TEXT PRIMARY KEY,
                        sink_type TEXT NOT NULL,
                        label TEXT NOT NULL,
                        tool_name TEXT,
                        tool_use_id TEXT,
                        session_id TEXT,
                        sequence_no INTEGER NOT NULL,
                        metadata_json TEXT NOT NULL,
                        recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                connection.execute(
                    """
                    INSERT INTO sink_candidates (
                        node_id,
                        sink_type,
                        label,
                        tool_name,
                        tool_use_id,
                        session_id,
                        sequence_no,
                        metadata_json
                    ) VALUES (
                        'legacy-sink',
                        'external_search',
                        'Search',
                        'Search',
                        't',
                        's',
                        1,
                        '{}'
                    )
                    """
                )

            store = EventStore(db_path)
            store.initialize()
            resources = store.list_resource_versions()
            sinks = store.list_sink_candidates()

        self.assertEqual([], resources)
        self.assertEqual([], sinks)

    def test_workspace_analysis_schema_repairs_without_losing_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            db_path = Path(temporary_directory) / "events.db"
            store = EventStore(db_path)
            store.initialize()
            run_id = store.start_analysis_run(
                "legacy-audit-v1",
                {"scope": "legacy"},
            )
            edge = FlowEdge(
                edge_id="legacy-source-edge",
                src_node_kind="source_chunk",
                src_node_id="legacy-source:0",
                dst_node_kind="artifact_fragment",
                dst_node_id="legacy-fragment",
                relation="source_similarity",
                evidence_level="content_similarity",
                method="exact_hash",
                score=1.0,
                reason="legacy audit edge",
            )
            store.upsert_source_binding_edges(run_id, [edge])
            store.upsert_lineage_assignments(
                [
                    LineageAssignment(
                        analysis_run_id=run_id,
                        source_node_kind="source_chunk",
                        source_node_id="legacy-source:0",
                        node_kind="artifact_fragment",
                        node_id="legacy-fragment",
                        best_path_score=1.0,
                        predecessor_edge_id=edge.edge_id,
                        hop_count=1,
                    )
                ]
            )
            decision = StoredPolicyDecision(
                decision_id="legacy-decision",
                finding_id="legacy-finding",
                analysis_run_id=run_id,
                hook_event="Stop",
                action="continue_review",
                severity="high",
                sink_type="final_answer",
                source_node_kind="source_chunk",
                source_node_id="legacy-source:0",
                sink_node_id="legacy-sink",
                path_score=1.0,
                reason="legacy reason",
                user_message="legacy message",
                technical_summary="legacy summary",
                trace_command="trace legacy",
                path_summary=("legacy path",),
            )
            store.upsert_policy_decision(decision)
            store.complete_analysis_run(run_id)

            with sqlite3.connect(db_path) as connection:
                connection.execute(
                    """
                    INSERT INTO resource_versions (
                        workspace_id, node_id, path, sequence_no, resource_state
                    ) VALUES ('legacy_unscoped', 'stale-resource', '/stale', 1, 'present')
                    """
                )
                connection.execute("DROP TABLE workspace_analysis_state")
                connection.execute(
                    """
                    CREATE TABLE workspace_analysis_state (
                        workspace_id TEXT NOT NULL,
                        key TEXT NOT NULL,
                        value TEXT NOT NULL,
                        PRIMARY KEY (workspace_id, key)
                    )
                    """
                )

            store.initialize()
            store.initialize()
            with sqlite3.connect(db_path) as connection:
                table_info = connection.execute(
                    "PRAGMA table_info(workspace_analysis_state)"
                ).fetchall()
                primary_key = tuple(
                    row[1]
                    for row in sorted(
                        (row for row in table_info if row[5]),
                        key=lambda row: row[5],
                    )
                )
                workspace_column = next(
                    row for row in table_info if row[1] == "workspace_id"
                )
                marker_count = connection.execute(
                    """
                    SELECT COUNT(*) FROM analysis_state
                    WHERE key = 'migration.workspace_analysis_scope.v1'
                      AND value = 'complete'
                    """
                ).fetchone()[0]

            self.assertEqual(("workspace_id", "key"), primary_key)
            self.assertEqual(1, workspace_column[3])
            self.assertEqual(1, marker_count)
            self.assertEqual([], store.list_resource_versions())
            self.assertEqual(run_id, store.get_analysis_run(run_id).analysis_run_id)
            self.assertEqual([edge], store.list_source_binding_edges(run_id))
            self.assertEqual(
                "legacy-fragment",
                store.list_lineage_assignments(run_id)[0].node_id,
            )
            stored_decision = store.get_policy_decision("legacy-decision")
            assert stored_decision is not None
            self.assertEqual(decision.decision_id, stored_decision.decision_id)
            self.assertEqual(decision.path_summary, stored_decision.path_summary)

    def test_workspace_source_path_cannot_escape_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            root = base / "workspace"
            root.mkdir()
            outside = base / "outside.txt"
            outside.write_text("outside", encoding="utf-8")
            (root / "protected_sources.json").write_text(
                json.dumps(
                    {
                        "sources": [
                            {
                                "id": "outside",
                                "path": "../outside.txt",
                                "type": "text",
                                "sensitivity": "confidential",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "inside workspace"):
                load_sources_and_chunks(root, workspace_id="ws_v1_test")

            (root / "outside-link.txt").symlink_to(outside)
            (root / "protected_sources.json").write_text(
                json.dumps(
                    {
                        "sources": [
                            {
                                "id": "outside-link",
                                "path": "outside-link.txt",
                                "type": "text",
                                "sensitivity": "confidential",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "inside workspace"):
                load_sources_and_chunks(root, workspace_id="ws_v1_test")

    def test_graph_sources_and_sinks_are_partitioned_by_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            store = EventStore(base / "events.db")
            store.initialize()
            query = "workspace scoped secret phrase"
            workspace_ids: dict[str, str] = {}
            for label in ("a", "b"):
                root = base / f"workspace-{label}"
                root.mkdir()
                event = normalize_event(
                    "pre_tool_use",
                    {
                        "session_id": "shared-session",
                        "turn_id": "shared-turn",
                        "tool_use_id": "shared-tool",
                        "tool_name": "Search",
                        "cwd": str(root),
                        "tool_input": {"query": query},
                    },
                )
                artifacts = build_artifacts(event)
                store.record(event, artifacts, build_fragments(artifacts))
                assert event.workspace_id is not None
                workspace_ids[label] = event.workspace_id

            contexts = store.list_artifact_contexts_for_session("shared-session")
            self.assertEqual(
                set(workspace_ids.values()),
                {context.workspace_id for context in contexts},
            )
            self.assertTrue(
                all(context.workspace_status == "ready" for context in contexts)
            )
            self.assertEqual([], build_artifact_flow_edges(contexts))

            adapter_result = run_adapters(contexts, base)
            self.assertEqual(2, len(adapter_result.sinks))
            self.assertEqual(
                set(workspace_ids.values()),
                {sink.workspace_id for sink in adapter_result.sinks},
            )
            self.assertEqual(
                2,
                len({sink.node_id for sink in adapter_result.sinks}),
            )

            source_id = "protected-source-a"
            chunk = SourceChunk(
                chunk_id=make_source_chunk_id(source_id, 0, query),
                source_id=source_id,
                ordinal=0,
                text=query,
                normalized_text=query,
                text_hash=hashlib.sha256(query.encode("utf-8")).hexdigest(),
                shingle_fingerprint="[]",
                token_count=4,
                workspace_id=workspace_ids["a"],
            )
            source_edges = build_source_binding_edges([chunk], contexts)
            context_by_fragment = {
                context.fragment.fragment_id: context for context in contexts
            }
            self.assertTrue(source_edges)
            self.assertEqual(
                {workspace_ids["a"]},
                {
                    context_by_fragment[edge.dst_node_id].workspace_id
                    for edge in source_edges
                },
            )

            sinks = list(adapter_result.sinks)
            for workspace_id in workspace_ids.values():
                workspace_sinks = [
                    sink for sink in sinks if sink.workspace_id == workspace_id
                ]
                store.upsert_sink_candidates(
                    workspace_sinks,
                    workspace_id=workspace_id,
                    session_id="shared-session",
                )
            stored_by_id = {
                sink.node_id: sink for sink in store.list_sink_candidates()
            }
            self.assertEqual(
                {sink.node_id: sink.workspace_id for sink in sinks},
                {
                    node_id: sink.workspace_id
                    for node_id, sink in stored_by_id.items()
                },
            )
            sink_a = next(
                sink for sink in sinks if sink.workspace_id == workspace_ids["a"]
            )
            forged = replace(sink_a, workspace_id=workspace_ids["b"])
            with self.assertRaisesRegex(ValueError, "does not match"):
                store.upsert_sink_candidates(
                    [forged],
                    workspace_id=workspace_ids["a"],
                    session_id="shared-session",
                )
            self.assertEqual(
                sink_a,
                next(
                    sink
                    for sink in store.list_sink_candidates()
                    if sink.node_id == sink_a.node_id
                ),
            )

    def test_filesystem_resources_use_execution_cwd_and_workspace_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            root = base / "workspace"
            nested = root / "packages" / "app"
            outside = base / "outside"
            nested.mkdir(parents=True)
            outside.mkdir()
            store = EventStore(base / "events.db")
            store.initialize()

            def record_write(tool_use_id: str, path: str) -> str:
                event = normalize_event(
                    "pre_tool_use",
                    {
                        "session_id": "filesystem-session",
                        "tool_use_id": tool_use_id,
                        "tool_name": "Write",
                        "cwd": str(nested),
                        "tool_input": {
                            "path": path,
                            "content": "workspace content",
                        },
                    },
                    workspace_root=str(root),
                )
                artifacts = build_artifacts(event)
                store.record(event, artifacts, build_fragments(artifacts))
                return event.event_id

            inside_event_id = record_write("inside-write", "result.txt")
            inside_contexts = [
                context
                for context in store.list_artifact_contexts()
                if context.event_id == inside_event_id
            ]
            result = run_adapters(inside_contexts, root)
            self.assertEqual(1, len(result.resources))
            resource = result.resources[0]
            self.assertEqual(str(nested.resolve() / "result.txt"), resource.path)
            self.assertEqual(inside_contexts[0].workspace_id, resource.workspace_id)

            cloned_contexts = [
                replace(context, workspace_id="ws_v1_other")
                for context in inside_contexts
            ]
            cloned_result = run_adapters(inside_contexts + cloned_contexts, root)
            self.assertEqual(2, len(cloned_result.resources))
            self.assertEqual(
                2,
                len({item.node_id for item in cloned_result.resources}),
            )

            assert resource.workspace_id is not None
            store.upsert_resource_versions(
                [resource],
                workspace_id=resource.workspace_id,
                session_id="filesystem-session",
            )
            forged = replace(resource, workspace_id="ws_v1_other")
            with self.assertRaisesRegex(ValueError, "does not match"):
                store.upsert_resource_versions(
                    [forged],
                    workspace_id=resource.workspace_id,
                    session_id="filesystem-session",
                )
            self.assertEqual(
                resource,
                next(
                    item
                    for item in store.list_resource_versions()
                    if item.node_id == resource.node_id
                ),
            )

            outside_event_id = record_write("outside-write", "../../../escape.txt")
            outside_contexts = [
                context
                for context in store.list_artifact_contexts()
                if context.event_id == outside_event_id
            ]
            self.assertEqual((), run_adapters(outside_contexts, root).resources)

            sibling_event_id = record_write(
                "absolute-sibling-write",
                str(root / "sibling.txt"),
            )
            sibling_contexts = [
                context
                for context in store.list_artifact_contexts()
                if context.event_id == sibling_event_id
            ]
            sibling_result = run_adapters(sibling_contexts, root)
            self.assertEqual(1, len(sibling_result.resources))
            self.assertEqual(
                str(root.resolve() / "sibling.txt"),
                sibling_result.resources[0].path,
            )

            link = nested / "outside-link"
            link.symlink_to(outside, target_is_directory=True)
            symlink_event_id = record_write("symlink-write", "outside-link/leak.txt")
            symlink_contexts = [
                context
                for context in store.list_artifact_contexts()
                if context.event_id == symlink_event_id
            ]
            self.assertEqual((), run_adapters(symlink_contexts, root).resources)

    def test_filesystem_rejects_snapshot_from_wrong_workspace_or_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            root = base / "workspace"
            nested = root / "nested"
            other = base / "other"
            nested.mkdir(parents=True)
            other.mkdir()
            store = EventStore(base / "events.db")
            store.initialize()
            command = (
                "*** Begin Patch\n"
                "*** Add File: result.txt\n"
                "+workspace content\n"
                "*** End Patch\n"
            )
            payload = {
                "session_id": "snapshot-session",
                "tool_use_id": "snapshot-tool",
                "tool_name": "apply_patch",
                "cwd": str(nested),
                "tool_input": {"command": command},
            }
            pre = normalize_event(
                "pre_tool_use",
                payload,
                workspace_root=str(root),
            )
            pre_artifacts = build_artifacts(pre)
            pre_fragments = build_fragments(pre_artifacts)
            extraction = extract_tool_operations(
                pre,
                pre_artifacts,
                pre_fragments,
            )
            pre_fragments.extend(extraction.fragments)
            store.record(
                pre,
                pre_artifacts,
                pre_fragments,
                list(extraction.operations),
            )
            post = normalize_event(
                "post_tool_use",
                {**payload, "tool_response": {"content": "Done!"}},
                workspace_root=str(root),
            )
            post_artifacts = build_artifacts(post)
            store.record(post, post_artifacts, build_fragments(post_artifacts))
            contexts = store.list_artifact_contexts_for_session("snapshot-session")
            operations = tuple(
                store.list_tool_operations_for_session("snapshot-session")
            )
            baseline = run_adapters(
                contexts,
                root,
                operations=operations,
            )
            self.assertEqual(1, len(baseline.resources))
            operation = operations[0]

            def snapshot(
                workspace_root: str,
                lexical_path: str,
                requested_path: str = "result.txt",
            ) -> ResourceSnapshot:
                identity = "\0".join(
                    (workspace_root, lexical_path, requested_path)
                )
                return ResourceSnapshot(
                    snapshot_id=(
                        "snapshot-"
                        f"{hashlib.sha256(identity.encode()).hexdigest()}"
                    ),
                    post_event_id=post.event_id,
                    operation_id=operation.operation_id,
                    session_id=post.session_id,
                    tool_use_id=post.tool_use_id,
                    path_role="target",
                    requested_path=requested_path,
                    workspace_root=workspace_root,
                    lexical_path=lexical_path,
                    resource_state="present",
                    capture_status="captured_hash_only",
                    file_kind="regular",
                    byte_size=17,
                    captured_bytes=17,
                    content_sha256="f" * 64,
                    encoding="utf-8",
                    body_text=None,
                    error_code=None,
                    duration_ms=0.1,
                )

            context = contexts[0]
            assert context.workspace_root is not None
            assert context.workspace_execution_cwd is not None
            expected_path = str(
                Path(context.workspace_execution_cwd) / "result.txt"
            )
            valid = snapshot(context.workspace_root, expected_path)
            valid_result = run_adapters(
                contexts,
                root,
                operations=operations,
                snapshots=(valid,),
            )
            self.assertEqual(1, len(valid_result.resources))
            self.assertEqual("f" * 64, valid_result.resources[0].content_hash)

            wrong_root = snapshot(str(other.resolve()), expected_path)
            outside_path = snapshot(
                context.workspace_root,
                str(other.resolve() / "result.txt"),
            )
            wrong_inside_path = snapshot(
                context.workspace_root,
                str(Path(context.workspace_execution_cwd) / "different.txt"),
            )
            wrong_requested_path = snapshot(
                context.workspace_root,
                expected_path,
                requested_path="different.txt",
            )
            missing_lexical_path = replace(valid, lexical_path=None)
            for forged in (
                wrong_root,
                outside_path,
                wrong_inside_path,
                wrong_requested_path,
                missing_lexical_path,
            ):
                with self.subTest(snapshot_id=forged.snapshot_id):
                    result = run_adapters(
                        contexts,
                        root,
                        operations=operations,
                        snapshots=(forged,),
                    )
                    self.assertEqual((), result.resources)

    def test_scoped_source_ids_are_stable_across_manifest_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            entries = [
                {
                    "id": source_key,
                    "path": f"{source_key}.txt",
                    "type": "text",
                    "sensitivity": "confidential",
                }
                for source_key in ("alpha", "beta")
            ]
            first = base / "first.json"
            second = base / "second.json"
            first.write_text(json.dumps({"sources": entries}), encoding="utf-8")
            second.write_text(
                json.dumps({"sources": list(reversed(entries))}, indent=2),
                encoding="utf-8",
            )

            first_sources = load_protected_sources(
                first,
                workspace_id="ws_v1_stable",
            )
            second_sources = load_protected_sources(
                second,
                workspace_id="ws_v1_stable",
            )

        self.assertEqual(
            {source.source_key: source.source_id for source in first_sources},
            {source.source_key: source.source_id for source in second_sources},
        )


if __name__ == "__main__":
    unittest.main()
