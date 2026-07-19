from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from hook_monitor.analysis.query import select_analysis_run_scope
from hook_monitor.runtime.ids import make_source_chunk_id
from hook_monitor.runtime.models import (
    FlowEdge,
    ProtectedSource,
    ProtectedSourceSelector,
    SinkCandidate,
    SourceChunk,
)
from hook_monitor.runtime.source_config import make_scoped_source_id
from hook_monitor.runtime.storage import (
    CURRENT_SCHEMA_VERSION,
    EventStore,
    SchemaCompatibilityError,
)
from hook_monitor.runtime.workspace import resolve_workspace


class SourceSelectorStorageTest(unittest.TestCase):
    def test_initialize_migrates_v4_source_chunks_with_safe_default(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            db_path = Path(temporary_directory) / "events.db"
            store = EventStore(db_path)
            store.initialize()
            with sqlite3.connect(db_path) as connection:
                connection.execute(
                    "ALTER TABLE source_chunks DROP COLUMN source_binding_signal"
                )
                connection.execute("PRAGMA user_version = 4")

            store.initialize()

            with sqlite3.connect(db_path) as connection:
                columns = {
                    row[1]: row[4]
                    for row in connection.execute(
                        "PRAGMA table_info(source_chunks)"
                    ).fetchall()
                }
                version = connection.execute("PRAGMA user_version").fetchone()[0]
            self.assertEqual(CURRENT_SCHEMA_VERSION, version)
            self.assertEqual("'registered_source'", columns["source_binding_signal"])

    def test_source_chunk_rejects_unknown_binding_signal(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid source_binding_signal"):
            SourceChunk(
                chunk_id="invalid-signal",
                source_id="source",
                ordinal=0,
                text="value",
                normalized_text="value",
                text_hash="0" * 64,
                shingle_fingerprint="[]",
                token_count=1,
                source_binding_signal="unknown",
            )

    def test_initialize_migrates_v1_catalog_and_preserves_legacy_row(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            db_path = Path(temporary_directory) / "events.db"
            with sqlite3.connect(db_path) as connection:
                connection.execute(
                    """
                    CREATE TABLE protected_sources (
                        source_id TEXT PRIMARY KEY,
                        workspace_id TEXT,
                        source_key TEXT,
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
                    INSERT INTO protected_sources (
                        source_id,
                        workspace_id,
                        source_key,
                        path,
                        source_type,
                        sensitivity,
                        policy_tags_json
                    ) VALUES (?, NULL, NULL, ?, ?, ?, ?)
                    """,
                    (
                        "legacy-source",
                        "legacy.txt",
                        "file",
                        "private",
                        '["legacy"]',
                    ),
                )
                connection.execute("PRAGMA user_version = 1")

            store = EventStore(db_path)
            store.initialize()

            with sqlite3.connect(db_path) as connection:
                schema_version = connection.execute(
                    "PRAGMA user_version"
                ).fetchone()[0]
                columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(protected_sources)"
                    ).fetchall()
                }
                stored_selector = connection.execute(
                    """
                    SELECT selector_json
                    FROM protected_sources
                    WHERE source_id = 'legacy-source'
                    """
                ).fetchone()[0]

            self.assertEqual(CURRENT_SCHEMA_VERSION, schema_version)
            self.assertIn("selector_json", columns)
            self.assertEqual("null", stored_selector)
            self.assertEqual(
                [
                    ProtectedSource(
                        source_id="legacy-source",
                        path="legacy.txt",
                        source_type="file",
                        sensitivity="private",
                        policy_tags=("legacy",),
                    )
                ],
                store.list_protected_sources(),
            )

    def test_workspace_catalog_round_trips_selector(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            store, workspace, workspace_id = self._initialized_workspace(
                Path(temporary_directory)
            )
            source, chunk = self._source_catalog(
                workspace,
                workspace_id,
                selector=ProtectedSourceSelector(
                    kind="dotenv_keys",
                    values=("PRIMARY_TOKEN", "SECONDARY_TOKEN"),
                ),
            )

            store.replace_sources_for_workspace(
                workspace_id,
                [source],
                [chunk],
            )

            self.assertEqual(
                [source],
                store.list_protected_sources_for_workspace(workspace_id),
            )
            self.assertEqual([chunk], store.list_source_chunks_for_workspace(workspace_id))
            with sqlite3.connect(store.db_path) as connection:
                selector_json = connection.execute(
                    """
                    SELECT selector_json
                    FROM protected_sources
                    WHERE source_id = ?
                    """,
                    (source.source_id,),
                ).fetchone()[0]
            self.assertEqual(
                '{"dotenv_keys":["PRIMARY_TOKEN","SECONDARY_TOKEN"]}',
                selector_json,
            )

    def test_workspace_revision_changes_when_only_selector_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            store, workspace, workspace_id = self._initialized_workspace(
                Path(temporary_directory)
            )
            first_source, chunk = self._source_catalog(
                workspace,
                workspace_id,
                selector=ProtectedSourceSelector(
                    kind="dotenv_keys",
                    values=("PRIMARY_TOKEN",),
                ),
            )
            store.replace_sources_for_workspace(
                workspace_id,
                [first_source],
                [chunk],
            )
            first_revision = store.get_workspace_analysis_input_revision(
                workspace_id
            )

            second_source = ProtectedSource(
                source_id=first_source.source_id,
                path=first_source.path,
                source_type=first_source.source_type,
                sensitivity=first_source.sensitivity,
                policy_tags=first_source.policy_tags,
                workspace_id=first_source.workspace_id,
                source_key=first_source.source_key,
                selector=ProtectedSourceSelector(
                    kind="dotenv_keys",
                    values=("SECONDARY_TOKEN",),
                ),
            )
            store.replace_sources_for_workspace(
                workspace_id,
                [second_source],
                [chunk],
            )
            second_revision = store.get_workspace_analysis_input_revision(
                workspace_id
            )

            self.assertNotEqual(first_revision, second_revision)

    def test_runtime_schema_rejects_current_version_without_selector_column(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            db_path = Path(temporary_directory) / "events.db"
            store = EventStore(db_path)
            store.initialize()
            with sqlite3.connect(db_path) as connection:
                connection.execute(
                    "ALTER TABLE protected_sources DROP COLUMN selector_json"
                )
                self.assertEqual(
                    CURRENT_SCHEMA_VERSION,
                    connection.execute("PRAGMA user_version").fetchone()[0],
                )

            with self.assertRaises(SchemaCompatibilityError) as raised:
                store.require_runtime_schema()

            self.assertEqual("schema_incomplete", raised.exception.code)
            self.assertIn(
                "protected_sources missing selector_json",
                str(raised.exception),
            )

    def test_completed_offline_snapshot_restores_selector_after_live_change(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            store, workspace, workspace_id = self._initialized_workspace(
                Path(temporary_directory)
            )
            snapshotted_source, chunk = self._source_catalog(
                workspace,
                workspace_id,
                selector=ProtectedSourceSelector(
                    kind="dotenv_keys",
                    values=("PRIMARY_TOKEN",),
                ),
            )
            run_id = self._completed_source_run(
                store,
                workspace_id,
                snapshotted_source,
                chunk,
            )

            live_source = ProtectedSource(
                source_id=snapshotted_source.source_id,
                path=snapshotted_source.path,
                source_type=snapshotted_source.source_type,
                sensitivity=snapshotted_source.sensitivity,
                policy_tags=snapshotted_source.policy_tags,
                workspace_id=snapshotted_source.workspace_id,
                source_key=snapshotted_source.source_key,
                selector=ProtectedSourceSelector(
                    kind="dotenv_keys",
                    values=("SECONDARY_TOKEN",),
                ),
            )
            store.replace_sources_for_workspace(
                workspace_id,
                [live_source],
                [chunk],
            )

            scope = select_analysis_run_scope(
                store,
                analysis_run_id=run_id,
                workspace_root=None,
                latest=False,
            )
            self.assertEqual(
                [snapshotted_source],
                scope.list_protected_sources(store),
            )
            self.assertEqual(
                [live_source],
                store.list_protected_sources_for_workspace(workspace_id),
            )

    def test_completed_offline_snapshot_accepts_legacy_missing_selector_key(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            store, workspace, workspace_id = self._initialized_workspace(
                Path(temporary_directory)
            )
            source, chunk = self._source_catalog(
                workspace,
                workspace_id,
                selector=None,
            )
            run_id = self._completed_source_run(
                store,
                workspace_id,
                source,
                chunk,
            )

            with sqlite3.connect(store.db_path) as connection:
                old_hash, metadata_json = connection.execute(
                    """
                    SELECT member.snapshot_hash, snapshot.metadata_json
                    FROM analysis_run_nodes AS member
                    JOIN analysis_node_snapshots AS snapshot
                      ON snapshot.workspace_id = member.workspace_id
                     AND snapshot.snapshot_hash = member.snapshot_hash
                    WHERE member.analysis_run_id = ?
                      AND member.node_kind = 'protected_source'
                    """,
                    (run_id,),
                ).fetchone()
                payload = json.loads(metadata_json)
                self.assertIsNone(payload.pop("selector"))
                legacy_metadata_json = json.dumps(
                    payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                new_hash = hashlib.sha256(
                    (
                        f"protected_source\0{source.source_id}\0"
                        f"{legacy_metadata_json}"
                    ).encode("utf-8")
                ).hexdigest()
                connection.execute(
                    """
                    UPDATE analysis_node_snapshots
                    SET snapshot_hash = ?, metadata_json = ?
                    WHERE workspace_id = ? AND snapshot_hash = ?
                    """,
                    (new_hash, legacy_metadata_json, workspace_id, old_hash),
                )
                connection.execute(
                    """
                    UPDATE analysis_run_nodes
                    SET snapshot_hash = ?
                    WHERE analysis_run_id = ?
                      AND node_kind = 'protected_source'
                    """,
                    (new_hash, run_id),
                )

            scope = select_analysis_run_scope(
                store,
                analysis_run_id=run_id,
                workspace_root=None,
                latest=False,
            )
            restored = scope.list_protected_sources(store)
            self.assertEqual([source], restored)
            self.assertIsNone(restored[0].selector)

    @staticmethod
    def _initialized_workspace(
        root: Path,
    ) -> tuple[EventStore, Path, str]:
        workspace = root / "workspace"
        workspace.mkdir()
        store = EventStore(root / "events.db")
        store.initialize()
        context = resolve_workspace(
            str(workspace),
            str(workspace),
            discovered_by="selector-storage-test",
        )
        if not context.ready or context.workspace_id is None:
            raise AssertionError("fixture workspace must resolve")
        store.register_workspace(context)
        return store, workspace, context.workspace_id

    @staticmethod
    def _source_catalog(
        workspace: Path,
        workspace_id: str,
        *,
        selector: ProtectedSourceSelector | None,
    ) -> tuple[ProtectedSource, SourceChunk]:
        path = ".env"
        (workspace / path).write_text(
            "PRIMARY_TOKEN=primary-secret\n"
            "SECONDARY_TOKEN=secondary-secret\n",
            encoding="utf-8",
        )
        source_key = "environment"
        source_id = make_scoped_source_id(workspace_id, source_key)
        source = ProtectedSource(
            source_id=source_id,
            path=path,
            source_type="secretfile",
            sensitivity="secret",
            policy_tags=("credential",),
            workspace_id=workspace_id,
            source_key=source_key,
            selector=selector,
        )
        text = "primary-secret"
        chunk = SourceChunk(
            chunk_id=make_source_chunk_id(source_id, 0, text),
            source_id=source_id,
            ordinal=0,
            text=text,
            normalized_text=text,
            text_hash=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            shingle_fingerprint="selector-storage-fixture",
            token_count=1,
            workspace_id=workspace_id,
            source_binding_signal="selected_security_field",
        )
        return source, chunk

    @staticmethod
    def _completed_source_run(
        store: EventStore,
        workspace_id: str,
        source: ProtectedSource,
        chunk: SourceChunk,
    ) -> str:
        sink = SinkCandidate(
            node_id="selector-storage-sink",
            sink_type="external_http_request",
            label="selector storage sink",
            tool_name="Bash",
            tool_use_id=None,
            session_id=None,
            sequence_no=1,
            metadata={},
            workspace_id=workspace_id,
        )
        edge = FlowEdge(
            edge_id="selector-storage-edge",
            src_node_kind="source_chunk",
            src_node_id=chunk.chunk_id,
            dst_node_kind="sink_candidate",
            dst_node_id=sink.node_id,
            relation="source_similarity",
            evidence_level="exact",
            method="selector_storage_fixture",
            score=1.0,
            reason="selector storage snapshot fixture",
        )
        store.replace_sources_for_workspace(workspace_id, [source], [chunk])
        store.replace_sink_candidates_for_workspace(workspace_id, [sink])
        store.replace_information_flow_edges_for_workspace(workspace_id, [edge])
        run_id = store.start_workspace_analysis_run(
            detector_version="selector-storage-test-v1",
            config={},
            workspace_id=workspace_id,
        )
        store.replace_analysis_run_graph(run_id, [edge], coverage="full")
        store.complete_analysis_run(run_id)
        return run_id


if __name__ == "__main__":
    unittest.main()
