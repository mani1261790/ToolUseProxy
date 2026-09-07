from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from hook_monitor.analysis.similarity import (
    SIMILARITY_PROFILE_VERSION,
    prepare_similarity_text,
)
from hook_monitor.runtime.pilot_review import initialize_pilot_review_schema
from hook_monitor.runtime.parser import build_artifacts, build_fragments, normalize_event
from hook_monitor.runtime.storage import (
    CURRENT_SCHEMA_VERSION,
    EventStore,
    SchemaCompatibilityError,
)
from tooluseproxy.cli import main as tooluseproxy_main


class StorageDeduplicationTest(unittest.TestCase):
    def test_v11_migration_requires_explicit_verified_backup_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            db_path = Path(temporary) / "events.db"
            self._create_v11_database(db_path, text="original", row_count=1)

            with self.assertRaises(SchemaCompatibilityError) as caught:
                EventStore(db_path).initialize()

            self.assertEqual("schema_upgrade_required", caught.exception.code)
            self.assertEqual(11, self._schema_version(db_path))
            with sqlite3.connect(db_path) as conn:
                self.assertEqual(
                    [("original",)], conn.execute("SELECT text FROM artifacts").fetchall()
                )

    def test_v11_migration_preserves_content_and_reduces_active_pages(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            db_path = Path(temporary) / "events.db"
            text = "A" * (128 * 1024)
            self._create_v11_database(db_path, text=text, row_count=80)
            before = self._active_database_bytes(db_path)

            store = EventStore(db_path)
            store.initialize(allow_content_migration=True)

            after = self._active_database_bytes(db_path)
            self.assertLess(after, before)
            self.assertEqual(CURRENT_SCHEMA_VERSION, self._schema_version(db_path))
            self.assertEqual(80, len(store.list_artifacts()))
            self.assertEqual(80, len(store.list_artifact_contexts()))
            self.assertTrue(all(item.text == text for item in store.list_artifacts()))
            with sqlite3.connect(db_path) as conn:
                self.assertEqual(
                    1,
                    conn.execute("SELECT COUNT(*) FROM artifact_contents").fetchone()[0],
                )
                artifact_columns = {
                    row[1] for row in conn.execute("PRAGMA table_info(artifacts)")
                }
                fragment_columns = {
                    row[1]
                    for row in conn.execute("PRAGMA table_info(artifact_fragments)")
                }
                self.assertFalse(
                    {"text", "normalized_text", "token_count"} & artifact_columns
                )
                self.assertFalse(
                    {"text", "normalized_text", "token_count"} & fragment_columns
                )
                self.assertIsNone(
                    conn.execute(
                        "SELECT 1 FROM sqlite_master WHERE name = 'fragment_shingles'"
                    ).fetchone()
                )
                operation_targets = {
                    row[2]
                    for row in conn.execute("PRAGMA foreign_key_list(tool_operations)")
                }
                self.assertIn("artifacts", operation_targets)
                self.assertNotIn("artifacts_v12_new", operation_targets)
                self.assertEqual("ok", conn.execute("PRAGMA quick_check").fetchone()[0])
                self.assertEqual(
                    [("review-preserved", "unnecessary_block")],
                    conn.execute(
                        "SELECT review_id, choice FROM pilot_reviews"
                    ).fetchall(),
                )

    def test_cli_creates_verified_v11_backup_before_migration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            data_dir = root / "data"
            workspace.mkdir()
            data_dir.mkdir()
            db_path = data_dir / "events.db"
            self._create_v11_database(db_path, text="preserved", row_count=2)
            stdout = StringIO()

            with redirect_stdout(stdout):
                exit_code = tooluseproxy_main(
                    [
                        "init",
                        "--workspace",
                        str(workspace),
                        "--data-dir",
                        str(data_dir),
                        "--json",
                    ]
                )

            self.assertEqual(0, exit_code)
            payload = json.loads(stdout.getvalue())
            backup = Path(payload["migration_backup"])
            self.assertTrue(backup.is_file())
            self.assertEqual(11, self._schema_version(backup))
            self.assertEqual(CURRENT_SCHEMA_VERSION, self._schema_version(db_path))
            self.assertEqual(
                ["preserved", "preserved"],
                [artifact.text for artifact in EventStore(db_path).list_artifacts()],
            )

    def test_failed_v11_migration_rolls_back_the_original_schema_and_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            db_path = Path(temporary) / "events.db"
            self._create_v11_database(db_path, text="original", row_count=2)

            with patch.object(
                EventStore,
                "_validate_deduplicated_artifact_contents",
                side_effect=RuntimeError("injected migration failure"),
            ):
                with self.assertRaisesRegex(RuntimeError, "injected migration failure"):
                    EventStore(db_path).initialize(allow_content_migration=True)

            self.assertEqual(11, self._schema_version(db_path))
            with sqlite3.connect(db_path) as conn:
                columns = {row[1] for row in conn.execute("PRAGMA table_info(artifacts)")}
                self.assertIn("text", columns)
                self.assertEqual(2, conn.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0])
                self.assertEqual(
                    [("original",), ("original",)],
                    conn.execute("SELECT text FROM artifacts ORDER BY artifact_id").fetchall(),
                )
                self.assertIsNone(
                    conn.execute(
                        "SELECT 1 FROM sqlite_master WHERE name = 'artifact_contents'"
                    ).fetchone()
                )

    def test_repeated_runtime_content_and_features_are_stored_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            db_path = root / "events.db"
            store = EventStore(db_path)
            store.initialize()
            selected = []
            for index in range(2):
                event = normalize_event(
                    "pre_tool_use",
                    {
                        "session_id": "session",
                        "turn_id": f"turn-{index}",
                        "tool_use_id": f"tool-{index}",
                        "tool_name": "Search",
                        "cwd": str(root),
                        "tool_input": {"query": "same repeated searchable content"},
                    },
                )
                artifacts = build_artifacts(event)
                fragments = build_fragments(artifacts)
                store.record(event, artifacts, fragments)
                selected.append(
                    next(
                        context
                        for context in store.list_artifact_contexts_for_session("session")
                        if context.event_id == event.event_id
                        and context.fragment.text == "same repeated searchable content"
                    )
                )
            assert selected[0].workspace_id is not None
            prepared = prepare_similarity_text(
                selected[0].fragment.text,
                normalized_text=selected[0].fragment.normalized_text,
            )
            store.upsert_fragment_shingles(
                "session",
                selected,
                {
                    context.fragment.fragment_id: set(prepared.candidate_features)
                    for context in selected
                },
                workspace_id=selected[0].workspace_id,
            )

            with sqlite3.connect(db_path) as conn:
                content_count = conn.execute(
                    "SELECT COUNT(*) FROM artifact_contents WHERE text_hash = ?",
                    (selected[0].fragment.text_hash,),
                ).fetchone()[0]
                feature_count = conn.execute(
                    """
                    SELECT COUNT(*) FROM content_similarity_features
                    WHERE text_hash = ?
                    """,
                    (selected[0].fragment.text_hash,),
                ).fetchone()[0]
                feature_profiles = {
                    row[0]
                    for row in conn.execute(
                        """
                        SELECT DISTINCT profile_version
                        FROM content_similarity_features
                        WHERE text_hash = ?
                        """,
                        (selected[0].fragment.text_hash,),
                    ).fetchall()
                }
                exact_count = conn.execute(
                    "SELECT COUNT(*) FROM fragment_exact_index WHERE session_id = 'session'"
                ).fetchone()[0]
            self.assertEqual(1, content_count)
            self.assertEqual(len(prepared.candidate_features), feature_count)
            self.assertEqual({SIMILARITY_PROFILE_VERSION}, feature_profiles)
            self.assertEqual(2, exact_count)

    def test_hash_collision_rejects_the_whole_event_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            db_path = root / "events.db"
            store = EventStore(db_path)
            store.initialize()
            first = normalize_event(
                "pre_tool_use",
                {
                    "session_id": "session",
                    "tool_use_id": "first",
                    "tool_name": "Search",
                    "cwd": str(root),
                    "tool_input": {"query": "first"},
                },
            )
            artifacts = build_artifacts(first)
            store.record(first, artifacts, build_fragments(artifacts))
            second = normalize_event(
                "pre_tool_use",
                {
                    "session_id": "session",
                    "tool_use_id": "second",
                    "tool_name": "Search",
                    "cwd": str(root),
                    "tool_input": {"query": "second"},
                },
            )
            conflicting = build_artifacts(second)[0]
            conflicting = type(conflicting)(
                artifact_id=conflicting.artifact_id,
                event_id=conflicting.event_id,
                role=conflicting.role,
                text="different text",
                text_hash=artifacts[0].text_hash,
                normalized_text="different text",
                token_count=2,
            )

            with self.assertRaisesRegex(sqlite3.IntegrityError, "hash collision"):
                store.record(second, [conflicting])
            with sqlite3.connect(db_path) as conn:
                self.assertEqual(
                    0,
                    conn.execute(
                        "SELECT COUNT(*) FROM events WHERE event_id = ?",
                        (second.event_id,),
                    ).fetchone()[0],
                )

    def test_session_cleanup_keeps_shared_features_until_last_reference(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            db_path = root / "events.db"
            store = EventStore(db_path)
            store.initialize()
            selected = []
            for session_id in ("session-a", "session-b"):
                event = normalize_event(
                    "pre_tool_use",
                    {
                        "session_id": session_id,
                        "tool_use_id": f"tool-{session_id}",
                        "tool_name": "Search",
                        "cwd": str(root),
                        "tool_input": {"query": "same shared searchable content"},
                    },
                )
                artifacts = build_artifacts(event)
                store.record(event, artifacts, build_fragments(artifacts))
                context = next(
                    item
                    for item in store.list_artifact_contexts_for_session(session_id)
                    if item.fragment.text == "same shared searchable content"
                )
                assert context.workspace_id is not None
                prepared = prepare_similarity_text(
                    context.fragment.text,
                    normalized_text=context.fragment.normalized_text,
                )
                store.upsert_fragment_shingles(
                    session_id,
                    [context],
                    {context.fragment.fragment_id: set(prepared.candidate_features)},
                    workspace_id=context.workspace_id,
                )
                selected.append((context, len(prepared.candidate_features)))

            workspace_id = selected[0][0].workspace_id
            assert workspace_id is not None
            text_hash = selected[0][0].fragment.text_hash
            expected_count = selected[0][1]
            store.clear_runtime_analysis_for_session(
                "session-a",
                workspace_id=workspace_id,
            )
            with sqlite3.connect(db_path) as conn:
                self.assertEqual(
                    expected_count,
                    conn.execute(
                        """
                        SELECT COUNT(*) FROM content_similarity_features
                        WHERE text_hash = ?
                        """,
                        (text_hash,),
                    ).fetchone()[0],
                )
            store.clear_runtime_analysis_for_session(
                "session-b",
                workspace_id=workspace_id,
            )
            with sqlite3.connect(db_path) as conn:
                self.assertEqual(
                    0,
                    conn.execute(
                        """
                        SELECT COUNT(*) FROM content_similarity_features
                        WHERE text_hash = ?
                        """,
                        (text_hash,),
                    ).fetchone()[0],
                )

    @staticmethod
    def _create_v11_database(db_path: Path, *, text: str, row_count: int) -> None:
        text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        with sqlite3.connect(db_path) as conn:
            conn.executescript(
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
                );
                CREATE TABLE artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    text TEXT NOT NULL,
                    text_hash TEXT NOT NULL,
                    normalized_text TEXT NOT NULL,
                    token_count INTEGER NOT NULL,
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE artifact_fragments (
                    fragment_id TEXT PRIMARY KEY,
                    artifact_id TEXT NOT NULL,
                    json_pointer TEXT NOT NULL,
                    semantic_role TEXT NOT NULL,
                    text TEXT NOT NULL,
                    text_hash TEXT NOT NULL,
                    normalized_text TEXT NOT NULL,
                    token_count INTEGER NOT NULL,
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                PRAGMA user_version = 11;
                """
            )
            initialize_pilot_review_schema(conn)
            conn.execute(
                """
                INSERT INTO pilot_reviews (
                    review_id, observation_id, choice, cause,
                    previous_review_id, recorded_at, comparable_count_at_record
                ) VALUES (
                    'review-preserved', 'observation-preserved',
                    'unnecessary_block', 'protected_match', NULL,
                    '2026-09-07T00:00:00Z', 20
                )
                """
            )
            for index in range(row_count):
                event_id = f"event-{index}"
                artifact_id = f"artifact-{index}"
                conn.execute(
                    """
                    INSERT INTO events (event_id, phase, session_id, payload_json)
                    VALUES (?, 'pre_tool_use', 'session', '{}')
                    """,
                    (event_id,),
                )
                conn.execute(
                    """
                    INSERT INTO artifacts (
                        artifact_id, event_id, role, text, text_hash,
                        normalized_text, token_count
                    ) VALUES (?, ?, 'tool_input', ?, ?, ?, 1)
                    """,
                    (artifact_id, event_id, text, text_hash, text.casefold()),
                )
                conn.execute(
                    """
                    INSERT INTO artifact_fragments (
                        fragment_id, artifact_id, json_pointer, semantic_role,
                        text, text_hash, normalized_text, token_count
                    ) VALUES (?, ?, '/', 'tool_input', ?, ?, ?, 1)
                    """,
                    (f"fragment-{index}", artifact_id, text, text_hash, text.casefold()),
                )

    @staticmethod
    def _active_database_bytes(db_path: Path) -> int:
        with sqlite3.connect(db_path) as conn:
            page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
            page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
            free_pages = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
        return page_size * (page_count - free_pages)

    @staticmethod
    def _schema_version(db_path: Path) -> int:
        with sqlite3.connect(db_path) as conn:
            return int(conn.execute("PRAGMA user_version").fetchone()[0])


if __name__ == "__main__":
    unittest.main()
