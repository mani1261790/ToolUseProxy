from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from hook_monitor.analysis.graph import (
    build_artifact_flow_edges,
    build_protected_source_resource_edges,
    build_source_binding_edges,
)
from hook_monitor.analysis.adapters.registry import run_adapters
from hook_monitor.analysis.lineage import propagate_lineage
from hook_monitor.runtime.parser import build_artifacts, build_fragments, normalize_event
from hook_monitor.runtime.models import ProtectedSource, SourceChunk
from hook_monitor.runtime.storage import EventStore


SECRET = "alpha secret design threshold 0.73"


class InformationFlowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temporary_directory.name) / "events.db"
        self.store = EventStore(self.db_path)
        self.store.initialize()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_fragment_extraction_assigns_semantic_roles(self) -> None:
        event = normalize_event(
            "pre_tool_use",
            {
                "session_id": "session-1",
                "turn_id": "turn-1",
                "tool_use_id": "tool-1",
                "tool_name": "Search",
                "tool_input": {"query": SECRET, "path": "private.py"},
            },
        )
        artifacts = build_artifacts(event)
        fragments = build_fragments(artifacts)

        roles = {fragment.semantic_role for fragment in fragments}
        self.assertIn("query", roles)
        self.assertIn("path", roles)
        self.assertIn("tool_input", roles)

    def test_multihop_and_branching_lineage_reaches_both_searches(self) -> None:
        self._record(
            "post_tool_use",
            "read-1",
            "Read",
            tool_input={"path": "private.py"},
            tool_response={"content": SECRET},
        )
        self._record(
            "pre_tool_use",
            "write-x",
            "Write",
            tool_input={"path": "xx.md", "content": SECRET},
        )
        self._record(
            "pre_tool_use",
            "search-x",
            "Search",
            tool_input={"query": f"{SECRET} implementation"},
        )
        self._record(
            "pre_tool_use",
            "write-y",
            "Write",
            tool_input={"path": "yy.md", "content": SECRET},
        )
        self._record(
            "pre_tool_use",
            "search-y",
            "Search",
            tool_input={"query": f"explain {SECRET}"},
        )

        contexts = self.store.list_artifact_contexts()
        artifact_edges = build_artifact_flow_edges(contexts)
        source_edges = build_source_binding_edges(
            [self._source_chunk()],
            contexts,
            artifact_edges,
        )
        assignments = propagate_lineage(
            "run-1",
            source_edges + artifact_edges,
            minimum_path_score=0.15,
        )

        query_fragments = {
            context.fragment.fragment_id
            for context in contexts
            if context.fragment.semantic_role == "query"
        }
        reached_query_fragments = {
            assignment.node_id
            for assignment in assignments
            if assignment.node_kind == "artifact_fragment"
            and assignment.node_id in query_fragments
        }

        self.assertEqual(query_fragments, reached_query_fragments)
        self.assertGreaterEqual(len(artifact_edges), 4)
        self.assertTrue(all(assignment.best_path_score >= 0.15 for assignment in assignments))
        query_hops = {
            assignment.hop_count
            for assignment in assignments
            if assignment.node_id in query_fragments
        }
        self.assertTrue(all(hop_count >= 2 for hop_count in query_hops))

        run_id = self.store.start_analysis_run(
            detector_version="test-v1",
            config={"minimum_path_score": 0.15},
        )
        persisted_assignments = [
            replace(assignment, analysis_run_id=run_id) for assignment in assignments
        ]
        self.store.replace_information_flow_edges(artifact_edges)
        self.store.upsert_source_binding_edges(run_id, source_edges)
        self.store.upsert_lineage_assignments(persisted_assignments)
        self.store.complete_analysis_run(run_id)

        with sqlite3.connect(self.db_path) as connection:
            self.assertEqual(
                len(artifact_edges),
                connection.execute(
                    "SELECT COUNT(*) FROM information_flow_edges"
                ).fetchone()[0],
            )
            self.assertEqual(
                len(source_edges),
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM source_binding_edges
                    WHERE analysis_run_id = ?
                    """,
                    (run_id,),
                ).fetchone()[0],
            )
            self.assertEqual(
                len(persisted_assignments),
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM lineage_assignments
                    WHERE analysis_run_id = ?
                    """,
                    (run_id,),
                ).fetchone()[0],
            )

    def test_artifact_graph_does_not_depend_on_source_configuration(self) -> None:
        self._record(
            "post_tool_use",
            "read-1",
            "Read",
            tool_input={"path": "private.py"},
            tool_response={"content": SECRET},
        )
        self._record(
            "pre_tool_use",
            "search-1",
            "Search",
            tool_input={"query": f"{SECRET} implementation"},
        )

        contexts = self.store.list_artifact_contexts()
        artifact_edges_before = build_artifact_flow_edges(contexts)
        source_edges = build_source_binding_edges(
            [self._source_chunk()],
            contexts,
            artifact_edges_before,
        )
        artifact_edges_after = build_artifact_flow_edges(contexts)

        self.assertEqual(artifact_edges_before, artifact_edges_after)
        self.assertTrue(source_edges)

    def test_filesystem_read_binds_protected_path_without_content_similarity(self) -> None:
        protected_path = Path(self.temporary_directory.name) / "private.py"
        unrelated_output = "content that does not resemble the configured source chunks"
        self._record(
            "post_tool_use",
            "read-protected",
            "Read",
            tool_input={"path": str(protected_path)},
            tool_response={"content": unrelated_output},
            cwd=self.temporary_directory.name,
        )

        contexts = self.store.list_artifact_contexts()
        adapter_result = run_adapters(contexts, Path(self.temporary_directory.name))
        source_edges = build_protected_source_resource_edges(
            [self._protected_source("private.py")],
            list(adapter_result.resources),
            Path(self.temporary_directory.name),
        )
        assignments = propagate_lineage(
            "run-path",
            source_edges + list(adapter_result.edges),
        )

        output_ids = {
            context.fragment.fragment_id
            for context in contexts
            if context.fragment.semantic_role == "content"
            and context.phase == "post_tool_use"
        }
        reached = {
            assignment.node_id
            for assignment in assignments
            if assignment.source_node_kind == "protected_source"
        }
        self.assertEqual(1, len(adapter_result.resources))
        self.assertTrue(source_edges)
        self.assertTrue(output_ids <= reached)

    def test_filesystem_write_then_read_uses_same_resource_version(self) -> None:
        path = Path(self.temporary_directory.name) / "notes.md"
        self._record(
            "pre_tool_use",
            "write-notes",
            "Write",
            tool_input={"path": str(path), "content": SECRET},
            cwd=self.temporary_directory.name,
        )
        self._record(
            "post_tool_use",
            "read-notes",
            "Read",
            tool_input={"path": str(path)},
            tool_response={"content": SECRET},
            cwd=self.temporary_directory.name,
        )

        result = run_adapters(
            self.store.list_artifact_contexts(),
            Path(self.temporary_directory.name),
        )
        relations = {edge.relation for edge in result.edges}
        resource_ids = {
            edge.dst_node_id
            for edge in result.edges
            if edge.relation == "written_to"
        }
        read_resource_ids = {
            edge.src_node_id
            for edge in result.edges
            if edge.relation == "read_from"
        }

        self.assertEqual({"written_to", "read_from"}, relations)
        self.assertEqual(resource_ids, read_resource_ids)
        self.assertEqual(1, len(result.resources))

        self.store.replace_resource_versions(list(result.resources))
        self.store.replace_information_flow_edges(list(result.edges))
        with sqlite3.connect(self.db_path) as connection:
            self.assertEqual(
                1,
                connection.execute(
                    "SELECT COUNT(*) FROM resource_versions"
                ).fetchone()[0],
            )
            self.assertEqual(
                2,
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM information_flow_edges
                    WHERE evidence_level = 'structured'
                    """
                ).fetchone()[0],
            )

    def test_unprotected_filesystem_path_remains_outside_source_lineage(self) -> None:
        public_path = Path(self.temporary_directory.name) / "public.md"
        self._record(
            "post_tool_use",
            "read-public",
            "Read",
            tool_input={"path": str(public_path)},
            tool_response={"content": "public information only"},
            cwd=self.temporary_directory.name,
        )

        contexts = self.store.list_artifact_contexts()
        adapter_result = run_adapters(contexts, Path(self.temporary_directory.name))
        source_edges = build_protected_source_resource_edges(
            [self._protected_source("private.py")],
            list(adapter_result.resources),
            Path(self.temporary_directory.name),
        )

        self.assertEqual([], source_edges)
        self.assertEqual(
            [],
            propagate_lineage("run-unprotected", list(adapter_result.edges)),
        )

    def _record(
        self,
        phase: str,
        tool_use_id: str,
        tool_name: str,
        *,
        tool_input: dict[str, object],
        tool_response: dict[str, object] | None = None,
        cwd: str | None = None,
    ) -> None:
        payload: dict[str, object] = {
            "session_id": "session-1",
            "turn_id": "turn-1",
            "tool_use_id": tool_use_id,
            "tool_name": tool_name,
            "tool_input": tool_input,
        }
        if cwd is not None:
            payload["cwd"] = cwd
        if tool_response is not None:
            payload["tool_response"] = tool_response
        event = normalize_event(phase, payload)
        artifacts = build_artifacts(event)
        self.store.record(event, artifacts, build_fragments(artifacts))

    def _source_chunk(self) -> SourceChunk:
        normalized = SECRET.lower()
        return SourceChunk(
            chunk_id="private-source:0",
            source_id="private-source",
            ordinal=0,
            text=SECRET,
            normalized_text=normalized,
            text_hash=hashlib.sha256(SECRET.encode("utf-8")).hexdigest(),
            shingle_fingerprint="[]",
            token_count=5,
        )

    def _protected_source(self, path: str) -> ProtectedSource:
        return ProtectedSource(
            source_id="protected-file",
            path=path,
            source_type="unpublished_impl",
            sensitivity="high",
            policy_tags=("no_external",),
        )


if __name__ == "__main__":
    unittest.main()
