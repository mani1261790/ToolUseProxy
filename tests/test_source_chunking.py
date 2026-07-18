from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hook_monitor.analysis.chunking import build_source_chunks
from hook_monitor.runtime.ids import make_source_chunk_id
from hook_monitor.runtime.models import ProtectedSource, SourceChunk


class SourceChunkingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name)

    def test_secretfile_dotenv_emits_decoded_nonempty_values_only(self) -> None:
        content = """# synthetic fixture comment
PLAIN_TOKEN=C.A4K8M2Q6V9
export DOUBLE_TOKEN="C.B7R3V9O5T2"
export SINGLE_TOKEN='C.C5Q9L3E7N2'
COMMENTED_TOKEN=C.D8L4A2X6R9 # ignored inline comment
HASH_TOKEN=C.E3M7T9R5V2#literal
EMPTY_TOKEN=
export ALSO_EMPTY=""
"""
        expected = [
            "C.A4K8M2Q6V9",
            "C.B7R3V9O5T2",
            "C.C5Q9L3E7N2",
            "C.D8L4A2X6R9",
            "C.E3M7T9R5V2#literal",
        ]
        for path in (".env", ".env.local"):
            with self.subTest(path=path):
                source, chunks = self._build(
                    path=path,
                    source_type="secretfile",
                    content=content,
                    source_id=f"dotenv-source-{path}",
                    workspace_id="workspace-dotenv",
                )

                self.assertEqual(expected, [chunk.text for chunk in chunks])
                self._assert_chunk_identity(source, chunks, expected)

    def test_secretfile_json_emits_nested_nonempty_string_leaves_in_order(
        self,
    ) -> None:
        content = """{
  "credential": "C.F6D2K8Q4A9",
  "nested": {
    "tokens": ["C.G9R5B3L7E2/path/value", "", 42, true, null],
    "label": "C.H2V6N8C4Q7"
  },
  "scalar_number": 7319,
  "scalar_false": false
}
"""
        source, chunks = self._build(
            path="config/secrets.json",
            source_type="secretfile",
            content=content,
            source_id="json-source",
            workspace_id="workspace-json",
        )

        expected = [
            "C.F6D2K8Q4A9",
            "C.G9R5B3L7E2/path/value",
            "C.H2V6N8C4Q7",
        ]
        self.assertEqual(expected, [chunk.text for chunk in chunks])
        self._assert_chunk_identity(source, chunks, expected)

    def test_invalid_secretfile_json_falls_back_to_paragraph_chunks(self) -> None:
        content = (
            '{"credential":"C.I5T9L3M7B2"\n'
            "\n"
            "fallback paragraph C.J8E4Q6R2V9\n"
        )
        source, chunks = self._build(
            path="config/broken.json",
            source_type="secretfile",
            content=content,
            source_id="broken-json-source",
            workspace_id="workspace-broken-json",
        )

        expected = [
            '{"credential":"C.I5T9L3M7B2"',
            "fallback paragraph C.J8E4Q6R2V9",
        ]
        self.assertEqual(expected, [chunk.text for chunk in chunks])
        self._assert_chunk_identity(source, chunks, expected)

    def test_ambiguous_dotenv_syntax_falls_back_without_dropping_text(self) -> None:
        cases = (
            "TOKEN=unquoted\\ value\nMODE=demo\n",
            'TOKEN="unterminated\nMODE=demo\n',
            "TOKEN=value\nnot-an-assignment\n",
        )
        for index, content in enumerate(cases):
            with self.subTest(index=index):
                source, chunks = self._build(
                    path=".env",
                    source_type="secretfile",
                    content=content,
                    source_id=f"fallback-dotenv-{index}",
                    workspace_id="workspace-fallback-dotenv",
                )

                expected = [content.strip()]
                self.assertEqual(expected, [chunk.text for chunk in chunks])
                self._assert_chunk_identity(source, chunks, expected)

    def test_dotenv_specialization_requires_secretfile_and_dotenv_name(
        self,
    ) -> None:
        cases = (
            (".env", "unpublished_impl"),
            ("config.env", "secretfile"),
        )
        content = "TOKEN=C.K6L2O8Q4\nMODE=demo\n"
        for path, source_type in cases:
            with self.subTest(path=path, source_type=source_type):
                source, chunks = self._build(
                    path=path,
                    source_type=source_type,
                    content=content,
                    source_id=f"legacy-source-{source_type}",
                    workspace_id="workspace-legacy",
                )

                expected = [content.strip()]
                self.assertEqual(expected, [chunk.text for chunk in chunks])
                self._assert_chunk_identity(source, chunks, expected)

    def test_non_secretfile_json_remains_paragraph_based(self) -> None:
        content = '{"token":"C.O7C3R9L5","mode":"demo"}\n'
        source, chunks = self._build(
            path="config/legacy.json",
            source_type="unpublished_impl",
            content=content,
            source_id="legacy-json-source",
            workspace_id="workspace-legacy-json",
        )

        expected = [content.strip()]
        self.assertEqual(expected, [chunk.text for chunk in chunks])
        self._assert_chunk_identity(source, chunks, expected)

    def test_python_chunking_remains_function_and_class_based(self) -> None:
        content = """MODULE_VALUE = "C.L7M3A9X5"

def first():
    return "C.M8K4R6L2"

class Second:
    value = "C.N9V5B3R7"
"""
        source, chunks = self._build(
            path="private.py",
            source_type="secretfile",
            content=content,
            source_id="python-source",
            workspace_id="workspace-python",
        )

        expected = [
            'MODULE_VALUE = "C.L7M3A9X5"',
            'def first():\n    return "C.M8K4R6L2"',
            'class Second:\n    value = "C.N9V5B3R7"',
        ]
        self.assertEqual(expected, [chunk.text for chunk in chunks])
        self._assert_chunk_identity(source, chunks, expected)

    def _build(
        self,
        *,
        path: str,
        source_type: str,
        content: str,
        source_id: str,
        workspace_id: str,
    ) -> tuple[ProtectedSource, list[SourceChunk]]:
        source_path = self.workspace / path
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_text(content, encoding="utf-8")
        source = ProtectedSource(
            source_id=source_id,
            path=path,
            source_type=source_type,
            sensitivity="high",
            policy_tags=("no_external",),
            workspace_id=workspace_id,
            source_key=source_id,
        )
        return source, build_source_chunks(self.workspace, source)

    def _assert_chunk_identity(
        self,
        source: ProtectedSource,
        chunks: list[SourceChunk],
        expected_texts: list[str],
    ) -> None:
        self.assertEqual(list(range(len(chunks))), [chunk.ordinal for chunk in chunks])
        self.assertEqual(
            [
                make_source_chunk_id(source.source_id, ordinal, text)
                for ordinal, text in enumerate(expected_texts)
            ],
            [chunk.chunk_id for chunk in chunks],
        )
        self.assertTrue(
            all(chunk.source_id == source.source_id for chunk in chunks)
        )
        self.assertTrue(
            all(chunk.workspace_id == source.workspace_id for chunk in chunks)
        )


if __name__ == "__main__":
    unittest.main()
