from __future__ import annotations

import hashlib
import unittest

from hook_monitor.analysis.mcp_payload_evidence import (
    verify_mcp_payload_against_sources,
)
from hook_monitor.analysis.sink_payload_evidence import (
    MAX_SINK_PAYLOAD_EVIDENCE_SOURCE_CHUNKS,
)
from hook_monitor.runtime.models import SourceChunk


class McpPayloadEvidenceTest(unittest.TestCase):
    def test_complete_public_payload_is_safe(self) -> None:
        result = verify_mcp_payload_against_sources(
            {"query": "public documentation", "page": 1},
            (self._chunk("private research threshold"),),
        )

        self.assertEqual("safe", result.status)
        self.assertIsNone(result.reason)
        self.assertGreater(result.compared_value_count, 0)

    def test_protected_value_or_key_is_matched(self) -> None:
        chunk = self._chunk("private research threshold")
        for payload in (
            {"query": "prefix private research threshold suffix"},
            {"private research threshold": "public"},
        ):
            with self.subTest(payload=payload):
                result = verify_mcp_payload_against_sources(payload, (chunk,))
                self.assertEqual("matched", result.status)

    def test_source_bound_excess_is_unsupported(self) -> None:
        chunks = tuple(
            self._chunk(f"private value {index}", ordinal=index)
            for index in range(MAX_SINK_PAYLOAD_EVIDENCE_SOURCE_CHUNKS + 1)
        )

        result = verify_mcp_payload_against_sources({"query": "public"}, chunks)

        self.assertEqual("unsupported", result.status)
        self.assertEqual("source_chunk_count_exceeded", result.reason)

    def test_invalid_input_is_unsupported(self) -> None:
        result = verify_mcp_payload_against_sources(
            ["not", "an", "object"],
            (self._chunk("private research threshold"),),
        )

        self.assertEqual("unsupported", result.status)
        self.assertEqual("input_not_object", result.reason)

    @staticmethod
    def _chunk(text: str, *, ordinal: int = 0) -> SourceChunk:
        return SourceChunk(
            chunk_id=f"chunk-{ordinal}",
            source_id="source",
            ordinal=ordinal,
            text=text,
            normalized_text=text.lower(),
            text_hash=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            shingle_fingerprint="[]",
            token_count=len(text.split()),
        )


if __name__ == "__main__":
    unittest.main()
