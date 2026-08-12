from __future__ import annotations

import json
import unittest

from hook_monitor.externality.models import (
    ExternalityEnvelope,
    ExternalitySchemaError,
    ExternalityVerdict,
)


class ExternalityEnvelopeTest(unittest.TestCase):
    def test_closed_envelope_round_trip_is_deterministic(self) -> None:
        envelope = ExternalityEnvelope.create(
            tool_family="bash",
            analysis_coverage="partial",
            executable_classes={"python_runtime", "custom_or_unknown"},
            capabilities={"child_process"},
            risk_signals={"dynamic_code", "unknown_executable"},
            counts={"segment_count": 2, "pipeline_count": 1},
        )

        restored = ExternalityEnvelope.from_mapping(json.loads(envelope.canonical_json()))

        self.assertEqual(envelope, restored)
        self.assertEqual(64, len(envelope.digest_sha256()))
        self.assertNotIn("command", envelope.canonical_json())
        self.assertNotIn("path", envelope.canonical_json())
        self.assertNotIn("host", envelope.canonical_json())
        self.assertNotIn("url", envelope.canonical_json())

    def test_unknown_field_and_arbitrary_value_are_rejected(self) -> None:
        envelope = ExternalityEnvelope.create(
            tool_family="bash",
            analysis_coverage="complete",
            executable_classes={"local_file_tool"},
            capabilities=set(),
            risk_signals=set(),
            counts={"segment_count": 1},
        ).to_dict()
        envelope["raw_command"] = "forbidden"
        with self.assertRaisesRegex(ExternalitySchemaError, "object keys differ"):
            ExternalityEnvelope.from_mapping(envelope)

        envelope.pop("raw_command")
        envelope["risk_signals"] = ["private-project-name"]
        with self.assertRaisesRegex(ExternalitySchemaError, "invalid risk_signals"):
            ExternalityEnvelope.from_mapping(envelope)

    def test_internal_counts_are_bounded_and_boolean_schema_version_is_rejected(self) -> None:
        envelope = ExternalityEnvelope.create(
            tool_family="bash",
            analysis_coverage="opaque",
            executable_classes={"custom_or_unknown"},
            capabilities=set(),
            risk_signals={"unknown_executable"},
            counts={"dynamic_token_count": 1_000_000},
        )
        self.assertEqual(10_000, dict(envelope.counts)["dynamic_token_count"])

        mapping = envelope.to_dict()
        mapping["schema_version"] = True
        with self.assertRaisesRegex(ExternalitySchemaError, "schema_version"):
            ExternalityEnvelope.from_mapping(mapping)

    def test_verdict_has_no_free_form_text(self) -> None:
        verdict = ExternalityVerdict.from_mapping(
            {
                "schema_version": 1,
                "verdict": "possibly_external",
                "confidence": "low",
                "reason_codes": ["insufficient_evidence"],
            }
        )
        self.assertEqual("possibly_external", verdict.verdict)

        with self.assertRaisesRegex(ExternalitySchemaError, "object keys differ"):
            ExternalityVerdict.from_mapping(
                {
                    **verdict.to_dict(),
                    "explanation": "could echo private input",
                }
            )

    def test_verdict_normalizes_order_but_rejects_duplicates_or_local_mismatch(self) -> None:
        verdict = ExternalityVerdict.from_mapping(
            {
                "schema_version": 1,
                "verdict": "possibly_external",
                "confidence": "medium",
                "reason_codes": [
                    "network_capable_child_process",
                    "dynamic_execution",
                ],
            }
        )
        self.assertEqual(
            ("dynamic_execution", "network_capable_child_process"),
            verdict.reason_codes,
        )

        with self.assertRaisesRegex(ExternalitySchemaError, "must be unique"):
            ExternalityVerdict.from_mapping(
                {
                    "schema_version": 1,
                    "verdict": "unknown",
                    "confidence": "low",
                    "reason_codes": ["insufficient_evidence", "insufficient_evidence"],
                }
            )
        with self.assertRaisesRegex(ExternalitySchemaError, "requires known_local_only"):
            ExternalityVerdict.from_mapping(
                {
                    "schema_version": 1,
                    "verdict": "local",
                    "confidence": "low",
                    "reason_codes": ["insufficient_evidence"],
                }
            )


if __name__ == "__main__":
    unittest.main()
