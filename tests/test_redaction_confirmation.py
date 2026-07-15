from __future__ import annotations

import unittest

from hook_monitor.analysis.adapters.mcp_profiles import (
    DEFAULT_MCP_PROFILE_REGISTRY,
    McpFieldSpec,
    McpProfileRegistry,
    McpToolProfile,
)
from hook_monitor.runtime.redaction_confirmation import compare_mcp_post_input
from hook_monitor.runtime.redaction_integrity import (
    canonical_json_bytes,
    sha256_bytes,
    structure_sha256,
)


PROFILE = DEFAULT_MCP_PROFILE_REGISTRY.profiles[0]
TOOL_NAME = "mcp__tooluseproxy_e2e__publish_text"


class RedactionPostInputComparisonTest(unittest.TestCase):
    def test_exact_bounded_stable_input_is_confirmed(self) -> None:
        rewritten_input = {"content": "[REDACTED BY TOOLUSEPROXY]"}

        result = self._compare(rewritten_input, rewritten_input)

        self.assertEqual("confirmed", result.disposition)
        self.assertIsNone(result.diagnostic_code)

    def test_bounded_full_input_difference_is_a_mismatch(self) -> None:
        expected = {"content": "[REDACTED BY TOOLUSEPROXY]"}

        result = self._compare(expected, {"content": "public but changed"})

        self.assertEqual("mismatch", result.disposition)
        self.assertIsNone(result.diagnostic_code)

    def test_unbounded_input_remains_unobserved(self) -> None:
        expected = {"content": "[REDACTED BY TOOLUSEPROXY]"}

        result = self._compare(expected, {"content": "x" * (33 * 1024)})

        self.assertEqual("unobserved", result.disposition)
        self.assertEqual("input_bytes_exceeded", result.diagnostic_code)

    def test_registry_drift_remains_unobserved(self) -> None:
        expected = {"content": "[REDACTED BY TOOLUSEPROXY]"}
        canonical = canonical_json_bytes(expected)
        expected_hash = sha256_bytes(canonical)
        expected_structure = structure_sha256(expected)
        assert expected_hash is not None and expected_structure is not None

        result = compare_mcp_post_input(
            tool_name=TOOL_NAME,
            tool_input=expected,
            profile_id=PROFILE.profile_id,
            profile_version=PROFILE.profile_version,
            profile_registry_version="mcp-registry-v1:" + "0" * 64,
            rewritten_input_sha256=expected_hash,
            structure_sha256_after=expected_structure,
        )

        self.assertEqual("unobserved", result.disposition)
        self.assertEqual("profile_version_mismatch", result.diagnostic_code)

    def test_codex_managed_file_input_is_never_full_input_confirmed(self) -> None:
        file_profile = McpToolProfile(
            profile_id="files/read_file",
            server="files",
            tool="read_file",
            sink_type="external_api_call",
            fields=(
                McpFieldSpec(
                    pointer="/path",
                    value_type="string",
                    field_class="file",
                    required=True,
                ),
            ),
            post_input_stable=False,
        )
        registry = McpProfileRegistry((file_profile,))
        expected = {"path": "notes.txt"}
        canonical = canonical_json_bytes(expected)
        expected_hash = sha256_bytes(canonical)
        expected_structure = structure_sha256(expected)
        assert expected_hash is not None and expected_structure is not None

        result = compare_mcp_post_input(
            tool_name="mcp__files__read_file",
            tool_input=expected,
            profile_id=file_profile.profile_id,
            profile_version=file_profile.profile_version,
            profile_registry_version=registry.registry_version,
            rewritten_input_sha256=expected_hash,
            structure_sha256_after=expected_structure,
            profile_registry=registry,
        )

        self.assertEqual("unobserved", result.disposition)
        self.assertEqual("post_input_unstable", result.diagnostic_code)

    def _compare(self, expected: dict[str, object], actual: object):
        canonical = canonical_json_bytes(expected)
        expected_hash = sha256_bytes(canonical)
        expected_structure = structure_sha256(expected)
        assert expected_hash is not None and expected_structure is not None
        return compare_mcp_post_input(
            tool_name=TOOL_NAME,
            tool_input=actual,
            profile_id=PROFILE.profile_id,
            profile_version=PROFILE.profile_version,
            profile_registry_version=(
                DEFAULT_MCP_PROFILE_REGISTRY.registry_version
            ),
            rewritten_input_sha256=expected_hash,
            structure_sha256_after=expected_structure,
        )


if __name__ == "__main__":
    unittest.main()
