from __future__ import annotations

import unittest
from dataclasses import replace

from hook_monitor.analysis.adapters.mcp_profiles import (
    DEFAULT_MCP_INPUT_LIMITS,
    DEFAULT_MCP_PROFILE_REGISTRY,
    TOOLUSEPROXY_E2E_PUBLISH_TEXT_PROFILE,
    McpFieldSpec,
    McpInputLimits,
    McpProfileRegistry,
    McpToolProfile,
    escape_json_pointer_segment,
    inspect_mcp_input,
)


class McpProfileTest(unittest.TestCase):
    def test_default_profile_is_exact_case_sensitive_and_closed_world(self) -> None:
        self.assertEqual(
            (TOOLUSEPROXY_E2E_PUBLISH_TEXT_PROFILE,),
            DEFAULT_MCP_PROFILE_REGISTRY.profiles,
        )
        profile = DEFAULT_MCP_PROFILE_REGISTRY.resolve(
            "tooluseproxy_e2e",
            "publish_text",
        )

        self.assertIs(TOOLUSEPROXY_E2E_PUBLISH_TEXT_PROFILE, profile)
        self.assertIsNone(
            DEFAULT_MCP_PROFILE_REGISTRY.resolve(
                "ToolUseProxy_E2E",
                "publish_text",
            )
        )
        assert profile is not None
        self.assertEqual(("/content",), profile.outbound_data_pointers)
        self.assertEqual((), profile.control_pointers)
        self.assertEqual(("/content",), profile.redactable_pointers)
        self.assertEqual((), profile.file_input_pointers)
        self.assertTrue(profile.preview_eligible)

    def test_profile_validation_rejects_partial_or_unknown_shapes(self) -> None:
        profile = TOOLUSEPROXY_E2E_PUBLISH_TEXT_PROFILE

        self.assertTrue(profile.validate({"content": "public"}).accepted)
        self.assertEqual(
            "missing_required_field",
            profile.validate({}).rejection_code,
        )
        self.assertEqual(
            "unknown_field",
            profile.validate(
                {
                    "content": "public",
                    "unknown": "value",
                }
            ).rejection_code,
        )
        self.assertEqual(
            "wrong_field_type",
            profile.validate({"content": 1}).rejection_code,
        )
        self.assertEqual(
            "unsupported_nesting",
            profile.validate({"content": {"text": "public"}}).rejection_code,
        )
        self.assertEqual(
            "unsupported_nesting",
            profile.validate({"content": ["public"]}).rejection_code,
        )

    def test_profile_rejection_is_independent_of_key_insertion_order(self) -> None:
        profile = McpToolProfile(
            profile_id="fixture/deterministic",
            server="fixture",
            tool="deterministic",
            sink_type="external_api_call",
            fields=(
                McpFieldSpec("/a", "string", "data"),
                McpFieldSpec("/b", "string", "data"),
            ),
            post_input_stable=True,
        )
        forward = {"a": {}, "b": None}
        reverse = {"b": None, "a": {}}

        self.assertEqual(
            profile.validate(forward),
            profile.validate(reverse),
        )
        self.assertEqual(
            "unsupported_nesting",
            profile.validate(forward).rejection_code,
        )

    def test_profile_and_registry_versions_follow_semantics(self) -> None:
        profile = TOOLUSEPROXY_E2E_PUBLISH_TEXT_PROFILE
        changed = replace(
            profile,
            fields=profile.fields
            + (
                McpFieldSpec(
                    pointer="/optional_note",
                    value_type="string",
                    field_class="data",
                ),
            ),
        )

        self.assertNotEqual(profile.profile_version, changed.profile_version)
        self.assertNotEqual(
            McpProfileRegistry((profile,)).registry_version,
            McpProfileRegistry((changed,)).registry_version,
        )

    def test_registry_rejects_duplicate_identity(self) -> None:
        profile = TOOLUSEPROXY_E2E_PUBLISH_TEXT_PROFILE
        with self.assertRaisesRegex(ValueError, "immutable tuple"):
            McpProfileRegistry([profile])  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "exact keys"):
            McpProfileRegistry((profile, replace(profile, profile_id="other")))
        with self.assertRaisesRegex(ValueError, "profile IDs"):
            McpProfileRegistry(
                (
                    profile,
                    replace(profile, server="other", tool="other"),
                )
            )

    def test_pointer_and_file_invariants_are_enforced(self) -> None:
        self.assertEqual("a~1b~0c", escape_json_pointer_segment("a/b~c"))
        with self.assertRaisesRegex(ValueError, "JSON Pointer"):
            McpFieldSpec("/bad~2pointer", "string", "data")
        with self.assertRaisesRegex(ValueError, "top-level"):
            McpFieldSpec("/nested/value", "string", "data")
        with self.assertRaisesRegex(ValueError, "only MCP data"):
            McpFieldSpec("/destination", "string", "control", redactable=True)
        with self.assertRaisesRegex(ValueError, "only MCP string"):
            McpFieldSpec("/count", "number", "data", redactable=True)

        with self.assertRaisesRegex(ValueError, "immutable tuple"):
            McpToolProfile(
                profile_id="fixture/mutable",
                server="fixture",
                tool="mutable",
                sink_type="external_api_call",
                fields=[McpFieldSpec("/content", "string", "data")],  # type: ignore[arg-type]
                post_input_stable=False,
            )

        file_field = McpFieldSpec("/file", "string", "file")
        with self.assertRaisesRegex(ValueError, "file inputs"):
            McpToolProfile(
                profile_id="fixture/file",
                server="fixture",
                tool="upload",
                sink_type="external_file_transfer",
                fields=(file_field,),
                post_input_stable=True,
            )

    def test_input_limits_must_be_positive(self) -> None:
        with self.assertRaisesRegex(ValueError, "positive"):
            McpInputLimits(max_fields=0)
        for invalid in (True, 1.5, float("nan"), float("inf")):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "positive integers"):
                    McpInputLimits(max_input_bytes=invalid)  # type: ignore[arg-type]

    def test_input_inspection_uses_canonical_utf8_byte_boundary(self) -> None:
        overhead = len(b'{"content":""}')
        accepted = {"content": "x" * (32 * 1024 - overhead)}
        rejected = {"content": "x" * (32 * 1024 - overhead + 1)}

        accepted_result = inspect_mcp_input(accepted)
        rejected_result = inspect_mcp_input(rejected)
        multibyte_result = inspect_mcp_input({"content": "秘" * 11_000})

        self.assertTrue(accepted_result.accepted)
        self.assertEqual(32 * 1024, accepted_result.input_bytes)
        self.assertEqual("input_bytes_exceeded", rejected_result.rejection_code)
        self.assertEqual("input_bytes_exceeded", multibyte_result.rejection_code)

    def test_input_inspection_counts_fields_and_depth_without_root(self) -> None:
        accepted_fields = {f"field_{index}": index for index in range(32)}
        rejected_fields = {f"field_{index}": index for index in range(33)}
        mixed = {"items": ["a", "b"], "metadata": {"ok": True}}

        accepted_result = inspect_mcp_input(accepted_fields)
        rejected_result = inspect_mcp_input(rejected_fields)
        mixed_result = inspect_mcp_input(mixed)

        self.assertTrue(accepted_result.accepted)
        self.assertEqual(DEFAULT_MCP_INPUT_LIMITS.max_fields, accepted_result.field_count)
        self.assertEqual("field_count_exceeded", rejected_result.rejection_code)
        self.assertEqual(5, mixed_result.field_count)

        depth_eight: object = "value"
        depth_nine: object = "value"
        for _ in range(8):
            depth_eight = {"child": depth_eight}
        for _ in range(9):
            depth_nine = {"child": depth_nine}

        self.assertTrue(inspect_mcp_input(depth_eight).accepted)
        self.assertEqual(
            "nesting_depth_exceeded",
            inspect_mcp_input(depth_nine).rejection_code,
        )

    def test_input_inspection_rejection_is_insertion_order_independent(self) -> None:
        limits = McpInputLimits(max_input_bytes=32, max_fields=8, max_depth=2)
        deep = {"child": {"child": "value"}}
        forward = {"a_large": "x" * 64, "b_deep": deep}
        reverse = {"b_deep": deep, "a_large": "x" * 64}

        forward_result = inspect_mcp_input(forward, limits)
        reverse_result = inspect_mcp_input(reverse, limits)

        self.assertEqual(forward_result, reverse_result)
        self.assertEqual("input_bytes_exceeded", forward_result.rejection_code)

    def test_input_inspection_handles_empty_and_unsupported_values(self) -> None:
        empty = inspect_mcp_input({})

        self.assertTrue(empty.accepted)
        self.assertEqual(0, empty.field_count)
        self.assertEqual(0, empty.max_depth_seen)
        self.assertEqual("input_not_object", inspect_mcp_input([]).rejection_code)
        self.assertEqual(
            "unsupported_input_type",
            inspect_mcp_input({"value": float("nan")}).rejection_code,
        )
        self.assertEqual(
            "unsupported_input_type",
            inspect_mcp_input({"value": object()}).rejection_code,
        )


if __name__ == "__main__":
    unittest.main()
