from __future__ import annotations

import unittest
from unittest.mock import patch

from hook_monitor.externality.configuration import resolve_judge_configuration
from hook_monitor.externality.providers import CodexExecutableIdentity


class ExternalityConfigurationTest(unittest.TestCase):
    def test_default_is_off_and_non_codex_routes_are_rejected(self) -> None:
        self.assertEqual("not_configured", resolve_judge_configuration({}).status)
        for route in ("openai", "openai-then-codex", "auto", "other"):
            with self.subTest(route=route):
                result = resolve_judge_configuration(
                    {"TOOLUSEPROXY_EXTERNALITY_JUDGE_PROVIDER": route}
                )
                self.assertEqual("failed", result.status)
                self.assertEqual("configuration_invalid", result.failure_code)

    def test_openai_api_key_environment_cannot_enable_a_provider(self) -> None:
        result = resolve_judge_configuration(
            {
                "TOOLUSEPROXY_EXTERNALITY_JUDGE_PROVIDER": "off",
                "TOOLUSEPROXY_JUDGE_OPENAI_API_KEY": "must-be-ignored",
                "TOOLUSEPROXY_EXTERNALITY_JUDGE_OPENAI_MODEL": "must-be-ignored",
            }
        )
        self.assertEqual("not_configured", result.status)
        self.assertIsNone(result.chain)

    def test_codex_requires_matching_probe_receipt(self) -> None:
        identity = CodexExecutableIdentity(
            executable_path="/test/codex",
            version="codex-cli test",
            binary_sha256="a" * 64,
            path_sha256="b" * 64,
        )
        with patch(
            "hook_monitor.externality.configuration.resolve_codex_executable_identity",
            return_value=identity,
        ), patch(
            "hook_monitor.externality.configuration.verify_codex_probe_receipt",
            return_value=(False, "codex_probe_receipt_stale"),
        ):
            result = resolve_judge_configuration(
                {
                    "TOOLUSEPROXY_EXTERNALITY_JUDGE_PROVIDER": "codex",
                    "PLUGIN_DATA": "/plugin/data",
                }
            )
        self.assertEqual("failed", result.status)
        self.assertEqual("codex_probe_receipt_stale", result.failure_code)


if __name__ == "__main__":
    unittest.main()
