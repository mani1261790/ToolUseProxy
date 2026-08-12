from __future__ import annotations

import json
import os
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from hook_monitor.evaluation.codex_network_live import (
    CodexNetworkLiveError,
    _isolated_probe_environment,
    _OtelState,
    _require_network_proxy_feature,
)


def _attribute(key: str, value: str | int) -> dict[str, object]:
    value_key = "intValue" if isinstance(value, int) else "stringValue"
    return {"key": key, "value": {value_key: value}}


def _payload(*records: dict[str, object]) -> bytes:
    return json.dumps(
        {"resourceLogs": [{"scopeLogs": [{"logRecords": list(records)}]}]},
        separators=(",", ":"),
    ).encode()


class CodexNetworkLiveOtelTest(unittest.TestCase):
    def test_probe_environment_does_not_inherit_credentials_or_proxy(self) -> None:
        with patch.dict(
            os.environ,
            {
                "HOME": "/test/home",
                "PATH": "/test/bin",
                "OPENAI_API_KEY": "secret",
                "HTTPS_PROXY": "https://proxy.invalid",
            },
            clear=True,
        ):
            environment = _isolated_probe_environment(Path("/test/codex-home"))

        self.assertEqual("/test/bin", environment["PATH"])
        self.assertEqual("/test/codex-home", environment["CODEX_HOME"])
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertNotIn("HTTPS_PROXY", environment)

    def test_network_proxy_feature_must_be_present_before_live_probe(self) -> None:
        completed = subprocess.CompletedProcess(
            ["codex", "features", "list"],
            0,
            stdout="shell_tool stable true\n",
            stderr="",
        )
        with patch(
            "hook_monitor.evaluation.codex_network_live.subprocess.run",
            return_value=completed,
        ):
            with self.assertRaisesRegex(
                CodexNetworkLiveError, "network proxy feature is unavailable"
            ):
                _require_network_proxy_feature("codex", 5.0)

    def test_network_event_is_reduced_to_value_free_booleans(self) -> None:
        state = _OtelState()
        state.set_turn_context("thread-fixed", 0.0)
        state.observe(
            _payload(
                {
                    "attributes": [
                        _attribute("event.name", "codex.network_proxy.policy_decision"),
                        _attribute("conversation.id", "thread-fixed"),
                        _attribute("network.policy.scope", "domain"),
                        _attribute("network.policy.decision", "deny"),
                        _attribute("network.policy.source", "baseline_policy"),
                        _attribute("network.policy.reason", "not_allowed"),
                        _attribute("network.transport.protocol", "https_connect"),
                        _attribute("server.address", "example.com"),
                        _attribute("server.port", 443),
                        _attribute("execution.id", "execution-fixed"),
                    ]
                }
            )
        )

        snapshot = state.snapshot()
        self.assertEqual(1, snapshot["request_count"])
        self.assertEqual(1, snapshot["network_event_count"])
        self.assertTrue(snapshot["context_matches_fixture"])
        self.assertTrue(snapshot["conversation_join"])
        self.assertEqual(1, snapshot["execution_id_count"])
        self.assertNotIn("example.com", json.dumps(snapshot, sort_keys=True))
        self.assertNotIn("thread-fixed", json.dumps(snapshot, sort_keys=True))

    def test_other_event_body_is_not_retained(self) -> None:
        state = _OtelState()
        state.observe(
            _payload(
                {
                    "body": {"stringValue": "sensitive tool output"},
                    "attributes": [_attribute("event.name", "codex.tool_result")],
                }
            )
        )

        snapshot = state.snapshot()
        self.assertEqual(1, snapshot["other_event_count"])
        self.assertEqual(1, snapshot["raw_capable_event_count"])
        self.assertNotIn("sensitive", json.dumps(snapshot, sort_keys=True))

    def test_invalid_otlp_is_counted_without_retaining_input(self) -> None:
        state = _OtelState()
        state.observe(b"not-json-sensitive")

        snapshot = state.snapshot()
        self.assertEqual(1, snapshot["parse_error_count"])
        self.assertNotIn("not-json-sensitive", json.dumps(snapshot, sort_keys=True))

    def test_malformed_attributes_are_counted_as_parse_errors(self) -> None:
        state = _OtelState()
        state.observe(_payload({"attributes": "not-an-attribute-list"}))

        snapshot = state.snapshot()
        self.assertEqual(1, snapshot["parse_error_count"])
        self.assertEqual(0, snapshot["other_event_count"])


if __name__ == "__main__":
    unittest.main()
