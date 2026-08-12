from __future__ import annotations

import json
import unittest

from hook_monitor.evaluation.codex_network_live import _OtelState


def _attribute(key: str, value: str | int) -> dict[str, object]:
    value_key = "intValue" if isinstance(value, int) else "stringValue"
    return {"key": key, "value": {value_key: value}}


def _payload(*records: dict[str, object]) -> bytes:
    return json.dumps(
        {"resourceLogs": [{"scopeLogs": [{"logRecords": list(records)}]}]},
        separators=(",", ":"),
    ).encode()


class CodexNetworkLiveOtelTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
