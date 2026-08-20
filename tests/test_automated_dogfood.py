from __future__ import annotations

import unittest

from scripts.dogfood_all import (
    AutomatedDogfoodFailure,
    REPORT_SCHEMAS,
    REQUIRED_CHECKS,
    _validate_child_report,
)


class AutomatedDogfoodTest(unittest.TestCase):
    @staticmethod
    def _payload(kind: str) -> dict[str, object]:
        checks = {
            name: name != "raw_value_exposure"
            for name in REQUIRED_CHECKS[kind]
        }
        metrics = {"external_side_effect_count": 0}
        if kind == "plugin":
            metrics.update(
                {
                    "public_side_effect_count": 1,
                    "protected_side_effect_count": 0,
                }
            )
        return {
            "schema_version": REPORT_SCHEMAS[kind],
            "status": "passed",
            "checks": checks,
            "metrics": metrics,
        }

    def test_value_free_child_summary_accepts_success_contract(self) -> None:
        payload = self._payload("plugin")
        payload["plugin_version"] = "0.1.0-alpha.test"
        summary = _validate_child_report(
            "plugin",
            payload,
        )

        self.assertEqual(len(REQUIRED_CHECKS["plugin"]), summary["check_count"])
        self.assertEqual(0, summary["external_side_effect_count"])
        self.assertEqual(1, summary["public_side_effect_count"])
        self.assertEqual(0, summary["protected_side_effect_count"])
        self.assertEqual("0.1.0-alpha.test", summary["plugin_version"])

    def test_child_summary_rejects_raw_exposure(self) -> None:
        payload = self._payload("plugin")
        checks = payload["checks"]
        assert isinstance(checks, dict)
        checks["raw_value_exposure"] = True
        with self.assertRaisesRegex(
            AutomatedDogfoodFailure,
            "child_check_failed",
        ):
            _validate_child_report("plugin", payload)

    def test_child_summary_rejects_external_side_effect(self) -> None:
        payload = self._payload("externality")
        metrics = payload["metrics"]
        assert isinstance(metrics, dict)
        metrics["external_side_effect_count"] = 1
        with self.assertRaisesRegex(
            AutomatedDogfoodFailure,
            "external_side_effect_observed",
        ):
            _validate_child_report("externality", payload)

    def test_lifecycle_summary_reads_candidate_version(self) -> None:
        payload = self._payload("lifecycle")
        payload["candidate"] = {"plugin_version": "0.1.0-alpha.test"}
        summary = _validate_child_report(
            "lifecycle",
            payload,
        )

        self.assertEqual("0.1.0-alpha.test", summary["plugin_version"])

    def test_child_summary_rejects_missing_required_check(self) -> None:
        payload = self._payload("externality")
        checks = payload["checks"]
        assert isinstance(checks, dict)
        checks.pop("hook_codex_call_count_zero")

        with self.assertRaisesRegex(
            AutomatedDogfoodFailure,
            "child_required_check_missing",
        ):
            _validate_child_report("externality", payload)

    def test_child_summary_rejects_unsupported_schema(self) -> None:
        payload = self._payload("lifecycle")
        payload["schema_version"] = 999

        with self.assertRaisesRegex(
            AutomatedDogfoodFailure,
            "child_schema_unsupported",
        ):
            _validate_child_report("lifecycle", payload)

    def test_child_summary_rejects_boolean_side_effect_count(self) -> None:
        payload = self._payload("plugin")
        metrics = payload["metrics"]
        assert isinstance(metrics, dict)
        metrics["external_side_effect_count"] = False

        with self.assertRaisesRegex(
            AutomatedDogfoodFailure,
            "side_effect_count_invalid",
        ):
            _validate_child_report("plugin", payload)


if __name__ == "__main__":
    unittest.main()
