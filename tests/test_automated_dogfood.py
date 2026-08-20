from __future__ import annotations

import unittest

from scripts.dogfood_all import (
    AutomatedDogfoodFailure,
    _validate_child_report,
)


class AutomatedDogfoodTest(unittest.TestCase):
    def test_value_free_child_summary_accepts_success_contract(self) -> None:
        summary = _validate_child_report(
            "plugin",
            {
                "status": "passed",
                "plugin_version": "0.1.0-alpha.test",
                "checks": {
                    "public_allowed": True,
                    "protected_denied": True,
                    "raw_value_exposure": False,
                },
                "metrics": {
                    "external_side_effect_count": 0,
                    "public_side_effect_count": 1,
                    "protected_side_effect_count": 0,
                },
            },
        )

        self.assertEqual(3, summary["check_count"])
        self.assertEqual(0, summary["external_side_effect_count"])
        self.assertEqual(1, summary["public_side_effect_count"])
        self.assertEqual(0, summary["protected_side_effect_count"])
        self.assertEqual("0.1.0-alpha.test", summary["plugin_version"])

    def test_child_summary_rejects_raw_exposure(self) -> None:
        with self.assertRaisesRegex(
            AutomatedDogfoodFailure,
            "child_check_failed",
        ):
            _validate_child_report(
                "plugin",
                {
                    "status": "passed",
                    "checks": {"raw_value_exposure": True},
                    "metrics": {
                        "external_side_effect_count": 0,
                        "public_side_effect_count": 1,
                        "protected_side_effect_count": 0,
                    },
                },
            )

    def test_child_summary_rejects_external_side_effect(self) -> None:
        with self.assertRaisesRegex(
            AutomatedDogfoodFailure,
            "external_side_effect_observed",
        ):
            _validate_child_report(
                "externality",
                {
                    "status": "passed",
                    "checks": {"protected_denied": True},
                    "metrics": {"external_side_effect_count": 1},
                },
            )

    def test_lifecycle_summary_reads_candidate_version(self) -> None:
        summary = _validate_child_report(
            "lifecycle",
            {
                "status": "passed",
                "candidate": {"plugin_version": "0.1.0-alpha.test"},
                "checks": {
                    "upgrade": True,
                    "rollback": True,
                    "raw_value_exposure": False,
                },
                "metrics": {"external_side_effect_count": 0},
            },
        )

        self.assertEqual("0.1.0-alpha.test", summary["plugin_version"])


if __name__ == "__main__":
    unittest.main()
