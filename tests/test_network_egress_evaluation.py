from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from hook_monitor.evaluation.network_egress import (
    NetworkEgressDatasetError,
    evaluate_network_egress,
    load_network_egress_dataset,
    render_network_egress_report,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET_ROOT = REPO_ROOT / "tests" / "fixtures" / "network_egress" / "v1"
CLI_MODULE = "hook_monitor.evaluation.network_egress_cli"


class NetworkEgressEvaluationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = load_network_egress_dataset(DATASET_ROOT)
        cls.report = evaluate_network_egress(cls.dataset, split=None)

    def test_baseline_exposes_adapter_gap_without_gating_accuracy(self) -> None:
        report = self.report

        self.assertEqual(
            "3583b34379e0b6888e78ec6ad35ef910fc12593b4336f56ba66ee7c6f78214b8",
            report["dataset"]["sha256"],
        )
        self.assertEqual(21, report["dataset"]["case_count"])
        self.assertEqual(17, report["coverage"]["local_case_count"])
        self.assertEqual(2, report["coverage"]["hosted_case_count"])
        self.assertEqual(2, report["coverage"]["unobservable_case_count"])
        self.assertEqual(
            0.307692,
            report["metrics"]["adapter_externality"]["recall"],
        )
        self.assertEqual(
            0.8,
            report["metrics"]["adapter_externality"]["precision"],
        )
        self.assertEqual(0.692308, report["metrics"]["unknown_egress_rate"])
        self.assertEqual(0.933333, report["metrics"]["observer_attempt"]["recall"])
        self.assertEqual(0.857143, report["metrics"]["exact_join_rate"])
        self.assertTrue(report["summary"]["foundation_gate_passed"])
        self.assertFalse(report["summary"]["accuracy_gated"])
        self.assertFalse(report["summary"]["production_behavior_changed"])

    def test_report_is_value_free_and_does_not_execute_network(self) -> None:
        serialized = json.dumps(self.report, ensure_ascii=False, sort_keys=True)
        rendered = render_network_egress_report(self.report)

        self.assertEqual(0, self.report["privacy"]["raw_value_exposure_count"])
        self.assertFalse(self.report["configuration"]["network_execution"])
        self.assertFalse(self.report["configuration"]["payload_values_stored"])
        for forbidden in (
            '"command":',
            '"argv":',
            '"host":',
            '"url":',
            '"payload":',
            '"protected_value":',
            "https://",
        ):
            self.assertNotIn(forbidden, serialized)
            self.assertNotIn(forbidden, rendered)

    def test_hosted_surfaces_are_not_counted_as_local_observer_misses(self) -> None:
        hosted_ids = self.report["coverage"]["hosted_case_ids"]
        confusion = self.report["metrics"]["observer_attempt"]["confusion"]

        self.assertEqual(
            ["dev-web-public-hosted", "validation-web-public-hosted"], hosted_ids
        )
        self.assertEqual(1, confusion["false_negative"])

    def test_unknown_or_raw_case_field_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "dataset"
            shutil.copytree(DATASET_ROOT, root)
            cases_path = root / "cases.jsonl"
            records = [
                json.loads(line)
                for line in cases_path.read_text(encoding="utf-8").splitlines()
            ]
            records[0]["host"] = "forbidden"
            cases_path.write_text(
                "\n".join(json.dumps(record, sort_keys=True) for record in records)
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                NetworkEgressDatasetError, "object keys differ"
            ):
                load_network_egress_dataset(root)

    def test_invalid_hosted_denominator_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "dataset"
            shutil.copytree(DATASET_ROOT, root)
            cases_path = root / "cases.jsonl"
            records = [
                json.loads(line)
                for line in cases_path.read_text(encoding="utf-8").splitlines()
            ]
            records[-1]["observer_result"] = "unobserved"
            cases_path.write_text(
                "\n".join(json.dumps(record, sort_keys=True) for record in records)
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                NetworkEgressDatasetError,
                "outside the local observer denominator",
            ):
                load_network_egress_dataset(root)

    def test_cli_atomically_writes_same_json_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "network-egress.json"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    CLI_MODULE,
                    "--split",
                    "all",
                    "--format",
                    "json",
                    "--output-json",
                    str(output_path),
                    "--check",
                ],
                cwd=REPO_ROOT,
                check=False,
                text=True,
                capture_output=True,
            )

            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(
                json.loads(result.stdout),
                json.loads(output_path.read_text(encoding="utf-8")),
            )
            self.assertEqual([], list(Path(temporary_directory).glob(".*.tmp")))


if __name__ == "__main__":
    unittest.main()
