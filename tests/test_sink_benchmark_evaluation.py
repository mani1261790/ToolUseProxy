from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import hook_monitor.evaluation.sink_benchmark as sink_benchmark_evaluation
from hook_monitor.evaluation.sink_benchmark import (
    PROFILE_DIRECT,
    PROFILE_LINEAGE,
    PROFILE_RESOLVED,
    PROFILE_SEMANTIC,
    evaluate_sink_benchmark,
    render_sink_benchmark_report,
)
from hook_monitor.evaluation.sink_benchmark_dataset import (
    load_sink_benchmark_dataset,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET_ROOT = REPO_ROOT / "tests" / "fixtures" / "sink_benchmark" / "v1"
CLI_MODULE = "hook_monitor.evaluation.sink_benchmark_cli"


class SelectiveSemanticBackend:
    def cosine_similarity(self, left_text: str, right_text: str) -> float:
        positive_pair = (
            ("Project Lantern" in left_text and "seaside release" in right_text)
            or ("violet migration" in left_text and "purple data move" in right_text)
        )
        return 0.95 if positive_pair else 0.05


class SinkBenchmarkEvaluationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = load_sink_benchmark_dataset(DATASET_ROOT)
        cls.report = evaluate_sink_benchmark(cls.dataset, split=None)

    def test_baseline_profiles_make_current_limits_explicit(self) -> None:
        report = self.report

        self.assertEqual(12, report["dataset"]["case_count"])
        self.assertEqual("all", report["dataset"]["split"])
        self.assertTrue(report["summary"]["quality_gate_passed"])
        self.assertFalse(report["summary"]["semantic_backend_available"])
        self.assertEqual(
            ["validation-http-file-reference-leak"],
            report["summary"]["unsupported_resolved_case_ids"],
        )
        self.assertEqual(
            0.5,
            report["metrics"][PROFILE_DIRECT]["all"]["detection"]["recall"],
        )
        self.assertEqual(
            0.6,
            report["metrics"][PROFILE_RESOLVED]["all"]["detection"]["recall"],
        )
        self.assertEqual(
            0,
            report["metrics"][PROFILE_SEMANTIC]["all"]["coverage"]["evaluated"],
        )
        self.assertEqual(
            0.5,
            report["metrics"][PROFILE_LINEAGE]["all"]["detection"]["recall"],
        )
        self.assertTrue(
            report["lineage_reference"]["full_incremental_parity_passed"]
        )

    def test_semantic_backend_is_pluggable_and_observe_only(self) -> None:
        report = evaluate_sink_benchmark(
            self.dataset,
            split=None,
            embedding_backend=SelectiveSemanticBackend(),
        )
        metric = report["metrics"][PROFILE_SEMANTIC]["all"]

        self.assertEqual(11, metric["coverage"]["evaluated"])
        self.assertEqual(1, metric["coverage"]["unsupported"])
        self.assertEqual(1.0, metric["detection"]["precision"])
        self.assertEqual(1.0, metric["detection"]["recall"])
        self.assertEqual(1.0, metric["action_accuracy"])
        self.assertEqual(
            [
                "dev-final-paraphrase-leak",
                "validation-final-paraphrase-leak",
            ],
            report["deltas"]["semantic_over_resolved"][
                "recovered_positive_ids"
            ],
        )
        self.assertTrue(report["configuration"]["semantic_observe_only"])

    def test_report_contains_no_fixture_content_or_target_payload(self) -> None:
        serialized = json.dumps(self.report, ensure_ascii=False, sort_keys=True)
        rendered = render_sink_benchmark_report(self.report)

        self.assertEqual(0, self.report["privacy"]["raw_fixture_values_in_report"])
        for case in self.dataset.cases:
            target = case.ingestion.events[-1].payload
            sensitive_literals = {
                case.ingestion.source.content,
                *case.ingestion.source.protected_values,
                json.dumps(target, ensure_ascii=False, sort_keys=True),
            }
            for literal in sensitive_literals:
                with self.subTest(case=case.case_id):
                    self.assertNotIn(literal, serialized)
                    self.assertNotIn(literal, rendered)

    def test_evaluator_reuses_public_source_ingestion_harness(self) -> None:
        real_evaluate = sink_benchmark_evaluation.evaluate_source_ingestion
        with patch.object(
            sink_benchmark_evaluation,
            "evaluate_source_ingestion",
            wraps=real_evaluate,
        ) as evaluate_source_ingestion:
            report = evaluate_sink_benchmark(self.dataset, split="development")

        evaluate_source_ingestion.assert_called_once()
        self.assertEqual(
            6,
            len(
                evaluate_source_ingestion.call_args.args[0].scenarios
            ),
        )
        self.assertTrue(
            report["lineage_reference"]["full_incremental_parity_passed"]
        )

    def test_cli_atomically_writes_same_json_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "sink-benchmark.json"
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

    def test_cli_rejects_missing_dataset_without_traceback(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                CLI_MODULE,
                "--dataset",
                str(REPO_ROOT / "missing-sink-benchmark"),
            ],
            cwd=REPO_ROOT,
            check=False,
            text=True,
            capture_output=True,
        )

        self.assertEqual(2, result.returncode)
        self.assertIn("sink benchmark error:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
