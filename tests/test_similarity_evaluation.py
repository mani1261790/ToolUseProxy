from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import hook_monitor.evaluation.similarity as similarity_evaluation
from hook_monitor.evaluation.dataset import PairExample, load_similarity_dataset
from hook_monitor.evaluation.similarity import (
    RetrievalCandidate,
    evaluate_similarity,
    nearest_rank_percentile,
    render_similarity_report,
    simulate_candidate_retrieval,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET_ROOT = REPO_ROOT / "tests" / "fixtures" / "similarity" / "v1"
CLI_MODULE = "hook_monitor.evaluation.cli"


class SimilarityEvaluationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = load_similarity_dataset(DATASET_ROOT)
        cls.report = evaluate_similarity(
            cls.dataset,
            split="development",
            benchmark_repeats=1,
        )

    def test_development_report_separates_each_evaluation_layer(self) -> None:
        report = self.report

        self.assertEqual(24, report["dataset"]["pair_count"])
        self.assertEqual(10, report["dataset"]["scenario_count"])
        self.assertEqual(
            {"artifact_flow", "source_binding"},
            set(report["metrics"]["candidate_retrieval"]),
        )
        pair_metrics = report["metrics"]["pair_classification"]["gate"]
        self.assertEqual(
            pair_metrics["case_count"],
            pair_metrics["tp"]
            + pair_metrics["fp"]
            + pair_metrics["tn"]
            + pair_metrics["fn"],
        )
        self.assertIn("action_confusion", report["metrics"]["end_to_end"]["gate"])
        self.assertTrue(report["summary"]["parity_passed"])
        self.assertEqual(
            [],
            report["metrics"]["full_incremental_parity"]["mismatch_ids"],
        )
        self.assertGreater(report["metrics"]["latency_ms"]["pair"]["samples"], 0)

    def test_report_contains_case_ids_but_no_fixture_literals(self) -> None:
        report = self.report
        serialized = json.dumps(report, ensure_ascii=False)
        rendered = render_similarity_report(report)
        self.assertIn("dev-af-exact-01", serialized)
        case_ids = [pair.example_id for pair in self.dataset.pairs] + [
            scenario.scenario_id for scenario in self.dataset.scenarios
        ]
        for case_id in case_ids:
            serialized = serialized.replace(case_id, "<case-id>")
            rendered = rendered.replace(case_id, "<case-id>")

        fixture_texts = {
            text
            for pair in self.dataset.pairs
            for text in (pair.left_text, pair.right_text)
        }
        fixture_texts.update(scenario.source_text for scenario in self.dataset.scenarios)
        fixture_texts.update(
            text
            for scenario in self.dataset.scenarios
            for text in scenario.artifact_texts
        )
        for fixture_text in fixture_texts:
            with self.subTest(fixture_text=fixture_text):
                self.assertNotIn(fixture_text, serialized)
                self.assertNotIn(fixture_text, rendered)
        self.assertIn("pair gate", rendered)

    def test_report_makes_candidate_pool_scope_explicit(self) -> None:
        retrieval = self.report["metrics"]["candidate_retrieval"]
        rendered = render_similarity_report(self.report)

        self.assertFalse(retrieval["artifact_flow"]["pool_exceeds_limit"])
        self.assertFalse(retrieval["source_binding"]["pool_exceeds_limit"])
        self.assertIn("pool=12 cap_not_exercised", rendered)

    def test_parity_cases_compare_intermediate_and_policy_state(self) -> None:
        for parity_case in self.report["cases"]["parity"]:
            with self.subTest(case_id=parity_case["id"]):
                self.assertTrue(parity_case["assignments_equal"])
                self.assertTrue(parity_case["findings_equal"])
                self.assertTrue(parity_case["decisions_equal"])

    def test_version_one_runner_measures_current_production_outcome(self) -> None:
        pair = self.report["metrics"]["pair_classification"]["gate"]
        reach = self.report["metrics"]["end_to_end"]["gate"]["reachability"]

        self.assertEqual(
            {"tp": 10, "fp": 0, "tn": 12, "fn": 0},
            {key: pair[key] for key in ("tp", "fp", "tn", "fn")},
        )
        self.assertEqual(1.0, pair["f1"])
        self.assertEqual(
            {"tp": 6, "fp": 0, "tn": 3, "fn": 0},
            {key: reach[key] for key in ("tp", "fp", "tn", "fn")},
        )
        self.assertEqual([], pair["false_negative_ids"])

    def test_artifact_retrieval_prefers_latest_exact_candidate(self) -> None:
        candidates = (
            RetrievalCandidate("older", "exact synthetic value", 1),
            RetrievalCandidate("newer", "exact synthetic value", 3),
            RetrievalCandidate("middle", "exact synthetic value", 2),
        )

        self.assertEqual(
            ("newer",),
            simulate_candidate_retrieval(
                scope="artifact_flow",
                query_text="exact synthetic value",
                candidates=candidates,
            ),
        )

    def test_artifact_retrieval_applies_the_fifty_candidate_tie_limit(self) -> None:
        candidates = tuple(
            RetrievalCandidate(
                candidate_id=f"candidate-{index:02d}",
                text=f"abcdefgh{chr(0x4E00 + index)}",
                sequence_no=index + 1,
            )
            for index in range(52)
        )

        retrieved = simulate_candidate_retrieval(
            scope="artifact_flow",
            query_text="abcdefgh終",
            candidates=candidates,
        )

        self.assertEqual(50, len(retrieved))
        self.assertEqual(
            tuple(f"candidate-{index:02d}" for index in range(50)),
            retrieved,
        )

    def test_source_retrieval_keeps_exact_matches_and_caps_lexical_candidates(self) -> None:
        candidates = tuple(
            RetrievalCandidate(
                candidate_id=f"candidate-{index:03d}",
                text=f"abcdefgh{chr(0x3400 + index)}",
                sequence_no=index + 1,
            )
            for index in range(202)
        ) + (
            RetrievalCandidate("exact-old", "abcdefgh終", 1),
            RetrievalCandidate("exact-new", "abcdefgh終", 999),
        )

        retrieved = simulate_candidate_retrieval(
            scope="source_binding",
            query_text="abcdefgh終",
            candidates=candidates,
        )

        self.assertIn("exact-old", retrieved)
        self.assertIn("exact-new", retrieved)
        self.assertEqual(202, len(retrieved))
        self.assertEqual(
            200,
            sum(candidate_id.startswith("candidate-") for candidate_id in retrieved),
        )

    def test_source_retrieval_queries_source_against_artifact_candidates(self) -> None:
        pair = PairExample(
            example_id="orientation",
            split="development",
            scope="source_binding",
            left_text="source-side query",
            right_text="artifact-side candidate",
            should_link=True,
            observe_only=False,
            tags=("positive",),
            rationale="orientation test",
        )
        with patch.object(
            similarity_evaluation,
            "simulate_candidate_retrieval",
            return_value=(),
        ) as simulated:
            similarity_evaluation._evaluate_retrieval([pair])

        call = simulated.call_args
        self.assertEqual("source-side query", call.kwargs["query_text"])
        self.assertEqual(
            ["artifact-side candidate"],
            [candidate.text for candidate in call.kwargs["candidates"]],
        )

    def test_nearest_rank_percentile_is_deterministic(self) -> None:
        values = [9.0, 1.0, 7.0, 3.0, 5.0]
        self.assertEqual(5.0, nearest_rank_percentile(values, 0.50))
        self.assertEqual(9.0, nearest_rank_percentile(values, 0.95))
        with self.assertRaises(ValueError):
            nearest_rank_percentile([], 0.50)
        with self.assertRaises(ValueError):
            nearest_rank_percentile(values, 0.0)

    def test_cli_renders_json_and_atomically_writes_the_same_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "baseline.json"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    CLI_MODULE,
                    "--benchmark-repeats",
                    "1",
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
            stdout_report = json.loads(result.stdout)
            saved_report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(stdout_report, saved_report)
            self.assertEqual("development", saved_report["dataset"]["split"])
            self.assertTrue(saved_report["summary"]["parity_passed"])
            self.assertEqual(
                [],
                list(Path(temporary_directory).glob(".*.tmp")),
            )

    def test_cli_rejects_a_missing_dataset_without_a_traceback(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                CLI_MODULE,
                "--dataset",
                str(REPO_ROOT / "missing-similarity-dataset"),
                "--benchmark-repeats",
                "1",
            ],
            cwd=REPO_ROOT,
            check=False,
            text=True,
            capture_output=True,
        )

        self.assertEqual(2, result.returncode)
        self.assertIn("missing similarity dataset file", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
