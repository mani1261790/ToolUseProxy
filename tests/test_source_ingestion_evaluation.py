from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import patch

import hook_monitor.evaluation.source_ingestion as source_ingestion_evaluation
from hook_monitor.evaluation.source_ingestion import (
    evaluate_source_ingestion,
    render_source_ingestion_report,
)
from hook_monitor.evaluation.source_ingestion_dataset import (
    load_source_ingestion_dataset,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET_ROOT = (
    REPO_ROOT / "tests" / "fixtures" / "similarity" / "ingestion" / "v2"
)
DATASET_V3_ROOT = (
    REPO_ROOT / "tests" / "fixtures" / "similarity" / "ingestion" / "v3"
)
CLI_MODULE = "hook_monitor.evaluation.source_ingestion_cli"


def iter_json_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from iter_json_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_json_strings(child)


class SourceIngestionEvaluationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = load_source_ingestion_dataset(DATASET_ROOT)
        cls.report = evaluate_source_ingestion(
            cls.dataset,
            split="development",
        )

    def test_version_two_selector_development_baseline_is_explicit(self) -> None:
        report = self.report
        reach = report["metrics"]["end_to_end"]["gate"]["reachability"]
        end_to_end = report["metrics"]["end_to_end"]["gate"]
        chunking = report["metrics"]["chunking"]
        adapters = report["metrics"]["adapter_extraction"]
        parity = report["metrics"]["full_incremental_parity"]

        self.assertEqual(6, report["dataset"]["scenario_count"])
        self.assertEqual("development", report["dataset"]["split"])
        self.assertEqual(
            {"tp": 3, "fp": 0, "tn": 3, "fn": 0},
            {key: reach[key] for key in ("tp", "fp", "tn", "fn")},
        )
        self.assertEqual(1.0, reach["f1"])
        self.assertEqual(1.0, end_to_end["action_accuracy"])
        self.assertEqual(1.0, chunking["exact_value_recall"])
        self.assertEqual(6, chunking["source_chunk_count"])
        self.assertEqual([], reach["false_negative_ids"])
        self.assertEqual([], reach["false_positive_ids"])
        self.assertEqual([], end_to_end["action_mismatch_ids"])
        self.assertEqual(1.0, adapters["accuracy"])
        self.assertEqual(6, adapters["matched"])
        self.assertTrue(parity["passed"])
        self.assertEqual(6, parity["case_count"])
        self.assertEqual([], parity["mismatch_ids"])
        self.assertEqual(1.0, report["summary"]["gate_reachability_f1"])
        self.assertEqual(1.0, report["summary"]["gate_action_accuracy"])
        self.assertEqual(1.0, report["summary"]["exact_value_chunk_recall"])
        self.assertEqual(1.0, report["summary"]["adapter_coverage_accuracy"])
        self.assertTrue(report["summary"]["parity_passed"])

    def test_full_and_incremental_modes_and_every_parity_layer_match(self) -> None:
        scenarios = self.report["cases"]["scenarios"]
        parity_cases = self.report["cases"]["parity"]

        self.assertEqual(6, len(scenarios))
        self.assertEqual(6, len(parity_cases))
        for scenario in scenarios:
            with self.subTest(scenario=scenario["id"]):
                self.assertEqual("session-full", scenario["full_mode"])
                self.assertEqual(
                    "session-incremental",
                    scenario["incremental_mode"],
                )

        parity_fields = (
            "sources_equal",
            "chunks_equal",
            "resources_equal",
            "sinks_equal",
            "artifact_edges_equal",
            "source_edges_equal",
            "assignments_equal",
            "findings_equal",
            "decisions_equal",
            "cursor_equal",
            "outcome_equal",
            "bash_submissions_equal",
            "full_mode_valid",
            "incremental_mode_valid",
            "passed",
        )
        for parity_case in parity_cases:
            with self.subTest(scenario=parity_case["id"]):
                for field in parity_fields:
                    self.assertTrue(parity_case[field], field)

    def test_report_contains_ids_but_no_source_or_raw_target_bodies(self) -> None:
        serialized = json.dumps(self.report, ensure_ascii=False, sort_keys=True)
        rendered = render_source_ingestion_report(self.report)
        development_scenarios = self.dataset.select_scenarios("development")

        self.assertIn(development_scenarios[0].scenario_id, serialized)
        for scenario in development_scenarios:
            target_payload = scenario.events[-1].payload
            raw_target = json.dumps(
                target_payload,
                ensure_ascii=False,
                sort_keys=True,
            )
            body_values: list[Any] = []
            if "tool_input" in target_payload:
                body_values.append(target_payload["tool_input"])
            for key in (
                "last_assistant_message",
                "final_answer",
                "response",
                "assistant_response",
                "message",
            ):
                if key in target_payload:
                    body_values.append(target_payload[key])

            fixture_literals = {
                scenario.source.content,
                raw_target,
                *scenario.source.protected_values,
                *(
                    text
                    for body in body_values
                    for text in iter_json_strings(body)
                ),
            }
            for fixture_literal in fixture_literals:
                with self.subTest(
                    scenario=scenario.scenario_id,
                    fixture_literal=fixture_literal,
                ):
                    self.assertNotIn(fixture_literal, serialized)
                    self.assertNotIn(fixture_literal, rendered)

    def test_evaluator_calls_public_runtime_analysis_entrypoint(self) -> None:
        scenario = self.dataset.select_scenarios("development")[0]
        single_scenario_dataset = replace(
            self.dataset,
            scenarios=(scenario,),
        )
        real_update = source_ingestion_evaluation.update_runtime_analysis

        with patch.object(
            source_ingestion_evaluation,
            "update_runtime_analysis",
            wraps=real_update,
        ) as update_runtime:
            report = evaluate_source_ingestion(
                single_scenario_dataset,
                split="development",
            )

        self.assertEqual(1 + len(scenario.events), update_runtime.call_count)
        self.assertEqual("session-full", report["cases"]["scenarios"][0]["full_mode"])
        self.assertEqual(
            "session-incremental",
            report["cases"]["scenarios"][0]["incremental_mode"],
        )
        for call in update_runtime.call_args_list:
            self.assertIn("current_event_id", call.kwargs)
            self.assertEqual(
                source_ingestion_evaluation.RUNTIME_GRAPH_DETECTOR_VERSION,
                call.kwargs["detector_version"],
            )

    def test_cli_renders_json_and_atomically_writes_the_same_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "source-ingestion.json"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    CLI_MODULE,
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
            self.assertEqual("3.0.0", saved_report["dataset"]["version"])
            self.assertTrue(saved_report["summary"]["parity_passed"])
            self.assertTrue(saved_report["summary"]["quality_gate_passed"])
            self.assertEqual([], list(Path(temporary_directory).glob(".*.tmp")))

    def test_cli_rejects_a_missing_dataset_without_a_traceback(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                CLI_MODULE,
                "--dataset",
                str(REPO_ROOT / "missing-source-ingestion-dataset"),
            ],
            cwd=REPO_ROOT,
            check=False,
            text=True,
            capture_output=True,
        )

        self.assertEqual(2, result.returncode)
        self.assertIn("missing source-ingestion dataset file", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


class SourceIngestionV3EvaluationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = load_source_ingestion_dataset(DATASET_V3_ROOT)
        cls.report = evaluate_source_ingestion(cls.dataset, split=None)

    def test_v3_closes_action_and_extraction_gates_without_false_blocks(
        self,
    ) -> None:
        report = self.report
        gate = report["metrics"]["end_to_end"]["gate"]
        reach = gate["reachability"]
        extraction = report["metrics"]["bash_submission_extraction"]
        parity = report["metrics"]["full_incremental_parity"]

        self.assertEqual(2, report["schema_version"])
        self.assertEqual("source-ingestion-evaluation-v3", report["runner_version"])
        self.assertEqual(20, report["dataset"]["scenario_count"])
        self.assertEqual(
            {"tp": 10, "fp": 0, "tn": 10, "fn": 0},
            {key: reach[key] for key in ("tp", "fp", "tn", "fn")},
        )
        self.assertEqual(1.0, reach["f1"])
        self.assertEqual(1.0, gate["action_accuracy"])
        self.assertEqual([], gate["false_blocks"])
        self.assertEqual([], gate["missed_blocks"])
        self.assertEqual(12, extraction["case_count"])
        self.assertEqual(1.0, extraction["case_accuracy"])
        self.assertEqual(13, extraction["segment_count"])
        self.assertEqual(1.0, extraction["segment_accuracy"])
        self.assertEqual(10, extraction["static_segment_count"])
        self.assertEqual(3, extraction["fallback_segment_count"])
        self.assertEqual(1.0, extraction["fallback_accuracy"])
        self.assertEqual(11, extraction["expected_value_count"])
        self.assertEqual(11, extraction["actual_value_count"])
        self.assertEqual(1.0, extraction["value_precision"])
        self.assertEqual(1.0, extraction["value_recall"])
        self.assertEqual(1.0, extraction["value_f1"])
        self.assertEqual([], extraction["case_mismatch_ids"])
        self.assertEqual([], extraction["segment_mismatch_ids"])
        self.assertEqual([], extraction["fallback_mismatch_ids"])
        self.assertTrue(parity["passed"])
        self.assertEqual(20, parity["case_count"])
        self.assertTrue(report["summary"]["quality_gate_passed"])

    def test_v3_report_exposes_counts_but_no_submission_values(self) -> None:
        serialized = json.dumps(self.report, ensure_ascii=False, sort_keys=True)
        rendered = render_source_ingestion_report(self.report)

        for scenario in self.dataset.scenarios:
            for projection in scenario.expected_bash_submissions:
                for submitted_value in projection.submitted_values:
                    with self.subTest(
                        scenario=scenario.scenario_id,
                        segment=projection.segment_index,
                    ):
                        self.assertNotIn(submitted_value, serialized)
                        self.assertNotIn(submitted_value, rendered)
        self.assertIn("bash submission extraction", rendered)

    def test_v3_quality_gate_fails_when_extraction_regresses(self) -> None:
        with patch.object(
            source_ingestion_evaluation,
            "extract_bash_http_submissions",
            return_value=(),
        ):
            report = evaluate_source_ingestion(self.dataset, split=None)

        extraction = report["metrics"]["bash_submission_extraction"]
        self.assertTrue(report["summary"]["parity_passed"])
        self.assertLess(extraction["case_accuracy"], 1.0)
        self.assertLess(extraction["segment_accuracy"], 1.0)
        self.assertFalse(report["summary"]["quality_gate_passed"])


if __name__ == "__main__":
    unittest.main()
