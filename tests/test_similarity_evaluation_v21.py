from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from hook_monitor.evaluation.dataset import (
    SimilarityDatasetError,
    load_similarity_dataset,
)
from hook_monitor.evaluation.similarity import evaluate_similarity


REPO_ROOT = Path(__file__).resolve().parents[1]
V2_ROOT = REPO_ROOT / "tests" / "fixtures" / "similarity" / "v2"
V21_ROOT = REPO_ROOT / "tests" / "fixtures" / "similarity" / "v2_1"
V2_DIGEST = "241a4f536ea53694b8172accc5a528961673a843983f99702651357cff3619b3"
V21_DIGEST = "1855ec5aae9fe3ecf61190f1631a1d72e0163c76dbbe6bc6954b221cb7b391cb"


class SimilarityEvaluationV21Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = load_similarity_dataset(V21_ROOT)

    def test_v21_is_independent_and_v2_remains_pinned(self) -> None:
        v2 = load_similarity_dataset(V2_ROOT)
        self.assertEqual(V2_DIGEST, v2.digest_sha256)
        self.assertEqual(V2_DIGEST, v2.pinned_digest_sha256)
        self.assertEqual(2, v2.schema_version)

        self.assertEqual(3, self.dataset.schema_version)
        self.assertEqual("2.1.0", self.dataset.dataset_version)
        self.assertEqual(V21_DIGEST, self.dataset.digest_sha256)
        self.assertEqual(V21_DIGEST, self.dataset.pinned_digest_sha256)

    def test_source_binding_signals_are_explicit_and_scope_safe(self) -> None:
        records = (*self.dataset.pairs, *self.dataset.retrieval_pools)
        for record in records:
            with self.subTest(record=record):
                if record.scope == "artifact_flow":
                    self.assertEqual(
                        "not_applicable",
                        record.source_binding_signal,
                    )
                else:
                    self.assertIn(
                        record.source_binding_signal,
                        {
                            "registered_source",
                            "selected_field",
                            "selected_security_field",
                        },
                    )
        self.assertTrue(
            all(
                scenario.source_binding_signal != "not_applicable"
                for scenario in self.dataset.scenarios
            )
        )

    def test_each_split_contains_declared_1k_to_10k_stress_sizes(self) -> None:
        contract = self.dataset.stress_contract
        assert contract is not None
        self.assertEqual((1_000, 5_000, 10_000), contract["generated_pool_sizes"])
        self.assertEqual(10_000, contract["maximum_candidate_count"])
        self.assertEqual(1.0, contract["minimum_saturation_rate"])
        for split in ("development", "validation"):
            sizes = {
                len(pool.candidates)
                for pool in self.dataset.select_retrieval_pools(split)
            }
            self.assertTrue({1_000, 5_000, 10_000}.issubset(sizes))

    def test_all_splits_reproduce_baseline_under_cap_pressure(self) -> None:
        for split in ("development", "validation", "all"):
            with self.subTest(split=split):
                report = evaluate_similarity(
                    self.dataset,
                    split=None if split == "all" else split,
                    benchmark_repeats=1,
                )
                self.assertEqual(3, report["schema_version"])
                self.assertEqual(
                    "similarity-evaluation-v2.1",
                    report["runner_version"],
                )
                self.assertTrue(report["baseline"]["reproduced"])
                self.assertTrue(report["summary"]["check_passed"])
                self.assertTrue(report["summary"]["go_no_go_passed"])
                for scope in ("artifact_flow", "source_binding"):
                    retrieval = report["metrics"]["candidate_retrieval"][scope]
                    self.assertEqual(1.0, retrieval["saturation_rate"])
                    self.assertEqual(1.0, retrieval["gate_saturated"]["recall"])

    def test_frozen_rule_passes_independent_development_and_validation_families(
        self,
    ) -> None:
        development_families = {
            pair.family for pair in self.dataset.select_pairs("development")
        }
        validation_families = {
            pair.family for pair in self.dataset.select_pairs("validation")
        }
        self.assertIn("alpha_source_signal_development", development_families)
        self.assertIn("alpha_source_signal_validation", validation_families)
        self.assertTrue(development_families.isdisjoint(validation_families))

        report = evaluate_similarity(
            self.dataset,
            split="validation",
            benchmark_repeats=1,
        )
        pairs = {case["id"]: case for case in report["cases"]["pairs"]}
        scenarios = {
            case["id"]: case for case in report["cases"]["scenarios"]
        }
        parity = {case["id"]: case for case in report["cases"]["parity"]}

        negative = pairs["v21-validation-open-catalog-negative"]
        positive = pairs["v21-validation-selected-credential-positive"]
        self.assertEqual((False, False, "none"), (
            negative["expected"],
            negative["actual"],
            negative["method"],
        ))
        self.assertEqual((True, True, "substring"), (
            positive["expected"],
            positive["actual"],
            positive["method"],
        ))

        negative_scenario = scenarios["v21-validation-open-catalog-scenario"]
        positive_scenario = scenarios[
            "v21-validation-selected-credential-scenario"
        ]
        self.assertEqual((False, "allow"), (
            negative_scenario["actual_reach"],
            negative_scenario["actual_action"],
        ))
        self.assertEqual((True, "block"), (
            positive_scenario["actual_reach"],
            positive_scenario["actual_action"],
        ))
        self.assertTrue(
            parity["v21-validation-open-catalog-scenario"]["passed"]
        )
        self.assertTrue(
            parity["v21-validation-selected-credential-scenario"]["passed"]
        )

    def test_builder_reproduces_committed_fixture(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "scripts.build_similarity_v21_fixture",
                "--check",
            ],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(V21_DIGEST, result.stdout.strip())

    def test_loader_rejects_missing_or_cross_scope_signal(self) -> None:
        mutations = (
            ("missing=source_binding_signal", self._remove_signal),
            ("artifact_flow requires", self._set_artifact_source_signal),
            ("requires an explicit source signal", self._remove_source_context),
        )
        for expected, mutate in mutations:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as temp:
                root = Path(temp) / "v2_1"
                shutil.copytree(V21_ROOT, root)
                mutate(root)
                with self.assertRaisesRegex(SimilarityDatasetError, expected):
                    load_similarity_dataset(root)

    @staticmethod
    def _records(path: Path) -> list[dict[str, object]]:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    @staticmethod
    def _write_records(path: Path, records: list[dict[str, object]]) -> None:
        path.write_text(
            "".join(json.dumps(item, separators=(",", ":")) + "\n" for item in records),
            encoding="utf-8",
        )

    def _remove_signal(self, root: Path) -> None:
        path = root / "pairs.jsonl"
        records = self._records(path)
        records[0].pop("source_binding_signal")
        self._write_records(path, records)

    def _set_artifact_source_signal(self, root: Path) -> None:
        path = root / "pairs.jsonl"
        records = self._records(path)
        artifact = next(item for item in records if item["scope"] == "artifact_flow")
        artifact["source_binding_signal"] = "registered_source"
        self._write_records(path, records)

    def _remove_source_context(self, root: Path) -> None:
        path = root / "pairs.jsonl"
        records = self._records(path)
        source = next(item for item in records if item["scope"] == "source_binding")
        source["source_binding_signal"] = "not_applicable"
        self._write_records(path, records)


if __name__ == "__main__":
    unittest.main()
