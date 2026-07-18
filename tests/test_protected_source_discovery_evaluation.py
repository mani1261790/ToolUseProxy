from __future__ import annotations

import hashlib
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from hook_monitor.evaluation import protected_source_discovery_cli
from hook_monitor.evaluation.protected_source_discovery import (
    EXPECTED_V1_DATASET_SHA256,
    EXPECTED_V2_DATASET_SHA256,
    ProtectedSourceDiscoveryDatasetError,
    evaluate_protected_source_discovery,
    load_protected_source_discovery_dataset,
    render_protected_source_discovery_report,
)
from tooluseproxy import protected_sources
from tooluseproxy.protected_sources import ProtectedSourceRegistrationError


REPO_ROOT = Path(__file__).resolve().parents[1]
V1_DATASET_ROOT = (
    REPO_ROOT / "tests" / "fixtures" / "protected_source_discovery" / "v1"
)
V2_DATASET_ROOT = (
    REPO_ROOT / "tests" / "fixtures" / "protected_source_discovery" / "v2"
)
_PRUNED_DIRECTORIES = frozenset(
    {
        ".git",
        ".cache",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "target",
        "vendor",
    }
)


class ProtectedSourceDiscoveryDatasetTest(unittest.TestCase):
    def test_version_one_fixture_bytes_are_immutable(self) -> None:
        expected = {
            "manifest.json": (
                "8d207c1194926bd959e774a90300301b142de77617cb5369e850f7358f0d8414"
            ),
            "scenarios.jsonl": (
                "db2937f990df3b58254cc5fb3de1787ff1414187161d64bfa1228937b091d654"
            ),
        }
        for name, digest in expected.items():
            with self.subTest(name=name):
                self.assertEqual(
                    digest,
                    hashlib.sha256((V1_DATASET_ROOT / name).read_bytes()).hexdigest(),
                )

    def test_version_one_corpus_has_the_pinned_24_by_10_template(self) -> None:
        dataset = load_protected_source_discovery_dataset(V1_DATASET_ROOT)

        self.assertEqual(EXPECTED_V1_DATASET_SHA256, dataset.digest_sha256)
        self.assertEqual(24, len(dataset.scenarios))
        self.assertEqual(240, sum(len(item.files) for item in dataset.scenarios))
        self.assertEqual(12, len(dataset.select_scenarios("development")))
        self.assertEqual(12, len(dataset.select_scenarios("validation")))
        self.assertEqual(
            {
                "scenarios": 24,
                "files": 240,
                "development_scenarios": 12,
                "validation_scenarios": 12,
                "supported_positive": 48,
                "supported_negative": 144,
                "out_of_scope_protected": 24,
                "excluded_irrelevant": 24,
            },
            dataset.expected_counts,
        )
        for scenario in dataset.scenarios:
            counts: dict[str, int] = {}
            for fixture in scenario.files:
                counts[fixture.category] = counts.get(fixture.category, 0) + 1
            self.assertEqual(
                {
                    "supported_positive": 2,
                    "supported_negative": 6,
                    "out_of_scope_protected": 1,
                    "excluded_irrelevant": 1,
                },
                counts,
            )

    def test_corpus_covers_required_paths_and_challenging_negatives(self) -> None:
        dataset = load_protected_source_discovery_dataset(V1_DATASET_ROOT)
        fixtures = [fixture for scenario in dataset.scenarios for fixture in scenario.files]
        tags = {tag for fixture in fixtures for tag in fixture.tags}
        paths = {fixture.relative_path for fixture in fixtures}

        self.assertTrue(
            {
                "arrays",
                "rfc6901",
                "gitignored",
                "unicode",
                "space_path",
                "examples",
                "fixtures",
                "placeholder",
                "auth",
                "token_type",
                "password_policy",
                "neutral_json",
            }.issubset(tags)
        )
        self.assertIn(".gitignore", paths)
        self.assertIn("設定/秘密 候補.JSON", paths)
        self.assertTrue(
            any(
                fixture.category == "supported_positive"
                and "examples" in fixture.tags
                for fixture in fixtures
            )
        )
        self.assertTrue(
            any(
                fixture.category == "supported_positive"
                and "fixtures" in fixture.tags
                for fixture in fixtures
            )
        )
        self.assertTrue(
            any(
                fixture.category == "supported_negative"
                and "placeholder" in fixture.tags
                and "fixtures" in fixture.tags
                for fixture in fixtures
            )
        )

    def test_loader_rejects_schema_count_id_and_path_drift(self) -> None:
        mutations = (
            ("schema mismatch", self._add_unknown_file_field),
            ("expected counts do not match", self._change_expected_count),
            ("duplicate file ids", self._duplicate_file_id),
            ("inside the workspace", self._escape_file_path),
            ("resembles a real AWS access key", self._add_credential_shape),
        )
        for expected, mutate in mutations:
            with self.subTest(expected=expected):
                with self._copied_dataset() as root:
                    mutate(root)
                    with self.assertRaisesRegex(
                        ProtectedSourceDiscoveryDatasetError,
                        expected,
                    ):
                        load_protected_source_discovery_dataset(root)

    def _copied_dataset(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name) / "v1"
        shutil.copytree(V1_DATASET_ROOT, root)

        class DatasetCopy:
            def __enter__(self) -> Path:
                return root

            def __exit__(self, *_args: object) -> None:
                temporary.cleanup()

        return DatasetCopy()

    @staticmethod
    def _read_scenarios(root: Path) -> list[dict[str, object]]:
        return [
            json.loads(line)
            for line in (root / "scenarios.jsonl").read_text(
                encoding="utf-8"
            ).splitlines()
        ]

    @staticmethod
    def _write_scenarios(root: Path, records: list[dict[str, object]]) -> None:
        (root / "scenarios.jsonl").write_text(
            "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records),
            encoding="utf-8",
        )

    def _add_unknown_file_field(self, root: Path) -> None:
        records = self._read_scenarios(root)
        records[0]["files"][0]["unknown"] = True  # type: ignore[index]
        self._write_scenarios(root, records)

    @staticmethod
    def _change_expected_count(root: Path) -> None:
        path = root / "manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["expected_counts"]["files"] = 239
        path.write_text(json.dumps(manifest), encoding="utf-8")

    def _duplicate_file_id(self, root: Path) -> None:
        records = self._read_scenarios(root)
        records[0]["files"][1]["id"] = records[0]["files"][0]["id"]  # type: ignore[index]
        self._write_scenarios(root, records)

    def _escape_file_path(self, root: Path) -> None:
        records = self._read_scenarios(root)
        records[0]["files"][0]["path"] = "../outside.json"  # type: ignore[index]
        self._write_scenarios(root, records)

    def _add_credential_shape(self, root: Path) -> None:
        records = self._read_scenarios(root)
        records[0]["files"][0]["content"] += "AKIA1234567890ABCDEF"  # type: ignore[index,operator]
        self._write_scenarios(root, records)


class ProtectedSourceDiscoveryV2DatasetTest(unittest.TestCase):
    def test_v2_corpus_has_pinned_32_by_13_stratification(self) -> None:
        dataset = load_protected_source_discovery_dataset(V2_DATASET_ROOT)

        self.assertEqual(EXPECTED_V2_DATASET_SHA256, dataset.digest_sha256)
        self.assertEqual(32, len(dataset.scenarios))
        self.assertEqual(416, sum(len(item.files) for item in dataset.scenarios))
        self.assertEqual(16, len(dataset.select_scenarios("development")))
        self.assertEqual(16, len(dataset.select_scenarios("validation")))
        self.assertEqual(
            {
                "scenarios": 32,
                "files": 416,
                "development_scenarios": 16,
                "validation_scenarios": 16,
                "supported_positive": 96,
                "supported_negative": 256,
                "out_of_scope_protected": 32,
                "excluded_irrelevant": 32,
            },
            dataset.expected_counts,
        )
        for scenario in dataset.scenarios:
            self.assertEqual(
                dataset.category_counts_per_scenario,
                _count_by(scenario.files, "category"),
            )
            self.assertEqual(
                dataset.challenge_family_counts_per_scenario,
                _count_by(scenario.files, "challenge_family"),
            )

    def test_v2_splits_have_disjoint_vocab_profiles_paths_and_shapes(self) -> None:
        dataset = load_protected_source_discovery_dataset(V2_DATASET_ROOT)
        development = dataset.select_scenarios("development")
        validation = dataset.select_scenarios("validation")

        self.assertFalse(
            {item.profile for item in development}
            & {item.profile for item in validation}
        )
        self.assertFalse(_fixture_paths(development) & _fixture_paths(validation))
        self.assertFalse(
            _expected_selector_terminals(development)
            & _expected_selector_terminals(validation)
        )
        for dimension in dataset.split_vocabulary["development"]:
            self.assertFalse(
                {
                    _normalize_fixture_token(item)
                    for item in dataset.split_vocabulary["development"][dimension]
                }
                & {
                    _normalize_fixture_token(item)
                    for item in dataset.split_vocabulary["validation"][dimension]
                }
            )
        self.assertLessEqual(
            dataset.cross_split_feature_overlap,
            dataset.maximum_cross_split_feature_overlap,
        )
        self.assertEqual(0.068182, dataset.cross_split_feature_overlap)
        self.assertNotEqual(
            dataset.split_shape_sha256["development"],
            dataset.split_shape_sha256["validation"],
        )

    def test_v2_counterfactual_pairs_are_path_matched_and_mixed_are_exact(self) -> None:
        dataset = load_protected_source_discovery_dataset(V2_DATASET_ROOT)
        groups: dict[str, list[object]] = {}
        mixed = []
        for scenario in dataset.scenarios:
            for fixture in scenario.files:
                if fixture.counterfactual_group is not None:
                    groups.setdefault(fixture.counterfactual_group, []).append(fixture)
                if fixture.challenge_family == "positive_mixed_selector":
                    mixed.append(fixture)

        self.assertEqual(32, len(groups))
        for fixtures in groups.values():
            self.assertEqual(2, len(fixtures))
            self.assertEqual(1, len({item.relative_path for item in fixtures}))
            self.assertEqual(
                {"supported_positive", "supported_negative"},
                {item.category for item in fixtures},
            )
        self.assertEqual(32, len(mixed))
        self.assertTrue(
            all(
                sum(map(len, fixture.expected_selector.values())) == 1
                for fixture in mixed
                if fixture.expected_selector is not None
            )
        )

    def test_v2_loader_rejects_cross_split_leak_profile_family_and_shape_drift(
        self,
    ) -> None:
        mutations = (
            ("declared vocabulary appears", self._leak_development_token),
            ("profiles must be disjoint", self._copy_development_profile),
            ("hard-positive families", self._mislabel_hard_positive_family),
            ("shape digest drifted", self._change_validation_quote_shape),
        )
        for expected, mutation in mutations:
            with self.subTest(expected=expected), self._copied_v2() as root:
                mutation(root)
                with self.assertRaisesRegex(
                    ProtectedSourceDiscoveryDatasetError, expected
                ):
                    load_protected_source_discovery_dataset(root)

    def _copied_v2(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name) / "v2"
        shutil.copytree(V2_DATASET_ROOT, root)

        class DatasetCopy:
            def __enter__(self) -> Path:
                return root

            def __exit__(self, *_args: object) -> None:
                temporary.cleanup()

        return DatasetCopy()

    @staticmethod
    def _read_v2_records(root: Path) -> list[dict[str, object]]:
        return [
            json.loads(line)
            for line in (root / "scenarios.jsonl").read_text(
                encoding="utf-8"
            ).splitlines()
        ]

    @staticmethod
    def _write_v2_records(root: Path, records: list[dict[str, object]]) -> None:
        (root / "scenarios.jsonl").write_text(
            "".join(
                json.dumps(record, ensure_ascii=False) + "\n" for record in records
            ),
            encoding="utf-8",
        )

    def _leak_development_token(self, root: Path) -> None:
        records = self._read_v2_records(root)
        records[16]["files"][10]["content"] += "\nAUTH\n"  # type: ignore[index,operator]
        self._write_v2_records(root, records)

    def _copy_development_profile(self, root: Path) -> None:
        records = self._read_v2_records(root)
        records[16]["profile"] = records[0]["profile"]
        self._write_v2_records(root, records)

    @staticmethod
    def _mislabel_hard_positive_family(root: Path) -> None:
        path = root / "manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["scenario_contract"]["hard_positive_families"] = [
            "negative_placeholder_literal"
        ]
        path.write_text(json.dumps(manifest), encoding="utf-8")

    def _change_validation_quote_shape(self, root: Path) -> None:
        records = self._read_v2_records(root)
        content = records[16]["files"][1]["content"]  # type: ignore[index]
        records[16]["files"][1]["content"] = content.replace("'", '"')  # type: ignore[index,union-attr]
        self._write_v2_records(root, records)


class ProtectedSourceDiscoveryEvaluationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = load_protected_source_discovery_dataset(V1_DATASET_ROOT)
        cls.report = evaluate_protected_source_discovery(
            cls.dataset,
            scanner=_historical_v1_scanner,
        )

    def test_current_detector_baseline_is_explicit_but_below_go_threshold(self) -> None:
        report = self.report
        files = report["metrics"]["file_classification"]
        selectors = report["metrics"]["selector_classification"]

        self.assertEqual(
            {"tp": 48, "fp": 96, "tn": 48, "fn": 0},
            {key: files[key] for key in ("tp", "fp", "tn", "fn")},
        )
        self.assertEqual(0.333333, files["precision"])
        self.assertEqual(1.0, files["recall"])
        self.assertEqual(
            {"tp": 48, "fp": 96, "fn": 0},
            {key: selectors[key] for key in ("tp", "fp", "fn")},
        )
        self.assertEqual(1.0, selectors["exact_match_rate"])
        self.assertEqual(6.0, report["scanner"]["workspace_candidate_median"])
        self.assertFalse(report["summary"]["go_no_go_passed"])
        self.assertEqual("no_go", report["summary"]["status"])
        self.assertTrue(report["summary"]["baseline_reproduced"])
        self.assertTrue(report["summary"]["check_passed"])

    def test_historical_scanner_reproduces_the_pinned_baseline(self) -> None:
        report = evaluate_protected_source_discovery(
            self.dataset, scanner=_historical_v1_scanner
        )

        self.assertEqual(
            self.report["metrics"]["file_classification"],
            report["metrics"]["file_classification"],
        )
        self.assertEqual(
            self.report["metrics"]["selector_classification"],
            report["metrics"]["selector_classification"],
        )
        self.assertEqual(
            self.report["cases"]["files"],
            report["cases"]["files"],
        )
        self.assertTrue(report["summary"]["baseline_reproduced"])
        self.assertTrue(report["summary"]["privacy_passed"])
        self.assertTrue(report["summary"]["invariants_passed"])
        self.assertTrue(report["summary"]["check_passed"])

    def test_report_separates_scope_tag_failures_and_scan_completion(self) -> None:
        report = self.report
        scope = report["metrics"]["scope_coverage"]
        tags = report["metrics"]["by_tag"]

        self.assertEqual(0.666667, scope["supported_fraction"])
        self.assertEqual(24, scope["out_of_scope_protected_files"])
        self.assertEqual(0, scope["out_of_scope_candidate_count"])
        self.assertEqual(0, scope["excluded_candidate_count"])
        self.assertEqual(48, tags["placeholder"]["fp"])
        self.assertEqual(48, tags["metadata"]["fp"])
        self.assertEqual(24, tags["metadata"]["tn"])
        self.assertEqual(24, report["scanner"]["scan_complete_count"])
        self.assertEqual(0, report["scanner"]["scan_incomplete_count"])
        self.assertTrue(report["invariants"]["passed"])

    def test_report_is_deterministic_and_contains_no_values_or_internal_identity(self) -> None:
        second = evaluate_protected_source_discovery(
            self.dataset,
            scanner=_historical_v1_scanner,
        )
        self.assertEqual(self.report, second)

        serialized = json.dumps(self.report, ensure_ascii=False, sort_keys=True)
        rendered = render_protected_source_discovery_report(self.report)
        self.assertNotIn("candidate_revision", serialized)
        self.assertNotIn("candidate_id", serialized)
        self.assertNotIn("source_sha256", serialized)
        self.assertNotIn("content_hash", serialized)
        for scenario in self.dataset.scenarios:
            for fixture in scenario.files:
                for canary in fixture.canaries:
                    self.assertNotIn(canary, serialized)
                    self.assertNotIn(canary, rendered)
        self.assertIn("go/no-go=NO-GO check=PASS", rendered)
        self.assertEqual(0, self.report["metrics"]["privacy"]["total_exposure_count"])

    def test_development_and_validation_are_distinct_reproducible_splits(self) -> None:
        development = evaluate_protected_source_discovery(
            self.dataset,
            split="development",
            scanner=_historical_v1_scanner,
        )
        validation = evaluate_protected_source_discovery(
            self.dataset,
            split="validation",
            scanner=_historical_v1_scanner,
        )

        for report, split in (
            (development, "development"),
            (validation, "validation"),
        ):
            self.assertEqual(split, report["dataset"]["split"])
            self.assertEqual(12, report["dataset"]["scenarios"])
            self.assertEqual(120, report["dataset"]["files"])
            self.assertEqual(24, report["metrics"]["file_classification"]["tp"])
            self.assertEqual(48, report["metrics"]["file_classification"]["fp"])
            self.assertTrue(report["summary"]["baseline_reproduced"])
            self.assertTrue(report["summary"]["check_passed"])
        self.assertNotEqual(
            development["cases"]["files"][0]["id"],
            validation["cases"]["files"][0]["id"],
        )

    def test_candidate_public_canary_leak_fails_privacy_and_check(self) -> None:
        leaking = evaluate_protected_source_discovery(
            self.dataset,
            scanner=_leaking_scanner,
        )

        self.assertGreater(
            leaking["metrics"]["privacy"][
                "candidate_public_canary_exposure_count"
            ],
            0,
        )
        self.assertFalse(leaking["summary"]["privacy_passed"])
        self.assertFalse(leaking["summary"]["check_passed"])

    def test_cli_check_passes_reproducibility_without_hiding_numeric_no_go(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "discovery.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                patch(
                    "hook_monitor.evaluation.protected_source_discovery._default_scanner",
                    _historical_v1_scanner,
                ),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                exit_code = protected_source_discovery_cli.main(
                    [
                        "--dataset",
                        str(V1_DATASET_ROOT),
                        "--format",
                        "json",
                        "--output-json",
                        str(output),
                        "--check",
                    ]
                )

            self.assertEqual(0, exit_code, stderr.getvalue())
            stdout_report = json.loads(stdout.getvalue())
            saved_report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(stdout_report, saved_report)
            self.assertFalse(stdout_report["summary"]["go_no_go_passed"])
            self.assertTrue(stdout_report["summary"]["check_passed"])
            self.assertEqual([], list(Path(temporary_directory).glob(".*.tmp")))


class ProtectedSourceDiscoveryV2EvaluationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = load_protected_source_discovery_dataset(V2_DATASET_ROOT)
        cls.report = evaluate_protected_source_discovery(cls.dataset)

    def test_production_detector_reproduces_perfect_v2_go_baseline(self) -> None:
        report = self.report
        files = report["metrics"]["file_classification"]
        selectors = report["metrics"]["selector_classification"]

        self.assertEqual(
            {"tp": 96, "fp": 0, "tn": 256, "fn": 0},
            {key: files[key] for key in ("tp", "fp", "tn", "fn")},
        )
        self.assertEqual(1.0, files["precision"])
        self.assertEqual(1.0, files["recall"])
        self.assertEqual(1.0, selectors["precision"])
        self.assertEqual(1.0, selectors["recall"])
        self.assertEqual(1.0, selectors["detected_exact_match_rate"])
        self.assertEqual(3.0, report["scanner"]["workspace_candidate_median"])
        self.assertTrue(report["summary"]["go_no_go_passed"])
        self.assertTrue(report["summary"]["baseline_reproduced"])
        self.assertTrue(report["summary"]["check_passed"])

    def test_every_v2_family_and_counterfactual_group_is_correct(self) -> None:
        families = self.report["metrics"]["by_challenge_family"]

        self.assertEqual(13, len(families))
        for family, metrics in families.items():
            with self.subTest(family=family):
                self.assertEqual([], metrics["false_positive_ids"])
                self.assertEqual([], metrics["false_negative_ids"])
        self.assertEqual(1.0, self.report["metrics"]["hard_positive_recall"])
        self.assertEqual(
            1.0,
            self.report["metrics"]["negative_family_specificity"][
                "minimum_specificity"
            ],
        )
        self.assertEqual(
            {
                "group_count": 32,
                "passed": 32,
                "failed": 0,
                "accuracy": 1.0,
                "failed_ids": [],
            },
            self.report["metrics"]["counterfactual"],
        )

    def test_v2_uses_explicit_distinct_split_outcome_baselines(self) -> None:
        reports = {
            split: evaluate_protected_source_discovery(self.dataset, split=split)
            for split in ("development", "validation")
        }
        for split, report in reports.items():
            with self.subTest(split=split):
                self.assertEqual(16, report["dataset"]["scenarios"])
                self.assertEqual(48, report["metrics"]["file_classification"]["tp"])
                self.assertEqual(128, report["metrics"]["file_classification"]["tn"])
                self.assertEqual(
                    self.dataset.baselines[split], report["baseline"]["observed"]
                    | {"detector_version": "protected-source-candidate-v2"},
                )
                self.assertTrue(report["summary"]["check_passed"])
        self.assertNotEqual(
            reports["development"]["baseline"]["observed"][
                "case_outcomes_sha256"
            ],
            reports["validation"]["baseline"]["observed"][
                "case_outcomes_sha256"
            ],
        )

    def test_v2_report_is_deterministic_and_value_free(self) -> None:
        self.assertEqual(
            self.report, evaluate_protected_source_discovery(self.dataset)
        )
        serialized = json.dumps(self.report, ensure_ascii=False, sort_keys=True)
        for scenario in self.dataset.scenarios:
            for fixture in scenario.files:
                for canary in fixture.canaries:
                    self.assertNotIn(canary, serialized)
        self.assertEqual(0, self.report["metrics"]["privacy"]["total_exposure_count"])

    def test_mixed_detector_versions_cannot_reproduce_baseline(self) -> None:
        report = evaluate_protected_source_discovery(
            self.dataset,
            scanner=_mixed_version_scanner,
        )

        self.assertEqual(
            [
                "protected-source-candidate-v1",
                "protected-source-candidate-v2",
            ],
            report["scanner"]["detector_versions"],
        )
        self.assertFalse(report["summary"]["baseline_reproduced"])
        self.assertFalse(report["summary"]["check_passed"])

    def test_selected_scalar_preview_leak_fails_privacy_and_check(self) -> None:
        report = evaluate_protected_source_discovery(
            self.dataset,
            scanner=_selected_scalar_leaking_scanner,
        )

        self.assertGreater(
            report["metrics"]["privacy"][
                "candidate_selected_scalar_leaf_exposure_count"
            ],
            0,
        )
        self.assertFalse(report["summary"]["privacy_passed"])
        self.assertFalse(report["summary"]["check_passed"])

    def test_selected_scalar_sha256_leak_fails_privacy_and_check(self) -> None:
        report = evaluate_protected_source_discovery(
            self.dataset,
            scanner=_selected_scalar_sha256_leaking_scanner,
        )

        self.assertGreater(
            report["metrics"]["privacy"][
                "candidate_selected_scalar_fingerprint_leaf_exposure_count"
            ],
            0,
        )
        self.assertFalse(report["summary"]["privacy_passed"])
        self.assertFalse(report["summary"]["check_passed"])

    def test_embedded_selected_scalar_leak_fails_privacy_and_check(self) -> None:
        report = evaluate_protected_source_discovery(
            self.dataset,
            scanner=_embedded_selected_scalar_leaking_scanner,
        )

        self.assertGreater(
            report["metrics"]["privacy"][
                "candidate_selected_scalar_leaf_exposure_count"
            ],
            0,
        )
        self.assertEqual(
            len(self.dataset.scenarios),
            report["scanner"]["invalid_candidate_public_contract_count"],
        )
        self.assertFalse(report["summary"]["privacy_passed"])
        self.assertFalse(report["summary"]["baseline_reproduced"])
        self.assertFalse(report["summary"]["invariants_passed"])
        self.assertFalse(report["summary"]["check_passed"])

    def test_embedded_selected_scalar_sha256_leak_fails_privacy(self) -> None:
        report = evaluate_protected_source_discovery(
            self.dataset,
            scanner=_embedded_selected_scalar_sha256_leaking_scanner,
        )

        self.assertGreater(
            report["metrics"]["privacy"][
                "candidate_selected_scalar_fingerprint_leaf_exposure_count"
            ],
            0,
        )
        self.assertEqual(
            len(self.dataset.scenarios),
            report["scanner"]["invalid_candidate_public_contract_count"],
        )
        self.assertFalse(report["summary"]["privacy_passed"])
        self.assertFalse(report["summary"]["baseline_reproduced"])
        self.assertFalse(report["summary"]["invariants_passed"])
        self.assertFalse(report["summary"]["check_passed"])

    def test_unexpected_proposed_source_field_fails_contract_and_check(self) -> None:
        report = evaluate_protected_source_discovery(
            self.dataset,
            scanner=_unexpected_proposed_source_field_scanner,
        )

        self.assertEqual(
            len(self.dataset.scenarios),
            report["scanner"]["invalid_candidate_public_contract_count"],
        )
        self.assertFalse(
            report["invariants"]["no_invalid_candidate_public_contracts"]
        )
        self.assertFalse(report["summary"]["check_passed"])

    def test_cli_default_v2_requires_go_and_historical_detector_fails(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            passed = protected_source_discovery_cli.main(
                ["--split", "validation", "--format", "json", "--check", "--require-go"]
            )
        self.assertEqual(0, passed, stderr.getvalue())
        self.assertEqual("2.0.0", json.loads(stdout.getvalue())["dataset"]["version"])

        with (
            patch(
                "hook_monitor.evaluation.protected_source_discovery._default_scanner",
                _historical_v1_scanner,
            ),
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            failed = protected_source_discovery_cli.main(
                ["--dataset", str(V2_DATASET_ROOT), "--require-go"]
            )
        self.assertEqual(1, failed)


def _count_by(fixtures, attribute: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for fixture in fixtures:
        value = getattr(fixture, attribute)
        result[value] = result.get(value, 0) + 1
    return result


def _fixture_paths(scenarios) -> set[str]:
    return {
        fixture.relative_path
        for scenario in scenarios
        for fixture in scenario.files
    }


def _expected_selector_terminals(scenarios) -> set[str]:
    return {
        value.rsplit("/", 1)[-1].replace("~1", "/").replace("~0", "~")
        for scenario in scenarios
        for fixture in scenario.files
        if fixture.expected_selector is not None
        for values in fixture.expected_selector.values()
        for value in values
    }


def _normalize_fixture_token(value: str) -> str:
    return protected_sources._canonical_scalar_label(value)


def _historical_v1_scanner(workspace: Path, *, workspace_id: str):
    del workspace_id
    candidates = []
    for path in sorted(
        workspace.rglob("*"),
        key=lambda item: item.relative_to(workspace).as_posix().encode("utf-8"),
    ):
        relative = path.relative_to(workspace).as_posix()
        parts = Path(relative).parts
        if (
            not path.is_file()
            or relative == "protected_sources.json"
            or any(part in _PRUNED_DIRECTORIES for part in parts[:-1])
        ):
            continue
        name = path.name.casefold()
        if not (
            name == ".env"
            or name.startswith(".env.")
            or name.endswith(".json")
        ):
            continue
        try:
            source_kind = protected_sources._source_kind(relative)
            selector, reason_codes, confidence = (
                protected_sources._discover_selector(
                    source_kind,
                    path.read_text(encoding="utf-8"),
                    relative_path=relative,
                    detector_version=protected_sources.LEGACY_DETECTOR_VERSION,
                )
            )
            proposed_source = protected_sources._build_proposed_source(
                relative,
                selector,
            )
        except (OSError, UnicodeError, ProtectedSourceRegistrationError):
            continue
        candidates.append(
            SimpleNamespace(
                relative_path=relative,
                detector_version=protected_sources.LEGACY_DETECTOR_VERSION,
                reason_codes=reason_codes,
                confidence=confidence,
                proposed_source=proposed_source,
            )
        )
    return SimpleNamespace(
        scanner_version="protected-source-scan-v1",
        scan_complete=True,
        truncation_reasons=(),
        candidates=tuple(candidates),
        skipped_counts={},
    )


def _mixed_version_scanner(workspace: Path, *, workspace_id: str):
    result = protected_sources.scan_protected_sources(
        workspace, workspace_id=workspace_id
    )
    first, *remaining = result.candidates
    legacy = SimpleNamespace(
        relative_path=first.relative_path,
        detector_version=protected_sources.LEGACY_DETECTOR_VERSION,
        reason_codes=first.reason_codes,
        confidence=first.confidence,
        proposed_source=first.proposed_source,
    )
    return SimpleNamespace(
        scanner_version=result.scanner_version,
        scan_complete=result.scan_complete,
        truncation_reasons=result.truncation_reasons,
        candidates=(legacy, *remaining),
        skipped_counts=result.skipped_counts,
    )


def _selected_scalar_leaking_scanner(workspace: Path, *, workspace_id: str):
    result = protected_sources.scan_protected_sources(
        workspace, workspace_id=workspace_id
    )
    first, *remaining = result.candidates
    selected_value = _selected_value_for_candidate(workspace, first)
    leaked_source = dict(first.proposed_source)
    leaked_source["raw_preview"] = selected_value
    leaked = SimpleNamespace(
        relative_path=first.relative_path,
        detector_version=first.detector_version,
        reason_codes=first.reason_codes,
        confidence=first.confidence,
        proposed_source=leaked_source,
    )
    return SimpleNamespace(
        scanner_version=result.scanner_version,
        scan_complete=result.scan_complete,
        truncation_reasons=result.truncation_reasons,
        candidates=(leaked, *remaining),
        skipped_counts=result.skipped_counts,
    )


def _selected_scalar_sha256_leaking_scanner(
    workspace: Path, *, workspace_id: str
):
    result = _selected_scalar_leaking_scanner(
        workspace, workspace_id=workspace_id
    )
    first, *remaining = result.candidates
    leaked_source = dict(first.proposed_source)
    selected_value = leaked_source.pop("raw_preview")
    leaked_source["value_sha256"] = hashlib.sha256(
        selected_value.encode("utf-8")
    ).hexdigest()
    leaked = SimpleNamespace(
        relative_path=first.relative_path,
        detector_version=first.detector_version,
        reason_codes=first.reason_codes,
        confidence=first.confidence,
        proposed_source=leaked_source,
    )
    return SimpleNamespace(
        scanner_version=result.scanner_version,
        scan_complete=result.scan_complete,
        truncation_reasons=result.truncation_reasons,
        candidates=(leaked, *remaining),
        skipped_counts=result.skipped_counts,
    )


def _embedded_selected_scalar_leaking_scanner(
    workspace: Path, *, workspace_id: str
):
    result = protected_sources.scan_protected_sources(
        workspace, workspace_id=workspace_id
    )
    first, *remaining = result.candidates
    selected_value = _selected_value_for_candidate(workspace, first)
    leaked = SimpleNamespace(
        relative_path=first.relative_path,
        detector_version=first.detector_version,
        reason_codes=(*first.reason_codes, f"debug={selected_value}"),
        confidence=first.confidence,
        proposed_source=first.proposed_source,
    )
    return SimpleNamespace(
        scanner_version=result.scanner_version,
        scan_complete=result.scan_complete,
        truncation_reasons=result.truncation_reasons,
        candidates=(leaked, *remaining),
        skipped_counts=result.skipped_counts,
    )


def _embedded_selected_scalar_sha256_leaking_scanner(
    workspace: Path, *, workspace_id: str
):
    result = protected_sources.scan_protected_sources(
        workspace, workspace_id=workspace_id
    )
    first, *remaining = result.candidates
    selected_value = _selected_value_for_candidate(workspace, first)
    fingerprint = hashlib.sha256(selected_value.encode("utf-8")).hexdigest()
    leaked = SimpleNamespace(
        relative_path=first.relative_path,
        detector_version=first.detector_version,
        reason_codes=(*first.reason_codes, f"debug={fingerprint}"),
        confidence=first.confidence,
        proposed_source=first.proposed_source,
    )
    return SimpleNamespace(
        scanner_version=result.scanner_version,
        scan_complete=result.scan_complete,
        truncation_reasons=result.truncation_reasons,
        candidates=(leaked, *remaining),
        skipped_counts=result.skipped_counts,
    )


def _selected_value_for_candidate(workspace: Path, candidate: object) -> str:
    selector = candidate.proposed_source["selector"]
    source = workspace / candidate.relative_path
    if "dotenv_keys" in selector:
        assignments = {
            line.split("=", 1)[0].removeprefix("export ").strip():
            line.split("=", 1)[1].strip().strip("'\"")
            for line in source.read_text(encoding="utf-8").splitlines()
            if "=" in line
        }
        return assignments[selector["dotenv_keys"][0]]
    payload = json.loads(source.read_text(encoding="utf-8"))
    selected_value = payload
    for segment in selector["json_pointers"][0][1:].split("/"):
        decoded = segment.replace("~1", "/").replace("~0", "~")
        selected_value = (
            selected_value[int(decoded)]
            if isinstance(selected_value, list)
            else selected_value[decoded]
        )
    return selected_value


def _unexpected_proposed_source_field_scanner(
    workspace: Path, *, workspace_id: str
):
    result = protected_sources.scan_protected_sources(
        workspace, workspace_id=workspace_id
    )
    first, *remaining = result.candidates
    mutated_source = dict(first.proposed_source)
    mutated_source["diagnostic_marker"] = "non-secret"
    mutated = SimpleNamespace(
        relative_path=first.relative_path,
        detector_version=first.detector_version,
        reason_codes=first.reason_codes,
        confidence=first.confidence,
        proposed_source=mutated_source,
    )
    return SimpleNamespace(
        scanner_version=result.scanner_version,
        scan_complete=result.scan_complete,
        truncation_reasons=result.truncation_reasons,
        candidates=(mutated, *remaining),
        skipped_counts=result.skipped_counts,
    )


def _leaking_scanner(workspace: Path, *, workspace_id: str):
    result = _historical_v1_scanner(workspace, workspace_id=workspace_id)
    if not result.candidates:
        return result
    first = result.candidates[0]
    canary = next(
        line.split("=", 1)[1]
        for line in (workspace / first.relative_path).read_text(encoding="utf-8").splitlines()
        if "=" in line and not line.startswith("PUBLIC_MODE")
    ).split(" ", 1)[0].strip('"')
    leaked_source = dict(first.proposed_source)
    leaked_source["raw_preview"] = canary
    leaked = SimpleNamespace(**{**vars(first), "proposed_source": leaked_source})
    return SimpleNamespace(
        scanner_version=result.scanner_version,
        scan_complete=result.scan_complete,
        truncation_reasons=result.truncation_reasons,
        candidates=(leaked, *result.candidates[1:]),
        skipped_counts=result.skipped_counts,
    )


if __name__ == "__main__":
    unittest.main()
