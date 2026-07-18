from __future__ import annotations

import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from hook_monitor.evaluation import protected_source_discovery_cli
from hook_monitor.evaluation.protected_source_discovery import (
    EXPECTED_V1_DATASET_SHA256,
    ProtectedSourceDiscoveryDatasetError,
    evaluate_protected_source_discovery,
    load_protected_source_discovery_dataset,
    render_protected_source_discovery_report,
)
from tooluseproxy.protected_sources import (
    ProtectedSourceRegistrationError,
    suggest_protected_source,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET_ROOT = (
    REPO_ROOT / "tests" / "fixtures" / "protected_source_discovery" / "v1"
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
    def test_version_one_corpus_has_the_pinned_24_by_10_template(self) -> None:
        dataset = load_protected_source_discovery_dataset(DATASET_ROOT)

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
        dataset = load_protected_source_discovery_dataset(DATASET_ROOT)
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
        shutil.copytree(DATASET_ROOT, root)

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


class ProtectedSourceDiscoveryEvaluationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = load_protected_source_discovery_dataset(DATASET_ROOT)
        cls.report = evaluate_protected_source_discovery(
            cls.dataset,
            scanner=_baseline_scanner,
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

    def test_production_scanner_reproduces_the_pinned_baseline(self) -> None:
        report = evaluate_protected_source_discovery(self.dataset)

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
            scanner=_baseline_scanner,
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
            scanner=_baseline_scanner,
        )
        validation = evaluate_protected_source_discovery(
            self.dataset,
            split="validation",
            scanner=_baseline_scanner,
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
                    _baseline_scanner,
                ),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                exit_code = protected_source_discovery_cli.main(
                    [
                        "--dataset",
                        str(DATASET_ROOT),
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


def _baseline_scanner(workspace: Path, *, workspace_id: str):
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
            candidate = suggest_protected_source(
                workspace,
                relative,
                workspace_id=workspace_id,
            )
        except ProtectedSourceRegistrationError:
            continue
        candidates.append(candidate)
    return SimpleNamespace(
        scanner_version="protected-source-scan-v1",
        scan_complete=True,
        truncation_reasons=(),
        candidates=tuple(candidates),
        skipped_counts={},
    )


def _leaking_scanner(workspace: Path, *, workspace_id: str):
    result = _baseline_scanner(workspace, workspace_id=workspace_id)
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
    leaked = replace(first, proposed_source=leaked_source)
    return SimpleNamespace(
        scanner_version=result.scanner_version,
        scan_complete=result.scan_complete,
        truncation_reasons=result.truncation_reasons,
        candidates=(leaked, *result.candidates[1:]),
        skipped_counts=result.skipped_counts,
    )


if __name__ == "__main__":
    unittest.main()
