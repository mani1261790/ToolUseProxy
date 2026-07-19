from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from hook_monitor.evaluation.external_holdout import (
    EXTERNAL_HOLDOUT_CONTRACT,
    EXTERNAL_HOLDOUT_CONTRACT_VERSION,
    ExternalHoldoutError,
    evaluate_external_holdout,
    load_external_holdout,
    render_external_holdout_report,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_MODULE = "hook_monitor.evaluation.external_holdout_cli"


class SimilarityExternalHoldoutTest(unittest.TestCase):
    def test_private_holdout_emits_only_aggregate_public_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "private-holdout"
            private_texts = self._write_holdout(root)
            dataset = load_external_holdout(
                root,
                forbidden_repository_root=REPO_ROOT,
            )

            report = evaluate_external_holdout(dataset, benchmark_repeats=1)
            serialized = json.dumps(report, ensure_ascii=False, sort_keys=True)
            rendered = render_external_holdout_report(report)
            private_root = str(root.resolve())

        self.assertEqual(
            {
                "schema_version",
                "runner_version",
                "contract",
                "counts",
                "metrics",
                "privacy",
                "quality",
                "summary",
            },
            set(report),
        )
        self.assertEqual(
            {
                "pair_classification",
                "end_to_end",
                "full_incremental_parity",
                "latency_ms",
            },
            set(report["metrics"]),
        )
        self.assertEqual("go", report["summary"]["status"])
        self.assertTrue(report["quality"]["passed"])
        self.assertTrue(report["privacy"]["passed"])
        self.assertEqual(4, report["counts"]["pairs"])
        self.assertEqual(4, report["counts"]["scenarios"])
        self.assertEqual(2, report["counts"]["public_categories"])
        self.assertNotIn("cases", report)
        self.assertNotIn("dataset", report)
        self.assertNotIn("digest", serialized.casefold())
        self.assertNotIn("sha256", serialized.casefold())
        self.assertNotIn("external-pair-", serialized)
        self.assertNotIn("external-scenario-", serialized)
        self.assertNotIn(private_root, serialized)
        for private_text in private_texts:
            self.assertNotIn(private_text, serialized)
            self.assertNotIn(private_text, rendered)
            self.assertNotIn(
                hashlib.sha256(private_text.encode("utf-8")).hexdigest(),
                serialized,
            )

        pair = report["metrics"]["pair_classification"]["overall"]
        self.assertEqual((2, 0, 2, 0), (
            pair["tp"],
            pair["fp"],
            pair["tn"],
            pair["fn"],
        ))
        e2e = report["metrics"]["end_to_end"]["overall"]
        self.assertEqual(1.0, e2e["reachability"]["f1"])
        self.assertEqual(1.0, e2e["action_accuracy"])
        self.assertTrue(report["metrics"]["full_incremental_parity"]["passed"])

    def test_cli_stdout_and_atomic_output_are_the_same_safe_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "private-holdout"
            private_texts = self._write_holdout(root)
            output = Path(temporary) / "public-report.json"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    CLI_MODULE,
                    "--dataset",
                    str(root),
                    "--format",
                    "json",
                    "--output-json",
                    str(output),
                    "--require-go",
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            saved = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(json.loads(result.stdout), saved)
        serialized = json.dumps(saved, ensure_ascii=False)
        for private_text in private_texts:
            self.assertNotIn(private_text, serialized)
        self.assertTrue(saved["contract"]["aggregate_only"])

    def test_require_go_returns_one_for_a_private_misclassification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "private-holdout"
            self._write_holdout(root, mislabel_positive=True)
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    CLI_MODULE,
                    "--dataset",
                    str(root),
                    "--format",
                    "json",
                    "--require-go",
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(1, result.returncode, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual("no_go", report["summary"]["status"])
        self.assertFalse(report["quality"]["passed"])
        self.assertEqual(
            1,
            report["metrics"]["pair_classification"]["overall"]["fp"],
        )

    def test_repository_contained_holdout_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=REPO_ROOT,
            prefix="private-holdout-test-",
        ) as temporary:
            root = Path(temporary)
            self._write_holdout(root)
            with self.assertRaisesRegex(
                ExternalHoldoutError,
                "holdout_must_be_outside_repository",
            ):
                load_external_holdout(
                    root,
                    forbidden_repository_root=REPO_ROOT,
                )

    def test_schema_errors_and_cli_stderr_do_not_echo_private_values(self) -> None:
        canary = "PRIVATE-CANARY-MUST-NOT-LEAK-4827"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "private-holdout"
            self._write_holdout(root)
            cases_path = root / "cases.jsonl"
            records = [
                json.loads(line)
                for line in cases_path.read_text(encoding="utf-8").splitlines()
            ]
            records[0]["unexpected_private_field"] = canary
            cases_path.write_text(
                "".join(
                    json.dumps(record, separators=(",", ":")) + "\n"
                    for record in records
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ExternalHoldoutError) as raised:
                load_external_holdout(
                    root,
                    forbidden_repository_root=REPO_ROOT,
                )
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    CLI_MODULE,
                    "--dataset",
                    str(root),
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual("case_keys_invalid", raised.exception.code)
        self.assertNotIn(canary, str(raised.exception))
        self.assertEqual(2, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertEqual(
            "external holdout error: case_keys_invalid record=1\n",
            result.stderr,
        )
        self.assertNotIn(canary, result.stderr)

    def test_manifest_requires_public_categories_and_non_live_attestation(self) -> None:
        mutations = (
            ("public_categories_invalid", {"public_categories": ["only_one"]}),
            (
                "live_credentials_not_allowed",
                {
                    "attestation": {
                        "contains_live_credentials": True,
                        "categories_are_public": True,
                    }
                },
            ),
        )
        for expected_code, mutation in mutations:
            with self.subTest(expected_code=expected_code), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "private-holdout"
                self._write_holdout(root)
                manifest_path = root / "manifest.json"
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                manifest.update(mutation)
                manifest_path.write_text(
                    json.dumps(manifest, indent=2) + "\n",
                    encoding="utf-8",
                )
                with self.assertRaises(ExternalHoldoutError) as raised:
                    load_external_holdout(
                        root,
                        forbidden_repository_root=REPO_ROOT,
                    )
                self.assertEqual(expected_code, raised.exception.code)

    def test_duplicate_records_and_symlinked_inputs_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "duplicate-holdout"
            self._write_holdout(root)
            cases_path = root / "cases.jsonl"
            first_line = cases_path.read_text(encoding="utf-8").splitlines()[0]
            with cases_path.open("a", encoding="utf-8") as handle:
                handle.write(first_line + "\n")
            with self.assertRaises(ExternalHoldoutError) as duplicate:
                load_external_holdout(
                    root,
                    forbidden_repository_root=REPO_ROOT,
                )
            self.assertEqual("duplicate_case_record", duplicate.exception.code)

            symlink_root = Path(temporary) / "symlink-holdout"
            self._write_holdout(symlink_root)
            manifest_path = symlink_root / "manifest.json"
            real_manifest = symlink_root / "manifest.private.json"
            manifest_path.rename(real_manifest)
            manifest_path.symlink_to(real_manifest)
            with self.assertRaises(ExternalHoldoutError) as symlinked:
                load_external_holdout(
                    symlink_root,
                    forbidden_repository_root=REPO_ROOT,
                )
            self.assertEqual(
                "manifest_symlink_not_allowed",
                symlinked.exception.code,
            )

    def test_json_errors_suppress_private_parser_context(self) -> None:
        canary = "PRIVATE-BROKEN-JSON-CANARY-5931"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "private-holdout"
            self._write_holdout(root)
            (root / "cases.jsonl").write_text(
                '{"kind":"pair","private":"' + canary + '"\n',
                encoding="utf-8",
            )
            with self.assertRaises(ExternalHoldoutError) as raised:
                load_external_holdout(
                    root,
                    forbidden_repository_root=REPO_ROOT,
                )

        self.assertEqual("case_json_invalid", raised.exception.code)
        self.assertTrue(raised.exception.__suppress_context__)
        self.assertIsNone(raised.exception.__cause__)
        self.assertNotIn(canary, str(raised.exception))

    @staticmethod
    def _write_holdout(
        root: Path,
        *,
        mislabel_positive: bool = False,
    ) -> tuple[str, ...]:
        root.mkdir(parents=True, exist_ok=True)
        manifest = {
            "schema_version": 1,
            "contract": EXTERNAL_HOLDOUT_CONTRACT,
            "contract_version": EXTERNAL_HOLDOUT_CONTRACT_VERSION,
            "public_categories": [
                "public_compound_negative",
                "selected_alpha_positive",
            ],
            "expected_counts": {"pairs": 4, "scenarios": 4},
            "attestation": {
                "contains_live_credentials": False,
                "categories_are_public": True,
            },
        }
        records: list[dict[str, object]] = [
            {
                "schema_version": 1,
                "kind": "pair",
                "public_category": "public_compound_negative",
                "source_binding_signal": "registered_source",
                "left_text": "documentationreference",
                "right_text": "publish documentationreference through public catalog",
                "should_link": False,
            },
            {
                "schema_version": 1,
                "kind": "pair",
                "public_category": "public_compound_negative",
                "source_binding_signal": "selected_field",
                "left_text": "interoperabilitydocumentation",
                "right_text": "index interoperabilitydocumentation in open archive",
                "should_link": False,
            },
            {
                "schema_version": 1,
                "kind": "pair",
                "public_category": "selected_alpha_positive",
                "source_binding_signal": "selected_security_field",
                "left_text": "ultravioletharbororchid",
                "right_text": "submit ultravioletharbororchid through payload channel",
                "should_link": not mislabel_positive,
            },
            {
                "schema_version": 1,
                "kind": "pair",
                "public_category": "selected_alpha_positive",
                "source_binding_signal": "selected_security_field",
                "left_text": "amberciphersparrowquartz",
                "right_text": "carry amberciphersparrowquartz as credential material",
                "should_link": True,
            },
            {
                "schema_version": 1,
                "kind": "scenario",
                "public_category": "public_compound_negative",
                "source_binding_signal": "registered_source",
                "source_text": "documentationreference",
                "artifact_texts": [
                    "publish documentationreference through public catalog"
                ],
                "sink_type": "external_message",
                "should_reach_sink": False,
                "expected_action": "allow",
            },
            {
                "schema_version": 1,
                "kind": "scenario",
                "public_category": "public_compound_negative",
                "source_binding_signal": "selected_field",
                "source_text": "interoperabilitydocumentation",
                "artifact_texts": [
                    "index interoperabilitydocumentation in open archive"
                ],
                "sink_type": "external_http_request",
                "should_reach_sink": False,
                "expected_action": "allow",
            },
            {
                "schema_version": 1,
                "kind": "scenario",
                "public_category": "selected_alpha_positive",
                "source_binding_signal": "selected_security_field",
                "source_text": "ultravioletharbororchid",
                "artifact_texts": [
                    "submit ultravioletharbororchid through payload channel"
                ],
                "sink_type": "external_message",
                "should_reach_sink": True,
                "expected_action": "block",
            },
            {
                "schema_version": 1,
                "kind": "scenario",
                "public_category": "selected_alpha_positive",
                "source_binding_signal": "selected_security_field",
                "source_text": "amberciphersparrowquartz",
                "artifact_texts": [
                    "carry amberciphersparrowquartz as credential material"
                ],
                "sink_type": "external_http_request",
                "should_reach_sink": True,
                "expected_action": "block",
            },
        ]
        (root / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n",
            encoding="utf-8",
        )
        (root / "cases.jsonl").write_text(
            "".join(
                json.dumps(record, separators=(",", ":")) + "\n"
                for record in records
            ),
            encoding="utf-8",
        )
        return tuple(
            value
            for record in records
            for key, raw in record.items()
            if key
            in {
                "left_text",
                "right_text",
                "source_text",
                "artifact_texts",
            }
            for value in (raw if isinstance(raw, list) else [raw])
            if isinstance(value, str)
        )


if __name__ == "__main__":
    unittest.main()
