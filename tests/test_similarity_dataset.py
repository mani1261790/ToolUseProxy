from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from hook_monitor.evaluation.dataset import (
    SimilarityDatasetError,
    load_similarity_dataset,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET_ROOT = REPO_ROOT / "tests" / "fixtures" / "similarity" / "v1"


class SimilarityDatasetTest(unittest.TestCase):
    def test_version_one_corpus_is_balanced_and_loadable(self) -> None:
        dataset = load_similarity_dataset(DATASET_ROOT)

        self.assertEqual("tooluseproxy-similarity", dataset.dataset_id)
        self.assertEqual("1.0.0", dataset.dataset_version)
        self.assertEqual(
            "066036e02e0b3747f59a0fa09ccd0352c7df6a9a5b6a65870163735639e3a848",
            dataset.digest_sha256,
        )
        self.assertEqual(40, len(dataset.pairs))
        self.assertEqual(16, len(dataset.scenarios))
        self.assertEqual(24, len(dataset.select_pairs("development")))
        self.assertEqual(16, len(dataset.select_pairs("validation")))
        self.assertEqual(10, len(dataset.select_scenarios("development")))
        self.assertEqual(6, len(dataset.select_scenarios("validation")))

        for split in ("development", "validation"):
            pairs = dataset.select_pairs(split)
            scenarios = dataset.select_scenarios(split)
            for scope in ("artifact_flow", "source_binding"):
                self.assertEqual(
                    {False, True},
                    {item.should_link for item in pairs if item.scope == scope},
                )
            self.assertEqual(
                {False, True},
                {item.should_reach_sink for item in scenarios},
            )

    def test_corpus_avoids_a_shared_scored_marker(self) -> None:
        dataset = load_similarity_dataset(DATASET_ROOT)
        texts = [
            text
            for pair in dataset.pairs
            for text in (pair.left_text, pair.right_text)
        ] + [
            text
            for scenario in dataset.scenarios
            for text in (scenario.source_text, *scenario.artifact_texts)
        ]

        self.assertTrue(texts)
        self.assertTrue(all("TUP_SYNTHETIC_" not in text for text in texts))
        coded_pairs = [
            pair
            for pair in dataset.pairs
            if "C." in pair.left_text or "C." in pair.right_text
        ]
        self.assertEqual({False, True}, {pair.should_link for pair in coded_pairs})
        self.assertTrue(
            all(
                not text.startswith(("S", "B", "P", "Q", "V"))
                for text in texts
                if "C." in text
            )
        )

    def test_observe_only_cases_are_kept_separate_from_gate_cases(self) -> None:
        dataset = load_similarity_dataset(DATASET_ROOT)
        pair_ids = {
            item.example_id for item in dataset.pairs if item.observe_only
        }
        scenario_ids = {
            item.scenario_id for item in dataset.scenarios if item.observe_only
        }

        self.assertEqual(4, len(pair_ids))
        self.assertEqual(2, len(scenario_ids))
        self.assertTrue(all("paraphrase" in item_id or "summary" in item_id for item_id in pair_ids))
        self.assertTrue(all("semantic" in item_id or "summary" in item_id for item_id in scenario_ids))

    def test_scope_controls_the_production_minimum_length(self) -> None:
        dataset = load_similarity_dataset(DATASET_ROOT)
        minimums = {
            scope: {
                item.minimum_length
                for item in dataset.pairs
                if item.scope == scope
            }
            for scope in ("artifact_flow", "source_binding")
        }
        self.assertEqual({"artifact_flow": {8}, "source_binding": {4}}, minimums)

    def test_loader_rejects_schema_drift_and_duplicate_ids(self) -> None:
        mutations = (
            ("unknown=unknown", self._add_unknown_pair_field),
            ("must be unique", self._duplicate_pair_id),
            ("version", self._change_manifest_version),
            ("blank JSONL", self._append_blank_line),
            ("local file name", self._make_manifest_file_escape),
            ("resembles a real AWS access key", self._add_credential_shape),
        )
        for expected_message, mutate in mutations:
            with self.subTest(expected_message=expected_message):
                with self._copied_dataset() as root:
                    mutate(root)
                    with self.assertRaisesRegex(
                        SimilarityDatasetError,
                        expected_message,
                    ):
                        load_similarity_dataset(root)

    def test_loader_rejects_an_invalid_policy_label(self) -> None:
        with self._copied_dataset() as root:
            records = self._read_jsonl(root / "scenarios.jsonl")
            negative = next(
                record for record in records if not record["should_reach_sink"]
            )
            negative["expected_action"] = "block"
            self._write_jsonl(root / "scenarios.jsonl", records)

            with self.assertRaisesRegex(
                SimilarityDatasetError,
                "unreachable sink must have expected_action=allow",
            ):
                load_similarity_dataset(root)

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
    def _read_jsonl(path: Path) -> list[dict[str, object]]:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    @staticmethod
    def _write_jsonl(path: Path, records: list[dict[str, object]]) -> None:
        path.write_text(
            "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records),
            encoding="utf-8",
        )

    def _add_unknown_pair_field(self, root: Path) -> None:
        path = root / "pairs.jsonl"
        records = self._read_jsonl(path)
        records[0]["unknown"] = True
        self._write_jsonl(path, records)

    def _duplicate_pair_id(self, root: Path) -> None:
        path = root / "pairs.jsonl"
        records = self._read_jsonl(path)
        records[1]["id"] = records[0]["id"]
        self._write_jsonl(path, records)

    def _add_credential_shape(self, root: Path) -> None:
        path = root / "pairs.jsonl"
        records = self._read_jsonl(path)
        records[0]["left_text"] = "AKIA1234567890ABCDEF"
        self._write_jsonl(path, records)

    @staticmethod
    def _change_manifest_version(root: Path) -> None:
        path = root / "manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["dataset_version"] = "2.0.0"
        path.write_text(json.dumps(manifest), encoding="utf-8")

    @staticmethod
    def _append_blank_line(root: Path) -> None:
        path = root / "pairs.jsonl"
        path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    @staticmethod
    def _make_manifest_file_escape(root: Path) -> None:
        path = root / "manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["files"]["pairs"] = "../pairs.jsonl"
        path.write_text(json.dumps(manifest), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
