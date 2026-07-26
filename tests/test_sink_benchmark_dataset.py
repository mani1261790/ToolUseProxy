from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from hook_monitor.evaluation.sink_benchmark_dataset import (
    SinkBenchmarkDatasetError,
    load_sink_benchmark_dataset,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET_ROOT = REPO_ROOT / "tests" / "fixtures" / "sink_benchmark" / "v1"
DATASET_V1_1_ROOT = (
    REPO_ROOT / "tests" / "fixtures" / "sink_benchmark" / "v1_1"
)


@contextmanager
def copied_dataset(source: Path = DATASET_ROOT) -> Iterator[Path]:
    temporary = tempfile.TemporaryDirectory()
    root = Path(temporary.name) / source.name
    shutil.copytree(source, root)
    try:
        yield root
    finally:
        temporary.cleanup()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(
            json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n"
            for record in records
        ),
        encoding="utf-8",
    )


class SinkBenchmarkDatasetTest(unittest.TestCase):
    def test_baseline_is_balanced_and_loadable(self) -> None:
        dataset = load_sink_benchmark_dataset(DATASET_ROOT)

        self.assertEqual("sink-benchmark-v1", dataset.dataset_id)
        self.assertEqual("1.0.0", dataset.dataset_version)
        self.assertEqual(12, len(dataset.cases))
        self.assertEqual(6, len(dataset.select_cases("development")))
        self.assertEqual(6, len(dataset.select_cases("validation")))
        self.assertEqual(64, len(dataset.digest_sha256))
        for split in ("development", "validation"):
            cases = dataset.select_cases(split)
            for adapter in ("bash", "codex_final_answer", "mcp"):
                self.assertEqual(
                    {False, True},
                    {
                        case.is_leak
                        for case in cases
                        if case.ingestion.expected_adapter == adapter
                    },
                )

    def test_case_metadata_must_match_ingestion_ground_truth(self) -> None:
        with copied_dataset() as root:
            cases_path = root / "cases.jsonl"
            records = read_jsonl(cases_path)
            records[0]["is_leak"] = False
            write_jsonl(cases_path, records)

            with self.assertRaisesRegex(
                SinkBenchmarkDatasetError,
                "is_leak differs from ingestion ground truth",
            ):
                load_sink_benchmark_dataset(root)

    def test_version_one_one_adds_bounded_workspace_files(self) -> None:
        dataset = load_sink_benchmark_dataset(DATASET_V1_1_ROOT)

        self.assertEqual("sink-benchmark-v1-1", dataset.dataset_id)
        self.assertEqual("1.1.0", dataset.dataset_version)
        self.assertEqual(
            "62747858a46e59be2c67ec8a02387448f6192d85e361c58e5c9eec8c427f8fe0",
            dataset.digest_sha256,
        )
        self.assertEqual(12, len(dataset.cases))
        self.assertEqual(
            4,
            sum(case.payload_visibility == "resolvable" for case in dataset.cases),
        )
        workspace_files = [
            workspace_file
            for case in dataset.cases
            for workspace_file in case.workspace_files
        ]
        self.assertEqual(2, len(workspace_files))
        self.assertTrue(
            all(not Path(item.path).is_absolute() for item in workspace_files)
        )

    def test_workspace_file_cannot_replace_protected_source(self) -> None:
        with copied_dataset(DATASET_V1_1_ROOT) as root:
            cases_path = root / "cases.jsonl"
            records = read_jsonl(cases_path)
            records[0]["workspace_files"] = [
                {
                    "path": ".env.sink-dev",
                    "content": "replacement",
                }
            ]
            write_jsonl(cases_path, records)

            with self.assertRaisesRegex(
                SinkBenchmarkDatasetError,
                "workspace file must not replace source",
            ):
                load_sink_benchmark_dataset(root)

    def test_workspace_file_rejects_real_secret_patterns(self) -> None:
        with copied_dataset(DATASET_V1_1_ROOT) as root:
            cases_path = root / "cases.jsonl"
            records = read_jsonl(cases_path)
            records[0]["workspace_files"] = [
                {
                    "path": "payloads/unsafe.txt",
                    "content": "gh" + "p_" + ("a" * 26) + "123456",
                }
            ]
            write_jsonl(cases_path, records)

            with self.assertRaisesRegex(
                SinkBenchmarkDatasetError,
                "matches forbidden GitHub token",
            ):
                load_sink_benchmark_dataset(root)

    def test_unknown_case_field_is_rejected(self) -> None:
        with copied_dataset() as root:
            cases_path = root / "cases.jsonl"
            records = read_jsonl(cases_path)
            records[0]["raw_secret_preview"] = "forbidden"
            write_jsonl(cases_path, records)

            with self.assertRaisesRegex(
                SinkBenchmarkDatasetError,
                "object keys differ",
            ):
                load_sink_benchmark_dataset(root)

    def test_ingestion_directory_cannot_escape_dataset_root(self) -> None:
        with copied_dataset() as root:
            manifest_path = root / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["ingestion_dataset"] = "../outside"
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                SinkBenchmarkDatasetError,
                "contained relative path",
            ):
                load_sink_benchmark_dataset(root)

    def test_unknown_split_is_rejected(self) -> None:
        dataset = load_sink_benchmark_dataset(DATASET_ROOT)
        with self.assertRaisesRegex(
            SinkBenchmarkDatasetError,
            "unsupported dataset split",
        ):
            dataset.select_cases("holdout")


if __name__ == "__main__":
    unittest.main()
