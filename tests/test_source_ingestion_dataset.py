from __future__ import annotations

import json
import re
import shutil
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from hook_monitor.evaluation.source_ingestion_dataset import (
    SourceIngestionDatasetError,
    load_source_ingestion_dataset,
    materialize_payload,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET_ROOT = (
    REPO_ROOT / "tests" / "fixtures" / "similarity" / "ingestion" / "v1"
)
SYNTHETIC_VALUE_PATTERN = re.compile(r"^C\.[A-Z0-9][A-Za-z0-9._/-]+$")


@contextmanager
def copied_dataset() -> Iterator[Path]:
    temporary = tempfile.TemporaryDirectory()
    root = Path(temporary.name) / "v1"
    shutil.copytree(DATASET_ROOT, root)
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


class SourceIngestionDatasetTest(unittest.TestCase):
    def test_version_one_corpus_is_balanced_and_loadable(self) -> None:
        dataset = load_source_ingestion_dataset(DATASET_ROOT)

        self.assertEqual("tooluseproxy-source-ingestion", dataset.dataset_id)
        self.assertEqual("1.0.0", dataset.dataset_version)
        self.assertEqual(
            "7f1406f884d385708f418c1ae59788fe492172cd3cdc01aac500c2e8f02dff73",
            dataset.digest_sha256,
        )
        self.assertEqual(12, len(dataset.scenarios))
        self.assertEqual(6, len(dataset.select_scenarios("development")))
        self.assertEqual(6, len(dataset.select_scenarios("validation")))

        for split in ("development", "validation"):
            scenarios = dataset.select_scenarios(split)
            formats_by_scenario = {
                scenario.scenario_id: (
                    "dotenv"
                    if Path(scenario.source.path).name.startswith(".env")
                    else "json"
                )
                for scenario in scenarios
            }
            formats = set(formats_by_scenario.values())
            self.assertEqual({"dotenv", "json"}, formats)
            for source_format in ("dotenv", "json"):
                self.assertEqual(
                    {False, True},
                    {
                        scenario.should_reach_sink
                        for scenario in scenarios
                        if formats_by_scenario[scenario.scenario_id]
                        == source_format
                    },
                )
            for adapter in ("bash", "codex_final_answer", "mcp"):
                self.assertEqual(
                    {False, True},
                    {
                        scenario.should_reach_sink
                        for scenario in scenarios
                        if scenario.expected_adapter == adapter
                    },
                )

        with self.assertRaisesRegex(
            SourceIngestionDatasetError,
            "unsupported dataset split",
        ):
            dataset.select_scenarios("holdout")

    def test_scored_fixture_text_uses_neutral_synthetic_values(self) -> None:
        dataset = load_source_ingestion_dataset(DATASET_ROOT)

        for scenario in dataset.scenarios:
            with self.subTest(scenario=scenario.scenario_id):
                protected_values = scenario.source.protected_values
                self.assertTrue(protected_values)
                self.assertTrue(
                    all(
                        SYNTHETIC_VALUE_PATTERN.fullmatch(value)
                        for value in protected_values
                    )
                )
                target_payload = scenario.events[-1].payload
                target_text = json.dumps(
                    target_payload,
                    ensure_ascii=False,
                    sort_keys=True,
                )
                scored_text = f"{scenario.source.content}\n{target_text}".lower()
                self.assertNotIn(scenario.scenario_id, scored_text)
                for label_word in (
                    "development",
                    "validation",
                    "positive",
                    "negative",
                ):
                    self.assertNotIn(label_word, scored_text)

                target_contains_protected_value = any(
                    value in target_text for value in protected_values
                )
                self.assertEqual(
                    scenario.should_reach_sink,
                    target_contains_protected_value,
                )

    def test_loader_rejects_representative_schema_and_safety_mutations(
        self,
    ) -> None:
        mutations = (
            ("unknown=unknown", self._add_unknown_scenario_field),
            ("missing=sensitivity", self._remove_source_field),
            ("unknown=unknown", self._add_unknown_event_field),
            ("dataset_version must be 1.0.0", self._change_dataset_version),
            ("dataset case ids must be unique", self._duplicate_scenario_id),
            ("relative workspace path", self._escape_source_path),
            ("resembles a real AWS access key", self._add_source_credential_shape),
            ("resembles a real GitHub token", self._add_payload_credential_shape),
        )
        for expected_message, mutate in mutations:
            with self.subTest(expected_message=expected_message):
                with copied_dataset() as root:
                    mutate(root)
                    with self.assertRaisesRegex(
                        SourceIngestionDatasetError,
                        expected_message,
                    ):
                        load_source_ingestion_dataset(root)

    def test_materialize_payload_is_deep_copy_and_non_destructive(self) -> None:
        dataset = load_source_ingestion_dataset(DATASET_ROOT)
        original = dataset.scenarios[0].events[-1].payload
        before = json.loads(json.dumps(original, ensure_ascii=False))

        first_workspace = Path("/tmp/source-ingestion-first")
        second_workspace = Path("/tmp/source-ingestion-second")
        first = materialize_payload(original, first_workspace)
        second = materialize_payload(original, second_workspace)

        self.assertEqual(before, original)
        self.assertEqual("${WORKSPACE}", original["cwd"])
        self.assertEqual(str(first_workspace), first["cwd"])
        self.assertEqual(str(second_workspace), second["cwd"])
        self.assertIsNot(first, original)
        self.assertIsNot(first["tool_input"], original["tool_input"])
        self.assertEqual(
            original["tool_input"],
            first["tool_input"],
        )
        self.assertEqual(
            original["tool_input"],
            second["tool_input"],
        )

        invalid = {**original, "cwd": "/tmp/already-materialized"}
        invalid_before = json.loads(json.dumps(invalid, ensure_ascii=False))
        with self.assertRaisesRegex(
            SourceIngestionDatasetError,
            "cwd must use the workspace placeholder",
        ):
            materialize_payload(invalid, first_workspace)
        self.assertEqual(invalid_before, invalid)

    @staticmethod
    def _mutate_first_scenario(
        root: Path,
        mutation: Any,
    ) -> None:
        path = root / "scenarios.jsonl"
        records = read_jsonl(path)
        mutation(records[0])
        write_jsonl(path, records)

    def _add_unknown_scenario_field(self, root: Path) -> None:
        self._mutate_first_scenario(
            root,
            lambda record: record.__setitem__("unknown", True),
        )

    def _remove_source_field(self, root: Path) -> None:
        self._mutate_first_scenario(
            root,
            lambda record: record["source"].pop("sensitivity"),
        )

    def _add_unknown_event_field(self, root: Path) -> None:
        self._mutate_first_scenario(
            root,
            lambda record: record["events"][0].__setitem__("unknown", True),
        )

    @staticmethod
    def _change_dataset_version(root: Path) -> None:
        path = root / "manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["dataset_version"] = "1.1.0"
        path.write_text(json.dumps(manifest), encoding="utf-8")

    def _duplicate_scenario_id(self, root: Path) -> None:
        path = root / "scenarios.jsonl"
        records = read_jsonl(path)
        records[1]["id"] = records[0]["id"]
        write_jsonl(path, records)

    def _escape_source_path(self, root: Path) -> None:
        self._mutate_first_scenario(
            root,
            lambda record: record["source"].__setitem__(
                "path",
                "../secrets.json",
            ),
        )

    def _add_source_credential_shape(self, root: Path) -> None:
        self._mutate_first_scenario(
            root,
            lambda record: record["source"].__setitem__(
                "content",
                "TOKEN=AKIA1234567890ABCDEF\n",
            ),
        )

    def _add_payload_credential_shape(self, root: Path) -> None:
        self._mutate_first_scenario(
            root,
            lambda record: record["events"][-1]["payload"][
                "tool_input"
            ].__setitem__("credential", "ghp_abcdefghijklmnopqrstuvwxyz"),
        )


if __name__ == "__main__":
    unittest.main()
