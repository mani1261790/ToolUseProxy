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
DATASET_V2_ROOT = (
    REPO_ROOT / "tests" / "fixtures" / "similarity" / "ingestion" / "v2"
)
DATASET_V3_ROOT = (
    REPO_ROOT / "tests" / "fixtures" / "similarity" / "ingestion" / "v3"
)
SYNTHETIC_VALUE_PATTERN = re.compile(r"^C\.[A-Z0-9][A-Za-z0-9._/-]+$")


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

    def test_version_two_corpus_adds_only_canonical_source_selectors(self) -> None:
        legacy = load_source_ingestion_dataset(DATASET_ROOT)
        selected = load_source_ingestion_dataset(DATASET_V2_ROOT)

        self.assertEqual("2.0.0", selected.dataset_version)
        self.assertEqual(
            "573fd04d7757929752aa654d2277011238a895e068002fdb325251ab42d99373",
            selected.digest_sha256,
        )
        self.assertEqual(
            [scenario.scenario_id for scenario in legacy.scenarios],
            [scenario.scenario_id for scenario in selected.scenarios],
        )
        for old, new in zip(legacy.scenarios, selected.scenarios, strict=True):
            with self.subTest(scenario=new.scenario_id):
                self.assertIsNone(old.source.selector)
                self.assertIsNotNone(new.source.selector)
                self.assertEqual(old.events, new.events)
                self.assertEqual(old.should_reach_sink, new.should_reach_sink)
                self.assertEqual(old.expected_action, new.expected_action)
                self.assertEqual(old.source.content, new.source.content)
                self.assertEqual(
                    old.source.protected_values,
                    new.source.protected_values,
                )

    def test_version_three_preserves_v2_and_adds_scored_bash_contract(
        self,
    ) -> None:
        selected = load_source_ingestion_dataset(DATASET_V2_ROOT)
        submitted = load_source_ingestion_dataset(DATASET_V3_ROOT)

        self.assertEqual("3.0.0", submitted.dataset_version)
        self.assertEqual(
            "9fec2f91e1ea39d9e3471723c4cf9ac6418b3ce3553ce45e3bc1670867b5ebfb",
            submitted.digest_sha256,
        )
        self.assertEqual(20, len(submitted.scenarios))
        self.assertEqual(10, len(submitted.select_scenarios("development")))
        self.assertEqual(10, len(submitted.select_scenarios("validation")))
        for old, new in zip(
            selected.scenarios,
            submitted.scenarios[: len(selected.scenarios)],
            strict=True,
        ):
            with self.subTest(scenario=new.scenario_id):
                self.assertEqual(old.scenario_id, new.scenario_id)
                self.assertEqual(old.source, new.source)
                self.assertEqual(old.events, new.events)
                self.assertEqual(old.should_reach_sink, new.should_reach_sink)
                self.assertEqual(old.expected_action, new.expected_action)

        bash_scenarios = [
            scenario
            for scenario in submitted.scenarios
            if scenario.expected_adapter == "bash"
        ]
        projections = [
            projection
            for scenario in bash_scenarios
            for projection in scenario.expected_bash_submissions
        ]
        self.assertEqual(12, len(bash_scenarios))
        self.assertEqual(13, len(projections))
        self.assertEqual(
            10,
            sum(item.extraction == "static_values" for item in projections),
        )
        self.assertEqual(
            3,
            sum(item.extraction == "coarse_fallback" for item in projections),
        )
        self.assertEqual(
            11,
            sum(len(item.submitted_values) for item in projections),
        )
        self.assertTrue(
            all(
                scenario.expected_bash_submissions
                for scenario in bash_scenarios
            )
        )
        self.assertTrue(
            all(
                not scenario.expected_bash_submissions
                for scenario in submitted.scenarios
                if scenario.expected_adapter != "bash"
            )
        )

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
            ("dataset_version is not supported", self._change_dataset_version),
            ("dataset case ids must be unique", self._duplicate_scenario_id),
            ("relative workspace path", self._escape_source_path),
            ("resembles a real AWS access key", self._add_source_credential_shape),
            ("resembles a real GitHub token", self._add_payload_credential_shape),
            ("resembles a real GitHub token", self._add_payload_credential_key),
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

    def test_v3_loader_rejects_invalid_bash_submission_contracts(self) -> None:
        mutations = (
            (
                "missing=expected_bash_submissions",
                lambda records: records[0].pop("expected_bash_submissions"),
            ),
            (
                "coarse_fallback cannot declare submitted values",
                lambda records: records[0]["expected_bash_submissions"][0].update(
                    {
                        "extraction": "coarse_fallback",
                        "submitted_values": ["C.SYNTHETIC_VALUE"],
                    }
                ),
            ),
            (
                "reserved for Bash scenarios",
                lambda records: records[2].__setitem__(
                    "expected_bash_submissions",
                    [
                        {
                            "segment_index": 0,
                            "extraction": "static_values",
                            "submitted_values": ["C.SYNTHETIC_VALUE"],
                        }
                    ],
                ),
            ),
            (
                "submitted value must appear in target event",
                lambda records: records[0]["expected_bash_submissions"][0].update(
                    {"submitted_values": ["C.NOT_IN_TARGET_EVENT"]}
                ),
            ),
        )
        for expected_message, mutate in mutations:
            with self.subTest(expected_message=expected_message):
                with copied_dataset(DATASET_V3_ROOT) as root:
                    path = root / "scenarios.jsonl"
                    records = read_jsonl(path)
                    mutate(records)
                    write_jsonl(path, records)
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

    def _add_payload_credential_key(self, root: Path) -> None:
        self._mutate_first_scenario(
            root,
            lambda record: record["events"][-1]["payload"][
                "tool_input"
            ].__setitem__("ghp_abcdefghijklmnopqrstuvwxyz", "synthetic"),
        )


if __name__ == "__main__":
    unittest.main()
