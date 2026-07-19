from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from hook_monitor.evaluation.dataset import (
    V21_DATASET_SCHEMA_VERSION,
    V21_DATASET_VERSION,
    _dataset_digest,
    _parse_pair,
    _parse_retrieval_pool,
    _parse_scenario,
    _split_contract_metrics,
    load_similarity_dataset,
)
from hook_monitor.evaluation.similarity import evaluate_similarity


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPO_ROOT / "tests" / "fixtures" / "similarity" / "v2"
DEFAULT_OUTPUT = REPO_ROOT / "tests" / "fixtures" / "similarity" / "v2_1"
STRESS_SIZES = (1_000, 5_000, 10_000)
DEVELOPMENT_SIGNAL_FAMILY = "alpha_source_signal_development"
VALIDATION_SIGNAL_FAMILY = "alpha_source_signal_validation"


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(
            json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
            for record in records
        ),
        encoding="utf-8",
    )


def _signal_for_record(record: dict[str, Any], *, scenario: bool = False) -> str:
    if not scenario and record.get("scope") == "artifact_flow":
        return "not_applicable"
    tags = set(record.get("tags", []))
    return (
        "selected_security_field"
        if "alpha_only" in tags and "positive" in tags
        else "registered_source"
    )


def _convert_records(
    records: list[dict[str, Any]],
    *,
    scenario: bool = False,
) -> list[dict[str, Any]]:
    converted: list[dict[str, Any]] = []
    for source in records:
        record = dict(source)
        record["schema_version"] = V21_DATASET_SCHEMA_VERSION
        record["dataset_version"] = V21_DATASET_VERSION
        record["source_binding_signal"] = _signal_for_record(
            record,
            scenario=scenario,
        )
        converted.append(record)
    return converted


def _development_signal_pairs() -> list[dict[str, Any]]:
    common = {
        "schema_version": V21_DATASET_SCHEMA_VERSION,
        "dataset_version": V21_DATASET_VERSION,
        "split": "development",
        "scope": "source_binding",
        "provenance": "synthetic",
        "observe_only": False,
        "family": DEVELOPMENT_SIGNAL_FAMILY,
        "counterfactual_group": None,
    }
    return [
        {
            **common,
            "id": "v21-dev-public-compound-negative",
            "left_text": "documentationreference",
            "right_text": (
                "publish documentationreference through public catalog endpoint"
            ),
            "should_link": False,
            "tags": ["alpha_only", "negative", "public_compound"],
            "rationale": (
                "A long diverse public compound from an unselected registered "
                "source is not protected-value lineage."
            ),
            "source_binding_signal": "registered_source",
        },
        {
            **common,
            "id": "v21-dev-selected-alpha-positive",
            "left_text": "ultravioletharbororchid",
            "right_text": (
                "submit ultravioletharbororchid through external payload channel"
            ),
            "should_link": True,
            "tags": [
                "alpha_only",
                "hard_positive",
                "positive",
                "selected_security_field",
            ],
            "rationale": (
                "A long diverse alpha-only value selected by a security field "
                "must retain source lineage inside a submission wrapper."
            ),
            "source_binding_signal": "selected_security_field",
        },
    ]


def _development_signal_scenarios() -> list[dict[str, Any]]:
    common = {
        "schema_version": V21_DATASET_SCHEMA_VERSION,
        "dataset_version": V21_DATASET_VERSION,
        "split": "development",
        "provenance": "synthetic",
        "sink_type": "external_message",
        "observe_only": False,
        "family": DEVELOPMENT_SIGNAL_FAMILY,
        "counterfactual_group": None,
    }
    return [
        {
            **common,
            "id": "v21-dev-public-compound-scenario",
            "source_text": "documentationreference",
            "artifact_texts": [
                "publish documentationreference through public catalog endpoint"
            ],
            "should_reach_sink": False,
            "expected_action": "allow",
            "tags": ["alpha_only", "negative", "public_compound"],
            "rationale": (
                "Registered public compound containment must not seed source "
                "lineage in the production graph path."
            ),
            "source_binding_signal": "registered_source",
        },
        {
            **common,
            "id": "v21-dev-selected-alpha-scenario",
            "source_text": "ultravioletharbororchid",
            "artifact_texts": [
                "submit ultravioletharbororchid through external payload channel"
            ],
            "should_reach_sink": True,
            "expected_action": "block",
            "tags": [
                "alpha_only",
                "hard_positive",
                "positive",
                "selected_security_field",
            ],
            "rationale": (
                "Explicitly selected security-field provenance must preserve "
                "alpha-only source lineage through the full graph."
            ),
            "source_binding_signal": "selected_security_field",
        },
    ]


def _validation_signal_pairs() -> list[dict[str, Any]]:
    common = {
        "schema_version": V21_DATASET_SCHEMA_VERSION,
        "dataset_version": V21_DATASET_VERSION,
        "split": "validation",
        "scope": "source_binding",
        "provenance": "synthetic",
        "observe_only": False,
        "family": VALIDATION_SIGNAL_FAMILY,
        "counterfactual_group": None,
    }
    return [
        {
            **common,
            "id": "v21-validation-open-catalog-negative",
            "left_text": "interoperabilitydocumentation",
            "right_text": (
                "catalog entry interoperabilitydocumentation has open visibility"
            ),
            "should_link": False,
            "tags": ["alpha_only", "negative", "public_compound"],
            "rationale": (
                "An unrelated open-catalog compound must not gain protected "
                "lineage from registered-source containment."
            ),
            "source_binding_signal": "registered_source",
        },
        {
            **common,
            "id": "v21-validation-selected-credential-positive",
            "left_text": "amberciphersparrowquartz",
            "right_text": (
                "outbound envelope carries amberciphersparrowquartz as credential material"
            ),
            "should_link": True,
            "tags": [
                "alpha_only",
                "hard_positive",
                "positive",
                "selected_security_field",
            ],
            "rationale": (
                "An independently named selected credential must retain alpha-only "
                "lineage in a different wrapper."
            ),
            "source_binding_signal": "selected_security_field",
        },
    ]


def _validation_signal_scenarios() -> list[dict[str, Any]]:
    common = {
        "schema_version": V21_DATASET_SCHEMA_VERSION,
        "dataset_version": V21_DATASET_VERSION,
        "split": "validation",
        "provenance": "synthetic",
        "sink_type": "external_http_request",
        "observe_only": False,
        "family": VALIDATION_SIGNAL_FAMILY,
        "counterfactual_group": None,
    }
    return [
        {
            **common,
            "id": "v21-validation-open-catalog-scenario",
            "source_text": "interoperabilitydocumentation",
            "artifact_texts": [
                "send catalog entry interoperabilitydocumentation to archive gateway",
            ],
            "should_reach_sink": False,
            "expected_action": "allow",
            "tags": ["alpha_only", "negative", "public_compound"],
            "rationale": (
                "A public catalog HTTP submission must remain outside source lineage."
            ),
            "source_binding_signal": "registered_source",
        },
        {
            **common,
            "id": "v21-validation-selected-credential-scenario",
            "source_text": "amberciphersparrowquartz",
            "artifact_texts": [
                "dispatch credential payload amberciphersparrowquartz is staged to partner",
            ],
            "should_reach_sink": True,
            "expected_action": "block",
            "tags": [
                "alpha_only",
                "hard_positive",
                "positive",
                "selected_security_field",
            ],
            "rationale": (
                "Selected credential provenance must reach a differently shaped HTTP sink."
            ),
            "source_binding_signal": "selected_security_field",
        },
    ]


def _apply_stress_sizes(records: list[dict[str, Any]]) -> None:
    for split in ("development", "validation"):
        split_records = [record for record in records if record["split"] == split]
        groups: dict[str, list[dict[str, Any]]] = {}
        for record in split_records:
            group = record["counterfactual_group"]
            if group is not None:
                groups.setdefault(group, []).append(record)
        selected_groups = list(groups.values())[: len(STRESS_SIZES)]
        if len(selected_groups) != len(STRESS_SIZES):
            raise RuntimeError(f"{split} does not have enough retrieval groups")
        for group_records, count in zip(
            selected_groups,
            STRESS_SIZES,
            strict=True,
        ):
            for record in group_records:
                recipe = record["candidates"]
                if not isinstance(recipe, dict):
                    raise RuntimeError(f"{record['id']} is not recipe-generated")
                prefix = recipe["id_prefix"]
                relevant_id = record["relevant_candidate_id"]
                expected_prefix = f"{prefix}-"
                if not relevant_id.startswith(expected_prefix):
                    raise RuntimeError(
                        f"{record['id']} has an incompatible relevant id"
                    )
                relevant_index = int(relevant_id[len(expected_prefix) :])
                recipe["count"] = count
                width = max(3, len(str(count - 1)))
                record["relevant_candidate_id"] = (
                    f"{prefix}-{relevant_index:0{width}d}"
                )


def _shape_contract(
    pairs_path: Path,
    scenarios_path: Path,
    retrieval_path: Path,
) -> dict[str, object]:
    pairs = tuple(
        _parse_pair(
            record,
            pairs_path,
            index,
            schema_version=V21_DATASET_SCHEMA_VERSION,
            dataset_version=V21_DATASET_VERSION,
        )
        for index, record in enumerate(_read_jsonl(pairs_path), start=1)
    )
    scenarios = tuple(
        _parse_scenario(
            record,
            scenarios_path,
            index,
            schema_version=V21_DATASET_SCHEMA_VERSION,
            dataset_version=V21_DATASET_VERSION,
        )
        for index, record in enumerate(_read_jsonl(scenarios_path), start=1)
    )
    pools = tuple(
        _parse_retrieval_pool(
            record,
            retrieval_path,
            index,
            schema_version=V21_DATASET_SCHEMA_VERSION,
            dataset_version=V21_DATASET_VERSION,
        )
        for index, record in enumerate(_read_jsonl(retrieval_path), start=1)
    )
    return _split_contract_metrics(pairs, scenarios, pools)


def _render_fixture(output: Path) -> str:
    output.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((SOURCE_ROOT / "manifest.json").read_text(encoding="utf-8"))
    manifest["schema_version"] = V21_DATASET_SCHEMA_VERSION
    manifest["dataset_version"] = V21_DATASET_VERSION
    manifest["description"] = (
        "Synthetic similarity v2.1 foundation with explicit source-binding "
        "signals and generated 1k-10k candidate stress pools."
    )
    manifest["stress_contract"] = {
        "generated_pool_sizes": list(STRESS_SIZES),
        "maximum_candidate_count": 10_000,
        "minimum_saturation_rate": 1.0,
        "latency_warning_ms": {
            "pair_p95": 10.0,
            "artifact_retrieval_p95": 2_000.0,
            "source_retrieval_p95": 3_000.0,
            "e2e_full_p95": 50.0,
            "e2e_incremental_p95": 500.0,
        },
    }

    pairs = _convert_records(_read_jsonl(SOURCE_ROOT / "pairs.jsonl"))
    pairs.extend(_development_signal_pairs())
    pairs.extend(_validation_signal_pairs())
    expected_counts = manifest["expected_counts"]
    expected_counts["pairs"] += 4
    expected_counts["development_pairs"] += 2
    expected_counts["development_gate_pairs"] += 2
    expected_counts["validation_pairs"] += 2
    expected_counts["validation_gate_pairs"] += 2
    development_families = manifest["family_contract"]["pair_families"][
        "development"
    ]
    development_families.append(DEVELOPMENT_SIGNAL_FAMILY)
    development_families.sort()
    validation_families = manifest["family_contract"]["pair_families"][
        "validation"
    ]
    validation_families.append(VALIDATION_SIGNAL_FAMILY)
    validation_families.sort()
    scenarios = _convert_records(
        _read_jsonl(SOURCE_ROOT / "scenarios.jsonl"),
        scenario=True,
    )
    scenarios.extend(_development_signal_scenarios())
    scenarios.extend(_validation_signal_scenarios())
    expected_counts["scenarios"] += 4
    expected_counts["development_scenarios"] += 2
    expected_counts["development_gate_scenarios"] += 2
    expected_counts["validation_scenarios"] += 2
    expected_counts["validation_gate_scenarios"] += 2
    development_scenario_families = manifest["family_contract"][
        "scenario_families"
    ]["development"]
    development_scenario_families.append(DEVELOPMENT_SIGNAL_FAMILY)
    development_scenario_families.sort()
    validation_scenario_families = manifest["family_contract"][
        "scenario_families"
    ]["validation"]
    validation_scenario_families.append(VALIDATION_SIGNAL_FAMILY)
    validation_scenario_families.sort()
    retrieval = _convert_records(_read_jsonl(SOURCE_ROOT / "retrieval_pools.jsonl"))
    _apply_stress_sizes(retrieval)

    pairs_path = output / "pairs.jsonl"
    scenarios_path = output / "scenarios.jsonl"
    retrieval_path = output / "retrieval_pools.jsonl"
    manifest_path = output / "manifest.json"
    _write_jsonl(pairs_path, pairs)
    _write_jsonl(scenarios_path, scenarios)
    _write_jsonl(retrieval_path, retrieval)

    shapes = _shape_contract(pairs_path, scenarios_path, retrieval_path)
    manifest["family_contract"]["development_shape_sha256"] = shapes[
        "development_shape_sha256"
    ]
    manifest["family_contract"]["validation_shape_sha256"] = shapes[
        "validation_shape_sha256"
    ]
    _write_json(manifest_path, manifest)

    dataset = load_similarity_dataset(output)
    manifest["baselines"] = {
        split: evaluate_similarity(
            dataset,
            split=None if split == "all" else split,
            benchmark_repeats=1,
        )["baseline"]["observed"]
        for split in ("all", "development", "validation")
    }
    _write_json(manifest_path, manifest)
    digest = _dataset_digest(
        (manifest_path, pairs_path, scenarios_path, retrieval_path)
    )
    (output / "README.md").write_text(
        "# Similarity v2.1 foundation\n\n"
        "This fixture is generated by `scripts/build_similarity_v21_fixture.py`.\n"
        "It preserves v2 cases while adding explicit source-binding signals and "
        "1,000 / 5,000 / 10,000 candidate stress pools in both splits.\n\n"
        f"Dataset digest: `{digest}`\n",
        encoding="utf-8",
    )
    return digest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if not args.check:
        print(_render_fixture(args.output))
        return 0
    with tempfile.TemporaryDirectory() as temporary:
        candidate = Path(temporary) / "v2_1"
        digest = _render_fixture(candidate)
        expected_files = (
            "manifest.json",
            "pairs.jsonl",
            "scenarios.jsonl",
            "retrieval_pools.jsonl",
            "README.md",
        )
        mismatches = [
            name
            for name in expected_files
            if not (args.output / name).exists()
            or (args.output / name).read_bytes() != (candidate / name).read_bytes()
        ]
    if mismatches:
        parser.error(f"generated fixture differs: {', '.join(mismatches)}")
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
