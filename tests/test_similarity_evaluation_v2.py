from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from fractions import Fraction
from pathlib import Path
from unittest.mock import patch

import hook_monitor.evaluation.similarity as similarity_evaluation
from hook_monitor.analysis.graph import build_source_binding_edges
from hook_monitor.analysis.similarity import compare_text
from hook_monitor.analysis.similarity import prepare_similarity_text
from hook_monitor.evaluation.dataset import (
    RetrievalPool,
    LineageScenario,
    SimilarityDatasetError,
    load_similarity_dataset,
)
from hook_monitor.evaluation.similarity import (
    RetrievalCandidate,
    evaluate_similarity,
    simulate_candidate_retrieval,
)
from hook_monitor.runtime.normalize import normalize_text


REPO_ROOT = Path(__file__).resolve().parents[1]
V1_ROOT = REPO_ROOT / "tests" / "fixtures" / "similarity" / "v1"
V2_ROOT = REPO_ROOT / "tests" / "fixtures" / "similarity" / "v2"
CLI_MODULE = "hook_monitor.evaluation.cli"
V1_DATASET_DIGEST = (
    "066036e02e0b3747f59a0fa09ccd0352c7df6a9a5b6a65870163735639e3a848"
)
V2_DATASET_DIGEST = (
    "241a4f536ea53694b8172accc5a528961673a843983f99702651357cff3619b3"
)
V1_FILE_DIGESTS = {
    "README.md": "de1e643bc7244590fdd5c7391fe1694ded98dcc63a9cc63d393d43a574ad51ee",
    "manifest.json": "94efe71e3ba3e5547e9865cc8017fcf2f9715fda2193bb9c8688cdec904a4bbe",
    "pairs.jsonl": "2fe7578ee9fe28fd394159186d3c37a33b02bdb9c52bc9d359155a2a40446fc0",
    "scenarios.jsonl": "336b6bc07d9e02162c6e9d59e5307ae8bfc8150c1467081ef8ea698ce0eda3f5",
}


class SimilarityEvaluationV2Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = load_similarity_dataset(V2_ROOT)
        cls.reports = {
            split: evaluate_similarity(
                cls.dataset,
                split=None if split == "all" else split,
                benchmark_repeats=1,
            )
            for split in ("development", "validation", "all")
        }

    def test_v1_fixture_bytes_and_registered_digest_remain_historical(self) -> None:
        dataset = load_similarity_dataset(V1_ROOT)

        self.assertEqual(V1_DATASET_DIGEST, dataset.digest_sha256)
        for name, expected_digest in V1_FILE_DIGESTS.items():
            with self.subTest(name=name):
                actual = hashlib.sha256((V1_ROOT / name).read_bytes()).hexdigest()
                self.assertEqual(expected_digest, actual)

    def test_v2_registry_counts_and_split_contract_are_exact(self) -> None:
        dataset = self.dataset

        self.assertEqual(2, dataset.schema_version)
        self.assertEqual(V2_DATASET_DIGEST, dataset.digest_sha256)
        self.assertEqual(dataset.pinned_digest_sha256, dataset.digest_sha256)
        self.assertEqual(38, len(dataset.pairs))
        self.assertEqual(9, len(dataset.scenarios))
        self.assertEqual(16, len(dataset.retrieval_pools))
        self.assertEqual(
            {
                "development_shape_sha256",
                "validation_shape_sha256",
                "split_vocabulary_jaccard",
                "split_feature_jaccard",
                "shared_scored_marker_count",
            },
            set(dataset.split_contract or {}),
        )
        assert dataset.split_contract is not None
        self.assertEqual(0, dataset.split_contract["shared_scored_marker_count"])
        self.assertLessEqual(
            dataset.split_contract["split_vocabulary_jaccard"],
            0.2,
        )
        self.assertLessEqual(
            dataset.split_contract["split_feature_jaccard"],
            0.2,
        )
        self.assertNotEqual(
            dataset.split_contract["development_shape_sha256"],
            dataset.split_contract["validation_shape_sha256"],
        )

    def test_development_and_validation_families_are_non_mirror(self) -> None:
        contract = self.dataset.family_contract
        assert contract is not None

        for layer in (
            "pair_families",
            "candidate_families",
            "scenario_families",
        ):
            with self.subTest(layer=layer):
                split_map = contract[layer]
                assert isinstance(split_map, dict)
                self.assertTrue(split_map["development"])
                self.assertTrue(split_map["validation"])
                self.assertTrue(
                    set(split_map["development"]).isdisjoint(
                        split_map["validation"]
                    )
                )

        for split in ("development", "validation"):
            semantic = [
                pair
                for pair in self.dataset.select_pairs(split)
                if pair.observe_only and "semantic" in pair.tags
            ]
            self.assertEqual(1, len(semantic), split)

    def test_conditional_polarity_negatives_are_scored_true_negatives(self) -> None:
        pair_cases = {
            item["id"]: item for item in self.reports["all"]["cases"]["pairs"]
        }
        expected_tags = {
            "dev-pair-unless-polarity": "unless",
            "validation-pair-except-polarity": "except",
            "validation-pair-revoked-state": "revoked",
        }

        for case_id, expected_tag in expected_tags.items():
            with self.subTest(case_id=case_id):
                case = pair_cases[case_id]
                self.assertFalse(case["observe_only"])
                self.assertIn(expected_tag, case["tags"])
                self.assertFalse(case["expected"])
                self.assertFalse(case["actual"])
                self.assertEqual("none", case["method"])

    def test_alpha_only_secret_and_common_label_counterfactuals_are_scored(
        self,
    ) -> None:
        pair_cases = {
            item["id"]: item for item in self.reports["all"]["cases"]["pairs"]
        }
        for positive_id, negative_id in (
            (
                "dev-pair-alpha-secret-positive",
                "dev-pair-alpha-secret-common-negative",
            ),
            (
                "validation-pair-alpha-secret-positive",
                "validation-pair-alpha-secret-common-negative",
            ),
        ):
            with self.subTest(positive_id=positive_id):
                positive = pair_cases[positive_id]
                negative = pair_cases[negative_id]
                self.assertTrue(positive["expected"])
                self.assertTrue(positive["actual"])
                self.assertEqual("substring", positive["method"])
                self.assertFalse(negative["expected"])
                self.assertFalse(negative["actual"])
                self.assertEqual("none", negative["method"])

        scenario = next(
            item
            for item in self.reports["all"]["cases"]["scenarios"]
            if item["id"] == "dev-scenario-alpha-secret-http"
        )
        self.assertTrue(scenario["expected_reach"])
        self.assertTrue(scenario["actual_reach"])
        self.assertEqual("block", scenario["expected_action"])
        self.assertEqual("block", scenario["actual_action"])

    def test_candidate_pools_exercise_real_cap_pressure(self) -> None:
        for pool in self.dataset.retrieval_pools:
            limit = 50 if pool.scope == "artifact_flow" else 200
            self.assertGreater(len(pool.candidates), limit)
            if (
                not pool.pool_id.endswith("miss")
                or "minimum_length" in pool.tags
                or "dual_objective" in pool.tags
            ):
                continue
            relevant = next(
                item
                for item in pool.candidates
                if item.candidate_id == pool.relevant_candidate_id
            )
            decoy = next(
                item
                for item in pool.candidates
                if item.candidate_id != pool.relevant_candidate_id
            )
            self.assertTrue(self._compare_pool_text(pool, relevant.text).matched)
            self.assertFalse(self._compare_pool_text(pool, decoy.text).matched)
            prepared_query = prepare_similarity_text(
                pool.query_text,
                normalized_text=normalize_text(pool.query_text),
            )
            raw_overlap_rank = sorted(
                (
                    -len(
                        prepared_query.candidate_features
                        & prepare_similarity_text(
                            item.text,
                            normalized_text=normalize_text(item.text),
                        ).candidate_features
                    ),
                    item.candidate_id,
                )
                for item in pool.candidates
            )
            relevant_rank = next(
                index
                for index, (_overlap, candidate_id) in enumerate(
                    raw_overlap_rank,
                    start=1,
                )
                if candidate_id == pool.relevant_candidate_id
            )
            self.assertGreater(relevant_rank, limit)
            retrieved = simulate_candidate_retrieval(
                scope=pool.scope,
                query_text=pool.query_text,
                candidates=tuple(
                    RetrievalCandidate(
                        item.candidate_id,
                        item.text,
                        item.sequence_no,
                    )
                    for item in pool.candidates
                ),
            )
            self.assertIn(pool.relevant_candidate_id, retrieved)

    def test_pair_ineligible_short_decoys_straddle_the_artifact_cap(self) -> None:
        pools = [
            pool
            for pool in self.dataset.retrieval_pools
            if "minimum_length" in pool.tags
        ]
        self.assertEqual(4, len(pools))

        for pool in pools:
            with self.subTest(pool_id=pool.pool_id):
                self.assertEqual("artifact_flow", pool.scope)
                self.assertEqual(53, len(pool.candidates))
                prepared_query = prepare_similarity_text(
                    pool.query_text,
                    normalized_text=normalize_text(pool.query_text),
                )
                ranked: list[tuple[Fraction, int, str]] = []
                pair_ineligible_overlap = 0
                for item in pool.candidates:
                    prepared = prepare_similarity_text(
                        item.text,
                        normalized_text=normalize_text(item.text),
                    )
                    overlap = len(
                        prepared_query.candidate_features
                        & prepared.candidate_features
                    )
                    if not overlap:
                        continue
                    denominator = min(
                        len(prepared_query.candidate_features),
                        len(prepared.candidate_features),
                    )
                    ranked.append(
                        (
                            -Fraction(overlap, denominator),
                            -overlap,
                            item.candidate_id,
                        )
                    )
                    if item.candidate_id != pool.relevant_candidate_id:
                        decision = self._compare_pool_text(pool, item.text)
                        self.assertEqual(5, len(normalize_text(item.text)))
                        self.assertFalse(decision.matched)
                        pair_ineligible_overlap += 1

                legacy_order = [item[2] for item in sorted(ranked)]
                legacy_rank = legacy_order.index(pool.relevant_candidate_id) + 1
                expected_rank = 50 if pool.pool_id.endswith("hit") else 51
                self.assertEqual(expected_rank - 1, pair_ineligible_overlap)
                self.assertEqual(expected_rank, legacy_rank)

                relevant = next(
                    item
                    for item in pool.candidates
                    if item.candidate_id == pool.relevant_candidate_id
                )
                self.assertTrue(self._compare_pool_text(pool, relevant.text).matched)
                retrieved = simulate_candidate_retrieval(
                    scope=pool.scope,
                    query_text=pool.query_text,
                    candidates=tuple(
                        RetrievalCandidate(
                            item.candidate_id,
                            item.text,
                            item.sequence_no,
                        )
                        for item in pool.candidates
                    ),
                )
                self.assertIn(pool.relevant_candidate_id, retrieved)

    def test_source_low_signal_decoys_require_overlap_ranking_lane(self) -> None:
        pools = [
            pool
            for pool in self.dataset.retrieval_pools
            if "dual_objective" in pool.tags
        ]
        self.assertEqual(4, len(pools))

        for pool in pools:
            with self.subTest(pool_id=pool.pool_id):
                self.assertEqual("source_binding", pool.scope)
                self.assertEqual(203, len(pool.candidates))
                prepared_query = prepare_similarity_text(
                    pool.query_text,
                    normalized_text=normalize_text(pool.query_text),
                )
                coverage_order: list[tuple[Fraction, int, str]] = []
                overlap_order: list[tuple[int, Fraction, str]] = []
                short_decoys = []
                for item in pool.candidates:
                    prepared = prepare_similarity_text(
                        item.text,
                        normalized_text=normalize_text(item.text),
                    )
                    overlap = len(
                        prepared_query.candidate_features
                        & prepared.candidate_features
                    )
                    if not overlap:
                        continue
                    denominator = min(
                        len(prepared_query.candidate_features),
                        len(prepared.candidate_features),
                    )
                    coverage = Fraction(overlap, denominator)
                    coverage_order.append(
                        (-coverage, -overlap, item.candidate_id)
                    )
                    overlap_order.append(
                        (-overlap, -coverage, item.candidate_id)
                    )
                    if (
                        item.candidate_id != pool.relevant_candidate_id
                        and len(normalize_text(item.text)) == 5
                    ):
                        short_decoys.append(item)

                expected_decoys = 199 if pool.pool_id.endswith("hit") else 201
                expected_legacy_rank = 200 if pool.pool_id.endswith("hit") else 202
                self.assertEqual(expected_decoys, len(short_decoys))
                self.assertFalse(
                    self._compare_pool_text(pool, short_decoys[0].text).matched
                )
                self.assertEqual(
                    expected_legacy_rank,
                    [item[2] for item in sorted(coverage_order)].index(
                        pool.relevant_candidate_id
                    )
                    + 1,
                )
                self.assertEqual(
                    1,
                    [item[2] for item in sorted(overlap_order)].index(
                        pool.relevant_candidate_id
                    )
                    + 1,
                )

                relevant = next(
                    item
                    for item in pool.candidates
                    if item.candidate_id == pool.relevant_candidate_id
                )
                self.assertTrue(self._compare_pool_text(pool, relevant.text).matched)
                retrieved = simulate_candidate_retrieval(
                    scope=pool.scope,
                    query_text=pool.query_text,
                    candidates=tuple(
                        RetrievalCandidate(
                            item.candidate_id,
                            item.text,
                            item.sequence_no,
                        )
                        for item in pool.candidates
                    ),
                )
                self.assertIn(pool.relevant_candidate_id, retrieved)

    def test_shared_production_apis_drive_candidate_simulation(self) -> None:
        candidates = (
            RetrievalCandidate("first", "Orchid corridor edit", 1),
            RetrievalCandidate("second", "Unrelated violet note", 2),
        )
        production_prepare = similarity_evaluation.prepare_similarity_text
        production_rank = similarity_evaluation.rank_similarity_candidate_ids

        with patch.object(
            similarity_evaluation,
            "prepare_similarity_text",
            wraps=production_prepare,
        ) as prepared, patch.object(
            similarity_evaluation,
            "rank_similarity_candidate_ids",
            wraps=production_rank,
        ) as ranked:
            simulate_candidate_retrieval(
                scope="artifact_flow",
                query_text="Orchid corridor edits",
                candidates=candidates,
            )

        self.assertEqual(1 + len(candidates), prepared.call_count)
        ranked.assert_called_once()
        self.assertEqual(8, ranked.call_args.kwargs["minimum_length"])

    def test_source_candidate_adapter_fixes_three_four_length_boundary(
        self,
    ) -> None:
        production_rank = similarity_evaluation.rank_similarity_candidate_ids
        with patch.object(
            similarity_evaluation,
            "rank_similarity_candidate_ids",
            wraps=production_rank,
        ) as ranked:
            simulate_candidate_retrieval(
                scope="source_binding",
                query_text="cobalt lane sequence",
                candidates=(
                    RetrievalCandidate(
                        "candidate",
                        "cobalt lane sequences",
                        1,
                    ),
                ),
            )

        ranked.assert_called_once()
        self.assertEqual(4, ranked.call_args.kwargs["minimum_length"])
        self.assertEqual(
            len(normalize_text("cobalt lane sequence")),
            ranked.call_args.kwargs["query_normalized_length"],
        )
        self.assertEqual(
            ("length-four",),
            production_rank(
                query_feature_count=1,
                query_normalized_length=4,
                minimum_length=4,
                candidates=(
                    similarity_evaluation.SimilarityCandidateStats(
                        "length-three",
                        1,
                        1,
                        3,
                    ),
                    similarity_evaluation.SimilarityCandidateStats(
                        "length-four",
                        1,
                        1,
                        4,
                    ),
                ),
                limit=2,
            ),
        )

    def test_source_cap_pool_reaches_true_short_candidate_in_full_graph(self) -> None:
        pools = [
            pool
            for pool in self.dataset.retrieval_pools
            if pool.scope == "source_binding" and pool.pool_id.endswith("miss")
        ]
        self.assertEqual(4, len(pools))
        for pool in pools:
            with self.subTest(pool_id=pool.pool_id):
                scenario = LineageScenario(
                    scenario_id=f"full-graph-{pool.pool_id}",
                    split=pool.split,
                    source_text=pool.query_text,
                    artifact_texts=tuple(item.text for item in pool.candidates),
                    sink_type="external_search",
                    should_reach_sink=True,
                    expected_action="block",
                    observe_only=False,
                    tags=("cap", "integration"),
                    rationale="Exercise production source candidate ranking.",
                    family=pool.family,
                )
                material = similarity_evaluation._make_scenario_material(scenario)
                relevant_index = next(
                    index
                    for index, item in enumerate(pool.candidates)
                    if item.candidate_id == pool.relevant_candidate_id
                )
                relevant_fragment_id = material.contexts[
                    relevant_index
                ].fragment.fragment_id

                edges = build_source_binding_edges(
                    [material.source],
                    list(material.contexts),
                    [],
                )

                self.assertEqual(
                    {relevant_fragment_id},
                    {edge.dst_node_id for edge in edges},
                )

    def test_json_escaped_query_wrapper_reaches_source_in_production_graph(
        self,
    ) -> None:
        scenario = LineageScenario(
            scenario_id="json-query-separator-integration",
            split="development",
            source_text="C.AB12/CD34/EF56",
            artifact_texts=(r"query=C.AB12\/CD34\/EF56",),
            sink_type="external_search",
            should_reach_sink=True,
            expected_action="block",
            observe_only=False,
            tags=("integration", "json_escape", "query", "separator"),
            rationale="Exercise separator transport inside a query wrapper.",
            family="json_query_separator_transport",
        )
        material = similarity_evaluation._make_scenario_material(scenario)
        original_context = material.contexts[0]
        query_context = replace(
            original_context,
            fragment=replace(
                original_context.fragment,
                json_pointer="/query",
                semantic_role="query",
            ),
        )

        edges = build_source_binding_edges(
            [material.source],
            [query_context],
            [],
        )

        self.assertEqual(1, len(edges))
        self.assertEqual(material.source.chunk_id, edges[0].src_node_id)
        self.assertEqual(query_context.fragment.fragment_id, edges[0].dst_node_id)
        self.assertEqual("source_binding", edges[0].relation)
        self.assertEqual("substring", edges[0].method)

    def test_each_split_reproduces_baseline_and_reports_family_metrics(self) -> None:
        for split, report in self.reports.items():
            with self.subTest(split=split):
                self.assertEqual(2, report["schema_version"])
                self.assertEqual("similarity-evaluation-v2", report["runner_version"])
                self.assertTrue(report["baseline"]["reproduced"])
                self.assertTrue(report["summary"]["check_passed"])
                self.assertTrue(report["summary"]["privacy_passed"])
                self.assertTrue(report["summary"]["parity_passed"])
                self.assertTrue(report["summary"]["go_no_go_passed"])
                self.assertTrue(
                    report["metrics"]["pair_classification"]["by_family"]
                )
                self.assertTrue(
                    report["metrics"]["candidate_retrieval"]["artifact_flow"][
                        "by_family"
                    ]
                )
                self.assertTrue(
                    report["metrics"]["candidate_retrieval"]["source_binding"][
                        "by_family"
                    ]
                )
                self.assertTrue(report["metrics"]["end_to_end"]["by_family"])

        development = self.reports["development"]
        for scope, expected_pool, expected_saturated in (
            ("artifact_flow", 53, 4),
            ("source_binding", 203, 4),
        ):
            candidate = development["metrics"]["candidate_retrieval"][scope]
            self.assertEqual(expected_pool, candidate["pool_size"])
            self.assertEqual(expected_saturated, candidate["saturated_case_count"])
            self.assertEqual(1.0, candidate["saturation_rate"])
            self.assertEqual(1.0, candidate["gate"]["recall"])
            self.assertEqual(1.0, candidate["gate_saturated"]["recall"])
            self.assertRegex(
                candidate["gate"]["candidate_sets_sha256"],
                r"^[0-9a-f]{64}$",
            )
            for case in self.reports["development"]["cases"]["retrieval"]:
                if case["scope"] == scope:
                    self.assertRegex(
                        case["candidate_set_sha256"],
                        r"^[0-9a-f]{64}$",
                    )

    def test_report_contains_no_fixture_body_or_individual_body_hash(self) -> None:
        serialized = json.dumps(
            self.reports["all"],
            ensure_ascii=False,
            sort_keys=True,
        )
        for case in self.reports["all"]["cases"].values():
            for item in case:
                serialized = serialized.replace(item["id"], "<case-id>")

        for fixture_text in similarity_evaluation._fixture_texts(self.dataset):
            with self.subTest(length=len(fixture_text)):
                if similarity_evaluation._is_privacy_body_probe(fixture_text):
                    self.assertNotIn(fixture_text, serialized)
                self.assertNotIn(
                    hashlib.sha256(fixture_text.encode("utf-8")).hexdigest(),
                    serialized,
                )

    def test_privacy_runtime_detects_distinctive_body_exposure(self) -> None:
        privacy = similarity_evaluation._privacy_metrics(
            self.dataset,
            {
                "accidental_values": [
                    "orchid-4827",
                    "correcthorsebatterystaple",
                ]
            },
        )

        self.assertGreaterEqual(privacy["fixture_body_exposure_count"], 2)
        self.assertGreaterEqual(privacy["total_exposure_count"], 2)
        self.assertTrue(
            similarity_evaluation._is_privacy_body_probe("orchid-4827")
        )
        self.assertTrue(
            similarity_evaluation._is_privacy_body_probe(
                "correcthorsebatterystaple"
            )
        )
        self.assertFalse(similarity_evaluation._is_privacy_body_probe("password"))

    def test_check_and_require_go_are_separate_cli_contracts(self) -> None:
        common = [
            sys.executable,
            "-m",
            CLI_MODULE,
            "--dataset",
            str(V2_ROOT),
            "--split",
            "development",
            "--benchmark-repeats",
            "1",
            "--format",
            "text",
        ]
        checked = subprocess.run(
            [*common, "--check"],
            cwd=REPO_ROOT,
            check=False,
            text=True,
            capture_output=True,
        )
        required = subprocess.run(
            [*common, "--require-go"],
            cwd=REPO_ROOT,
            check=False,
            text=True,
            capture_output=True,
        )

        self.assertEqual(0, checked.returncode, checked.stderr)
        self.assertIn("contract check=PASS", checked.stdout)
        self.assertEqual(0, required.returncode, required.stderr)
        self.assertIn("quality require-go=PASS", required.stdout)

    def test_loader_rejects_mirror_cap_and_shape_contract_mutations(self) -> None:
        mutations = {
            "mirror": lambda manifest: manifest["family_contract"][
                "pair_families"
            ].__setitem__(
                "validation",
                manifest["family_contract"]["pair_families"]["development"],
            ),
            "cap": lambda manifest: manifest["family_contract"].__setitem__(
                "minimum_source_pool_size", 204
            ),
            "shape": lambda manifest: manifest["family_contract"].__setitem__(
                "development_shape_sha256", "0" * 64
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "v2"
                shutil.copytree(V2_ROOT, root)
                manifest_path = root / "manifest.json"
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                mutate(manifest)
                manifest_path.write_text(
                    json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
                with self.assertRaises(SimilarityDatasetError):
                    load_similarity_dataset(root)

    def test_loader_rejects_oversized_text_recipe_before_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "v2"
            shutil.copytree(V2_ROOT, root)
            pairs_path = root / "pairs.jsonl"
            records = [
                json.loads(line)
                for line in pairs_path.read_text(encoding="utf-8").splitlines()
            ]
            recipe_record = next(
                record
                for record in records
                if record["id"] == "dev-pair-bounded-middle-change"
            )
            recipe_record["left_text"]["head"] = "AA"
            recipe_record["left_text"]["head_count"] = 65_536
            pairs_path.write_text(
                "".join(
                    json.dumps(record, ensure_ascii=False, separators=(",", ":"))
                    + "\n"
                    for record in records
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                SimilarityDatasetError,
                "expanded text exceeds 65536 characters",
            ):
                load_similarity_dataset(root)

    def test_loader_rejects_oversized_candidate_series_before_expansion(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "v2"
            shutil.copytree(V2_ROOT, root)
            pools_path = root / "retrieval_pools.jsonl"
            records = [
                json.loads(line)
                for line in pools_path.read_text(encoding="utf-8").splitlines()
            ]
            series = records[0]["candidates"]
            series["decoy_text_prefix"] = "x" * 5_000
            series["count"] = 1_000
            pools_path.write_text(
                "".join(
                    json.dumps(record, ensure_ascii=False, separators=(",", ":"))
                    + "\n"
                    for record in records
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                SimilarityDatasetError,
                "expanded candidate pool is too large",
            ):
                load_similarity_dataset(root)

    def test_loader_bounds_constant_decoy_series(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "v2"
            shutil.copytree(V2_ROOT, root)
            pools_path = root / "retrieval_pools.jsonl"
            records = [
                json.loads(line)
                for line in pools_path.read_text(encoding="utf-8").splitlines()
            ]
            record = next(
                item for item in records if "dual_objective" in item["tags"]
            )
            record["candidates"]["matching_decoy_count"] = record["candidates"][
                "count"
            ]
            pools_path.write_text(
                "".join(
                    json.dumps(item, ensure_ascii=False, separators=(",", ":"))
                    + "\n"
                    for item in records
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                SimilarityDatasetError,
                "matching_decoy_count must be between zero and count - 1",
            ):
                load_similarity_dataset(root)

    def test_baseline_or_digest_drift_fails_check_but_not_quality(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "v2"
            shutil.copytree(V2_ROOT, root)
            manifest_path = root / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["baselines"]["development"]["pair_tp"] += 1
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )

            report = evaluate_similarity(
                load_similarity_dataset(root),
                split="development",
                benchmark_repeats=1,
            )

        self.assertFalse(report["baseline"]["reproduced"])
        self.assertFalse(report["summary"]["check_passed"])
        self.assertTrue(report["summary"]["go_no_go_passed"])

    @staticmethod
    def _compare_pool_text(pool: RetrievalPool, candidate_text: str):
        query_text = pool.query_text
        return compare_text(
            left_text=query_text,
            left_normalized=normalize_text(query_text),
            left_hash=hashlib.sha256(query_text.encode("utf-8")).hexdigest(),
            right_text=candidate_text,
            right_normalized=normalize_text(candidate_text),
            right_hash=hashlib.sha256(candidate_text.encode("utf-8")).hexdigest(),
            minimum_length=4 if pool.scope == "source_binding" else 8,
        )


if __name__ == "__main__":
    unittest.main()
