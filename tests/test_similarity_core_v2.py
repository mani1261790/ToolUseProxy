from __future__ import annotations

import hashlib
import unittest

from hook_monitor.analysis.similarity import (
    SIMILARITY_CANONICAL_MAX_CHARS,
    SIMILARITY_PROFILE_VERSION,
    SIMILARITY_TOKEN_EQUIVALENT_SCORE,
    PreparedSimilarityText,
    SimilarityCandidateStats,
    compare_source_binding_text,
    compare_text,
    prepare_similarity_text,
    rank_similarity_candidate_ids,
)
from hook_monitor.runtime.normalize import normalize_text


class _RecordingEmbeddingBackend:
    def __init__(self) -> None:
        self.calls = 0

    def cosine_similarity(self, left_text: str, right_text: str) -> float:
        self.calls += 1
        return 1.0


class SimilarityCoreV2Test(unittest.TestCase):
    def test_source_binding_alpha_containment_requires_selected_security_field(
        self,
    ) -> None:
        value = "ultravioletharbororchid"
        wrapper = f"submit {value} through external payload channel"
        for signal in ("registered_source", "selected_field"):
            with self.subTest(signal=signal):
                decision = self._compare_source_binding(value, wrapper, signal)
                self.assertFalse(decision.matched)
                self.assertEqual("none", decision.method)

        selected = self._compare_source_binding(
            value,
            wrapper,
            "selected_security_field",
        )
        self.assertTrue(selected.matched)
        self.assertEqual("substring", selected.method)
        self.assertTrue(self._compare(value, wrapper).matched)

        exact = self._compare_source_binding(
            value,
            value,
            "registered_source",
        )
        self.assertTrue(exact.matched)
        self.assertEqual("exact", exact.method)

    def test_profile_prepares_one_origin_independent_exact_key_and_feature_set(
        self,
    ) -> None:
        literal = "C.AB12-CD34/EF56"
        transported = "C%2EAB12-CD34%2FEF56"

        prepared_literal = prepare_similarity_text(literal)
        prepared_transport = prepare_similarity_text(transported)

        self.assertEqual("similarity-profile-v2", SIMILARITY_PROFILE_VERSION)
        self.assertEqual(
            prepared_literal.primary_exact_key,
            prepared_transport.primary_exact_key,
        )
        self.assertEqual(
            prepared_literal.candidate_features,
            prepared_transport.candidate_features,
        )
        self.assertEqual(64, len(prepared_literal.primary_exact_key))
        self.assertTrue(
            all(feature.startswith("c5:") for feature in prepared_literal.candidate_features)
        )

    def test_percent_transport_is_strict_and_decoded_only_once(self) -> None:
        literal_text = "C.AB12/CD34/EF56"
        one_pass_text = "C%2EAB12%2FCD34%2FEF56"
        double_pass_text = "C%252EAB12%252FCD34%252FEF56"
        literal = prepare_similarity_text(literal_text)
        malformed = prepare_similarity_text("C%2GAB12/CD34/EF56")
        invalid_utf8 = prepare_similarity_text("C%FFAB12/CD34/EF56")
        double_encoded = prepare_similarity_text(double_pass_text)

        self.assertNotEqual(literal.primary_exact_key, malformed.primary_exact_key)
        self.assertNotEqual(literal.primary_exact_key, invalid_utf8.primary_exact_key)
        self.assertNotEqual(
            literal.primary_exact_key,
            double_encoded.primary_exact_key,
        )
        literal_decision = self._compare(literal_text, one_pass_text)
        self.assertTrue(literal_decision.matched)
        self.assertEqual("exact", literal_decision.method)

        backend = _RecordingEmbeddingBackend()
        double_decision = self._compare(
            one_pass_text,
            double_pass_text,
            embedding_backend=backend,
        )
        self.assertFalse(double_decision.matched)
        self.assertEqual("none", double_decision.method)
        self.assertEqual(0, backend.calls)

    def test_nfkc_json_slash_and_identifier_separators_are_canonical_exact(self) -> None:
        cases = (
            ("ＡＢ１２-ＣＤ３４-ＥＦ５６", "AB12-CD34-EF56"),
            ("C.AB12\\/CD34\\/EF56", "C.AB12/CD34/EF56"),
            ("C.AB12-CD34-EF56", "C.AB12 CD34 EF56"),
            ("ZX91-QR82-LM73", "ZX91 QR82 LM73"),
            ("DV-4827-ALPHA-9031", "DV 4827 ALPHA 9031"),
            ("ab-12-cd-34", "ab 12 cd 34"),
        )
        for left, right in cases:
            with self.subTest(left=left, right=right):
                decision = self._compare(left, right)
                self.assertTrue(decision.matched)
                self.assertEqual("exact", decision.method)
                self.assertEqual(1.0, decision.score)

    def test_identifier_separator_canonicalization_preserves_token_boundaries(
        self,
    ) -> None:
        left = "ab-12-cd-34"
        right = "a-b1-2c-d34"

        self.assertNotEqual(
            prepare_similarity_text(left).primary_exact_key,
            prepare_similarity_text(right).primary_exact_key,
        )
        self.assertFalse(self._compare(left, right).matched)

        generic = "api key 2026"
        for transported in ("api-key-2026", "api%20key%202026"):
            with self.subTest(transported=transported):
                self.assertNotEqual(
                    prepare_similarity_text(generic).primary_exact_key,
                    prepare_similarity_text(transported).primary_exact_key,
                )
                self.assertFalse(self._compare(generic, transported).matched)

    def test_distinctive_complete_containment_has_critical_strength(self) -> None:
        cases = (
            (
                "C.AB12-CD34",
                "submit payload=C.AB12-CD34 to the remote endpoint",
            ),
            (
                "A94KM2TQ7VX5RN8C",
                "submit payload=A94KM2TQ7VX5RN8C to the remote endpoint",
            ),
        )
        for shorter, wrapper in cases:
            with self.subTest(shorter=shorter):
                decision = self._compare(shorter, wrapper)

                self.assertTrue(decision.matched)
                self.assertEqual("substring", decision.method)
                self.assertEqual(1.0, decision.score)
                self.assertNotIn(shorter, decision.reason)

    def test_identifier_containment_rejects_adjacent_alphanumeric_changes(self) -> None:
        identifier = "A94KM2TQ7VX5RN8C"
        variants = (
            f"{identifier}X",
            f"X{identifier}",
            identifier[:-1],
        )

        for variant in variants:
            with self.subTest(variant=variant):
                self.assertFalse(self._compare(identifier, variant).matched)

    def test_low_information_security_terms_do_not_create_lineage(self) -> None:
        cases = (
            ("password", "password policy"),
            ("authorization", "authorization header"),
            ("client secret", "client secret key"),
            ("access token", "access token metadata"),
            ("private key", "private key format"),
            ("authentication token", "authentication token metadata"),
            ("bearer authorization", "bearer authorization header"),
            ("secret access key", "secret access key identifier"),
            ("database password", "database password policy"),
            ("service account token", "service account token documentation"),
            ("production access", "production access policy"),
            (
                "public api authentication token",
                "public api authentication token guide",
            ),
            ("api key 2026", "api key 2026 policy"),
        )
        for left, right in cases:
            with self.subTest(left=left):
                self.assertFalse(self._compare(left, right).matched)

        for phrase in (
            "production access",
            "service account token",
            "public api authentication token",
            "api key 2026",
        ):
            with self.subTest(exact_only_phrase=phrase):
                self.assertEqual(frozenset(), prepare_similarity_text(phrase).candidate_features)

        exact = self._compare("database password", "DATABASE   PASSWORD")
        self.assertTrue(exact.matched)
        self.assertEqual("exact", exact.method)
        generic_exact = self._compare("api key 2026", "API   KEY 2026")
        self.assertTrue(generic_exact.matched)
        self.assertEqual("exact", generic_exact.method)

    def test_short_numeric_labels_do_not_link_to_wrappers(self) -> None:
        phrases = (
            "release 2026",
            "status 200",
            "version 1234",
            "invoice 2026",
        )
        for phrase in phrases:
            with self.subTest(phrase=phrase):
                backend = _RecordingEmbeddingBackend()
                decision = self._compare(
                    phrase,
                    f"payload={phrase} for the public report",
                    embedding_backend=backend,
                )

                self.assertFalse(decision.matched)
                self.assertEqual("none", decision.method)
                self.assertEqual(0, backend.calls)
                self.assertEqual(
                    frozenset(),
                    prepare_similarity_text(phrase).candidate_features,
                )

    def test_long_numeric_secrets_keep_features_and_wrapper_containment(self) -> None:
        phrases = (
            "api key 927461839205",
            "password 73920518",
            "access token 1234567890123456",
            "client secret 202607189273",
        )
        for phrase in phrases:
            with self.subTest(phrase=phrase):
                prepared = prepare_similarity_text(phrase)
                decision = self._compare(
                    phrase,
                    f"submit payload={phrase} to the remote endpoint",
                )

                self.assertTrue(prepared.candidate_features)
                self.assertTrue(decision.matched)
                self.assertEqual("substring", decision.method)
                self.assertEqual(1.0, decision.score)

    def test_low_signal_prose_containment_requires_high_coverage(self) -> None:
        base = "production deployment is approved for release"
        suffixes = (
            "only for internal users",
            "if audit passes",
            "subject to final review",
            "excluding contractors",
            "pending compliance review",
            "until tomorrow",
            "provided audit passes",
        )
        for suffix in suffixes:
            with self.subTest(suffix=suffix):
                backend = _RecordingEmbeddingBackend()
                decision = self._compare(
                    base,
                    f"{base} {suffix}",
                    embedding_backend=backend,
                )

                self.assertFalse(decision.matched)
                self.assertEqual("none", decision.method)
                self.assertEqual(0, backend.calls)

    def test_explicit_security_value_and_short_identifier_containment_survive(
        self,
    ) -> None:
        cases = (
            (
                "alpha secret design threshold 0.73",
                "query=alpha secret design threshold 0.73 implementation",
            ),
            (
                "orchid-4827",
                "dispatch orchid-4827 through cedar corridor after review",
            ),
        )
        for shorter, wrapper in cases:
            with self.subTest(shorter=shorter):
                decision = self._compare(shorter, wrapper)

                self.assertTrue(decision.matched)
                self.assertEqual("substring", decision.method)
                self.assertEqual(1.0, decision.score)

    def test_long_diverse_alpha_secrets_survive_wrapper_containment(self) -> None:
        cases = (
            (
                "correcthorsebatterystaple",
                "payload=correcthorsebatterystaple&scope=external",
            ),
            (
                "api key abcdefghijklmnopqrstuvwxyz",
                "submit api key abcdefghijklmnopqrstuvwxyz to the remote endpoint",
            ),
            (
                "password correcthorsebatterystaple",
                "submit password correcthorsebatterystaple to the remote endpoint",
            ),
            (
                "client secret ultravioletharbororchid",
                "submit client secret ultravioletharbororchid to the remote endpoint",
            ),
            (
                "access token velvetmarblelanternquartz",
                "submit access token velvetmarblelanternquartz to the remote endpoint",
            ),
        )
        for secret, wrapper in cases:
            with self.subTest(secret=secret):
                prepared = prepare_similarity_text(secret)
                decision = self._compare(secret, wrapper)

                self.assertTrue(prepared.candidate_features)
                self.assertTrue(decision.matched)
                self.assertEqual("substring", decision.method)
                self.assertEqual(1.0, decision.score)

    def test_long_diverse_alpha_secret_rejects_adjacent_suffix(self) -> None:
        secrets = (
            "correcthorsebatterystaple",
            "api key abcdefghijklmnopqrstuvwxyz",
            "password correcthorsebatterystaple",
            "client secret ultravioletharbororchid",
            "access token velvetmarblelanternquartz",
        )
        for secret in secrets:
            with self.subTest(secret=secret):
                self.assertFalse(self._compare(secret, f"{secret}x").matched)

        self.assertFalse(self._compare("documentation", "documentation portal").matched)

    def test_long_alpha_token_in_conditional_prose_is_not_distinctive(self) -> None:
        bases = (
            "production deployment documentationreference is approved",
            "public configurationmanagement release is approved",
            "authenticationdocumentation rollout is approved",
        )
        suffixes = (
            "only for internal users",
            "if audit passes",
            "subject to final review",
            "excluding contractors",
            "pending public review",
        )
        for base in bases:
            for suffix in suffixes:
                with self.subTest(base=base, suffix=suffix):
                    backend = _RecordingEmbeddingBackend()
                    decision = self._compare(
                        base,
                        f"{base} {suffix}",
                        embedding_backend=backend,
                    )

                    self.assertFalse(decision.matched)
                    self.assertEqual("none", decision.method)
                    self.assertEqual(0, backend.calls)

    def test_long_diverse_alpha_thresholds_are_exact(self) -> None:
        threshold_value = "abcdefghijabcdefghij"
        below_length = "abcdefghijklmnopqrs"
        below_diversity = "abcdefghiabcdefghiab"

        threshold = self._compare(
            threshold_value,
            f"payload={threshold_value}&scope=external",
        )
        self.assertTrue(threshold.matched)
        self.assertEqual("substring", threshold.method)
        self.assertEqual(1.0, threshold.score)

        for value in (below_length, below_diversity):
            with self.subTest(value=value):
                decision = self._compare(
                    value,
                    f"payload={value}&scope=external",
                )
                self.assertFalse(decision.matched)

        self.assertEqual(20, len(threshold_value))
        self.assertEqual(10, len(set(threshold_value)))
        self.assertEqual(19, len(below_length))
        self.assertEqual(9, len(set(below_diversity)))

    def test_identifier_separator_transport_survives_punctuation_wrappers(self) -> None:
        identifier = "DV-4827-ALPHA-9031"
        wrappers = (
            "send: DV 4827 ALPHA 9031 externally",
            "send (DV 4827 ALPHA 9031) externally",
            '{"payload":"DV 4827 ALPHA 9031"}',
            "payload=DV 4827 ALPHA 9031&x=1",
        )
        for wrapper in wrappers:
            with self.subTest(wrapper=wrapper):
                decision = self._compare(identifier, wrapper)

                self.assertTrue(decision.matched)
                self.assertEqual("substring", decision.method)
                self.assertEqual(1.0, decision.score)

    def test_negation_conflict_vetoes_high_lexical_overlap(self) -> None:
        cases = (
            (
                "production deployment is approved for release",
                "production deployment is not approved for release",
            ),
            (
                "production deployment is approved for release",
                "production deployment is approved for release unless audit passes",
            ),
            (
                "production deployment is approved for release",
                "production deployment is approved for release except contractors",
            ),
            (
                "production deployment access for release",
                "production deployment access for release revoked",
            ),
        )
        for left, right in cases:
            with self.subTest(right=right):
                backend = _RecordingEmbeddingBackend()
                decision = self._compare(
                    left,
                    right,
                    embedding_backend=backend,
                )

                self.assertFalse(decision.matched)
                self.assertEqual("none", decision.method)
                self.assertEqual(0, backend.calls)

    def test_transformed_conflicts_are_vetoed_before_positive_matching(self) -> None:
        cases = (
            (
                "production deployment is approved for release",
                "production%20deployment%20is%20approved%20for%20release%20unless%20audit%20passes",
            ),
            (
                "production deployment is approved for release",
                "production deployment is approved for release ｅｘｃｅｐｔ contractors",
            ),
            (
                "production deployment access for release",
                "production%20deployment%20access%20for%20release%20revoked",
            ),
            (
                "generated report owner alpha region east status active",
                "archived%20generated%20report%20owner%20beta%20region%20west%20status%20active",
            ),
        )
        for left, transformed_conflict in cases:
            with self.subTest(transformed_conflict=transformed_conflict):
                backend = _RecordingEmbeddingBackend()
                decision = self._compare(
                    left,
                    transformed_conflict,
                    embedding_backend=backend,
                )

                self.assertFalse(decision.matched)
                self.assertEqual("none", decision.method)
                self.assertIn("content conflict", decision.reason)
                self.assertEqual(0, backend.calls)

    def test_template_value_conflicts_are_not_treated_as_edits(self) -> None:
        cases = (
            (
                "generated report owner alpha region east status active",
                "generated report owner beta region west status active",
            ),
            (
                "service alpha latency high retries three",
                "service beta latency high retries three",
            ),
            (
                "generated report owner alpha region east status active",
                "archived generated report owner beta region west status active",
            ),
        )
        for left, right in cases:
            with self.subTest(left=left):
                self.assertFalse(self._compare(left, right).matched)

    def test_shared_identifier_prefix_does_not_hide_a_distinct_suffix(self) -> None:
        cases = (
            ("C.AB12-CD34.0000000001", "C.AB12-CD34.9999999999"),
            ("C.AB12-CD34-EF56-X", "C.AB12-CD34-EF56-Y"),
        )
        for left, right in cases:
            with self.subTest(left=left):
                self.assertFalse(self._compare(left, right).matched)

    def test_only_explicit_low_risk_token_equivalences_survive_conflict_guard(
        self,
    ) -> None:
        cases = (
            (
                "confidential launch sequence nine for tomorrow",
                "confidential launch sequences nine for tomorrow",
            ),
            (
                "confidential architecture revision seven",
                "confidential architecture revision 7",
            ),
        )
        for left, right in cases:
            with self.subTest(left=left):
                decision = self._compare(left, right)
                self.assertTrue(decision.matched)
                self.assertEqual("token_equivalent", decision.method)
                self.assertEqual(SIMILARITY_TOKEN_EQUIVALENT_SCORE, decision.score)

    def test_unlisted_trailing_s_pairs_are_not_token_aliases(self) -> None:
        cases = (
            (
                "confidential clas marker seven",
                "confidential class marker seven",
            ),
            (
                "confidential analysi marker seven",
                "confidential analysis marker seven",
            ),
        )
        for left, right in cases:
            with self.subTest(left=left):
                decision = self._compare(left, right)

                self.assertFalse(decision.matched)
                self.assertNotEqual("token_equivalent", decision.method)

    def test_long_input_skips_added_transforms_and_candidate_features(
        self,
    ) -> None:
        private_marker = "PRIVATE-MIDDLE-MARKER"
        text = (
            "A" * SIMILARITY_CANONICAL_MAX_CHARS
            + private_marker
            + "Z" * SIMILARITY_CANONICAL_MAX_CHARS
        )

        prepared = prepare_similarity_text(text)

        self.assertIsInstance(prepared, PreparedSimilarityText)
        self.assertFalse(prepared.canonicalization_bounded)
        self.assertEqual(frozenset(), prepared.candidate_features)
        self.assertNotIn(private_marker, repr(prepared))
        self.assertEqual(prepared, prepare_similarity_text(text))

        compatibility_expansion = "\ufdfa" * SIMILARITY_CANONICAL_MAX_CHARS
        expanded = prepare_similarity_text(compatibility_expansion)
        self.assertFalse(expanded.canonicalization_bounded)
        self.assertEqual(frozenset(), expanded.candidate_features)

    def test_over_limit_pairs_require_raw_exact_and_skip_embedding(self) -> None:
        half = SIMILARITY_CANONICAL_MAX_CHARS // 2
        left = ("A" * half) + "X" + ("B" * half)
        right = ("A" * half) + "Y" + ("B" * half)
        prepared_left = prepare_similarity_text(left)
        prepared_right = prepare_similarity_text(right)

        self.assertFalse(prepared_left.canonicalization_bounded)
        self.assertFalse(prepared_right.canonicalization_bounded)
        self.assertEqual(frozenset(), prepared_left.candidate_features)
        self.assertEqual(frozenset(), prepared_right.candidate_features)
        backend = _RecordingEmbeddingBackend()
        decision = self._compare(left, right, embedding_backend=backend)

        self.assertFalse(decision.matched)
        self.assertEqual("none", decision.method)
        self.assertEqual(0.0, decision.score)
        self.assertIn("raw exact match required", decision.reason)
        self.assertEqual(0, backend.calls)

        raw_exact = self._compare(left, left)
        self.assertTrue(raw_exact.matched)
        self.assertEqual("exact", raw_exact.method)

    def test_over_limit_exact_index_key_uses_raw_not_normalized_identity(self) -> None:
        upper = "A" * (SIMILARITY_CANONICAL_MAX_CHARS + 1)
        lower = upper.casefold()
        prepared_upper = prepare_similarity_text(
            upper,
            normalized_text=normalize_text(upper),
        )
        prepared_lower = prepare_similarity_text(
            lower,
            normalized_text=normalize_text(lower),
        )

        self.assertFalse(prepared_upper.canonicalization_bounded)
        self.assertFalse(prepared_lower.canonicalization_bounded)
        self.assertEqual(frozenset(), prepared_upper.candidate_features)
        self.assertEqual(frozenset(), prepared_lower.candidate_features)
        self.assertNotEqual(
            prepared_upper.primary_exact_key,
            prepared_lower.primary_exact_key,
        )
        self.assertEqual(
            prepared_upper.primary_exact_key,
            prepare_similarity_text(
                upper,
                normalized_text=normalize_text(upper),
            ).primary_exact_key,
        )
        self.assertFalse(self._compare(upper, lower).matched)
        self.assertTrue(self._compare(upper, upper).matched)

    def test_invalid_input_types_fail_before_feature_materialization(self) -> None:
        with self.assertRaises(TypeError):
            prepare_similarity_text(123)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            prepare_similarity_text("valid", normalized_text=123)  # type: ignore[arg-type]

    def test_candidate_ranking_uses_exact_coverage_then_overlap_then_id(self) -> None:
        candidates = (
            SimilarityCandidateStats("coverage-one-small", 5, 5, 8),
            SimilarityCandidateStats("coverage-nine-tenths", 9, 10, 8),
            SimilarityCandidateStats("coverage-one-large", 7, 7, 8),
            SimilarityCandidateStats("tie-b", 4, 8, 8),
            SimilarityCandidateStats("tie-a", 4, 8, 8),
        )

        self.assertEqual(
            (
                "coverage-one-large",
                "coverage-one-small",
                "coverage-nine-tenths",
                "tie-a",
            ),
            rank_similarity_candidate_ids(
                query_feature_count=10,
                query_normalized_length=10,
                minimum_length=8,
                candidates=candidates,
                limit=4,
            ),
        )

    def test_candidate_ranking_balances_coverage_and_overlap_objectives(self) -> None:
        candidates = (
            SimilarityCandidateStats("coverage-a", 1, 1, 8),
            SimilarityCandidateStats("coverage-b", 1, 1, 8),
            SimilarityCandidateStats("coverage-c", 1, 1, 8),
            SimilarityCandidateStats("overlap-a", 50, 100, 100),
            SimilarityCandidateStats("overlap-b", 40, 100, 100),
        )

        self.assertEqual(
            ("coverage-a", "coverage-b", "overlap-a", "overlap-b"),
            rank_similarity_candidate_ids(
                query_feature_count=100,
                query_normalized_length=100,
                minimum_length=8,
                candidates=candidates,
                limit=4,
            ),
        )
        self.assertEqual(
            ("coverage-a", "coverage-b", "overlap-a"),
            rank_similarity_candidate_ids(
                query_feature_count=100,
                query_normalized_length=100,
                minimum_length=8,
                candidates=candidates,
                limit=3,
            ),
        )

    def test_overlap_lane_quota_counts_unique_candidates_after_duplicates(self) -> None:
        shared_lane_leaders = tuple(
            SimilarityCandidateStats(
                f"shared-{index:03d}",
                900 - index,
                900 - index,
                100,
            )
            for index in range(100)
        )
        coverage_only_decoys = tuple(
            SimilarityCandidateStats(f"coverage-only-{index:03d}", 1, 1, 8) for index in range(101)
        )
        overlap_true = SimilarityCandidateStats("overlap-rank-101", 800, 1000, 100)

        ranked = rank_similarity_candidate_ids(
            query_feature_count=1000,
            query_normalized_length=100,
            minimum_length=8,
            candidates=(*shared_lane_leaders, *coverage_only_decoys, overlap_true),
            limit=200,
        )

        self.assertEqual(200, len(ranked))
        self.assertIn(overlap_true.candidate_id, ranked)
        self.assertEqual(100, ranked.index(overlap_true.candidate_id))

    def test_candidate_ranking_filters_pair_ineligible_unicode_lengths(self) -> None:
        candidates = (
            SimilarityCandidateStats("seven-code-points", 1, 1, 7),
            SimilarityCandidateStats("eight-code-points", 1, 1, 8),
        )

        self.assertEqual(
            ("eight-code-points",),
            rank_similarity_candidate_ids(
                query_feature_count=1,
                query_normalized_length=len("あいうえおかきく"),
                minimum_length=8,
                candidates=candidates,
                limit=2,
            ),
        )
        self.assertEqual(
            (),
            rank_similarity_candidate_ids(
                query_feature_count=1,
                query_normalized_length=len("あいうえおかき"),
                minimum_length=8,
                candidates=candidates,
                limit=2,
            ),
        )

    def test_source_minimum_has_short_non_exact_shingle_positive(self) -> None:
        left = "alpha!"
        right = "alpha?"

        decision = self._compare(left, right)

        self.assertEqual(6, len(normalize_text(left)))
        self.assertTrue(decision.matched)
        self.assertEqual("shingle_jaccard", decision.method)
        self.assertAlmostEqual(1 / 3, decision.score)
        artifact_scope = compare_text(
            left_text=left,
            left_normalized=normalize_text(left),
            left_hash=hashlib.sha256(left.encode("utf-8")).hexdigest(),
            right_text=right,
            right_normalized=normalize_text(right),
            right_hash=hashlib.sha256(right.encode("utf-8")).hexdigest(),
            minimum_length=8,
        )
        self.assertFalse(artifact_scope.matched)
        self.assertIn("minimum_length=8", artifact_scope.reason)

    def test_candidate_ranking_empty_and_validation_contract(self) -> None:
        valid = SimilarityCandidateStats("valid", 1, 1, 8)
        self.assertEqual(
            (),
            rank_similarity_candidate_ids(
                query_feature_count=0,
                query_normalized_length=8,
                minimum_length=8,
                candidates=(valid,),
                limit=1,
            ),
        )
        self.assertEqual(
            (),
            rank_similarity_candidate_ids(
                query_feature_count=1,
                query_normalized_length=8,
                minimum_length=8,
                candidates=(valid,),
                limit=0,
            ),
        )

        invalid_calls = (
            lambda: rank_similarity_candidate_ids(
                query_feature_count=-1,
                query_normalized_length=8,
                minimum_length=8,
                candidates=(),
                limit=1,
            ),
            lambda: rank_similarity_candidate_ids(
                query_feature_count=1,
                query_normalized_length=-1,
                minimum_length=8,
                candidates=(),
                limit=1,
            ),
            lambda: rank_similarity_candidate_ids(
                query_feature_count=1,
                query_normalized_length=8,
                minimum_length=0,
                candidates=(),
                limit=1,
            ),
            lambda: rank_similarity_candidate_ids(
                query_feature_count=1,
                query_normalized_length=8,
                minimum_length=8,
                candidates=(),
                limit=-1,
            ),
            lambda: rank_similarity_candidate_ids(
                query_feature_count=1,
                query_normalized_length=8,
                minimum_length=8,
                candidates=(SimilarityCandidateStats("", 1, 1, 8),),
                limit=1,
            ),
            lambda: rank_similarity_candidate_ids(
                query_feature_count=1,
                query_normalized_length=8,
                minimum_length=8,
                candidates=(SimilarityCandidateStats(1, 1, 1, 8),),  # type: ignore[arg-type]
                limit=1,
            ),
            lambda: rank_similarity_candidate_ids(
                query_feature_count=1,
                query_normalized_length=8,
                minimum_length=8,
                candidates=(
                    SimilarityCandidateStats("duplicate", 1, 1, 8),
                    SimilarityCandidateStats("duplicate", 1, 1, 8),
                ),
                limit=1,
            ),
            lambda: rank_similarity_candidate_ids(
                query_feature_count=1,
                query_normalized_length=8,
                minimum_length=8,
                candidates=(SimilarityCandidateStats("zero-overlap", 0, 1, 8),),
                limit=1,
            ),
            lambda: rank_similarity_candidate_ids(
                query_feature_count=2,
                query_normalized_length=8,
                minimum_length=8,
                candidates=(SimilarityCandidateStats("too-much-overlap", 2, 1, 8),),
                limit=1,
            ),
            lambda: rank_similarity_candidate_ids(
                query_feature_count=1,
                query_normalized_length=8,
                minimum_length=8,
                candidates=(SimilarityCandidateStats("negative-length", 1, 1, -1),),
                limit=1,
            ),
        )
        for invalid_call in invalid_calls:
            with self.subTest(invalid_call=invalid_call):
                with self.assertRaises(ValueError):
                    invalid_call()

    @staticmethod
    def _compare(
        left: str,
        right: str,
        *,
        embedding_backend: _RecordingEmbeddingBackend | None = None,
    ):
        return compare_text(
            left_text=left,
            left_normalized=normalize_text(left),
            left_hash=hashlib.sha256(left.encode("utf-8")).hexdigest(),
            right_text=right,
            right_normalized=normalize_text(right),
            right_hash=hashlib.sha256(right.encode("utf-8")).hexdigest(),
            embedding_backend=embedding_backend,
            minimum_length=4,
        )

    @staticmethod
    def _compare_source_binding(left: str, right: str, signal: str):
        return compare_source_binding_text(
            source_binding_signal=signal,
            left_text=left,
            left_normalized=normalize_text(left),
            left_hash=hashlib.sha256(left.encode("utf-8")).hexdigest(),
            right_text=right,
            right_normalized=normalize_text(right),
            right_hash=hashlib.sha256(right.encode("utf-8")).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
