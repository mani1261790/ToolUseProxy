from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from hook_monitor.evaluation.pilot_aggregate import build_pilot_comparisons
from hook_monitor.runtime.pilot_models import (
    CauseCategory,
    ClassifiedBy,
    EvidenceSource,
    Externality,
    PayloadResolution,
    PilotObservation,
    PilotProblemEvent,
    PolicyAction,
    ProblemSymptom,
    ReasonCode,
    RecordState,
    ReviewState,
    StudyCohort,
    ToolFamily,
)


PRIVATE_MARKER = "PRIVATE-PROJECT-ALPHA"
PROTECTED_MARKER = "protected-example-value"


class PilotAggregateTest(unittest.TestCase):
    def test_requires_two_projects_at_the_same_twenty_item_boundary(self) -> None:
        observations = self._observations(1, 40)

        self.assertEqual((), build_pilot_comparisons(observations))

    def test_builds_initial_comparison_for_every_qualified_project(self) -> None:
        observations = (
            *self._observations(1, 25),
            *self._observations(2, 20),
            *self._observations(3, 19),
        )

        reports = build_pilot_comparisons(observations)

        self.assertEqual(1, len(reports))
        report = reports[0]
        self.assertEqual(1, report["comparison"]["round"])
        self.assertEqual(2, report["comparison"]["project_count"])
        self.assertEqual(40, report["comparison"]["observation_count"])
        self.assertEqual(
            ["project_1", "project_2"],
            [item["project"] for item in report["projects"]],
        )

    def test_pending_blocks_are_excluded_without_stalling_comparison(self) -> None:
        project_one = list(self._observations(1, 20))
        project_one.insert(
            5,
            self._observation(
                1,
                100,
                action=PolicyAction.BLOCK,
                review=ReviewState.PENDING,
            ),
        )
        observations = (*project_one, *self._observations(2, 20))

        report = build_pilot_comparisons(observations)[0]

        self.assertEqual(40, report["comparison"]["observation_count"])
        self.assertEqual(1, report["comparison"]["excluded_pending_count"])
        self.assertEqual(1, report["projects"][0]["excluded_pending_count"])

    def test_problem_groups_keep_cause_reason_and_tool_association_without_ids(self) -> None:
        observations = list(self._observations(1, 20)) + list(self._observations(2, 20))
        observations[0] = replace(observations[0], policy_action=PolicyAction.BLOCK,
                                  review_state=ReviewState.UNNECESSARY_BLOCK,
                                  cause_candidate=CauseCategory.EXTERNALITY)
        report = build_pilot_comparisons(observations)[0]
        groups = report["problem_groups"]
        self.assertEqual(1, len(groups))
        self.assertEqual("externality", groups[0]["cause"])
        self.assertEqual("shell", groups[0]["tool_family"])
        self.assertEqual(1, groups[0]["problem_count"])
        self.assertEqual(1, groups[0]["symptom"]["unnecessary_block"])
        self.assertNotIn("observation-", str(groups))
        self.assertNotIn("ws_v1_", str(groups))

    def test_incomplete_records_are_reported_but_do_not_count_toward_threshold(self) -> None:
        project_one = list(self._observations(1, 20))
        project_one.insert(
            5,
            replace(
                self._observation(1, 100),
                record_state=RecordState.INCOMPLETE,
            ),
        )

        report = build_pilot_comparisons(
            (*project_one, *self._observations(2, 20))
        )[0]

        self.assertEqual(40, report["comparison"]["observation_count"])
        self.assertEqual(1, report["comparison"]["excluded_incomplete_count"])
        self.assertEqual(1, report["projects"][0]["excluded_incomplete_count"])

    def test_legacy_observations_do_not_count_toward_a_new_comparison(self) -> None:
        observations = (
            *self._observations(1, 20, cohort=StudyCohort.LEGACY),
            *self._observations(2, 20),
        )

        self.assertEqual((), build_pilot_comparisons(observations))

    def test_detector_versions_are_never_mixed(self) -> None:
        observations = (
            *self._observations(1, 20, detector="detector-v1"),
            *self._observations(2, 20, detector="detector-v2"),
        )

        self.assertEqual((), build_pilot_comparisons(observations))

    def test_continued_comparisons_use_twenty_item_rounds(self) -> None:
        observations = (
            *self._observations(1, 45),
            *self._observations(2, 40),
            *self._observations(3, 20),
        )

        reports = build_pilot_comparisons(observations)

        self.assertEqual([1, 2], [item["comparison"]["round"] for item in reports])
        self.assertEqual([3, 2], [item["comparison"]["project_count"] for item in reports])
        self.assertEqual([60, 80], [item["comparison"]["observation_count"] for item in reports])

    def test_project_aliases_stay_stable_when_a_project_misses_a_later_round(self) -> None:
        observations = (
            *self._observations(1, 20),
            *self._observations(2, 40),
            *self._observations(3, 40),
        )

        reports = build_pilot_comparisons(observations)

        self.assertEqual(
            ["project_1", "project_2", "project_3"],
            [item["project"] for item in reports[0]["projects"]],
        )
        self.assertEqual(
            ["project_2", "project_3"],
            [item["project"] for item in reports[1]["projects"]],
        )

    def test_report_separates_reviewed_blocks_without_claiming_accuracy(self) -> None:
        first = list(self._observations(1, 20))
        first[0] = self._observation(
            1,
            0,
            action=PolicyAction.BLOCK,
            review=ReviewState.CORRECT_BLOCK,
        )
        first[1] = self._observation(
            1,
            1,
            action=PolicyAction.BLOCK,
            review=ReviewState.UNNECESSARY_BLOCK,
            cause=CauseCategory.EXTERNALITY,
        )
        first[2] = self._observation(
            1,
            2,
            action=PolicyAction.BLOCK,
            review=ReviewState.UNABLE_TO_JUDGE,
            cause=CauseCategory.EXPLANATION,
        )

        report = build_pilot_comparisons(
            (*first, *self._observations(2, 20))
        )[0]

        self.assertEqual(1, report["totals"]["review"]["correct_block"])
        self.assertEqual(1, report["totals"]["review"]["unnecessary_block"])
        self.assertEqual(1, report["totals"]["review"]["unable_to_judge"])
        self.assertEqual(1, report["totals"]["problem_cause"]["externality"])
        self.assertEqual(1, report["totals"]["problem_cause"]["explanation"])
        self.assertFalse(report["limitations"]["accuracy_calculated"])
        self.assertFalse(report["limitations"]["recall_calculated"])
        self.assertNotIn("accuracy", report["totals"])
        self.assertNotIn("recall", report["totals"])

    def test_latest_problem_correction_is_counted_without_overwriting_history(self) -> None:
        observations = (*self._observations(1, 20), *self._observations(2, 20))
        original = self._problem(
            "problem-original",
            observations[0],
            cause=CauseCategory.EXTERNALITY,
        )
        correction = replace(
            original,
            problem_event_id="problem-correction",
            cause=CauseCategory.PAYLOAD_RESOLUTION,
            classified_by=ClassifiedBy.HUMAN,
            previous_problem_event_id=original.problem_event_id,
            recorded_at="2026-09-05T00:10:00Z",
        )

        report = build_pilot_comparisons(
            observations,
            (original, correction),
        )[0]

        self.assertEqual(0, report["totals"]["problem_cause"]["externality"])
        self.assertEqual(1, report["totals"]["problem_cause"]["payload_resolution"])

    def test_not_visible_problem_may_exist_without_an_observation(self) -> None:
        observations = (*self._observations(1, 20), *self._observations(2, 20))
        invisible = PilotProblemEvent(
            problem_event_id="problem-not-visible",
            observation_id=None,
            workspace_id=self._workspace_id(1),
            detector_version="detector-v1",
            symptom=ProblemSymptom.NOT_VISIBLE,
            cause=CauseCategory.COVERAGE_BOUNDARY,
            classified_by=ClassifiedBy.AUTOMATIC,
            previous_problem_event_id=None,
            comparable_count_at_record=1,
            recorded_at="2026-09-05T00:05:00Z",
        )

        report = build_pilot_comparisons(observations, (invisible,))[0]

        self.assertEqual(1, report["totals"]["problem_symptom"]["not_visible"])
        self.assertEqual(1, report["totals"]["problem_cause"]["coverage_boundary"])

    def test_report_contains_no_project_or_observation_identity(self) -> None:
        observations = (*self._observations(1, 20), *self._observations(2, 20))

        rendered = json.dumps(build_pilot_comparisons(observations), sort_keys=True)

        self.assertNotIn(self._workspace_id(1), rendered)
        self.assertNotIn(self._workspace_id(2), rendered)
        self.assertNotIn("observation-1-0", rendered)
        self.assertNotIn(PRIVATE_MARKER, rendered)
        self.assertNotIn(PROTECTED_MARKER, rendered)

    def test_closed_fields_reject_free_text(self) -> None:
        with self.assertRaises(ValueError):
            replace(self._observation(1, 0), tool_family=f"shell {PROTECTED_MARKER}")
        with self.assertRaises(ValueError):
            replace(self._observation(1, 0), detector_version=PROTECTED_MARKER + " /tmp/private")

    def test_rejects_duplicate_and_cross_project_problem_links(self) -> None:
        observations = (*self._observations(1, 20), *self._observations(2, 20))
        duplicate = replace(observations[1], observation_id=observations[0].observation_id)
        with self.assertRaisesRegex(ValueError, "observation IDs must be unique"):
            build_pilot_comparisons((observations[0], duplicate))

        wrong_scope = replace(
            self._problem("problem-wrong", observations[0]),
            workspace_id=self._workspace_id(2),
        )
        with self.assertRaisesRegex(ValueError, "scope must match"):
            build_pilot_comparisons(observations, (wrong_scope,))

    def test_rejects_branching_or_out_of_order_problem_corrections(self) -> None:
        observations = (*self._observations(1, 20), *self._observations(2, 20))
        original = self._problem("problem-original", observations[0])
        first = replace(
            original,
            problem_event_id="problem-first",
            previous_problem_event_id=original.problem_event_id,
            recorded_at="2026-09-05T00:10:00Z",
        )
        second = replace(
            first,
            problem_event_id="problem-second",
            recorded_at="2026-09-05T00:20:00Z",
        )
        with self.assertRaisesRegex(ValueError, "only one replacement"):
            build_pilot_comparisons(observations, (original, first, second))

        out_of_order = replace(first, recorded_at="2026-09-04T23:59:00Z")
        with self.assertRaisesRegex(ValueError, "recorded in order"):
            build_pilot_comparisons(observations, (original, out_of_order))

    def test_repeated_problem_registration_requires_correction_link(self) -> None:
        items = (*self._observations(1, 20), *self._observations(2, 20))
        first = self._problem("first", items[0])
        duplicate = replace(first, problem_event_id="second")
        with self.assertRaisesRegex(ValueError, "correction link"):
            build_pilot_comparisons(items, (first, duplicate))

    def test_corrected_stop_review_does_not_keep_stale_false_block(self) -> None:
        items = list((*self._observations(1, 20), *self._observations(2, 20)))
        items[0] = replace(items[0], policy_action=PolicyAction.BLOCK,
                           review_state=ReviewState.CORRECT_BLOCK)
        old_problem = replace(self._problem("old", items[0]),
                              symptom=ProblemSymptom.UNNECESSARY_BLOCK)
        report = build_pilot_comparisons(items, (old_problem,))[0]
        self.assertEqual(0, report["totals"]["problem_symptom"]["unnecessary_block"])

    def test_median_uses_middle_pair_and_input_order_does_not_change_report(self) -> None:
        items = (*self._observations(1, 20), *self._observations(2, 20))
        reports = build_pilot_comparisons(items)
        self.assertEqual(10.5, reports[0]["totals"]["decision_ms"]["p50"])
        self.assertEqual(reports, build_pilot_comparisons(reversed(items)))

    def test_reproduced_miss_replaces_candidate_instead_of_counting_both(self) -> None:
        items = (*self._observations(1, 40), *self._observations(2, 40))
        candidate = replace(self._problem("candidate", items[0]),
                            comparable_count_at_record=21)
        reproduced = replace(candidate, problem_event_id="reproduced",
                             previous_problem_event_id="candidate",
                             symptom=ProblemSymptom.REPRODUCED_MISS,
                             recorded_at="2026-09-05T00:10:00Z")
        reports = build_pilot_comparisons(items, (candidate, reproduced))
        self.assertEqual(0, reports[0]["totals"]["problem_symptom"]["reproduced_miss"])
        self.assertEqual(1, reports[1]["totals"]["problem_symptom"]["reproduced_miss"])
        self.assertEqual(0, reports[1]["totals"]["problem_symptom"]["miss_candidate"])

    def _observations(
        self,
        project: int,
        count: int,
        *,
        cohort: StudyCohort = StudyCohort.PILOT,
        detector: str = "detector-v1",
    ) -> tuple[PilotObservation, ...]:
        return tuple(
            self._observation(
                project,
                index,
                cohort=cohort,
                detector=detector,
            )
            for index in range(count)
        )

    def _observation(
        self,
        project: int,
        index: int,
        *,
        action: PolicyAction = PolicyAction.ALLOW,
        review: ReviewState = ReviewState.NOT_NEEDED,
        cause: CauseCategory | None = None,
        cohort: StudyCohort = StudyCohort.PILOT,
        detector: str = "detector-v1",
    ) -> PilotObservation:
        observed_at = datetime(2026, 9, 5, tzinfo=UTC) + timedelta(
            minutes=project * 100 + index
        )
        return PilotObservation(
            observation_id=f"observation-{project}-{index}",
            observed_at=observed_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
            workspace_id=self._workspace_id(project),
            event_ref_sha256=f"{project:01x}" * 64,
            product_version="0.1.0-alpha.13",
            detector_version=detector,
            settings_revision=f"{project + 3:01x}" * 64,
            tool_family=ToolFamily.SHELL,
            externality=Externality.EXTERNAL,
            payload_resolution=PayloadResolution.DIRECT,
            evidence_source=EvidenceSource.DIRECT,
            policy_action=action,
            reason_code=(
                ReasonCode.PROTECTED_EXACT_MATCH
                if action == PolicyAction.BLOCK
                else ReasonCode.PUBLIC_FLOW_ABSENT
            ),
            decision_ms=float(index + 1),
            review_state=review,
            cause_candidate=cause,
            record_state=RecordState.COMPLETE,
            study_cohort=cohort,
        )

    @staticmethod
    def _workspace_id(project: int) -> str:
        return f"ws_v1_{project:01x}" + ("0" * 63)

    @staticmethod
    def _problem(
        problem_id: str,
        observation: PilotObservation,
        *,
        cause: CauseCategory = CauseCategory.EXTERNALITY,
    ) -> PilotProblemEvent:
        return PilotProblemEvent(
            problem_event_id=problem_id,
            observation_id=observation.observation_id,
            workspace_id=observation.workspace_id,
            detector_version=observation.detector_version,
            symptom=ProblemSymptom.MISS_CANDIDATE,
            cause=cause,
            classified_by=ClassifiedBy.AUTOMATIC,
            previous_problem_event_id=None,
            comparable_count_at_record=1,
            recorded_at="2026-09-05T00:00:00Z",
        )


if __name__ == "__main__":
    unittest.main()
