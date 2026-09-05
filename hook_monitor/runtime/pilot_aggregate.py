from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from statistics import median
from typing import Any, TypeVar

from hook_monitor.runtime.pilot_models import (
    PILOT_COMPARISON_SCHEMA_VERSION,
    PILOT_COMPARISON_THRESHOLD,
    CauseCategory,
    EvidenceSource,
    Externality,
    PayloadResolution,
    PilotObservation,
    PilotProblemEvent,
    PolicyAction,
    ProblemSymptom,
    RecordState,
    ReasonCode,
    ReviewState,
    StudyCohort,
    ToolFamily,
    parse_utc_timestamp,
)


_EnumValue = TypeVar("_EnumValue")


def build_pilot_comparisons(
    observations: Iterable[PilotObservation],
    problem_events: Iterable[PilotProblemEvent] = (),
    *,
    threshold: int = PILOT_COMPARISON_THRESHOLD,
    project_aliases: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any], ...]:
    """Build deterministic cumulative comparisons without exposing project IDs."""
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
        raise ValueError("threshold must be a positive integer")
    if project_aliases is not None and (
        len(set(project_aliases.values())) != len(project_aliases)
        or any(not isinstance(alias, str) or not re.fullmatch(r"project_[1-9][0-9]{0,8}", alias)
               for alias in project_aliases.values())
    ):
        raise ValueError("project aliases must be unique content-free counters")

    observation_items = tuple(observations)
    problem_items = tuple(problem_events)
    _validate_unique_ids(observation_items, problem_items)
    observations_by_id = {item.observation_id: item for item in observation_items}
    _validate_problem_links(problem_items, observations_by_id)
    terminal_problems = _terminal_problem_events(problem_items)

    grouped: dict[str, dict[str, list[PilotObservation]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for item in observation_items:
        if item.study_cohort != StudyCohort.PILOT or not _is_comparable(item):
            continue
        grouped[item.detector_version][item.workspace_id].append(item)
    for workspaces in grouped.values():
        for items in workspaces.values():
            items.sort(key=_observation_sort_key)

    reports: list[dict[str, Any]] = []
    for detector_version in sorted(grouped):
        workspaces = grouped[detector_version]
        maximum_round = max(
            (len(items) // threshold for items in workspaces.values()),
            default=0,
        )
        for round_number in range(1, maximum_round + 1):
            boundary = round_number * threshold
            participants = sorted(
                workspace_id
                for workspace_id, items in workspaces.items()
                if len(items) >= boundary
            )
            if len(participants) < 2:
                continue
            selected_by_workspace = {
                workspace_id: tuple(workspaces[workspace_id][:boundary])
                for workspace_id in participants
            }
            workspace_aliases = {
                workspace_id: f"project_{index}"
                for index, workspace_id in enumerate(sorted(workspaces), start=1)
            }
            if project_aliases is not None:
                workspace_aliases = {key: project_aliases[key] for key in workspaces}
            reports.append(
                _build_report(
                    detector_version=detector_version,
                    round_number=round_number,
                    threshold=threshold,
                    selected_by_workspace=selected_by_workspace,
                    workspace_aliases=workspace_aliases,
                    all_observations=observation_items,
                    terminal_problems=terminal_problems,
                )
            )
    return tuple(reports)


def _build_report(
    *,
    detector_version: str,
    round_number: int,
    threshold: int,
    selected_by_workspace: Mapping[str, Sequence[PilotObservation]],
    workspace_aliases: Mapping[str, str],
    all_observations: Sequence[PilotObservation],
    terminal_problems: Sequence[PilotProblemEvent],
) -> dict[str, Any]:
    selected = tuple(
        item
        for workspace_id in sorted(selected_by_workspace)
        for item in selected_by_workspace[workspace_id]
    )
    selected_ids = {item.observation_id for item in selected}
    report_end = max(parse_utc_timestamp(item.observed_at) for item in selected)
    report_start = min(parse_utc_timestamp(item.observed_at) for item in selected)
    participant_ids = set(selected_by_workspace)
    pending = tuple(
        item
        for item in all_observations
        if item.study_cohort == StudyCohort.PILOT
        and item.detector_version == detector_version
        and item.workspace_id in participant_ids
        and item.review_state == ReviewState.PENDING
        and parse_utc_timestamp(item.observed_at) <= report_end
    )
    incomplete = tuple(
        item
        for item in all_observations
        if item.study_cohort == StudyCohort.PILOT
        and item.detector_version == detector_version
        and item.workspace_id in participant_ids
        and item.record_state == RecordState.INCOMPLETE
        and parse_utc_timestamp(item.observed_at) <= report_end
    )
    boundary = round_number * threshold
    problems = tuple(
        item
        for item in terminal_problems
        if item.detector_version == detector_version
        and item.workspace_id in participant_ids
        and item.comparable_count_at_record <= boundary
        and (item.observation_id is None or item.observation_id in selected_ids)
    )
    problem_rows = _problem_rows(selected, problems)

    project_reports = []
    for workspace_id in sorted(participant_ids):
        project_items = tuple(selected_by_workspace[workspace_id])
        project_problems = tuple(
            row for row in problem_rows if row[0] == workspace_id
        )
        project_pending = sum(item.workspace_id == workspace_id for item in pending)
        project_incomplete = sum(
            item.workspace_id == workspace_id for item in incomplete
        )
        project_reports.append(
            {
                "project": workspace_aliases[workspace_id],
                "observation_count": len(project_items),
                "action": _enum_counts(
                    (item.policy_action for item in project_items),
                    PolicyAction,
                ),
                "review": _enum_counts(
                    (item.review_state for item in project_items),
                    ReviewState,
                ),
                "problem_symptom": _enum_counts(
                    (row[1] for row in project_problems),
                    ProblemSymptom,
                ),
                "problem_cause": _enum_counts(
                    (row[2] for row in project_problems),
                    CauseCategory,
                ),
                "excluded_pending_count": project_pending,
                "excluded_incomplete_count": project_incomplete,
            }
        )

    decision_values = sorted(float(item.decision_ms) for item in selected)
    report = {
        "schema_version": PILOT_COMPARISON_SCHEMA_VERSION,
        "comparison": {
            "detector_version": detector_version,
            "round": round_number,
            "threshold_per_project": threshold,
            "period_start": _format_utc(report_start),
            "period_end": _format_utc(report_end),
            "project_count": len(participant_ids),
            "observation_count": len(selected),
            "excluded_pending_count": len(pending),
            "excluded_incomplete_count": len(incomplete),
        },
        "totals": {
            "action": _enum_counts(
                (item.policy_action for item in selected),
                PolicyAction,
            ),
            "review": _enum_counts(
                (item.review_state for item in selected),
                ReviewState,
            ),
            "tool_family": _enum_counts(
                (item.tool_family for item in selected),
                ToolFamily,
            ),
            "externality": _enum_counts(
                (item.externality for item in selected),
                Externality,
            ),
            "payload_resolution": _enum_counts(
                (item.payload_resolution for item in selected),
                PayloadResolution,
            ),
            "evidence_source": _enum_counts(
                (item.evidence_source for item in selected),
                EvidenceSource,
            ),
            "record_state": _enum_counts(
                (item.record_state for item in selected),
                RecordState,
            ),
            "problem_symptom": _enum_counts(
                (row[1] for row in problem_rows),
                ProblemSymptom,
            ),
            "problem_cause": _enum_counts(
                (row[2] for row in problem_rows),
                CauseCategory,
            ),
            "decision_ms": {
                "p50": median(decision_values) if decision_values else None,
                "p95": _percentile(decision_values, 0.95),
            },
        },
        "projects": project_reports,
        "problem_groups": _group_problems(problem_rows),
        "limitations": {
            "allow_correctness_reviewed": False,
            "accuracy_calculated": False,
            "recall_calculated": False,
            "pending_blocks_excluded": True,
            "legacy_observations_excluded": True,
        },
        "privacy": {
            "raw_content_fields": 0,
            "project_names_included": False,
            "project_ids_included": False,
            "observation_ids_included": False,
        },
    }
    return report


def _problem_rows(
    observations: Sequence[PilotObservation],
    problems: Sequence[PilotProblemEvent],
) -> tuple[tuple[str, ProblemSymptom, CauseCategory, ReasonCode, ToolFamily], ...]:
    explicit = {
        (item.observation_id, item.symptom)
        for item in problems
        if item.observation_id is not None
    }
    current_reviews = {item.observation_id: item.review_state for item in observations}
    observed = {item.observation_id: item for item in observations}
    required_reviews = {
        ProblemSymptom.UNNECESSARY_BLOCK: ReviewState.UNNECESSARY_BLOCK,
        ProblemSymptom.UNABLE_TO_JUDGE: ReviewState.UNABLE_TO_JUDGE,
    }
    rows = [
        (item.workspace_id, item.symptom, item.cause,
         observed[item.observation_id].reason_code if item.observation_id in observed else ReasonCode.TOOL_NOT_VISIBLE,
         observed[item.observation_id].tool_family if item.observation_id in observed else ToolFamily.OTHER)
        for item in problems
        if item.symptom not in required_reviews
        or current_reviews.get(item.observation_id) == required_reviews[item.symptom]
    ]
    for item in observations:
        derived: ProblemSymptom | None = None
        if item.review_state == ReviewState.UNNECESSARY_BLOCK:
            derived = ProblemSymptom.UNNECESSARY_BLOCK
        elif item.review_state == ReviewState.UNABLE_TO_JUDGE:
            derived = ProblemSymptom.UNABLE_TO_JUDGE
        elif item.record_state == RecordState.INCOMPLETE:
            derived = ProblemSymptom.RECORD_FAILURE
        if derived is None or (item.observation_id, derived) in explicit:
            continue
        rows.append(
            (
                item.workspace_id,
                derived,
                item.cause_candidate or CauseCategory.UNIDENTIFIED,
                item.reason_code,
                item.tool_family,
            )
        )
    rows.sort(key=lambda row: (row[0], row[1].value, row[2].value))
    return tuple(rows)


def _group_problems(rows) -> list[dict[str, Any]]:
    grouped = defaultdict(list)
    for row in rows:
        grouped[(row[2], row[3], row[4])].append(row)
    return [{
        "cause": cause.value, "reason_code": reason.value, "tool_family": family.value,
        "problem_count": len(items), "project_count": len({item[0] for item in items}),
        "symptom": _enum_counts((item[1] for item in items), ProblemSymptom),
    } for (cause, reason, family), items in sorted(grouped.items())]


def _terminal_problem_events(
    events: Sequence[PilotProblemEvent],
) -> tuple[PilotProblemEvent, ...]:
    replaced_ids = {
        item.previous_problem_event_id
        for item in events
        if item.previous_problem_event_id is not None
    }
    terminal = [item for item in events if item.problem_event_id not in replaced_ids]
    terminal.sort(
        key=lambda item: (
            parse_utc_timestamp(item.recorded_at),
            item.problem_event_id,
        )
    )
    return tuple(terminal)


def _validate_unique_ids(
    observations: Sequence[PilotObservation],
    problems: Sequence[PilotProblemEvent],
) -> None:
    observation_ids = [item.observation_id for item in observations]
    if len(observation_ids) != len(set(observation_ids)):
        raise ValueError("observation IDs must be unique")
    problem_ids = [item.problem_event_id for item in problems]
    if len(problem_ids) != len(set(problem_ids)):
        raise ValueError("problem event IDs must be unique")


def _validate_problem_links(
    problems: Sequence[PilotProblemEvent],
    observations_by_id: Mapping[str, PilotObservation],
) -> None:
    problem_ids = {item.problem_event_id for item in problems}
    problems_by_id = {item.problem_event_id: item for item in problems}
    replaced_ids = [
        item.previous_problem_event_id
        for item in problems
        if item.previous_problem_event_id is not None
    ]
    if len(replaced_ids) != len(set(replaced_ids)):
        raise ValueError("a problem event may have only one replacement")
    roots: set[tuple[str, str]] = set()
    for item in problems:
        if item.previous_problem_event_id is None and item.observation_id is not None:
            symptom_group = (
                "miss"
                if item.symptom in {ProblemSymptom.MISS_CANDIDATE, ProblemSymptom.REPRODUCED_MISS}
                else item.symptom.value
            )
            root = (item.observation_id, symptom_group)
            if root in roots:
                raise ValueError("duplicate problem requires a correction link")
            roots.add(root)
        if (
            item.previous_problem_event_id is not None
            and item.previous_problem_event_id not in problem_ids
        ):
            raise ValueError("previous problem event does not exist")
        if item.previous_problem_event_id is not None:
            previous = problems_by_id[item.previous_problem_event_id]
            if (
                previous.workspace_id != item.workspace_id
                or previous.detector_version != item.detector_version
                or previous.observation_id != item.observation_id
                or previous.comparable_count_at_record
                != item.comparable_count_at_record
            ):
                raise ValueError("problem correction scope must match")
            valid_symptom_change = (
                previous.symptom == item.symptom
                or (
                    previous.symptom == ProblemSymptom.MISS_CANDIDATE
                    and item.symptom == ProblemSymptom.REPRODUCED_MISS
                )
            )
            if not valid_symptom_change:
                raise ValueError("problem correction symptom transition is invalid")
            if parse_utc_timestamp(previous.recorded_at) >= parse_utc_timestamp(
                item.recorded_at
            ):
                raise ValueError("problem corrections must be recorded in order")
        if item.observation_id is None:
            if item.symptom != ProblemSymptom.NOT_VISIBLE:
                raise ValueError("only not-visible problems may omit observation_id")
            continue
        if item.comparable_count_at_record < 1:
            raise ValueError("an observed problem requires a positive comparable count")
        observation = observations_by_id.get(item.observation_id)
        if observation is None:
            raise ValueError("problem observation does not exist")
        if (
            observation.workspace_id != item.workspace_id
            or observation.detector_version != item.detector_version
        ):
            raise ValueError("problem and observation scope must match")


def _is_comparable(item: PilotObservation) -> bool:
    return (
        item.review_state != ReviewState.PENDING
        and item.record_state != RecordState.INCOMPLETE
    )


def _observation_sort_key(item: PilotObservation) -> tuple[object, str]:
    return (parse_utc_timestamp(item.observed_at), item.observation_id)


def _enum_counts(
    values: Iterable[_EnumValue],
    enum_type: type[_EnumValue],
) -> dict[str, int]:
    counts = Counter(str(getattr(value, "value", value)) for value in values)
    return {
        str(getattr(value, "value", value)): counts.get(
            str(getattr(value, "value", value)), 0
        )
        for value in enum_type  # type: ignore[union-attr]
    }


def _percentile(values: Sequence[float], percentile: float) -> float | None:
    if not values:
        return None
    index = max(0, math.ceil(len(values) * percentile) - 1)
    return values[index]


def _format_utc(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")
