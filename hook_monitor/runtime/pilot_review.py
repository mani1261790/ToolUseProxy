"""Append-only, closed-choice feedback. No free-text field is accepted."""

from __future__ import annotations

import sqlite3
import hashlib
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from hook_monitor.runtime.pilot_models import (
    CauseCategory, ClassifiedBy, PilotObservation, PilotProblemEvent, PolicyAction,
    ProblemSymptom, ReviewState, RecordState, _require_opaque_id,
    _require_utc_timestamp, parse_utc_timestamp,
)
from hook_monitor.runtime.pilot_storage import list_pilot_observations

REVIEW_CHOICES = (ReviewState.CORRECT_BLOCK, ReviewState.UNNECESSARY_BLOCK,
                  ReviewState.UNABLE_TO_JUDGE)


@dataclass(frozen=True)
class PilotReview:
    review_id: str
    observation_id: str
    choice: ReviewState
    cause: CauseCategory
    previous_review_id: str | None
    recorded_at: str
    comparable_count_at_record: int = 0

    def __post_init__(self) -> None:
        _require_opaque_id(self.review_id, "review_id")
        _require_opaque_id(self.observation_id, "observation_id")
        if not isinstance(self.choice, ReviewState) or self.choice not in REVIEW_CHOICES:
            raise ValueError("review must use one of the three choices")
        if not isinstance(self.cause, CauseCategory):
            raise ValueError("cause must use a closed classification")
        if self.previous_review_id is not None:
            _require_opaque_id(self.previous_review_id, "previous_review_id")
            if self.previous_review_id == self.review_id:
                raise ValueError("review cannot replace itself")
        _require_utc_timestamp(self.recorded_at, "recorded_at")
        if (isinstance(self.comparable_count_at_record, bool)
                or not isinstance(self.comparable_count_at_record, int)
                or self.comparable_count_at_record < 0):
            raise ValueError("review comparison count must be a nonnegative integer")


def initialize_pilot_review_schema(conn: sqlite3.Connection) -> None:
    choices = ",".join(f"'{item}'" for item in REVIEW_CHOICES)
    causes = ",".join(f"'{item}'" for item in CauseCategory)
    conn.execute(f"""CREATE TABLE IF NOT EXISTS pilot_reviews (
        review_id TEXT PRIMARY KEY NOT NULL,
        observation_id TEXT NOT NULL,
        choice TEXT NOT NULL CHECK(choice IN ({choices})),
        cause TEXT NOT NULL CHECK(cause IN ({causes})),
        previous_review_id TEXT UNIQUE,
        recorded_at TEXT NOT NULL,
        comparable_count_at_record INTEGER NOT NULL CHECK(comparable_count_at_record >= 0)
    )""")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS pilot_review_root "
                 "ON pilot_reviews(observation_id) WHERE previous_review_id IS NULL")
    conn.execute(f"""CREATE TABLE IF NOT EXISTS pilot_miss_events (
        problem_event_id TEXT PRIMARY KEY NOT NULL,
        observation_id TEXT NOT NULL,
        workspace_id TEXT NOT NULL,
        detector_version TEXT NOT NULL,
        symptom TEXT NOT NULL CHECK(symptom IN ('miss_candidate','reproduced_miss')),
        cause TEXT NOT NULL CHECK(cause IN ({causes})),
        classified_by TEXT NOT NULL CHECK(classified_by = 'human'),
        previous_problem_event_id TEXT UNIQUE,
        comparable_count_at_record INTEGER NOT NULL CHECK(comparable_count_at_record >= 0),
        recorded_at TEXT NOT NULL
    )""")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS pilot_miss_root "
                 "ON pilot_miss_events(observation_id) WHERE previous_problem_event_id IS NULL")
    for table in ("pilot_reviews", "pilot_miss_events"):
        conn.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_no_update "
                     f"BEFORE UPDATE ON {table} BEGIN "
                     "SELECT RAISE(ABORT, 'pilot history is immutable'); END")
        ids = (("review_id", "observation_id", "previous_review_id") if table == "pilot_reviews"
               else ("problem_event_id", "observation_id", "previous_problem_event_id"))
        invalid = " OR ".join(
            f"(NEW.{name} IS NOT NULL AND (length(NEW.{name}) NOT BETWEEN 1 AND 128 "
            f"OR NEW.{name} GLOB '*[^A-Za-z0-9_.:-]*'))" for name in ids)
        conn.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_bounded_insert BEFORE INSERT ON {table} "
                     f"WHEN {invalid} OR length(NEW.recorded_at) NOT BETWEEN 20 AND 32 "
                     "OR substr(NEW.recorded_at, -1) != 'Z' OR julianday(NEW.recorded_at) IS NULL "
                     "BEGIN SELECT RAISE(ABORT, 'invalid pilot history field'); END")


def _connection(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path.resolve().as_uri() + "?mode=rw", uri=True, timeout=1)
    conn.row_factory = sqlite3.Row
    return conn


def _review(row: sqlite3.Row) -> PilotReview:
    values = dict(row)
    values["choice"] = ReviewState(values["choice"])
    values["cause"] = CauseCategory(values["cause"])
    return PilotReview(**values)


def review_history(path: Path, *, workspace_id: str) -> tuple[PilotReview, ...]:
    with _connection(path) as conn:
        rows = conn.execute("SELECT r.* FROM pilot_reviews r JOIN pilot_observations o "
                            "ON o.observation_id = r.observation_id WHERE o.workspace_id = ? "
                            "ORDER BY r.recorded_at, r.review_id", (workspace_id,)).fetchall()
    return tuple(sorted((_review(row) for row in rows),
                        key=lambda item: parse_utc_timestamp(item.recorded_at)))


def _scoped_observation(conn: sqlite3.Connection, workspace_id: str, observation_id: str):
    row = conn.execute("SELECT * FROM pilot_observations WHERE workspace_id = ? "
                       "AND observation_id = ?", (workspace_id, observation_id)).fetchone()
    if row is None:
        raise ValueError("observation not found in this workspace")
    return row


def save_review(path: Path, *, workspace_id: str, review: PilotReview) -> None:
    review = PilotReview(**asdict(review))
    with _connection(path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        observation = _scoped_observation(conn, workspace_id, review.observation_id)
        if observation["policy_action"] != PolicyAction.BLOCK:
            raise ValueError("only a blocked operation can be reviewed")
        existing = conn.execute("SELECT * FROM pilot_reviews WHERE review_id = ?",
                                (review.review_id,)).fetchone()
        if existing is not None:
            # Retry timestamps are generated by the caller, not new feedback.
            if replace(_review(existing), recorded_at=review.recorded_at,
                       comparable_count_at_record=review.comparable_count_at_record) != review:
                raise ValueError("review replay mismatch")
            return
        latest = conn.execute("SELECT * FROM pilot_reviews r WHERE observation_id = ? "
                              "AND NOT EXISTS (SELECT 1 FROM pilot_reviews n "
                              "WHERE n.previous_review_id = r.review_id)",
                              (review.observation_id,)).fetchone()
        expected = latest["review_id"] if latest else None
        if review.previous_review_id != expected:
            raise ValueError("review changed; read the latest review before amending")
        earliest = latest["recorded_at"] if latest else observation["observed_at"]
        if parse_utc_timestamp(review.recorded_at) <= parse_utc_timestamp(earliest):
            raise ValueError("review timestamp must follow the observation and previous review")
        count = (latest["comparable_count_at_record"] if latest else conn.execute(
            "SELECT COUNT(*) FROM pilot_observations o WHERE workspace_id = ? "
            "AND detector_version = ? AND study_cohort = 'pilot' AND record_state != 'incomplete' "
            "AND (policy_action = 'allow' OR observation_id = ? OR EXISTS "
            "(SELECT 1 FROM pilot_reviews r WHERE r.observation_id = o.observation_id))",
            (workspace_id, observation["detector_version"], review.observation_id),
        ).fetchone()[0])
        review = replace(review, comparable_count_at_record=count)
        conn.execute("INSERT INTO pilot_reviews VALUES (?,?,?,?,?,?,?)", tuple(asdict(review).values()))


def reviewed_observations(path: Path, *, workspace_id: str) -> tuple[PilotObservation, ...]:
    latest = {item.observation_id: item for item in review_history(path, workspace_id=workspace_id)}
    return tuple(replace(item, review_state=latest[item.observation_id].choice,
                         cause_candidate=latest[item.observation_id].cause)
                 if item.observation_id in latest else item
                 for item in list_pilot_observations(path, workspace_id=workspace_id))


def save_miss(
    path: Path, *, workspace_id: str, observation_id: str, request_id: str,
    cause: CauseCategory, previous_id: str | None = None, reproduced: bool = False,
    artificial_reproduction_confirmed: bool = False,
    recorded_at: str | None = None,
) -> PilotProblemEvent:
    if reproduced and previous_id is None:
        raise ValueError("a reproduced miss must follow a registered candidate")
    if reproduced and not artificial_reproduction_confirmed:
        raise ValueError("confirm an artificial reproduction before classifying a reproduced miss")
    with _connection(path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        observation = _scoped_observation(conn, workspace_id, observation_id)
        if observation["policy_action"] != PolicyAction.ALLOW:
            raise ValueError("a missed stop must refer to an allowed operation")
        count = conn.execute("SELECT COUNT(*) FROM pilot_observations WHERE workspace_id = ? "
                             "AND detector_version = ? AND study_cohort = 'pilot' "
                             "AND record_state != 'incomplete' AND (policy_action = 'allow' "
                             "OR EXISTS (SELECT 1 FROM pilot_reviews r WHERE "
                             "r.observation_id = pilot_observations.observation_id))",
                             (workspace_id, observation["detector_version"])).fetchone()[0]
        item = PilotProblemEvent(
            request_id, observation_id, workspace_id, observation["detector_version"],
            ProblemSymptom.REPRODUCED_MISS if reproduced else ProblemSymptom.MISS_CANDIDATE,
            cause, ClassifiedBy.HUMAN, previous_id, count,
            recorded_at or datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        )
        existing = conn.execute("SELECT * FROM pilot_miss_events WHERE problem_event_id = ?",
                                (request_id,)).fetchone()
        if existing is not None:
            prior = _problem(existing)
            if replace(prior, recorded_at=item.recorded_at,
                       comparable_count_at_record=count) != item:
                raise ValueError("miss replay mismatch")
            return prior
        latest = conn.execute("SELECT * FROM pilot_miss_events r WHERE observation_id = ? "
                              "AND NOT EXISTS (SELECT 1 FROM pilot_miss_events n "
                              "WHERE n.previous_problem_event_id = r.problem_event_id)",
                              (observation_id,)).fetchone()
        if previous_id != (latest["problem_event_id"] if latest else None):
            raise ValueError("miss changed; read the latest event before amending")
        if latest:
            if latest["symptom"] == ProblemSymptom.REPRODUCED_MISS and not reproduced:
                raise ValueError("a reproduced miss cannot be downgraded to a candidate")
            item = replace(item, comparable_count_at_record=latest["comparable_count_at_record"])
        earliest = latest["recorded_at"] if latest else observation["observed_at"]
        if parse_utc_timestamp(item.recorded_at) <= parse_utc_timestamp(earliest):
            raise ValueError("miss timestamp must follow the observation and previous event")
        conn.execute("INSERT INTO pilot_miss_events VALUES (?,?,?,?,?,?,?,?,?,?)",
                     tuple(asdict(item).values()))
        return item


def _problem(row: sqlite3.Row) -> PilotProblemEvent:
    values = dict(row)
    for key, enum in (("symptom", ProblemSymptom), ("cause", CauseCategory),
                      ("classified_by", ClassifiedBy)):
        values[key] = enum(values[key])
    return PilotProblemEvent(**values)


def problem_history(path: Path, *, workspace_id: str) -> tuple[PilotProblemEvent, ...]:
    with _connection(path) as conn:
        rows = conn.execute("SELECT * FROM pilot_miss_events WHERE workspace_id = ? "
                            "ORDER BY recorded_at, problem_event_id", (workspace_id,)).fetchall()
    return tuple(_problem(row) for row in rows)


def comparison_inputs(path: Path, *, workspace_id: str):
    observations = reviewed_observations(path, workspace_id=workspace_id)
    latest = {item.observation_id: item for item in review_history(path, workspace_id=workspace_id)}
    problems = list(problem_history(path, workspace_id=workspace_id))
    for item in observations:
        review = latest.get(item.observation_id)
        if (review is None or review.choice == ReviewState.CORRECT_BLOCK
                or item.record_state == RecordState.INCOMPLETE):
            continue
        count = review.comparable_count_at_record
        problems.append(PilotProblemEvent(
            hashlib.sha256(("review:" + review.review_id).encode()).hexdigest(),
            item.observation_id, workspace_id, item.detector_version,
            ProblemSymptom.UNNECESSARY_BLOCK if review.choice == ReviewState.UNNECESSARY_BLOCK
            else ProblemSymptom.UNABLE_TO_JUDGE,
            review.cause, ClassifiedBy.HUMAN, None, count, review.recorded_at,
        ))
    return observations, tuple(problems)


def review_prompt(path: Path, *, workspace_id: str, event_id: str) -> str | None:
    """Only an opaque confirmation ID leaves this optional feedback boundary."""
    try:
        with _connection(path) as conn:
            row = conn.execute("SELECT observation_id FROM pilot_observations o "
                               "WHERE workspace_id = ? AND event_ref_sha256 = ? "
                               "AND policy_action = 'block' AND NOT EXISTS "
                               "(SELECT 1 FROM pilot_reviews r WHERE r.observation_id = o.observation_id)",
                               (workspace_id, hashlib.sha256(event_id.encode()).hexdigest())).fetchone()
        if row is None:
            return None
        identifier = row["observation_id"]
        _require_opaque_id(identifier, "observation_id")
        return (
            f"操作評価の確認ID: {identifier}。利用者へ「正しく止めた」「止める必要はなかった」"
            "「判断できない」の3択で確認してください。回答がなければ未回答のまま進めてください。"
            "選択肢UIが使えなければ通常のチャットで質問してください。利用者の回答を推測せず、"
            "回答後に同じプロジェクトで tooluseproxy pilot review "
            f"{identifier} <選択値> --request-id review-{identifier} を実行してください。"
            "選択値は順に correct_block / unnecessary_block / unable_to_judge です。"
            "自由記述は保存しません。この確認は操作の許可や再実行を意味しません。"
        )
    except (OSError, sqlite3.Error, ValueError):
        return None
