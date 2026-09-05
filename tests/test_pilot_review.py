from __future__ import annotations

import io
import json
import sqlite3
import hashlib
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor

from hook_monitor.runtime.pilot_models import (
    CauseCategory, PolicyAction, ReviewState,
)
from hook_monitor.runtime.pilot_review import (
    PilotReview, comparison_inputs, problem_history, review_history,
    reviewed_observations, save_miss, save_review,
    review_prompt,
)
from hook_monitor.runtime.pilot_storage import store_pilot_observation, list_pilot_observations
from hook_monitor.runtime.storage import EventStore
from hook_monitor.runtime.workspace import resolve_workspace
from hook_monitor.evaluation.pilot_aggregate import build_pilot_comparisons
from tooluseproxy.cli import main
from tests import test_pilot_aggregate as fixtures


class PilotReviewTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "events.db"
        self.workspace = resolve_workspace(str(self.root), str(self.root))
        store = EventStore(self.path)
        store.initialize()
        store.register_workspace(self.workspace)
        self.item = replace(fixtures.PilotAggregateTest()._observation(1, 0),
                            workspace_id=self.workspace.workspace_id,
                            policy_action=PolicyAction.BLOCK, review_state=ReviewState.PENDING)
        store_pilot_observation(self.path, self.item)

    def review(self, identifier="review-1", previous=None, choice=ReviewState.UNNECESSARY_BLOCK,
               timestamp="2026-09-06T01:00:00Z"):
        return PilotReview(identifier, self.item.observation_id, choice,
                           CauseCategory.UNIDENTIFIED, previous, timestamp)

    def save(self, review):
        save_review(self.path, workspace_id=self.workspace.workspace_id, review=review)

    def test_three_choices_only_and_no_extra_text(self):
        for choice in ("private text", ReviewState.PENDING, ReviewState.NOT_NEEDED):
            with self.assertRaises(ValueError):
                self.review(choice=choice)
        with self.assertRaises(TypeError):
            PilotReview(**{**self.review().__dict__, "note": "private text"})

    def test_prompt_is_scoped_and_disappears_after_review(self):
        item = replace(self.item, observation_id="prompt-observation",
                       event_ref_sha256=hashlib.sha256(b"event-input-id").hexdigest())
        store_pilot_observation(self.path, item)
        args = dict(workspace_id=self.workspace.workspace_id, event_id="event-input-id")
        prompt = review_prompt(self.path, **args)
        self.assertIn("prompt-observation", prompt)
        self.assertNotIn("event-input-id", prompt)
        self.assertNotIn(str(self.root), prompt)
        self.assertIsNone(review_prompt(self.path, workspace_id="ws_v1_" + "f" * 64,
                                       event_id="event-input-id"))
        self.save(replace(self.review(), observation_id=item.observation_id))
        self.assertIsNone(review_prompt(self.path, **args))

    def test_schema_eight_upgrade_preserves_existing_observations(self):
        with sqlite3.connect(self.path) as conn:
            conn.execute("DROP TABLE pilot_reviews")
            conn.execute("DROP TABLE pilot_miss_events")
            conn.execute("PRAGMA user_version = 8")
        EventStore(self.path).initialize()
        self.assertEqual((self.item,), list_pilot_observations(
            self.path, workspace_id=self.workspace.workspace_id))
        self.save(self.review())

    def test_correction_is_append_only_and_latest_is_used(self):
        self.save(self.review())
        self.save(self.review("review-2", "review-1", ReviewState.CORRECT_BLOCK,
                              "2026-09-06T02:00:00Z"))
        self.assertEqual(2, len(review_history(self.path, workspace_id=self.workspace.workspace_id)))
        latest, problems = comparison_inputs(self.path, workspace_id=self.workspace.workspace_id)
        self.assertEqual(ReviewState.CORRECT_BLOCK, latest[0].review_state)
        self.assertEqual((), problems)
        self.assertEqual(ReviewState.PENDING, list_pilot_observations(
            self.path, workspace_id=self.workspace.workspace_id)[0].review_state)
        with sqlite3.connect(self.path) as conn:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("UPDATE pilot_reviews SET choice='correct_block'")

    def test_replay_and_stale_correction(self):
        self.save(self.review())
        self.save(self.review(timestamp="2026-09-06T03:00:00Z"))
        with self.assertRaisesRegex(ValueError, "replay mismatch"):
            self.save(self.review(choice=ReviewState.CORRECT_BLOCK))
        with self.assertRaisesRegex(ValueError, "changed"):
            self.save(self.review("new-root"))
        self.assertEqual(1, len(review_history(self.path, workspace_id=self.workspace.workspace_id)))

    def test_other_workspace_and_allowed_operation_are_rejected(self):
        with self.assertRaises(ValueError):
            save_review(self.path, workspace_id="ws_v1_" + "f" * 64, review=self.review())
        allowed = replace(self.item, observation_id="allowed", event_ref_sha256="a" * 64,
                          policy_action=PolicyAction.ALLOW, review_state=ReviewState.NOT_NEEDED)
        store_pilot_observation(self.path, allowed)
        with self.assertRaises(ValueError):
            self.save(replace(self.review(), observation_id="allowed"))

    def test_simultaneous_reviews_do_not_branch(self):
        def attempt(identifier):
            try:
                self.save(self.review(identifier))
                return True
            except ValueError:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(1, sum(pool.map(attempt, ("one", "two"))))

    def test_miss_candidate_is_not_a_reproduced_miss(self):
        allowed = replace(self.item, observation_id="allowed", event_ref_sha256="a" * 64,
                          policy_action=PolicyAction.ALLOW, review_state=ReviewState.NOT_NEEDED)
        store_pilot_observation(self.path, allowed)
        args = dict(workspace_id=self.workspace.workspace_id, observation_id="allowed",
                    cause=CauseCategory.UNIDENTIFIED)
        candidate = save_miss(self.path, **args, request_id="miss-one",
                              recorded_at="2026-09-06T01:00:00Z")
        self.assertEqual("miss_candidate", candidate.symptom)
        with self.assertRaises(ValueError):
            save_miss(self.path, **args, request_id="invalid", reproduced=True)
        reproduced = save_miss(self.path, **args, request_id="miss-two", previous_id="miss-one",
                               reproduced=True, artificial_reproduction_confirmed=True,
                               recorded_at="2026-09-06T02:00:00Z")
        self.assertEqual("reproduced_miss", reproduced.symptom)
        replay = save_miss(self.path, **args, request_id="miss-two", previous_id="miss-one",
                           reproduced=True, artificial_reproduction_confirmed=True,
                           recorded_at="2026-09-06T03:00:00Z")
        self.assertEqual(reproduced, replay)
        self.assertEqual(2, len(problem_history(self.path, workspace_id=self.workspace.workspace_id)))

    def test_correction_keeps_original_comparison_position(self):
        self.save(self.review())
        first_count = review_history(self.path, workspace_id=self.workspace.workspace_id)[0].comparable_count_at_record
        store_pilot_observation(self.path, replace(
            self.item, observation_id="later", event_ref_sha256="b" * 64,
            policy_action=PolicyAction.ALLOW, review_state=ReviewState.NOT_NEEDED))
        self.save(self.review("review-2", "review-1", ReviewState.UNABLE_TO_JUDGE,
                              "2026-09-06T02:00:00Z"))
        history = review_history(self.path, workspace_id=self.workspace.workspace_id)
        self.assertEqual(first_count, history[-1].comparable_count_at_record)
        self.assertEqual(first_count, comparison_inputs(
            self.path, workspace_id=self.workspace.workspace_id)[1][0].comparable_count_at_record)

    def test_pending_does_not_prevent_comparison(self):
        all_items = []
        for project in (1, 2):
            all_items.extend(fixtures.PilotAggregateTest()._observation(project, index)
                             for index in range(20))
        all_items.append(replace(self.item, observation_id="pending-extra"))
        self.assertEqual(1, len(build_pilot_comparisons(all_items)))

    def test_cli_records_and_lists_without_paths(self):
        def invoke(*args):
            with patch("sys.stdout", new_callable=io.StringIO) as output:
                result = main(["pilot", *args, "--db", str(self.path),
                               "--workspace", str(self.root), "--json"])
            self.assertNotIn(str(self.root), output.getvalue())
            return result, json.loads(output.getvalue())
        status, pending = invoke("pending")
        self.assertEqual(0, status)
        self.assertEqual(1, len(pending["observations"]))
        self.assertEqual(0, invoke("review", self.item.observation_id, "correct_block",
                                   "--request-id", "cli-review")[0])
        self.assertEqual([], invoke("pending")[1]["observations"])
        self.assertEqual(0, invoke("amend", self.item.observation_id, "unable_to_judge",
                                   "--request-id", "cli-amend", "--previous-id", "cli-review")[0])
        self.assertEqual(2, len(invoke("history")[1]["reviews"]))
        self.assertEqual(ReviewState.UNABLE_TO_JUDGE, reviewed_observations(
            self.path, workspace_id=self.workspace.workspace_id)[0].review_state)
