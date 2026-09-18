"""Explicit adaptive-lab command, isolated from installed Plugin and real projects."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sqlite3
import time
import uuid

from .budget import Budget
from .codex_agent import CodexProvider
from .controller import TERMINAL, run_search, validate_state
from .models import RecordError, RunSpec, from_mapping, utc_now
from .preflight import LabError, build_context, build_image, check_isolation
from .runner import SCENARIOS, run_scenario, validate_controls
from .search_state import SearchJournal
from .storage import StoreError, TrialStore
from .transport import FixedTransport


def execute(repository: Path, output: Path, model: str, *, mode="adaptive_search",
            budget: Budget | None = None) -> dict:
    started = time.time()
    budget = budget or Budget()
    provider = CodexProvider(model)
    with SearchJournal(output) as journal, journal.lease("launch.lock"):
        saved = journal.read()
        with TrialStore(output / "trials") as store:
            if saved:
                try:
                    spec = from_mapping(RunSpec, saved["identity"]["spec"])
                except (KeyError, TypeError):
                    raise LabError("invalid_search_state") from None
                validate_state(saved, budget)
                if (saved["identity"] != {"spec": asdict(spec), "budget": asdict(budget),
                                          "model": model} or spec.mode != mode):
                    raise LabError("search_revision_mismatch")
                if store.pending(spec):
                    return {"status": "operation_requires_reconciliation"}
                if saved.get("phase") == "requesting":
                    return {"status": "model_response_unknown"}
                if saved.get("status") in TERMINAL:
                    if store.summary(spec)["state"] == "running":
                        store.finish(spec, utc_now(),
                                     exhausted=saved["status"].endswith("budget_exhausted"))
                    return {"status": saved["status"], "summary": store.summary(spec),
                            "synthetic_only": True, "model": model}
            context = build_context(repository)
            revision = "source-" + hashlib.sha256(context).hexdigest()
            if saved and spec.detector_revision != revision:
                raise LabError("search_revision_mismatch")
            image = build_image(repository, context=context)
            check_isolation(image)
            if saved:
                if spec.environment_digest != image[7:] or spec.mode != mode:
                    raise LabError("search_revision_mismatch")
            else:
                spec = RunSpec(run_id=uuid.uuid4().hex, suite_version="adaptive-http-v1",
                               detector_revision=revision, policy_revision="fixed-exact-externality-v1",
                               environment_digest=image[7:], started_at=utc_now(), mode=mode,
                               max_trials=budget.trials, max_steps=budget.steps)
            # Initial fixed baseline; on resume, fresh public/protected receiver controls.
            # All control attempts consume the SAME global trial budget as search.
            with TrialStore(output / "controls") as controls:
                controls.require_no_unfinished_runs()
                scenarios = SCENARIOS if controls.trial_count() == 0 else (SCENARIOS[0], SCENARIOS[2])
                used_search = len(saved["plans"]) if saved else 0
                if controls.trial_count() + used_search + len(scenarios) >= budget.trials:
                    return {"status": "trial_budget_exhausted", "synthetic_only": True}
                control_spec = RunSpec(run_id=uuid.uuid4().hex, suite_version="fixed-http-v1",
                                       detector_revision=revision,
                                       policy_revision=spec.policy_revision,
                                       environment_digest=image[7:], started_at=utc_now())
                controls.start_fixed_suite(control_spec)
                with FixedTransport(image) as transport:
                    results = [run_scenario(transport, controls, control_spec, s) for s in scenarios]
                checks = validate_controls(results) if len(scenarios) == len(SCENARIOS) else {
                    "public_receiver_control": results[0].receiver_arrival == "yes"
                    and results[0].protected_arrival == "no",
                    "protected_receiver_control": results[1].protected_arrival == "yes",
                }
                if not all(checks.values()):
                    raise LabError("trial_control_failed")
                controls.finish(control_spec, utc_now())
                control_count = controls.trial_count()
            with FixedTransport(image) as transport:
                result = run_search(journal, store, spec, transport, provider, budget,
                                    control_trials=control_count, started_at=started)
            return {**result, "controls": checks, "model": model, "synthetic_only": True,
                    "native_codex_delivery": "not_tested", "proposal_language": "fixed-http-v1",
                    "arbitrary_command_search": False, "public_internet": False,
                    "defense_perfect": False}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="人工試験専用のCodex適応探索")
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--mode", choices=["adaptive_search", "benign_task"], default="adaptive_search")
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--seconds", type=int, default=1800)
    options = parser.parse_args(argv)
    try:
        result = execute(options.repository, options.output_directory, options.model,
                         mode=options.mode, budget=Budget(trials=options.trials, seconds=options.seconds))
    except (LabError, RecordError, StoreError, OSError, sqlite3.Error) as exc:
        reason = str(exc) if isinstance(exc, (LabError, RecordError, StoreError)) else "trial_io_error"
        print(json.dumps({"status": "not_completed", "reason": reason}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] in {"completed", "trial_budget_exhausted", "repeated_proposal"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
