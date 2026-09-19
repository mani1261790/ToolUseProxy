"""Explicit adaptive-lab command, isolated from installed Plugin and real projects."""
from __future__ import annotations

import argparse
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sqlite3
import time
import uuid

from .budget import Budget
from .call_history import summarize as summarize_calls
from .codex_agent import CodexProvider
from .controller import TERMINAL, run_search, validate_state
from .models import RecordError, RunSpec, from_mapping, utc_now
from .preflight import LabError, build_context, build_image, check_isolation
from .runner import SCENARIOS, run_scenario, validate_controls
from .search_state import SearchJournal
from .revision import implementation_revision
from .storage import StoreError, TrialStore
from .transport import FixedTransport
from .task_assignment import load as load_assignment, validate as validate_assignment
from .task_completion import evaluate as evaluate_completion
from .adaptive_transport import AdaptiveTransport


def execute(repository: Path, output: Path, model: str, *, mode="adaptive_search",
            budget: Budget | None = None, task_assignment: dict | None = None) -> dict:
    if task_assignment is not None:
        task_assignment = deepcopy(task_assignment)
        validate_assignment(task_assignment)
    started = time.time()
    budget = budget or Budget()
    with SearchJournal(output) as journal, journal.lease("launch.lock"):
        saved = journal.read()
        with TrialStore(output / "trials") as store:
            if saved:
                try:
                    spec = from_mapping(RunSpec, saved["identity"]["spec"])
                except (KeyError, TypeError):
                    raise LabError("invalid_search_state") from None
                validate_state(saved, budget)
                identity = saved["identity"]
                base_identity = {key: identity.get(key) for key in ("spec", "budget", "model")}
                if (base_identity != {"spec": asdict(spec), "budget": asdict(budget),
                                      "model": model} or spec.mode != mode):
                    raise LabError("search_revision_mismatch")
                if identity.get('task_assignment') != task_assignment:
                    raise LabError('search_task_assignment_mismatch')
                if store.pending(spec):
                    return {"status": "operation_requires_reconciliation"}
                if saved.get("phase") == "requesting":
                    return {"status": "model_response_unknown"}
                if saved.get("status") in TERMINAL:
                    if store.summary(spec)["state"] == "running":
                        store.finish(spec, utc_now(),
                                     exhausted=saved["status"].endswith("budget_exhausted"))
                    return {"status": saved["status"], "summary": store.summary(spec),
                            "synthetic_only": True, "model": model, "generation_costs": summarize_calls(saved),
                            "task_completion": evaluate_completion(saved, store.read(spec))}
                if identity.get("agent_revision") != implementation_revision():
                    raise LabError("search_revision_mismatch")
            if journal.storage_size() >= budget.storage_bytes:
                return {"status": "storage_budget_exhausted", "synthetic_only": True}
            provider = CodexProvider(model)
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
                spec = RunSpec(run_id=uuid.uuid4().hex, suite_version="adaptive-http-v2",
                               detector_revision=revision, policy_revision="fixed-exact-externality-v1",
                               environment_digest=image[7:], started_at=utc_now(), mode=mode,
                               max_trials=budget.trials, max_steps=budget.steps)
            # Controls and exploration share the global trial budget. Every actual
            # exploration receiver is tested before the first guarded model action.
            with TrialStore(output / "controls") as controls:
                controls.require_no_unfinished_runs()
                initial = controls.trial_count() == 0
                if not initial:
                    baselines = [run for run in controls.runs() if run.suite_version == "fixed-http-v1"]
                    if (len(baselines) != 1 or baselines[0].detector_revision != revision
                            or baselines[0].environment_digest != image[7:]
                            or controls.summary(baselines[0])["state"] != "complete"
                            or not all(validate_controls(controls.read(baselines[0])).values())):
                        raise LabError("trial_control_failed")
                needed = (len(SCENARIOS) if initial else 0) + 2
                used_search = len(saved["plans"]) if saved else 0
                if controls.trial_count() + used_search + needed > budget.trials:
                    if saved:
                        saved["status"] = "trial_budget_exhausted"
                        journal.write(saved)
                        store.finish(spec, utc_now(), exhausted=True)
                    return {"status": "trial_budget_exhausted", "synthetic_only": True}

                def control_run(transport, scenarios, suite_version):
                    control_spec = RunSpec(
                        run_id=uuid.uuid4().hex, suite_version=suite_version,
                        detector_revision=revision, policy_revision=spec.policy_revision,
                        environment_digest=image[7:], started_at=utc_now())
                    controls.start_fixed_suite(control_spec)
                    results = []
                    for scenario in scenarios:
                        origin = saved["started"] if saved else started
                        if budget.remaining_seconds(origin, time.time()) <= 0:
                            controls.finish(control_spec, utc_now(), exhausted=True)
                            raise LabError("time_budget_exhausted")
                        if journal.storage_size() >= budget.storage_bytes:
                            controls.finish(control_spec, utc_now(), exhausted=True)
                            raise LabError("storage_budget_exhausted")
                        results.append(run_scenario(transport, controls, control_spec, scenario))
                    controls.finish(control_spec, utc_now())
                    return results

                checks = {}
                if initial:
                    with FixedTransport(image) as baseline:
                        checks = validate_controls(control_run(baseline, SCENARIOS, "fixed-http-v1"))
                    if not all(checks.values()):
                        raise LabError("trial_control_failed")
                with AdaptiveTransport(image) as transport:
                    current = control_run(transport, (SCENARIOS[0], SCENARIOS[2]),
                                          "adaptive-receiver-v1")
                    checks.update({
                        "current_public_receiver_control": current[0].receiver_arrival == "yes"
                        and current[0].protected_arrival == "no",
                        "current_protected_receiver_control": current[1].protected_arrival == "yes",
                    })
                    if not all(checks.values()):
                        raise LabError("trial_control_failed")
                    result = run_search(journal, store, spec, transport, provider, budget,
                                        control_trials=controls.trial_count(), started_at=started, task_assignment=task_assignment)
            return {**result, "controls": checks, "model": model, "synthetic_only": True,
                    "native_codex_delivery": "not_tested", "proposal_language": "composed-http-v2",
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
    parser.add_argument("--model-calls", type=int, default=20)
    parser.add_argument('--task-assignment', type=Path)
    options = parser.parse_args(argv)
    try:
        result = execute(options.repository, options.output_directory, options.model,
                         mode=options.mode, budget=Budget(trials=options.trials, seconds=options.seconds, model_calls=options.model_calls),
                         task_assignment=load_assignment(options.task_assignment) if options.task_assignment else None)
    except (LabError, RecordError, StoreError, OSError, sqlite3.Error) as exc:
        reason = str(exc) if isinstance(exc, (LabError, RecordError, StoreError)) else "trial_io_error"
        print(json.dumps({"status": "not_completed", "reason": reason}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] in {"completed", "trial_budget_exhausted", "repeated_proposal"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
