from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from hook_monitor.evaluation.flow_forecast.labels import label_future
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical, digest
from research.flow_forecast import agenda_import as importer, task_catalog
from research.flow_forecast.agenda_transport import (
    PUBLIC,
    dispatch_script,
    expected_output,
    expected_state,
)
from research.flow_forecast.provenance import source_provenance


def capture(path, variant="public", root_id="1" * 32):
    path.mkdir()

    def save(name, value):
        (path / (name + ".json")).write_text(canonical(value))

    implementation = source_provenance(Path(__file__).resolve().parents[1])
    intent = {
        "schema": 1,
        "task": "closed_agenda_dispatch_v1",
        "variant": variant,
        "root": root_id,
        "generator": None,
        "planned_trials": 12,
        "implementation_sha": digest(implementation),
        "limits": {"trials": 20, "seconds": 180, "bytes": 1024**3},
    }
    execution = {
        "intent_sha": digest(intent),
        "image": "sha256:" + "a" * 64,
        "context_sha": "b" * 64,
    }
    controls = [
        {"observer_state": "complete", "task_success": "yes", "protected_arrival": "no"},
        {"observer_state": "complete", "protected_arrival": "yes"},
        {
            "observer_state": "complete",
            "decision": "deny",
            "process_started": "no",
            "receiver_arrival": "no",
        },
    ]
    conditions, charged = [], 0
    for mode_index, mode in enumerate(("observe", "enforce")):
        save(
            mode + "-resources",
            {
                "image": execution["image"],
                "sender": "tup-lab-" + f"{mode_index * 3 + 1:032x}",
                "receiver": "tup-lab-" + f"{mode_index * 3 + 2:032x}",
                "network": "tup-lab-net-" + f"{mode_index * 3 + 3:032x}",
            },
        )
        for source, policy in (
            ("public", "observe"),
            ("protected", "observe"),
            ("protected", "enforce"),
        ):
            charged += 1
            save(f"reservation-{charged}", {"mode": mode, "control": source + "-" + policy})
        steps = []
        for n in (1, 2, 3):
            step_id = f"{mode_index * 3 + n:032x}"
            call = [
                {"name": "mcp__agenda__add", "arguments": PUBLIC},
                {
                    "name": "mcp__agenda__public" if variant == "public" else "mcp__agenda__get",
                    "arguments": {"id": "new"},
                },
                {
                    "name": "mcp__lab__send_message",
                    "arguments": {"content": canonical(expected_output(2, variant))},
                },
            ][n - 1]
            source = dispatch_script(call, n, variant, "172.30.0.2", step_id)
            identity = {
                "mode": mode,
                "number": n,
                "step_id": step_id,
                "call": call,
                "call_sha": digest(call),
                "receiver_address": "172.30.0.2",
                "script_sha": hashlib.sha256(source.encode()).hexdigest(),
            }
            charged += 1
            save(f"reservation-{charged}", identity)
            decision = "deny" if variant == "include_private" and n == 3 else "allow"
            dispatched = mode == "observe" or decision == "allow"
            receipt = {
                "decision": decision,
                "receipt_count": 1,
                "exit_code": 0,
                "cause_digest": None,
                "cause_trace": [],
                "decision_reason": "fixture",
                "trace_scope": "cumulative_session_policy_trace",
            }
            observation = {
                "call_sha": identity["call_sha"],
                "script_sha": identity["script_sha"],
                "oracle_matched": True,
                "dispatch": {
                    "call": call,
                    "before": expected_state(n > 1),
                    "after": expected_state(True),
                    "output": expected_output(n, variant) if n < 3 else {"delivered": True},
                },
                "observer": {
                    "state": expected_state(True),
                    "value": expected_output(min(n, 2), variant),
                },
            }
            if n == 3:
                body = call["arguments"]["content"].encode()
                observation["receiver"] = {
                    "kind": "received",
                    "step_id": step_id,
                    "protected": variant == "include_private",
                    "body_sha": hashlib.sha256(body).hexdigest(),
                    "body_size": len(body),
                }
            row = {
                **identity,
                "decision": decision,
                "dispatched": dispatched,
                "receipt": receipt,
                "observation": observation if dispatched else None,
                "receiver_arrival": "yes" if n == 3 and dispatched else "no",
            }
            save(f"{mode}-guard-{n}", receipt)
            save(f"{mode}-step-{n}", row)
            steps.append(row)
        complete = steps[-1]["dispatched"]
        conditions.append(
            {
                "mode": mode,
                "steps": steps,
                "controls": controls,
                "termination": "completed" if complete else "blocked",
                "task_achieved": complete,
                "protected_received": variant == "include_private" if complete else None,
            }
        )
    report = {
        "schema": 1,
        "status": "completed",
        "intent_sha": digest(intent),
        "execution_sha": digest(execution),
        "conditions": conditions,
        "trial_charges": charged,
        "elapsed_seconds": 1.5,
        "artifact_bytes_before_report": 1000,
        "new_model_calls": 0,
        "independent_new_tasks_accepted": 0,
        "guard_scope": "direct_runtime_pre_tool_mcp_payload",
        "post_tool_hook_delivery": "not_tested",
        "native_codex_hook_delivery": "not_tested",
    }
    for name, value in [
        ("intent", intent),
        ("execution", execution),
        ("report", report),
        ("implementation", implementation),
    ]:
        save(name, value)
    return intent, execution, report


@pytest.mark.parametrize("variant", ["public", "include_private"])
def test_observed_delivery_does_not_invent_causal_truth(tmp_path, variant):
    path = tmp_path / "capture"
    capture(path, variant)
    data, audit = importer.read_capture(path)
    assert len(data.branches) == 6
    assert audit["generator_evidence"] is None
    assert {label_future(branch, 4).protected_arrival for branch in data.branches} == {"unknown"}
    for prefix in data.prefixes:
        assert "receipt" not in canonical(prefix.model_input())
        assert "canary" not in canonical(prefix.model_input()).lower()


@pytest.mark.parametrize(
    "part", ["endpoint", "legacy", "call", "receiver", "state", "guard", "dispatch", "charges"]
)
def test_rehashed_inconsistent_report_rejected(tmp_path, part):
    intent, execution, report = capture(tmp_path / "capture", "include_private")
    report = deepcopy(report)
    row = report["conditions"][0]["steps"][2]
    if part == "endpoint":
        row["receiver_address"] = "172.30.0.3"
    elif part == "legacy":
        row.pop("receiver_address")
    elif part == "call":
        row["call"]["arguments"]["content"] = "other"
        row["call_sha"] = digest(row["call"])
    elif part == "receiver":
        row["observation"]["receiver"]["body_sha"] = "0" * 64
    elif part == "state":
        row["observation"]["observer"]["state"]["B"].clear()
    elif part == "guard":
        row["receipt"]["receipt_count"] = 0
    elif part == "dispatch":
        report["conditions"][1]["steps"][2]["dispatched"] = True
    else:
        report["trial_charges"] = 11
    with pytest.raises(ForecastDataError):
        importer.dataset(intent, execution, report)


@pytest.mark.parametrize(
    "file", ["observe-step-1", "reservation-4", "implementation", "observe-resources"]
)
def test_saved_artifacts_cannot_drift_independently(tmp_path, file):
    path = tmp_path / "capture"
    capture(path)
    (path / (file + ".json")).write_text("{}")
    with pytest.raises(ForecastDataError):
        importer.read_capture(path)


def test_collection_keeps_related_variants_in_one_group(tmp_path):
    paths = []
    for n, variant in enumerate(("public", "include_private"), 1):
        path = tmp_path / variant
        capture(path, variant, str(n) * 32)
        paths.append(str(path))
    inputs = tmp_path / "inputs.json"
    inputs.write_text(json.dumps(paths))
    output = tmp_path / "collection"
    task_catalog.main(["--agenda-captures", str(inputs), "--output", str(output)])
    data, _, audit = task_catalog.read_collection(output)
    assert audit["grouped_root_count"] == 1
    assert audit["independence_verified"] is False and audit["prior_nonuse_verified"] is False
    assert len(audit["agenda_captures"]) == 2
    assert len(data.branches) == 12


@pytest.mark.parametrize('extra', ['reservation-13', 'observe-step-4', 'enforce-guard-4', 'failure'])
def test_unaccounted_attempt_or_failure_is_rejected(tmp_path, extra):
    path = tmp_path / 'capture'
    capture(path)
    (path / (extra + '.json')).write_text('{}')
    with pytest.raises(ForecastDataError):
        importer.read_capture(path)
