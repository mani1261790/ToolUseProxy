from copy import deepcopy
import hashlib
from pathlib import Path

import pytest

from hook_monitor.evaluation.flow_forecast.labels import label_future
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical, digest
from research.flow_forecast import bfcl_ticket_import as importer, bfcl_ticket_transport as transport
from research.flow_forecast.bfcl_ticket_transport import dispatch_script, expected_output, state as expected_state, call_for
from research.flow_forecast.provenance import source_provenance

SOURCE = '# artificial source used only to construct scripts\n'

@pytest.fixture(autouse=True)
def source_digest(monkeypatch):
    sha = hashlib.sha256(SOURCE.encode()).hexdigest()
    monkeypatch.setattr(transport, 'SOURCE_SHA', sha)
    monkeypatch.setattr(importer, 'SOURCE_SHA', sha)


def capture(path, variant="public", root_id="1" * 32):
    path.mkdir()

    def save(name, value):
        (path / (name + ".json")).write_text(canonical(value))

    implementation = source_provenance(Path(__file__).resolve().parents[1])
    intent = {
        "schema": 1,
        "task": "closed_ticket_dispatch_v1",
        "variant": variant,
        "root": root_id,
        "generator": None,
        "planned_trials": 18,
        "source_commit": importer.COMMIT, "source_sha": importer.SOURCE_SHA,
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
            call = call_for(SOURCE, n, variant)
            source = dispatch_script(SOURCE, call, n, variant, "172.30.0.2", step_id)
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
            save(f"reservation-{charged}", {"mode":mode,"number":n,"step_id":step_id,"setup":"ticket_state_restore"})
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
                    "before": expected_state(SOURCE, n > 1),
                    "after": expected_state(SOURCE, True),
                    "output": expected_output(SOURCE, n, variant) if n < 3 else {"delivered": True},
                },
                "observer": {
                    "state": expected_state(SOURCE, True),
                    "value": expected_output(SOURCE, min(n, 2), variant),
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
                "task_achieved": complete and variant == "public",
                "pipeline_completed": complete,
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
    data, audit = importer.read_capture(path, SOURCE)
    assert len(data.branches) == 6
    assert audit["generator_evidence"] is None
    assert {label_future(branch, 4).protected_arrival for branch in data.branches} == {"unknown"}
    for prefix in data.prefixes:
        assert "receipt" not in canonical(prefix.model_input())
        assert "canary" not in canonical(prefix.model_input()).lower()


@pytest.mark.parametrize(
    "part", ["endpoint", "legacy", "call", "receiver", "state", "guard", "dispatch", "charges", "task_success", "pipeline"]
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
        row["observation"]["observer"]["state"]["ticket_queue"].clear()
    elif part == "guard":
        row["receipt"]["receipt_count"] = 0
    elif part == "dispatch":
        report["conditions"][1]["steps"][2]["dispatched"] = True
    elif part == "task_success":
        report["conditions"][0]["task_achieved"] = True
    elif part == "pipeline":
        report["conditions"][1]["pipeline_completed"] = True
    else:
        report["trial_charges"] = 11
    with pytest.raises(ForecastDataError):
        importer.dataset(intent, execution, report, SOURCE)


@pytest.mark.parametrize(
    "file", ["observe-step-1", "reservation-4", "implementation", "observe-resources"]
)
def test_saved_artifacts_cannot_drift_independently(tmp_path, file):
    path = tmp_path / "capture"
    capture(path)
    (path / (file + ".json")).write_text("{}")
    with pytest.raises(ForecastDataError):
        importer.read_capture(path, SOURCE)



@pytest.mark.parametrize('extra', ['reservation-19', 'observe-step-4', 'enforce-guard-4', 'failure'])
def test_unaccounted_attempt_or_failure_is_rejected(tmp_path, extra):
    path = tmp_path / 'capture'
    capture(path)
    (path / (extra + '.json')).write_text('{}')
    with pytest.raises(ForecastDataError):
        importer.read_capture(path, SOURCE)


def test_creation_prefix_exposes_acknowledgment_not_internal_record(tmp_path):
    datasets = []
    for variant in ('public', 'include_private'):
        path = tmp_path / variant
        capture(path, variant)
        data, _ = importer.read_capture(path, SOURCE)
        datasets.append(data)
        for prefix in data.prefixes:
            assert prefix.source_version == 'closed-ticket-io-v2'
            assert all(obj.object_id != 'ticket-record' for obj in prefix.objects)
            if prefix.max_sequence_no >= 1:
                first = prefix.observations[0]
                assert first.outputs == ('ticket-ack',)
                assert first.inputs == ('ticket-input',)
            if prefix.max_sequence_no == 2:
                query = prefix.observations[1]
                assert ('protected-source' in query.inputs) == (variant == 'include_private')
    # Both variants have the same visible add result; later private output must
    # not leak into the earlier prediction boundary.
    for cut in (0, 1):
        values = [next(p.model_input() for p in d.prefixes if p.max_sequence_no == cut) for d in datasets]
        assert values[0] == values[1]


def test_wrong_upstream_source_rejected(tmp_path):
    path = tmp_path / 'capture'
    capture(path)
    with pytest.raises(importer.LabError, match='ticket_source_digest_mismatch'):
        importer.read_capture(path, SOURCE + 'changed')
