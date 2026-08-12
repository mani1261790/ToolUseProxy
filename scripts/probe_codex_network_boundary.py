from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


REPORT_SCHEMA_VERSION = 1
PROBE_VERSION = "codex-network-boundary-v1"
_MAX_SCHEMA_BYTES = 2 * 1024 * 1024
_VERSION_PATTERN = re.compile(r"^codex-cli ([0-9][A-Za-z0-9.+-]*)$")
_FEATURE_PATTERN = re.compile(
    r"^network_proxy\s+(?P<stage>[a-z][a-z0-9_-]*)\s+(?P<enabled>true|false)$"
)


class ProbeError(RuntimeError):
    """Raised when the local Codex contract cannot be inspected safely."""


def probe_codex_network_boundary(
    codex_bin: str = "codex",
    *,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    """Inspect local capability metadata without executing a network request."""
    version_output = _run_codex(
        [codex_bin, "--version"], timeout_seconds=timeout_seconds
    )
    version = _parse_version(version_output)
    features_output = _run_codex(
        [codex_bin, "features", "list"], timeout_seconds=timeout_seconds
    )
    feature = _parse_network_proxy_feature(features_output)

    with tempfile.TemporaryDirectory(prefix="tooluseproxy-codex-contract-") as temp:
        output_root = Path(temp)
        _run_codex(
            [
                codex_bin,
                "app-server",
                "generate-json-schema",
                "--experimental",
                "--out",
                str(output_root),
            ],
            timeout_seconds=timeout_seconds,
        )
        params = _load_schema(
            output_root / "CommandExecutionRequestApprovalParams.json"
        )
        response = _load_schema(
            output_root / "CommandExecutionRequestApprovalResponse.json"
        )
        server_request = _load_schema(output_root / "ServerRequest.json")

    request_contract = _inspect_request_contract(params, server_request)
    response_contract = _inspect_response_contract(response)
    candidate = bool(
        feature["listed"]
        and request_contract["request_method_present"]
        and request_contract["correlation_fields_present"]
        and request_contract["structured_network_context_present"]
        and response_contract["per_request_decisions_present"]
    )
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "probe_version": PROBE_VERSION,
        "codex": {
            "version": version,
            "network_proxy": feature,
        },
        "app_server_contract": {
            **request_contract,
            **response_contract,
            "experimental_schema_requested": True,
        },
        "privacy": {
            "network_executed": False,
            "configuration_file_read_directly": False,
            "network_policy_values_stored": False,
            "event_hosts_read": False,
            "raw_command_stored": False,
        },
        "summary": {
            "candidate_contract_available": candidate,
            "production_integration_enabled": False,
            "hook_contract_inferred_from_app_server": False,
        },
    }


def render_probe_report(report: dict[str, Any]) -> str:
    feature = report["codex"]["network_proxy"]
    contract = report["app_server_contract"]
    return "\n".join(
        (
            f"Codex version={report['codex']['version']}",
            (
                "network_proxy "
                f"listed={_yes_no(feature['listed'])} "
                f"stage={feature['stage'] or 'unknown'} "
                f"enabled={_yes_no(feature['enabled'])}"
            ),
            (
                "app-server request "
                f"method={_yes_no(contract['request_method_present'])} "
                f"correlation={_yes_no(contract['correlation_fields_present'])} "
                f"network_context={_yes_no(contract['structured_network_context_present'])}"
            ),
            (
                "app-server response "
                f"per_request_decisions={_yes_no(contract['per_request_decisions_present'])} "
                f"persistent_network_rule={_yes_no(contract['persistent_network_rule_present'])}"
            ),
            "network executed=no; production integration=no",
            (
                "candidate contract="
                f"{'AVAILABLE' if report['summary']['candidate_contract_available'] else 'UNAVAILABLE'}"
            ),
        )
    )


def _run_codex(argv: list[str], *, timeout_seconds: float) -> str:
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except FileNotFoundError:
        raise ProbeError("Codex CLI was not found") from None
    except subprocess.TimeoutExpired:
        raise ProbeError("Codex capability inspection timed out") from None
    if completed.returncode != 0:
        raise ProbeError(
            f"Codex capability inspection failed with exit code {completed.returncode}"
        )
    return completed.stdout


def _parse_version(output: str) -> str:
    match = _VERSION_PATTERN.fullmatch(output.strip())
    if match is None:
        raise ProbeError("Codex version output did not match the expected contract")
    return match.group(1)


def _parse_network_proxy_feature(output: str) -> dict[str, Any]:
    matches = [
        match
        for line in output.splitlines()
        if (match := _FEATURE_PATTERN.fullmatch(line.strip())) is not None
    ]
    if len(matches) != 1:
        return {"listed": False, "stage": None, "enabled": None}
    match = matches[0]
    return {
        "listed": True,
        "stage": match.group("stage"),
        "enabled": match.group("enabled") == "true",
    }


def _load_schema(path: Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        raise ProbeError(f"Codex schema bundle is missing {path.name}") from None
    if size > _MAX_SCHEMA_BYTES:
        raise ProbeError(f"Codex schema file is too large: {path.name}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        raise ProbeError(f"Codex schema file is invalid JSON: {path.name}") from None
    if not isinstance(value, dict):
        raise ProbeError(f"Codex schema file is not an object: {path.name}")
    return value


def _inspect_request_contract(
    params: dict[str, Any], server_request: dict[str, Any]
) -> dict[str, bool]:
    required = _string_set_field(params, "required")
    properties = _object_field(params, "properties")
    definitions = _object_field(params, "definitions")
    network_context = _object_field(definitions, "NetworkApprovalContext")
    network_required = _string_set_field(network_context, "required")
    network_properties = _object_field(network_context, "properties")
    request_method_present = _contains_enum_value(
        server_request, "item/commandExecution/requestApproval"
    )
    return {
        "request_method_present": request_method_present,
        "correlation_fields_present": {"itemId", "threadId", "turnId"}.issubset(
            required
        ),
        "structured_network_context_present": (
            "networkApprovalContext" in properties
            and {"host", "protocol"}.issubset(network_required)
            and {"host", "protocol"}.issubset(network_properties)
        ),
    }


def _inspect_response_contract(response: dict[str, Any]) -> dict[str, bool]:
    decisions = _object_field(
        _object_field(response, "definitions"),
        "CommandExecutionApprovalDecision",
    )
    return {
        "per_request_decisions_present": (
            _contains_enum_value(decisions, "accept")
            and _contains_enum_value(decisions, "decline")
            and _contains_enum_value(decisions, "cancel")
        ),
        "session_decision_present": _contains_enum_value(
            decisions, "acceptForSession"
        ),
        "persistent_network_rule_present": _contains_key(
            decisions, "applyNetworkPolicyAmendment"
        ),
    }


def _object_field(value: dict[str, Any], key: str) -> dict[str, Any]:
    nested = value.get(key)
    if nested is None:
        return {}
    if not isinstance(nested, dict):
        raise ProbeError(f"Codex schema field {key} is not an object")
    return nested


def _string_set_field(value: dict[str, Any], key: str) -> set[str]:
    nested = value.get(key)
    if nested is None:
        return set()
    if not isinstance(nested, list) or any(
        not isinstance(item, str) for item in nested
    ):
        raise ProbeError(f"Codex schema field {key} is not a string array")
    return set(nested)


def _contains_enum_value(value: Any, expected: str) -> bool:
    if isinstance(value, dict):
        enum = value.get("enum")
        if isinstance(enum, list) and expected in enum:
            return True
        return any(_contains_enum_value(nested, expected) for nested in value.values())
    if isinstance(value, list):
        return any(_contains_enum_value(nested, expected) for nested in value)
    return False


def _contains_key(value: Any, expected: str) -> bool:
    if isinstance(value, dict):
        return expected in value or any(
            _contains_key(nested, expected) for nested in value.values()
        )
    if isinstance(value, list):
        return any(_contains_key(nested, expected) for nested in value)
    return False


def _yes_no(value: Any) -> str:
    if value is None:
        return "unknown"
    return "yes" if value else "no"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect the local Codex network approval contract without making "
            "a network request or reading event values."
        )
    )
    parser.add_argument("--codex-bin", default="codex", help="Codex executable.")
    parser.add_argument(
        "--format", choices=("text", "json"), default="text", help="Stdout format."
    )
    parser.add_argument(
        "--require-candidate",
        action="store_true",
        help="Return exit code 1 unless the candidate app-server contract is present.",
    )
    args = parser.parse_args(argv)
    try:
        report = probe_codex_network_boundary(args.codex_bin)
    except (OSError, ProbeError, ValueError) as error:
        print(f"Codex network boundary probe error: {error}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(render_probe_report(report))
    if args.require_candidate and not report["summary"]["candidate_contract_available"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
