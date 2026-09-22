from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal, Mapping


EXTERNALITY_ENVELOPE_SCHEMA_VERSION = 1
EXTERNALITY_VERDICT_SCHEMA_VERSION = 1
MAX_ENVELOPE_JSON_BYTES = 16 * 1024

TOOL_FAMILIES = frozenset({"bash", "mcp", "unknown"})
ANALYSIS_COVERAGES = frozenset({"complete", "partial", "opaque"})
EXECUTABLE_CLASSES = frozenset(
    {
        "custom_or_unknown",
        "deployment_client",
        "dns_client",
        "file_transfer_client",
        "http_client",
        "local_build_or_test",
        "local_file_tool",
        "mcp_tool",
        "node_runtime",
        "package_publisher",
        "python_runtime",
        "remote_vcs_client",
        "shell_runtime",
        "socket_client",
    }
)
CAPABILITIES = frozenset(
    {
        "child_process",
        "deployment",
        "dns",
        "external_file_transfer",
        "http",
        "mcp_mutation",
        "package_publish",
        "remote_vcs_write",
        "socket",
    }
)
RISK_SIGNALS = frozenset(
    {
        "dynamic_code",
        "dynamic_shell_token",
        "environment_override",
        "execution_capable_tool",
        "inline_program",
        "mcp_unclassified",
        "outside_workspace_reference",
        "script_parse_failed",
        "script_size_exceeded",
        "unsupported_shell_syntax",
        "untrusted_executable_path",
        "unknown_executable",
    }
)
COUNT_KEYS = (
    "dynamic_token_count",
    "file_read_count",
    "pipeline_count",
    "redirection_count",
    "script_file_count",
    "segment_count",
)

VERDICTS = frozenset({"external", "possibly_external", "local", "unknown"})
CONFIDENCE_LEVELS = frozenset({"high", "medium", "low"})
JUDGE_REASON_CODES = frozenset(
    {
        "direct_network_capability",
        "dynamic_execution",
        "insufficient_evidence",
        "known_external_operation",
        "known_local_only",
        "mcp_external_operation",
        "network_capable_child_process",
        "opaque_executable",
    }
)


class ExternalitySchemaError(ValueError):
    """Raised when a value-free envelope or verdict violates its closed schema."""


@dataclass(frozen=True)
class ExternalityEnvelope:
    tool_family: Literal["bash", "mcp", "unknown"]
    analysis_coverage: Literal["complete", "partial", "opaque"]
    executable_classes: tuple[str, ...]
    capabilities: tuple[str, ...]
    risk_signals: tuple[str, ...]
    counts: tuple[tuple[str, int], ...]
    schema_version: int = EXTERNALITY_ENVELOPE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_member(self.tool_family, TOOL_FAMILIES, "tool_family")
        _require_member(
            self.analysis_coverage,
            ANALYSIS_COVERAGES,
            "analysis_coverage",
        )
        _require_closed_values(
            self.executable_classes,
            EXECUTABLE_CLASSES,
            "executable_classes",
        )
        _require_closed_values(self.capabilities, CAPABILITIES, "capabilities")
        _require_closed_values(self.risk_signals, RISK_SIGNALS, "risk_signals")
        if (
            type(self.schema_version) is not int
            or self.schema_version != EXTERNALITY_ENVELOPE_SCHEMA_VERSION
        ):
            raise ExternalitySchemaError("unsupported envelope schema_version")
        if tuple(key for key, _value in self.counts) != COUNT_KEYS:
            raise ExternalitySchemaError("counts must contain the closed key set in order")
        for key, value in self.counts:
            if type(value) is not int or value < 0 or value > 10_000:
                raise ExternalitySchemaError(f"invalid bounded count: {key}")
        if tuple(sorted(set(self.executable_classes))) != self.executable_classes:
            raise ExternalitySchemaError("executable_classes must be sorted and unique")
        if tuple(sorted(set(self.capabilities))) != self.capabilities:
            raise ExternalitySchemaError("capabilities must be sorted and unique")
        if tuple(sorted(set(self.risk_signals))) != self.risk_signals:
            raise ExternalitySchemaError("risk_signals must be sorted and unique")
        if len(self.canonical_json().encode("utf-8")) > MAX_ENVELOPE_JSON_BYTES:
            raise ExternalitySchemaError("envelope JSON exceeds the bounded size")

    @classmethod
    def create(
        cls,
        *,
        tool_family: str,
        analysis_coverage: str,
        executable_classes: set[str] | frozenset[str],
        capabilities: set[str] | frozenset[str],
        risk_signals: set[str] | frozenset[str],
        counts: Mapping[str, int],
    ) -> ExternalityEnvelope:
        return cls(
            tool_family=tool_family,  # type: ignore[arg-type]
            analysis_coverage=analysis_coverage,  # type: ignore[arg-type]
            executable_classes=tuple(sorted(executable_classes)),
            capabilities=tuple(sorted(capabilities)),
            risk_signals=tuple(sorted(risk_signals)),
            counts=tuple(
                (key, _bounded_count(counts.get(key, 0), key)) for key in COUNT_KEYS
            ),
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ExternalityEnvelope:
        required = {
            "schema_version",
            "tool_family",
            "analysis_coverage",
            "executable_classes",
            "capabilities",
            "risk_signals",
            "counts",
        }
        if set(value) != required:
            raise ExternalitySchemaError("envelope object keys differ from the closed schema")
        counts = value["counts"]
        if not isinstance(counts, dict) or set(counts) != set(COUNT_KEYS):
            raise ExternalitySchemaError("counts object keys differ from the closed schema")
        return cls(
            schema_version=value["schema_version"],
            tool_family=value["tool_family"],
            analysis_coverage=value["analysis_coverage"],
            executable_classes=_require_string_tuple(
                value["executable_classes"], "executable_classes"
            ),
            capabilities=_require_string_tuple(value["capabilities"], "capabilities"),
            risk_signals=_require_string_tuple(value["risk_signals"], "risk_signals"),
            counts=tuple((key, counts[key]) for key in COUNT_KEYS),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool_family": self.tool_family,
            "analysis_coverage": self.analysis_coverage,
            "executable_classes": list(self.executable_classes),
            "capabilities": list(self.capabilities),
            "risk_signals": list(self.risk_signals),
            "counts": dict(self.counts),
        }

    def canonical_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )

    def digest_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ExternalityVerdict:
    verdict: Literal["external", "possibly_external", "local", "unknown"]
    confidence: Literal["high", "medium", "low"]
    reason_codes: tuple[str, ...]
    schema_version: int = EXTERNALITY_VERDICT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != EXTERNALITY_VERDICT_SCHEMA_VERSION
        ):
            raise ExternalitySchemaError("unsupported verdict schema_version")
        _require_member(self.verdict, VERDICTS, "verdict")
        _require_member(self.confidence, CONFIDENCE_LEVELS, "confidence")
        _require_closed_values(self.reason_codes, JUDGE_REASON_CODES, "reason_codes")
        if not self.reason_codes or len(self.reason_codes) > 4:
            raise ExternalitySchemaError("reason_codes must contain between 1 and 4 values")
        if tuple(sorted(set(self.reason_codes))) != self.reason_codes:
            raise ExternalitySchemaError("reason_codes must be sorted and unique")
        if self.verdict == "local" and self.reason_codes != ("known_local_only",):
            raise ExternalitySchemaError("local verdict requires known_local_only only")
        if self.verdict != "local" and "known_local_only" in self.reason_codes:
            raise ExternalitySchemaError("non-local verdict cannot use known_local_only")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ExternalityVerdict:
        required = {"schema_version", "verdict", "confidence", "reason_codes"}
        if set(value) != required:
            raise ExternalitySchemaError("verdict object keys differ from the closed schema")
        reason_codes = _require_string_tuple(value["reason_codes"], "reason_codes")
        if len(reason_codes) != len(set(reason_codes)):
            raise ExternalitySchemaError("reason_codes must be unique")
        return cls(
            schema_version=value["schema_version"],
            verdict=value["verdict"],
            confidence=value["confidence"],
            reason_codes=tuple(sorted(reason_codes)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "reason_codes": list(self.reason_codes),
        }


EXTERNALITY_VERDICT_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "verdict", "confidence", "reason_codes"],
    "properties": {
        "schema_version": {
            "type": "integer",
            "const": EXTERNALITY_VERDICT_SCHEMA_VERSION,
        },
        "verdict": {"type": "string", "enum": sorted(VERDICTS)},
        "confidence": {"type": "string", "enum": sorted(CONFIDENCE_LEVELS)},
        "reason_codes": {
            "type": "array",
            "minItems": 1,
            "maxItems": 4,
            "items": {"type": "string", "enum": sorted(JUDGE_REASON_CODES)},
        },
    },
}


def _require_member(value: object, allowed: frozenset[str], field: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise ExternalitySchemaError(f"invalid {field}")


def _require_closed_values(
    values: tuple[str, ...], allowed: frozenset[str], field: str
) -> None:
    if any(value not in allowed for value in values):
        raise ExternalitySchemaError(f"invalid {field}")


def _require_string_tuple(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ExternalitySchemaError(f"{field} must be an array of strings")
    return tuple(value)


def _bounded_count(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ExternalitySchemaError(f"invalid bounded count: {field}")
    return min(value, 10_000)
