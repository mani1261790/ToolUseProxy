from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any


_FIELD_CLASSES = frozenset({"data", "control", "file"})
_SCALAR_TYPES = frozenset({"string", "number", "boolean"})
_INVALID_POINTER_ESCAPE = re.compile(r"~(?![01])")


@dataclass(frozen=True)
class McpFieldSpec:
    """One closed-world scalar field in an exact MCP tool profile."""

    pointer: str
    value_type: str
    field_class: str
    required: bool = False
    redactable: bool = False

    def __post_init__(self) -> None:
        _validate_profile_pointer(self.pointer)
        if self.value_type not in _SCALAR_TYPES:
            raise ValueError(f"unsupported MCP field type: {self.value_type}")
        if self.field_class not in _FIELD_CLASSES:
            raise ValueError(f"unsupported MCP field class: {self.field_class}")
        if self.redactable and self.field_class != "data":
            raise ValueError("only MCP data fields can be redactable")
        if self.redactable and self.value_type != "string":
            raise ValueError("only MCP string fields can be redactable")


@dataclass(frozen=True)
class McpProfileValidation:
    accepted: bool
    rejection_code: str | None = None


@dataclass(frozen=True)
class McpInputLimits:
    max_input_bytes: int = 32 * 1024
    max_fields: int = 32
    max_depth: int = 8

    def __post_init__(self) -> None:
        if min(self.max_input_bytes, self.max_fields, self.max_depth) < 1:
            raise ValueError("MCP input limits must be positive")


@dataclass(frozen=True)
class McpInputInspection:
    accepted: bool
    rejection_code: str | None = None
    input_bytes: int | None = None
    field_count: int = 0
    max_depth_seen: int = 0


@dataclass(frozen=True)
class McpToolProfile:
    """Exact, immutable schema used by both sink generation and redaction planning."""

    profile_id: str
    server: str
    tool: str
    sink_type: str
    fields: tuple[McpFieldSpec, ...]
    post_input_stable: bool

    def __post_init__(self) -> None:
        if not isinstance(self.fields, tuple):
            raise ValueError("MCP profile fields must be an immutable tuple")
        if not self.profile_id or not self.server or not self.tool:
            raise ValueError("MCP profile identity fields must be non-empty")
        if not self.sink_type.startswith("external_"):
            raise ValueError("MCP profile sink type must be external")
        if not self.fields:
            raise ValueError("MCP profile must classify at least one field")
        pointers = [field.pointer for field in self.fields]
        if len(pointers) != len(set(pointers)):
            raise ValueError("MCP profile field pointers must be unique")
        if self.file_input_pointers and self.post_input_stable:
            raise ValueError(
                "MCP profiles with Codex-managed file inputs cannot be post-input stable"
            )

    @property
    def exact_key(self) -> tuple[str, str]:
        return self.server, self.tool

    @property
    def profile_version(self) -> str:
        return _semantic_version("mcp-profile-v1", self._semantic_payload())

    @property
    def outbound_data_pointers(self) -> tuple[str, ...]:
        return tuple(
            field.pointer for field in self.fields if field.field_class == "data"
        )

    @property
    def control_pointers(self) -> tuple[str, ...]:
        return tuple(
            field.pointer for field in self.fields if field.field_class == "control"
        )

    @property
    def file_input_pointers(self) -> tuple[str, ...]:
        return tuple(
            field.pointer for field in self.fields if field.field_class == "file"
        )

    @property
    def redactable_pointers(self) -> tuple[str, ...]:
        return tuple(field.pointer for field in self.fields if field.redactable)

    @property
    def preview_eligible(self) -> bool:
        return self.post_input_stable and not self.file_input_pointers

    def field_for_pointer(self, pointer: str) -> McpFieldSpec | None:
        return next((field for field in self.fields if field.pointer == pointer), None)

    def validate(self, arguments: dict[str, Any]) -> McpProfileValidation:
        observed: dict[str, Any] = {}
        for key, value in arguments.items():
            pointer = f"/{escape_json_pointer_segment(str(key))}"
            if isinstance(value, (dict, list)):
                return McpProfileValidation(False, "unsupported_nesting")
            if value is None:
                return McpProfileValidation(False, "unsupported_null")
            observed[pointer] = value

        fields_by_pointer = {field.pointer: field for field in self.fields}
        if any(pointer not in fields_by_pointer for pointer in observed):
            return McpProfileValidation(False, "unknown_field")
        if any(
            field.required and field.pointer not in observed for field in self.fields
        ):
            return McpProfileValidation(False, "missing_required_field")
        if any(
            _json_scalar_type(value) != fields_by_pointer[pointer].value_type
            for pointer, value in observed.items()
        ):
            return McpProfileValidation(False, "wrong_field_type")
        return McpProfileValidation(True)

    def _semantic_payload(self) -> dict[str, object]:
        return {
            "profile_id": self.profile_id,
            "server": self.server,
            "tool": self.tool,
            "sink_type": self.sink_type,
            "post_input_stable": self.post_input_stable,
            "fields": [
                {
                    "pointer": field.pointer,
                    "value_type": field.value_type,
                    "field_class": field.field_class,
                    "required": field.required,
                    "redactable": field.redactable,
                }
                for field in sorted(self.fields, key=lambda item: item.pointer)
            ],
        }


@dataclass(frozen=True)
class McpProfileRegistry:
    profiles: tuple[McpToolProfile, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.profiles, tuple):
            raise ValueError("MCP profile registry must be an immutable tuple")
        exact_keys = [profile.exact_key for profile in self.profiles]
        profile_ids = [profile.profile_id for profile in self.profiles]
        if len(exact_keys) != len(set(exact_keys)):
            raise ValueError("MCP profile exact keys must be unique")
        if len(profile_ids) != len(set(profile_ids)):
            raise ValueError("MCP profile IDs must be unique")

    @property
    def registry_version(self) -> str:
        payload = [
            {
                "profile_id": profile.profile_id,
                "profile_version": profile.profile_version,
                "server": profile.server,
                "tool": profile.tool,
            }
            for profile in sorted(self.profiles, key=lambda item: item.exact_key)
        ]
        return _semantic_version("mcp-registry-v1", payload)

    def resolve(self, server: str | None, tool: str | None) -> McpToolProfile | None:
        if server is None or tool is None:
            return None
        return next(
            (
                profile
                for profile in self.profiles
                if profile.exact_key == (server, tool)
            ),
            None,
        )


def escape_json_pointer_segment(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _validate_profile_pointer(pointer: str) -> None:
    if not pointer.startswith("/") or pointer == "/" or pointer.count("/") != 1:
        raise ValueError("initial MCP profile pointers must name one top-level field")
    encoded = pointer[1:]
    if not encoded or _INVALID_POINTER_ESCAPE.search(encoded):
        raise ValueError(f"invalid JSON Pointer: {pointer}")
    decoded = encoded.replace("~1", "/").replace("~0", "~")
    if escape_json_pointer_segment(decoded) != encoded:
        raise ValueError(f"non-canonical JSON Pointer: {pointer}")


def _json_scalar_type(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    return "unsupported"


def _semantic_version(prefix: str, payload: object) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(prefix.encode("utf-8") + b"\0" + encoded).hexdigest()
    return f"{prefix}:{digest}"


TOOLUSEPROXY_E2E_PUBLISH_TEXT_PROFILE = McpToolProfile(
    profile_id="tooluseproxy-e2e/publish_text",
    server="tooluseproxy_e2e",
    tool="publish_text",
    sink_type="external_api_call",
    fields=(
        McpFieldSpec(
            pointer="/content",
            value_type="string",
            field_class="data",
            required=True,
            redactable=True,
        ),
    ),
    post_input_stable=True,
)


DEFAULT_MCP_PROFILE_REGISTRY = McpProfileRegistry(
    profiles=(TOOLUSEPROXY_E2E_PUBLISH_TEXT_PROFILE,),
)

DEFAULT_MCP_INPUT_LIMITS = McpInputLimits()


def inspect_mcp_input(
    arguments: object,
    limits: McpInputLimits = DEFAULT_MCP_INPUT_LIMITS,
) -> McpInputInspection:
    """Bound work before fragments or graph nodes are materialized."""
    if not isinstance(arguments, dict):
        return McpInputInspection(False, "input_not_object")

    field_count = 0
    max_depth_seen = 0
    character_count = 0
    stack: list[tuple[object, int]] = [(arguments, 0)]
    while stack:
        value, depth = stack.pop()
        max_depth_seen = max(max_depth_seen, depth)
        if depth > limits.max_depth:
            return McpInputInspection(
                False,
                "nesting_depth_exceeded",
                field_count=field_count,
                max_depth_seen=max_depth_seen,
            )
        if isinstance(value, dict):
            for key, child in value.items():
                field_count += 1
                if field_count > limits.max_fields:
                    return McpInputInspection(
                        False,
                        "field_count_exceeded",
                        field_count=field_count,
                        max_depth_seen=max_depth_seen,
                    )
                key_text = str(key)
                character_count += len(key_text)
                if character_count > limits.max_input_bytes:
                    return McpInputInspection(
                        False,
                        "input_bytes_exceeded",
                        field_count=field_count,
                        max_depth_seen=max_depth_seen,
                    )
                stack.append((child, depth + 1))
            continue
        if isinstance(value, list):
            for child in value:
                field_count += 1
                if field_count > limits.max_fields:
                    return McpInputInspection(
                        False,
                        "field_count_exceeded",
                        field_count=field_count,
                        max_depth_seen=max_depth_seen,
                    )
                stack.append((child, depth + 1))
            continue
        if isinstance(value, str):
            character_count += len(value)
        elif isinstance(value, bool) or value is None:
            character_count += 5
        elif isinstance(value, (int, float)):
            character_count += len(str(value))
        else:
            return McpInputInspection(
                False,
                "unsupported_input_type",
                field_count=field_count,
                max_depth_seen=max_depth_seen,
            )
        if character_count > limits.max_input_bytes:
            return McpInputInspection(
                False,
                "input_bytes_exceeded",
                field_count=field_count,
                max_depth_seen=max_depth_seen,
            )

    try:
        encoded = json.dumps(
            arguments,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        return McpInputInspection(
            False,
            "unsupported_input_type",
            field_count=field_count,
            max_depth_seen=max_depth_seen,
        )
    if len(encoded) > limits.max_input_bytes:
        return McpInputInspection(
            False,
            "input_bytes_exceeded",
            input_bytes=len(encoded),
            field_count=field_count,
            max_depth_seen=max_depth_seen,
        )
    return McpInputInspection(
        True,
        input_bytes=len(encoded),
        field_count=field_count,
        max_depth_seen=max_depth_seen,
    )
