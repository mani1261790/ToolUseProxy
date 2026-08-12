from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Mapping


RUNTIME_SETTINGS_SCHEMA_VERSION = 1
RUNTIME_SETTINGS_REVISION_VERSION = "workspace-runtime-settings-v1"

PRE_TOOL_POLICY_KEY = "pre-tool-policy"
FILE_PAYLOAD_SHADOW_KEY = "file-payload-shadow"
FILE_PAYLOAD_EXACT_ENFORCEMENT_KEY = "file-payload-exact-enforcement"
EXTERNALITY_PROTECTION_KEY = "externality-protection"

RUNTIME_SETTING_KEYS = (
    PRE_TOOL_POLICY_KEY,
    FILE_PAYLOAD_SHADOW_KEY,
    FILE_PAYLOAD_EXACT_ENFORCEMENT_KEY,
    EXTERNALITY_PROTECTION_KEY,
)
RUNTIME_SETTING_ENVIRONMENT = {
    PRE_TOOL_POLICY_KEY: "TOOLUSEPROXY_PRE_TOOL_POLICY",
    FILE_PAYLOAD_SHADOW_KEY: "TOOLUSEPROXY_PRE_TOOL_FILE_PAYLOAD_SHADOW",
    FILE_PAYLOAD_EXACT_ENFORCEMENT_KEY: (
        "TOOLUSEPROXY_PRE_TOOL_FILE_PAYLOAD_EXACT_ENFORCEMENT"
    ),
    EXTERNALITY_PROTECTION_KEY: "TOOLUSEPROXY_EXTERNALITY_PROTECTION",
}
RUNTIME_SETTING_DEFAULTS = {key: False for key in RUNTIME_SETTING_KEYS}

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})
_DEPENDENT_PRE_TOOL_KEYS = frozenset(
    {
        FILE_PAYLOAD_SHADOW_KEY,
        FILE_PAYLOAD_EXACT_ENFORCEMENT_KEY,
        EXTERNALITY_PROTECTION_KEY,
    }
)


class RuntimeSettingsError(ValueError):
    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        super().__init__(detail)


@dataclass(frozen=True)
class WorkspaceRuntimeSettings:
    workspace_id: str
    settings: dict[str, bool]
    revision: str
    schema_version: int = RUNTIME_SETTINGS_SCHEMA_VERSION


@dataclass(frozen=True)
class EffectiveRuntimeSetting:
    key: str
    configured_value: bool | None
    effective_value: bool
    source: str
    environment_variable: str
    diagnostic_code: str | None = None


@dataclass(frozen=True)
class EffectiveRuntimeSettings:
    workspace_id: str
    revision: str
    settings: dict[str, EffectiveRuntimeSetting]

    def enabled(self, key: str) -> bool:
        try:
            return self.settings[key].effective_value
        except KeyError:
            raise RuntimeSettingsError(
                "setting_key_unknown",
                f"runtime setting is not supported: {key}",
            ) from None


@dataclass(frozen=True)
class RuntimeSettingChange:
    change_id: str
    workspace_id: str
    action: str
    setting_key: str
    previous_value: bool | None
    new_value: bool | None
    previous_revision: str
    new_revision: str
    recorded_at: str


def empty_workspace_runtime_settings(workspace_id: str) -> WorkspaceRuntimeSettings:
    return make_workspace_runtime_settings(workspace_id, {})


def make_workspace_runtime_settings(
    workspace_id: str,
    settings: Mapping[str, bool],
) -> WorkspaceRuntimeSettings:
    if not isinstance(workspace_id, str) or not workspace_id:
        raise RuntimeSettingsError(
            "workspace_id_invalid",
            "workspace runtime settings require a workspace identity",
        )
    normalized = validate_runtime_settings(settings)
    return WorkspaceRuntimeSettings(
        workspace_id=workspace_id,
        settings=normalized,
        revision=runtime_settings_revision(normalized),
    )


def validate_runtime_settings(
    settings: Mapping[str, bool],
    *,
    validate_dependencies: bool = True,
) -> dict[str, bool]:
    if not isinstance(settings, Mapping):
        raise RuntimeSettingsError(
            "settings_invalid",
            "runtime settings must be an object",
        )
    normalized: dict[str, bool] = {}
    for key, value in settings.items():
        validate_runtime_setting_key(key)
        if type(value) is not bool:
            raise RuntimeSettingsError(
                "setting_value_invalid",
                f"runtime setting {key} must be on or off",
            )
        normalized[key] = value
    if validate_dependencies:
        validate_runtime_settings_dependencies(normalized)
    return {key: normalized[key] for key in RUNTIME_SETTING_KEYS if key in normalized}


def validate_runtime_setting_key(key: object) -> str:
    if not isinstance(key, str) or key not in RUNTIME_SETTING_KEYS:
        raise RuntimeSettingsError(
            "setting_key_unknown",
            f"runtime setting is not supported: {key}",
        )
    return key


def parse_runtime_setting_value(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise RuntimeSettingsError(
        "setting_value_invalid",
        "runtime setting value must be one of: on, off",
    )


def validate_runtime_settings_dependencies(settings: Mapping[str, bool]) -> None:
    pre_tool_enabled = settings.get(PRE_TOOL_POLICY_KEY, False)
    enabled_dependents = sorted(
        key for key in _DEPENDENT_PRE_TOOL_KEYS if settings.get(key, False)
    )
    if enabled_dependents and not pre_tool_enabled:
        raise RuntimeSettingsError(
            "setting_dependency_invalid",
            "pre-tool-policy must be on before enabling: "
            + ", ".join(enabled_dependents),
        )


def runtime_settings_payload(settings: Mapping[str, bool]) -> dict[str, object]:
    normalized = validate_runtime_settings(settings)
    return {
        "schema_version": RUNTIME_SETTINGS_SCHEMA_VERSION,
        "settings": normalized,
    }


def runtime_settings_json(settings: Mapping[str, bool]) -> str:
    return json.dumps(
        runtime_settings_payload(settings),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def runtime_settings_revision(settings: Mapping[str, bool]) -> str:
    encoded = b"\0".join(
        (
            RUNTIME_SETTINGS_REVISION_VERSION.encode("ascii"),
            runtime_settings_json(settings).encode("utf-8"),
        )
    )
    return hashlib.sha256(encoded).hexdigest()


def parse_runtime_settings_json(value: str) -> dict[str, bool]:
    try:
        payload = json.loads(value)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise RuntimeSettingsError(
            "settings_payload_invalid",
            "stored runtime settings are not valid JSON",
        ) from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "settings",
    }:
        raise RuntimeSettingsError(
            "settings_payload_invalid",
            "stored runtime settings have an invalid shape",
        )
    schema_version = payload["schema_version"]
    if schema_version != RUNTIME_SETTINGS_SCHEMA_VERSION:
        raise RuntimeSettingsError(
            "settings_schema_unsupported",
            "stored runtime settings use an unsupported schema",
        )
    settings = payload["settings"]
    if not isinstance(settings, dict):
        raise RuntimeSettingsError(
            "settings_payload_invalid",
            "stored runtime settings have an invalid settings object",
        )
    return validate_runtime_settings(settings)


def resolve_effective_runtime_settings(
    state: WorkspaceRuntimeSettings,
    environ: Mapping[str, str],
) -> EffectiveRuntimeSettings:
    resolved: dict[str, EffectiveRuntimeSetting] = {}
    raw_effective: dict[str, bool] = {}
    for key in RUNTIME_SETTING_KEYS:
        environment_variable = RUNTIME_SETTING_ENVIRONMENT[key]
        configured_value = state.settings.get(key)
        environment_value = environ.get(environment_variable)
        diagnostic_code: str | None = None
        if environment_value is not None:
            try:
                effective_value = parse_runtime_setting_value(environment_value)
            except RuntimeSettingsError:
                effective_value = False
                source = "invalid_environment"
                diagnostic_code = "environment_value_invalid"
            else:
                source = "environment"
        elif configured_value is not None:
            effective_value = configured_value
            source = "workspace"
        else:
            effective_value = RUNTIME_SETTING_DEFAULTS[key]
            source = "default"
        raw_effective[key] = effective_value
        resolved[key] = EffectiveRuntimeSetting(
            key=key,
            configured_value=configured_value,
            effective_value=effective_value,
            source=source,
            environment_variable=environment_variable,
            diagnostic_code=diagnostic_code,
        )

    if not raw_effective[PRE_TOOL_POLICY_KEY]:
        for key in _DEPENDENT_PRE_TOOL_KEYS:
            item = resolved[key]
            if not item.effective_value:
                continue
            resolved[key] = EffectiveRuntimeSetting(
                key=key,
                configured_value=item.configured_value,
                effective_value=False,
                source=item.source,
                environment_variable=item.environment_variable,
                diagnostic_code="pre_tool_policy_disabled",
            )

    return EffectiveRuntimeSettings(
        workspace_id=state.workspace_id,
        revision=state.revision,
        settings=resolved,
    )
