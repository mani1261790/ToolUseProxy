from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from hook_monitor.externality.providers import (
    CodexExecJudge,
    CodexJudgeRunner,
    JudgeProviderError,
    resolve_codex_executable_identity,
    verify_codex_probe_receipt,
)


JUDGE_ROUTE_ENV = "TOOLUSEPROXY_EXTERNALITY_JUDGE_PROVIDER"
CODEX_MODEL_ENV = "TOOLUSEPROXY_EXTERNALITY_JUDGE_CODEX_MODEL"
CODEX_RECEIPT_ENV = "TOOLUSEPROXY_EXTERNALITY_JUDGE_CODEX_RECEIPT"
TIMEOUT_ENV = "TOOLUSEPROXY_EXTERNALITY_JUDGE_TIMEOUT_SECONDS"
PLUGIN_DATA_ENV = "PLUGIN_DATA"

JUDGE_ROUTES = frozenset({"off", "codex"})
DEFAULT_TIMEOUT_SECONDS = 7.0
MAX_TIMEOUT_SECONDS = 8.0


class JudgeConfigurationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ResolvedJudgeConfiguration:
    route: str
    chain: CodexJudgeRunner | None
    status: str
    failure_code: str | None = None


def resolve_judge_configuration(
    environ: Mapping[str, str],
) -> ResolvedJudgeConfiguration:
    route = environ.get(JUDGE_ROUTE_ENV, "off").strip().lower()
    if route not in JUDGE_ROUTES:
        return ResolvedJudgeConfiguration(
            route="invalid",
            chain=None,
            status="failed",
            failure_code="configuration_invalid",
        )
    if route == "off":
        return ResolvedJudgeConfiguration(route, None, "not_configured")
    try:
        timeout = _parse_timeout(environ.get(TIMEOUT_ENV))
        provider = _codex_provider(environ, timeout=timeout)
    except JudgeConfigurationError as exc:
        return ResolvedJudgeConfiguration(
            route=route,
            chain=None,
            status="failed",
            failure_code=exc.code,
        )
    return ResolvedJudgeConfiguration(
        route=route,
        chain=CodexJudgeRunner(
            provider,
            total_timeout_seconds=timeout,
        ),
        status="ready",
    )


def _codex_provider(
    environ: Mapping[str, str],
    *,
    timeout: float,
) -> CodexExecJudge:
    model = environ.get(CODEX_MODEL_ENV) or None
    receipt_value = environ.get(CODEX_RECEIPT_ENV)
    if receipt_value:
        receipt_path = Path(receipt_value)
    else:
        plugin_data = environ.get(PLUGIN_DATA_ENV)
        if not plugin_data:
            raise JudgeConfigurationError("codex_probe_receipt_unavailable")
        receipt_path = Path(plugin_data) / "externality-codex-probe.json"
    try:
        identity = resolve_codex_executable_identity("codex")
    except JudgeProviderError as exc:
        raise JudgeConfigurationError(exc.code) from exc
    eligible, failure_code = verify_codex_probe_receipt(
        receipt_path,
        identity=identity,
        model=model,
    )
    if not eligible:
        raise JudgeConfigurationError(
            failure_code or "codex_probe_receipt_invalid"
        )
    try:
        return CodexExecJudge(
            executable=identity.executable_path,
            model=model,
            timeout_seconds=timeout,
        )
    except ValueError as exc:
        raise JudgeConfigurationError("configuration_invalid") from exc


def _parse_timeout(value: str | None) -> float:
    if value is None:
        return DEFAULT_TIMEOUT_SECONDS
    try:
        timeout = float(value)
    except ValueError as exc:
        raise JudgeConfigurationError("configuration_invalid") from exc
    if not 0 < timeout <= MAX_TIMEOUT_SECONDS:
        raise JudgeConfigurationError("configuration_invalid")
    return timeout
