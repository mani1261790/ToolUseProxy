from __future__ import annotations

import re


HOOK_PROBE_TOKEN_PREFIX = "tup-probe-v1-"
HOOK_PROBE_TOKEN_PATTERN = re.compile(
    rf"{re.escape(HOOK_PROBE_TOKEN_PREFIX)}[0-9a-f]{{32}}"
)


def hook_probe_token_is_valid(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and HOOK_PROBE_TOKEN_PATTERN.fullmatch(value) is not None
    )


def payload_contains_hook_probe_token(
    payload: object,
    probe_token: str,
) -> bool:
    """Find one opaque probe marker without interpreting arbitrary commands."""

    if isinstance(payload, str):
        return probe_token in payload
    if isinstance(payload, list):
        return any(
            payload_contains_hook_probe_token(item, probe_token)
            for item in payload
        )
    if isinstance(payload, dict):
        return any(
            payload_contains_hook_probe_token(item, probe_token)
            for item in payload.values()
        )
    return False
