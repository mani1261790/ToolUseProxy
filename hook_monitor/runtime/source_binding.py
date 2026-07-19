from __future__ import annotations

import re


SOURCE_BINDING_REGISTERED_SOURCE = "registered_source"
SOURCE_BINDING_SELECTED_FIELD = "selected_field"
SOURCE_BINDING_SELECTED_SECURITY_FIELD = "selected_security_field"

SOURCE_BINDING_SIGNALS = frozenset(
    {
        SOURCE_BINDING_REGISTERED_SOURCE,
        SOURCE_BINDING_SELECTED_FIELD,
        SOURCE_BINDING_SELECTED_SECURITY_FIELD,
    }
)

_SECURITY_FIELD_TOKENS = frozenset(
    {
        "credential",
        "credentials",
        "key",
        "password",
        "secret",
        "token",
    }
)
_SECURITY_COMPACT_FIELDS = frozenset(
    {
        "accesskey",
        "accesstoken",
        "apikey",
        "clientsecret",
        "privatekey",
        "secretkey",
    }
)


def selected_field_source_binding_signal(field_name: str) -> str:
    """Classify an explicitly selected dotenv key or JSON pointer terminal."""
    tokens = tuple(
        token
        for token in re.split(r"[^a-z0-9]+", field_name.casefold())
        if token
    )
    if any(
        token in _SECURITY_FIELD_TOKENS or token in _SECURITY_COMPACT_FIELDS
        for token in tokens
    ):
        return SOURCE_BINDING_SELECTED_SECURITY_FIELD
    return SOURCE_BINDING_SELECTED_FIELD
