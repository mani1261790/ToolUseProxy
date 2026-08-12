"""Value-free externality analysis and judge providers.

This package is intentionally disconnected from the production Hook policy until
its privacy and accuracy gates have passed.
"""

from hook_monitor.externality.envelope import (
    StaticExternalityResult,
    analyze_bash_externality,
    analyze_mcp_externality,
)
from hook_monitor.externality.models import (
    EXTERNALITY_ENVELOPE_SCHEMA_VERSION,
    ExternalityEnvelope,
    ExternalityVerdict,
)

__all__ = [
    "EXTERNALITY_ENVELOPE_SCHEMA_VERSION",
    "ExternalityEnvelope",
    "ExternalityVerdict",
    "StaticExternalityResult",
    "analyze_bash_externality",
    "analyze_mcp_externality",
]
