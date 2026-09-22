from __future__ import annotations

import json
import re
from typing import Any


def stringify_content(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)


def normalize_text(text: str) -> str:
    lowered = text.casefold()
    collapsed = re.sub(r"\s+", " ", lowered)
    return collapsed.strip()


def estimate_token_count(text: str) -> int:
    if not text:
        return 0
    return len(text.split())
