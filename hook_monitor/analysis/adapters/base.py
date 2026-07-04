from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from hook_monitor.runtime.models import ArtifactContext, FlowEdge, ResourceVersion


@dataclass(frozen=True)
class AdapterResult:
    edges: tuple[FlowEdge, ...]
    resources: tuple[ResourceVersion, ...]


class ToolAdapter(Protocol):
    name: str

    def analyze(
        self,
        contexts: list[ArtifactContext],
        repo_root: Path,
    ) -> AdapterResult:
        ...
