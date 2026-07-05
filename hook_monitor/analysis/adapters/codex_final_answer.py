from __future__ import annotations

from pathlib import Path

from hook_monitor.analysis.adapters.base import AdapterResult
from hook_monitor.analysis.adapters.common import make_sink_candidate, make_submitted_to_edge
from hook_monitor.runtime.models import ArtifactContext, FlowEdge, SinkCandidate


class CodexFinalAnswerAdapter:
    """Codex Stop hookの最終応答をfinal_answer sink candidateへ変換する。"""

    name = "codex_final_answer"

    def analyze(
        self,
        contexts: list[ArtifactContext],
        repo_root: Path,
    ) -> AdapterResult:
        del repo_root
        edges: list[FlowEdge] = []
        sinks: dict[str, SinkCandidate] = {}

        for context in _select_final_answer_contexts(contexts):
            sink = make_sink_candidate(
                sink_type="final_answer",
                label="Codex final answer",
                context=context,
                metadata={
                    "adapter": self.name,
                    "final_answer_fragment_id": context.fragment.fragment_id,
                    "final_answer_json_pointer": context.fragment.json_pointer,
                    "event_id": context.event_id,
                },
            )
            sinks[sink.node_id] = sink
            edges.append(
                make_submitted_to_edge(
                    src_id=context.fragment.fragment_id,
                    sink_id=sink.node_id,
                    method="codex_final_answer",
                    reason="Codex Stop hook final answer is shown to the user",
                )
            )

        return AdapterResult(tuple(edges), (), tuple(sinks.values()))


def _select_final_answer_contexts(contexts: list[ArtifactContext]) -> list[ArtifactContext]:
    candidates = [
        context
        for context in contexts
        if context.phase == "stop"
        and context.artifact_role == "final_answer"
        and context.fragment.semantic_role == "final_answer"
    ]
    leaves = [context for context in candidates if context.fragment.json_pointer != "/"]
    return sorted(leaves or candidates, key=lambda context: context.fragment.fragment_id)
