from __future__ import annotations

from pathlib import Path

from hook_monitor.analysis.chunking import build_source_chunks
from hook_monitor.runtime.models import ProtectedSource, SourceChunk
from hook_monitor.runtime.source_config import DEFAULT_CONFIG_PATH, load_protected_sources


def load_sources_and_chunks(
    repo_root: Path,
    config_path: Path | None = None,
    *,
    workspace_id: str | None = None,
) -> tuple[list[ProtectedSource], list[SourceChunk]]:
    # source 定義を読み、その場で chunk 一覧まで作る。
    # 後から protected source を追加して再解析する時の入口になる。
    config = config_path or (repo_root / DEFAULT_CONFIG_PATH)
    sources = load_protected_sources(config, workspace_id=workspace_id)
    chunks: list[SourceChunk] = []
    for source in sources:
        chunks.extend(build_source_chunks(repo_root, source))
    return sources, chunks
