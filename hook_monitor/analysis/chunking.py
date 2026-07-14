from __future__ import annotations

import hashlib
import json
from pathlib import Path

from hook_monitor.runtime.models import ProtectedSource, SourceChunk
from hook_monitor.runtime.ids import make_source_chunk_id
from hook_monitor.runtime.normalize import estimate_token_count, normalize_text
from hook_monitor.runtime.source_config import resolve_protected_source_path


def build_source_chunks(repo_root: Path, source: ProtectedSource) -> list[SourceChunk]:
    # protected source を読み、比較単位に分解して後段の比較器へ渡す。
    source_path = resolve_protected_source_path(repo_root, source.path)
    text = source_path.read_text(encoding="utf-8")

    chunks = _split_chunks(source_path, text)
    records: list[SourceChunk] = []
    for ordinal, chunk_text in enumerate(chunks):
        normalized = normalize_text(chunk_text)
        shingles = _make_shingles(normalized, size=5)
        records.append(
            SourceChunk(
                chunk_id=make_source_chunk_id(source.source_id, ordinal, chunk_text),
                source_id=source.source_id,
                ordinal=ordinal,
                text=chunk_text,
                normalized_text=normalized,
                text_hash=hashlib.sha256(chunk_text.encode("utf-8")).hexdigest(),
                shingle_fingerprint=json.dumps(shingles, ensure_ascii=False, sort_keys=True),
                token_count=estimate_token_count(normalized),
                workspace_id=source.workspace_id,
            )
        )
    return records


def _split_chunks(source_path: Path, text: str) -> list[str]:
    # コードは関数・class 単位、文章は段落単位で切る。
    # ここは後で source type ごとに分岐を増やせるようにしている。
    if source_path.suffix == ".py":
        return _split_python_like(text)
    return _split_paragraphs(text)


def _split_python_like(text: str) -> list[str]:
    # Python は def / class の境界を優先して chunk 化する。
    # 研究途中の実装方針や関数名がまとまって残るので、段落分割より追いやすい。
    lines = text.splitlines()
    chunks: list[str] = []
    current: list[str] = []
    for line in lines:
        if line.startswith("def ") or line.startswith("class "):
            if current:
                chunks.append("\n".join(current).strip())
                current = []
        current.append(line)
    if current:
        chunks.append("\n".join(current).strip())
    return [chunk for chunk in chunks if chunk]


def _split_paragraphs(text: str) -> list[str]:
    # Markdown やメモ類はまず段落単位で扱う。
    chunks = [chunk.strip() for chunk in text.split("\n\n")]
    return [chunk for chunk in chunks if chunk]


def _make_shingles(text: str, size: int) -> list[str]:
    # 類似度計算で使う 5-gram を前計算しておく。
    if len(text) < size:
        return [text] if text else []
    return sorted({text[index : index + size] for index in range(len(text) - size + 1)})
