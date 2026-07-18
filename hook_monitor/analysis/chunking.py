from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator
from pathlib import Path

from hook_monitor.runtime.models import ProtectedSource, ProtectedSourceSelector, SourceChunk
from hook_monitor.runtime.ids import make_source_chunk_id
from hook_monitor.runtime.normalize import estimate_token_count, normalize_text
from hook_monitor.runtime.source_config import SourceConfigError, resolve_protected_source_path


SOURCE_CHUNKER_VERSION = "source-chunker-v3-secret-selectors"
_DOTENV_ASSIGNMENT = re.compile(
    r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=(.*)$"
)


def build_source_chunks(repo_root: Path, source: ProtectedSource) -> list[SourceChunk]:
    # protected source を読み、比較単位に分解して後段の比較器へ渡す。
    source_path = resolve_protected_source_path(repo_root, source.path)
    text = source_path.read_text(encoding="utf-8")

    chunks = _split_chunks(source_path, text, source)
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


def _split_chunks(
    source_path: Path,
    text: str,
    source: ProtectedSource,
) -> list[str]:
    # secret fileはkeyや構文wrapperをsource本文として扱わず、送信され得る
    # decoded valueを比較単位にする。解釈できない形式は従来の段落単位へ
    # fail-safeし、parserの不完全さによって保護対象を消さない。
    if source.source_type == "secretfile" and _is_dotenv_path(source_path):
        values = _split_dotenv_values(text, source.selector)
        if values is None:
            if source.selector is not None:
                raise SourceConfigError(
                    "selected dotenv source is not statically parseable"
                )
            return _split_paragraphs(text)
        return values
    if (
        source.source_type == "secretfile"
        and source_path.suffix.casefold() == ".json"
    ):
        values = _split_json_string_values(text, source.selector)
        if values is None:
            if source.selector is not None:
                raise SourceConfigError("selected JSON source is not valid JSON")
            return _split_paragraphs(text)
        return values
    if source.selector is not None:
        raise SourceConfigError(
            "source selector does not match a supported secretfile format"
        )

    # コードは関数・class 単位、文章は段落単位で切る。
    if source_path.suffix == ".py":
        return _split_python_like(text)
    return _split_paragraphs(text)


def _is_dotenv_path(source_path: Path) -> bool:
    name = source_path.name.casefold()
    return name == ".env" or name.startswith(".env.")


def _split_dotenv_values(
    text: str,
    selector: ProtectedSourceSelector | None,
) -> list[str] | None:
    if selector is not None and selector.kind != "dotenv_keys":
        raise SourceConfigError("dotenv source requires selector.dotenv_keys")
    selected = None if selector is None else frozenset(selector.values)
    resolved: set[str] = set()
    values: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _DOTENV_ASSIGNMENT.fullmatch(line)
        if match is None:
            return None
        key = match.group(1)
        value = _parse_dotenv_value(match.group(2))
        if value is None:
            return None
        if value.strip() and (selected is None or key in selected):
            values.append(value)
            resolved.add(key)
    if selected is not None and resolved != selected:
        raise SourceConfigError(
            "selector.dotenv_keys contains a missing or empty key"
        )
    return values


def _parse_dotenv_value(raw_value: str) -> str | None:
    value = raw_value.lstrip()
    if not value:
        return ""
    if value[0] == "'":
        closing = value.find("'", 1)
        if closing < 0 or not _valid_dotenv_trailing(value[closing + 1 :]):
            return None
        return value[1:closing]
    if value[0] == '"':
        decoded: list[str] = []
        escaped = False
        closing: int | None = None
        for index, character in enumerate(value[1:], start=1):
            if escaped:
                decoded.append(
                    {
                        "n": "\n",
                        "r": "\r",
                        "t": "\t",
                        '"': '"',
                        "\\": "\\",
                    }.get(character, f"\\{character}")
                )
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                closing = index
                break
            else:
                decoded.append(character)
        if escaped or closing is None:
            return None
        if not _valid_dotenv_trailing(value[closing + 1 :]):
            return None
        return "".join(decoded)
    if "\\" in value or "'" in value or '"' in value:
        return None
    return _strip_dotenv_inline_comment(value).rstrip()


def _valid_dotenv_trailing(trailing: str) -> bool:
    stripped = trailing.strip()
    return not stripped or stripped.startswith("#")


def _strip_dotenv_inline_comment(value: str) -> str:
    for index, character in enumerate(value):
        if character == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index]
    return value


def _split_json_string_values(
    text: str,
    selector: ProtectedSourceSelector | None,
) -> list[str] | None:
    if selector is not None and selector.kind != "json_pointers":
        raise SourceConfigError("JSON source requires selector.json_pointers")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None

    selected = None if selector is None else frozenset(selector.values)
    values: list[str] = []
    resolved: set[str] = set()
    for pointer, value in _walk_json_nodes(payload):
        if selected is None:
            if isinstance(value, str) and value.strip():
                values.append(value)
            continue
        if pointer not in selected:
            continue
        if not isinstance(value, str) or not value.strip():
            raise SourceConfigError(
                "selector.json_pointers must resolve to non-empty string values"
            )
        values.append(value)
        resolved.add(pointer)
    if selected is not None and resolved != selected:
        raise SourceConfigError("selector.json_pointers contains a missing pointer")
    return values


def _walk_json_nodes(
    value: object,
    pointer: str = "",
) -> Iterator[tuple[str, object]]:
    yield pointer, value
    if isinstance(value, dict):
        for key, child in value.items():
            child_pointer = f"{pointer}/{_escape_json_pointer_segment(str(key))}"
            yield from _walk_json_nodes(child, child_pointer)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_json_nodes(child, f"{pointer}/{index}")


def _escape_json_pointer_segment(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


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
