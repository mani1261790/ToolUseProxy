from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from hook_monitor.analysis.chunking import build_source_chunks
from hook_monitor.runtime.models import ProtectedSource
from hook_monitor.runtime.source_config import (
    MAX_SOURCE_SELECTOR_VALUE_BYTES,
    MAX_SOURCE_SELECTOR_VALUES,
    SourceConfigError,
    load_protected_sources,
)


_UNSET = object()


class SourceSelectionContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name)
        self.manifest_path = self.workspace / "protected_sources.json"

    def test_schema_v2_dotenv_selector_emits_selected_values_in_file_order(
        self,
    ) -> None:
        first = "C.SELECTOR.DOTENV.FIRST"
        repeated = "C.SELECTOR.DOTENV.REPEATED"
        public = "C.SELECTOR.DOTENV.PUBLIC"
        third = "C.SELECTOR.DOTENV.THIRD"
        content = (
            f"ZETA_TOKEN={first}\n"
            f"PUBLIC_LABEL={public}\n"
            f"ZETA_TOKEN={repeated}\n"
            f'export ALPHA_TOKEN="{third}"\n'
        )
        source = self._load_source(
            path=".env.production",
            content=content,
            schema_version=2,
            selector={"dotenv_keys": ["ALPHA_TOKEN", "ZETA_TOKEN"]},
        )

        self.assertIsNotNone(source.selector)
        assert source.selector is not None
        self.assertEqual("dotenv_keys", source.selector.kind)
        self.assertCountEqual(
            ("ALPHA_TOKEN", "ZETA_TOKEN"),
            source.selector.values,
        )
        chunks = build_source_chunks(self.workspace, source)
        self.assertEqual(
            [first, repeated, third],
            [chunk.text for chunk in chunks],
        )

        reordered_source = self._load_source(
            path=".env.production",
            content=content,
            schema_version=2,
            selector={"dotenv_keys": ["ZETA_TOKEN", "ALPHA_TOKEN"]},
        )
        self.assertEqual(
            chunks,
            build_source_chunks(self.workspace, reordered_source),
        )

    def test_schema_v2_json_selector_supports_nested_arrays_and_pointer_escapes(
        self,
    ) -> None:
        nested = "C.SELECTOR.JSON.NESTED"
        array_scalar = "C.SELECTOR.JSON.ARRAY.SCALAR"
        array_nested = "C.SELECTOR.JSON.ARRAY.NESTED"
        slash = "C.SELECTOR.JSON.SLASH"
        tilde = "C.SELECTOR.JSON.TILDE"
        public = "C.SELECTOR.JSON.PUBLIC"
        content = json.dumps(
            {
                "public": public,
                "nested": {"token": nested},
                "items": [array_scalar, {"token": array_nested}],
                "path/key": slash,
                "tilde~key": tilde,
            }
        )
        selector_values = [
            "/tilde~0key",
            "/path~1key",
            "/items/1/token",
            "/items/0",
            "/nested/token",
        ]
        source = self._load_source(
            path="config/secrets.json",
            content=content,
            schema_version=2,
            selector={"json_pointers": selector_values},
        )

        self.assertIsNotNone(source.selector)
        assert source.selector is not None
        self.assertEqual("json_pointers", source.selector.kind)
        self.assertCountEqual(selector_values, source.selector.values)
        self.assertEqual(
            [nested, array_scalar, array_nested, slash, tilde],
            [chunk.text for chunk in build_source_chunks(self.workspace, source)],
        )

    def test_json_pointer_empty_string_selects_document_root(self) -> None:
        root_value = "C.SELECTOR.JSON.ROOT"
        source = self._load_source(
            path="root.json",
            content=json.dumps(root_value),
            schema_version=2,
            selector={"json_pointers": [""]},
        )

        self.assertEqual(
            [root_value],
            [chunk.text for chunk in build_source_chunks(self.workspace, source)],
        )

    def test_legacy_omitted_and_v1_manifests_continue_to_emit_all_values(
        self,
    ) -> None:
        cases = (
            (
                _UNSET,
                ".env",
                "FIRST=C.LEGACY.OMITTED.FIRST\nSECOND=C.LEGACY.OMITTED.SECOND\n",
                ["C.LEGACY.OMITTED.FIRST", "C.LEGACY.OMITTED.SECOND"],
            ),
            (
                1,
                "legacy.json",
                json.dumps(
                    {
                        "first": "C.LEGACY.V1.FIRST",
                        "nested": {"second": "C.LEGACY.V1.SECOND"},
                    }
                ),
                ["C.LEGACY.V1.FIRST", "C.LEGACY.V1.SECOND"],
            ),
            (
                2,
                ".env.local",
                "FIRST=C.V2.NO_SELECTOR.FIRST\nSECOND=C.V2.NO_SELECTOR.SECOND\n",
                ["C.V2.NO_SELECTOR.FIRST", "C.V2.NO_SELECTOR.SECOND"],
            ),
        )
        for schema_version, path, content, expected in cases:
            with self.subTest(schema_version=schema_version, path=path):
                source = self._load_source(
                    path=path,
                    content=content,
                    schema_version=schema_version,
                )

                self.assertIsNone(source.selector)
                self.assertEqual(
                    expected,
                    [
                        chunk.text
                        for chunk in build_source_chunks(self.workspace, source)
                    ],
                )

    def test_legacy_manifests_reject_selectors(self) -> None:
        secret = "C.REJECT.LEGACY.SELECTOR"
        for schema_version in (_UNSET, 1):
            with self.subTest(schema_version=schema_version):
                self._write_source(".env", f"TOKEN={secret}\n")
                self._write_manifest(
                    path=".env",
                    schema_version=schema_version,
                    selector={"dotenv_keys": ["TOKEN"]},
                )

                self._assert_load_rejected(secret)

    def test_selector_requires_exactly_one_known_kind(self) -> None:
        secret = "C.REJECT.SELECTOR.SHAPE"
        cases: tuple[object, ...] = (
            {},
            [],
            None,
            {"unknown": ["TOKEN"]},
            {
                "dotenv_keys": ["TOKEN"],
                "json_pointers": ["/token"],
            },
        )
        for selector in cases:
            with self.subTest(selector=selector):
                self._write_source(".env", f"TOKEN={secret}\n")
                self._write_manifest(
                    path=".env",
                    schema_version=2,
                    selector=selector,
                )

                self._assert_load_rejected(secret)

    def test_selector_values_reject_empty_duplicate_invalid_types_and_bounds(
        self,
    ) -> None:
        secret = "C.REJECT.SELECTOR.VALUES"
        cases: tuple[object, ...] = (
            {"dotenv_keys": []},
            {"dotenv_keys": [""]},
            {"dotenv_keys": ["NOT A KEY"]},
            {"dotenv_keys": ["TOKEN", "TOKEN"]},
            {"dotenv_keys": "TOKEN"},
            {"dotenv_keys": ["TOKEN", 7]},
            {"dotenv_keys": ["TOKEN", True]},
            {
                "dotenv_keys": [
                    f"KEY_{index}" for index in range(MAX_SOURCE_SELECTOR_VALUES + 1)
                ]
            },
            {
                "dotenv_keys": [
                    "K" * (MAX_SOURCE_SELECTOR_VALUE_BYTES + 1)
                ]
            },
        )
        for selector in cases:
            with self.subTest(selector_type=type(selector).__name__):
                self._write_source(".env", f"TOKEN={secret}\n")
                self._write_manifest(
                    path=".env",
                    schema_version=2,
                    selector=selector,
                )

                self._assert_load_rejected(secret)

    def test_selector_kind_path_and_source_type_must_match(self) -> None:
        secret = "C.REJECT.SELECTOR.MISMATCH"
        cases = (
            (
                "config/secrets.json",
                "secretfile",
                {"dotenv_keys": ["TOKEN"]},
            ),
            (
                ".env",
                "secretfile",
                {"json_pointers": ["/token"]},
            ),
            (
                ".env.json",
                "secretfile",
                {"json_pointers": ["/token"]},
            ),
            (
                ".env",
                "unpublished_impl",
                {"dotenv_keys": ["TOKEN"]},
            ),
        )
        for path, source_type, selector in cases:
            with self.subTest(path=path, source_type=source_type):
                self._write_source(path, f"TOKEN={secret}\n")
                self._write_manifest(
                    path=path,
                    source_type=source_type,
                    schema_version=2,
                    selector=selector,
                )

                self._assert_load_rejected(secret)

    def test_json_pointer_rejects_invalid_rfc_6901_syntax(self) -> None:
        secret = "C.REJECT.INVALID.POINTER"
        for pointer in (
            f"{secret}-without-leading-slash",
            f"/{secret}~",
            f"/{secret}~2value",
        ):
            with self.subTest(pointer=pointer):
                self._write_source(
                    "config/secrets.json",
                    json.dumps({"token": secret}),
                )
                self._write_manifest(
                    path="config/secrets.json",
                    schema_version=2,
                    selector={"json_pointers": [pointer]},
                )

                self._assert_load_rejected(secret)

    def test_selected_targets_must_exist_and_be_nonempty_strings(self) -> None:
        file_secret = "C.REJECT.SELECTED.TARGET.FILE"
        cases = (
            (
                ".env",
                f"TOKEN={file_secret}\nEMPTY=\n",
                {"dotenv_keys": ["MISSING"]},
            ),
            (
                ".env",
                f"TOKEN={file_secret}\nEMPTY=\n",
                {"dotenv_keys": ["EMPTY"]},
            ),
            (
                "config/secrets.json",
                json.dumps({"token": file_secret}),
                {"json_pointers": ["/missing"]},
            ),
            (
                "config/secrets.json",
                json.dumps({"token": file_secret, "empty": "   "}),
                {"json_pointers": ["/empty"]},
            ),
            (
                "config/secrets.json",
                json.dumps({"token": file_secret, "number": 42}),
                {"json_pointers": ["/number"]},
            ),
            (
                "config/secrets.json",
                json.dumps(
                    {"token": file_secret, "object": {"child": "public"}}
                ),
                {"json_pointers": ["/object"]},
            ),
        )
        for path, content, selector in cases:
            with self.subTest(path=path, selector=selector):
                source = self._load_source(
                    path=path,
                    content=content,
                    schema_version=2,
                    selector=selector,
                )

                self._assert_build_rejected(source, file_secret)

    def test_selected_malformed_files_fail_without_legacy_fallback(self) -> None:
        dotenv_secret = "C.REJECT.MALFORMED.DOTENV"
        json_secret = "C.REJECT.MALFORMED.JSON"
        cases = (
            (
                ".env",
                f'TOKEN="{dotenv_secret}\n',
                {"dotenv_keys": ["TOKEN"]},
                dotenv_secret,
            ),
            (
                "config/secrets.json",
                f'{{"token":"{json_secret}"',
                {"json_pointers": ["/token"]},
                json_secret,
            ),
        )
        for path, content, selector, secret in cases:
            with self.subTest(path=path):
                source = self._load_source(
                    path=path,
                    content=content,
                    schema_version=2,
                    selector=selector,
                )

                self._assert_build_rejected(source, secret)

    def _load_source(
        self,
        *,
        path: str,
        content: str,
        schema_version: object = _UNSET,
        selector: object = _UNSET,
        source_type: str = "secretfile",
    ) -> ProtectedSource:
        self._write_source(path, content)
        self._write_manifest(
            path=path,
            schema_version=schema_version,
            selector=selector,
            source_type=source_type,
        )
        sources = load_protected_sources(
            self.manifest_path,
            workspace_id="ws_v1_source_selection_contract",
        )
        self.assertEqual(1, len(sources))
        return sources[0]

    def _write_source(self, path: str, content: str) -> None:
        source_path = self.workspace / path
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_text(content, encoding="utf-8")

    def _write_manifest(
        self,
        *,
        path: str,
        schema_version: object = _UNSET,
        selector: object = _UNSET,
        source_type: str = "secretfile",
    ) -> None:
        source: dict[str, Any] = {
            "id": "selected-source",
            "path": path,
            "type": source_type,
            "sensitivity": "high",
            "policy_tags": ["no_external"],
        }
        if selector is not _UNSET:
            source["selector"] = selector
        manifest: dict[str, Any] = {"sources": [source]}
        if schema_version is not _UNSET:
            manifest["schema_version"] = schema_version
        self.manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False),
            encoding="utf-8",
        )

    def _assert_load_rejected(self, *forbidden_values: str) -> None:
        with self.assertRaises(SourceConfigError) as raised:
            load_protected_sources(self.manifest_path)
        self._assert_values_absent(raised.exception, forbidden_values)

    def _assert_build_rejected(
        self,
        source: ProtectedSource,
        *forbidden_values: str,
    ) -> None:
        with self.assertRaises(SourceConfigError) as raised:
            build_source_chunks(self.workspace, source)
        self._assert_values_absent(raised.exception, forbidden_values)

    def _assert_values_absent(
        self,
        error: BaseException,
        forbidden_values: tuple[str, ...],
    ) -> None:
        rendered = f"{error!s}\n{error!r}"
        for value in forbidden_values:
            self.assertNotIn(value, rendered)


if __name__ == "__main__":
    unittest.main()
