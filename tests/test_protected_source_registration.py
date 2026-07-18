from __future__ import annotations

import hashlib
import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from hook_monitor.analysis.source_index import load_sources_and_chunks
from hook_monitor.runtime.source_config import CURRENT_MANIFEST_SCHEMA_VERSION
from hook_monitor.runtime.storage import EventStore
from hook_monitor.runtime.workspace import resolve_workspace
from tooluseproxy import protected_sources as protected_source_registration
from tooluseproxy.cli import (
    _ProtectCliError,
    _approve_protected_source_candidate,
    _review_protected_source_candidate,
    _suggest_protected_sources,
    main as cli_main,
)
from tooluseproxy.protected_sources import (
    MAX_MANIFEST_SOURCES,
    ProtectedSourceRegistrationError,
    approve_protected_source,
    suggest_protected_source,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
MAX_DISCOVERY_FILE_BYTES = 1024 * 1024


class ProtectedSourceRegistrationCoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary_directory.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self._write_manifest({"schema_version": 2, "sources": []})

    def tearDown(self) -> None:
        self._temporary_directory.cleanup()

    @property
    def manifest_path(self) -> Path:
        return self.workspace / "protected_sources.json"

    def _write_manifest(self, payload: dict[str, object]) -> None:
        self.manifest_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def test_core_accepts_an_approving_candidate_storage_record(self) -> None:
        source = self.workspace / ".env.approving"
        source.write_text(
            "PRIVATE_TOKEN=APPROVING.STATUS.SECRET.4a32\n",
            encoding="utf-8",
        )
        candidate = suggest_protected_source(
            self.workspace,
            source.name,
            workspace_id="core-approving-test",
        )
        self.assertIsNotNone(candidate.candidate_revision)
        storage_record = candidate.to_storage_record()
        storage_record.update(
            {
                "candidate_id": "a" * 32,
                "status": "approving",
            }
        )

        result = approve_protected_source(
            self.workspace,
            storage_record,
            candidate_revision=candidate.candidate_revision,
            expected_manifest_sha256=candidate.manifest_sha256,
        )

        self.assertEqual("approved", result.status)
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual([source.name], [entry["path"] for entry in manifest["sources"]])

    def test_approval_rejects_appending_after_the_manifest_source_limit(self) -> None:
        sources: list[dict[str, object]] = []
        for index in range(MAX_MANIFEST_SOURCES):
            path = f".env.existing-{index}"
            (self.workspace / path).write_text(
                f"PRIVATE_TOKEN=EXISTING.{index}.SECRET\n",
                encoding="utf-8",
            )
            sources.append(
                {
                    "id": f"existing_{index}",
                    "path": path,
                    "type": "secretfile",
                    "sensitivity": "high",
                    "selector": {"dotenv_keys": ["PRIVATE_TOKEN"]},
                }
            )
        self._write_manifest({"schema_version": 2, "sources": sources})
        candidate_path = ".env.limit-candidate"
        (self.workspace / candidate_path).write_text(
            "PRIVATE_TOKEN=LIMIT.CANDIDATE.SECRET.8c21\n",
            encoding="utf-8",
        )
        candidate = suggest_protected_source(
            self.workspace,
            candidate_path,
            workspace_id="core-source-limit-test",
        )
        candidate = replace(candidate, candidate_id="b" * 32)
        manifest_before = self.manifest_path.read_bytes()

        with self.assertRaises(ProtectedSourceRegistrationError) as raised:
            approve_protected_source(
                self.workspace,
                candidate,
                candidate_revision=candidate.candidate_revision,
                expected_manifest_sha256=candidate.manifest_sha256,
            )

        self.assertEqual("manifest_too_many_sources", raised.exception.code)
        self.assertEqual(manifest_before, self.manifest_path.read_bytes())


class ProtectedSourceRegistrationCliTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary_directory.name)
        self.workspace = self.root / "workspace"
        self.data_dir = self.root / "data"
        self.workspace.mkdir()
        exit_code, payload, stderr = self._run_json(
            "init",
            "--workspace",
            str(self.workspace),
            "--data-dir",
            str(self.data_dir),
            "--json",
        )
        self.assertEqual(0, exit_code, stderr)
        self.assertEqual("initialized", payload["status"])

    def tearDown(self) -> None:
        self._temporary_directory.cleanup()

    @property
    def manifest_path(self) -> Path:
        return self.workspace / "protected_sources.json"

    def _run_json(self, *arguments: str) -> tuple[int, dict[str, object], str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = cli_main(list(arguments))
        raw_stdout = stdout.getvalue()
        payload = json.loads(raw_stdout) if raw_stdout else {}
        self.assertIsInstance(payload, dict)
        return exit_code, payload, stderr.getvalue()

    def _protect_arguments(self, action: str, *arguments: str) -> tuple[str, ...]:
        return (
            "protect",
            action,
            *arguments,
            "--workspace",
            str(self.workspace),
            "--data-dir",
            str(self.data_dir),
            "--json",
        )

    def _suggest(self, relative_path: str) -> tuple[dict[str, object], str]:
        exit_code, payload, stderr = self._run_json(
            *self._protect_arguments("suggest", "--path", relative_path)
        )
        self.assertEqual(0, exit_code, stderr)
        return payload, stderr

    def _single_candidate(self, payload: dict[str, object]) -> dict[str, object]:
        self.assertEqual(1, payload["schema_version"])
        self.assertEqual("review_required", payload["status"])
        self.assertIs(payload["scan_complete"], True)
        candidates = payload["candidates"]
        self.assertIsInstance(candidates, list)
        self.assertEqual(1, len(candidates))
        candidate = candidates[0]
        self.assertIsInstance(candidate, dict)
        self.assertIs(candidate["review_required"], True)
        self.assertTrue(candidate["candidate_id"])
        self.assertTrue(candidate["candidate_revision"])
        self.assertIsInstance(candidate["reason_codes"], list)
        self.assertTrue(candidate["reason_codes"])
        self.assertIsInstance(candidate["confidence"], (int, float))
        return candidate

    def _approve(
        self,
        payload: dict[str, object],
        candidate: dict[str, object],
    ) -> tuple[int, dict[str, object], str]:
        return self._run_json(
            *self._protect_arguments(
                "approve",
                str(candidate["candidate_id"]),
                "--candidate-revision",
                str(candidate["candidate_revision"]),
                "--expected-manifest-sha256",
                str(payload["manifest_sha256"]),
            )
        )

    def _review(
        self,
        action: str,
        candidate: dict[str, object],
    ) -> tuple[int, dict[str, object], str]:
        return self._run_json(
            *self._protect_arguments(
                action,
                str(candidate["candidate_id"]),
                "--candidate-revision",
                str(candidate["candidate_revision"]),
            )
        )

    def _database_text(self) -> tuple[str, set[str]]:
        values: list[str] = []
        column_names: set[str] = set()
        with sqlite3.connect(self.data_dir / "events.db") as conn:
            tables = conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            for (table_name,) in tables:
                columns = conn.execute(f'PRAGMA table_info("{table_name}")').fetchall()
                names = [str(row[1]) for row in columns]
                column_names.update(names)
                if not names:
                    continue
                quoted = ", ".join(f'"{name}"' for name in names)
                for row in conn.execute(f'SELECT {quoted} FROM "{table_name}"'):
                    values.extend(str(value) for value in row if value is not None)
        return "\n".join(values), column_names

    def _write_manifest(self, payload: dict[str, object]) -> None:
        self.manifest_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def test_dotenv_suggest_is_value_free_and_requires_explicit_approval(self) -> None:
        secret = "DOTENV.REGISTRATION.SECRET.7a1d"
        source = self.workspace / ".env"
        source.write_text(
            f"PUBLIC_URL=https://example.invalid\nPRIVATE_TOKEN={secret}\n",
            encoding="utf-8",
        )
        manifest_before = self.manifest_path.read_bytes()

        payload, stderr = self._suggest(".env")
        candidate = self._single_candidate(payload)

        self.assertEqual(manifest_before, self.manifest_path.read_bytes())
        self.assertEqual(".env", candidate["path"])
        self.assertEqual(
            {"dotenv_keys": ["PRIVATE_TOKEN"]},
            candidate["proposed_source"]["selector"],
        )
        self.assertNotIn("PUBLIC_URL", candidate["proposed_source"]["selector"])
        rendered = json.dumps(payload, ensure_ascii=False)
        source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
        self.assertNotIn(secret, rendered)
        self.assertNotIn(secret, stderr)
        self.assertNotIn(str(self.workspace.resolve()), rendered)
        self.assertNotIn(source_sha256, rendered)
        self.assertNotEqual(source_sha256, candidate["candidate_revision"])
        self.assertFalse(
            {"source_sha256", "content_sha256", "source_hash", "content_hash"}
            & set(candidate)
        )

        database_text, column_names = self._database_text()
        self.assertNotIn(secret, database_text)
        self.assertNotIn(str(candidate["candidate_revision"]), database_text)
        self.assertNotIn("candidate_revision", column_names)

    def test_dotenv_approval_registers_only_the_selected_value(self) -> None:
        secret = "DOTENV.APPROVAL.SECRET.40bb"
        (self.workspace / ".env.local").write_text(
            f"PRIVATE_TOKEN={secret}\nPUBLIC_URL=https://example.invalid\n",
            encoding="utf-8",
        )
        suggestion, _ = self._suggest(".env.local")
        candidate = self._single_candidate(suggestion)

        exit_code, approved, stderr = self._approve(suggestion, candidate)

        self.assertEqual(0, exit_code, stderr)
        self.assertEqual(1, approved["schema_version"])
        self.assertEqual("approved", approved["status"])
        self.assertEqual(candidate["candidate_id"], approved["candidate_id"])
        self.assertTrue(approved["source_id"])
        self.assertEqual(
            hashlib.sha256(self.manifest_path.read_bytes()).hexdigest(),
            approved["manifest_sha256"],
        )
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(CURRENT_MANIFEST_SCHEMA_VERSION, manifest["schema_version"])
        self.assertEqual(1, len(manifest["sources"]))
        source = manifest["sources"][0]
        self.assertEqual(".env.local", source["path"])
        self.assertEqual("secretfile", source["type"])
        self.assertEqual({"dotenv_keys": ["PRIVATE_TOKEN"]}, source["selector"])
        loaded_sources, loaded_chunks = load_sources_and_chunks(
            self.workspace,
            self.manifest_path,
        )
        self.assertEqual(1, len(loaded_sources))
        self.assertEqual([secret], [chunk.text for chunk in loaded_chunks])
        doctor_code, doctor, doctor_stderr = self._run_json(
            "doctor",
            "--workspace",
            str(self.workspace),
            "--data-dir",
            str(self.data_dir),
            "--json",
        )
        self.assertEqual(0, doctor_code, doctor_stderr)
        self.assertEqual("ok", doctor["status"])
        rendered = json.dumps(approved, ensure_ascii=False)
        database_text, _ = self._database_text()
        self.assertNotIn(secret, rendered)
        self.assertNotIn(secret, stderr)
        self.assertNotIn(secret, database_text)

    def test_nested_json_approval_uses_rfc_6901_pointers_without_values(self) -> None:
        secret = "JSON.REGISTRATION.SECRET.11a0"
        source_payload = {
            "service": {
                "api_key": secret,
                "public_url": "https://example.invalid",
            },
            "private/token": secret + ".second",
        }
        (self.workspace / "secrets.json").write_text(
            json.dumps(source_payload),
            encoding="utf-8",
        )

        suggestion, stderr = self._suggest("secrets.json")
        candidate = self._single_candidate(suggestion)
        proposed = candidate["proposed_source"]
        self.assertEqual("secrets.json", candidate["path"])
        self.assertEqual(
            ["/private~1token", "/service/api_key"],
            proposed["selector"]["json_pointers"],
        )
        self.assertNotIn(secret, json.dumps(suggestion, ensure_ascii=False))
        self.assertNotIn(secret, stderr)

        exit_code, approved, stderr = self._approve(suggestion, candidate)
        self.assertEqual(0, exit_code, stderr)
        self.assertEqual("approved", approved["status"])
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(proposed["selector"], manifest["sources"][0]["selector"])
        database_text, _ = self._database_text()
        self.assertNotIn(secret, database_text)
        self.assertNotIn(secret + ".second", database_text)

    def test_json_arrays_pointer_escaping_and_exported_dotenv_are_supported(self) -> None:
        json_secret = "JSON.ARRAY.SECRET.21c8"
        (self.workspace / "credentials.json").write_text(
            json.dumps(
                {
                    "accounts": [{"access_key": json_secret}],
                    "private~group": {"token": json_secret + ".second"},
                }
            ),
            encoding="utf-8",
        )
        json_suggestion, _ = self._suggest("credentials.json")
        json_candidate = self._single_candidate(json_suggestion)
        self.assertEqual(
            ["/accounts/0/access_key", "/private~0group/token"],
            json_candidate["proposed_source"]["selector"]["json_pointers"],
        )

        dotenv_secret = "DOTENV.QUOTED.SECRET.7ea2"
        (self.workspace / ".env.quoted").write_text(
            f'export PRIVATE_TOKEN="{dotenv_secret}"\nPUBLIC_MODE=demo\n',
            encoding="utf-8",
        )
        dotenv_suggestion, _ = self._suggest(".env.quoted")
        dotenv_candidate = self._single_candidate(dotenv_suggestion)
        self.assertEqual(
            {"dotenv_keys": ["PRIVATE_TOKEN"]},
            dotenv_candidate["proposed_source"]["selector"],
        )
        rendered = json.dumps(
            [json_suggestion, dotenv_suggestion],
            ensure_ascii=False,
        )
        self.assertNotIn(json_secret, rendered)
        self.assertNotIn(dotenv_secret, rendered)

    def test_duplicate_source_keys_and_overdeep_json_are_rejected(self) -> None:
        duplicate_secret = "DUPLICATE.KEY.SECRET.5af2"
        (self.workspace / ".env.duplicate").write_text(
            f"PRIVATE_TOKEN={duplicate_secret}\nPRIVATE_TOKEN={duplicate_secret}.two\n",
            encoding="utf-8",
        )
        nested: object = {"token": "DEEP.JSON.SECRET.4d19"}
        for _ in range(34):
            nested = {"private": nested}
        (self.workspace / "deep.json").write_text(
            json.dumps(nested),
            encoding="utf-8",
        )

        for source_path, expected_code, secret in (
            (".env.duplicate", "dotenv_duplicate_key", duplicate_secret),
            ("deep.json", "json_too_deep", "DEEP.JSON.SECRET.4d19"),
        ):
            with self.subTest(source_path=source_path):
                exit_code, payload, stderr = self._run_json(
                    *self._protect_arguments("suggest", "--path", source_path)
                )
                self.assertEqual(1, exit_code)
                self.assertEqual({}, payload)
                self.assertIn(expected_code, stderr)
                self.assertNotIn(secret, stderr)

    def test_reject_and_ignore_suppress_an_unchanged_candidate(self) -> None:
        for action, terminal_status in (("reject", "rejected"), ("ignore", "ignored")):
            with self.subTest(action=action):
                source_path = f".env.{action}"
                (self.workspace / source_path).write_text(
                    f"PRIVATE_TOKEN={action.upper()}.SECRET.33a1\n",
                    encoding="utf-8",
                )
                suggestion, _ = self._suggest(source_path)
                candidate = self._single_candidate(suggestion)

                exit_code, reviewed, stderr = self._review(action, candidate)
                self.assertEqual(0, exit_code, stderr)
                self.assertEqual(1, reviewed["schema_version"])
                self.assertEqual(terminal_status, reviewed["status"])
                self.assertEqual(candidate["candidate_id"], reviewed["candidate_id"])

                exit_code, repeated, stderr = self._run_json(
                    *self._protect_arguments("suggest", "--path", source_path)
                )
                self.assertEqual(0, exit_code, stderr)
                self.assertEqual("suppressed", repeated["status"])
                self.assertEqual([], repeated["candidates"])
                self.assertIs(repeated["scan_complete"], True)

    def test_approval_rejects_wrong_revision_and_manifest_precondition(self) -> None:
        (self.workspace / ".env").write_text(
            "PRIVATE_TOKEN=PRECONDITION.SECRET.55d0\n",
            encoding="utf-8",
        )
        suggestion, _ = self._suggest(".env")
        candidate = self._single_candidate(suggestion)
        manifest_before = self.manifest_path.read_bytes()

        exit_code, _, stderr = self._run_json(
            *self._protect_arguments(
                "approve",
                str(candidate["candidate_id"]),
                "--candidate-revision",
                "0" * 64,
                "--expected-manifest-sha256",
                str(suggestion["manifest_sha256"]),
            )
        )
        self.assertEqual(1, exit_code)
        self.assertNotIn("PRECONDITION.SECRET.55d0", stderr)
        self.assertEqual(manifest_before, self.manifest_path.read_bytes())

        concurrent = json.loads(manifest_before)
        concurrent["concurrent_editor"] = True
        self._write_manifest(concurrent)
        concurrent_bytes = self.manifest_path.read_bytes()
        exit_code, _, stderr = self._approve(suggestion, candidate)
        self.assertEqual(1, exit_code)
        self.assertNotIn("PRECONDITION.SECRET.55d0", stderr)
        self.assertEqual(concurrent_bytes, self.manifest_path.read_bytes())

    def test_approval_rejects_a_stale_or_replaced_source(self) -> None:
        for replacement in ("changed", "symlink"):
            with self.subTest(replacement=replacement):
                path = self.workspace / f".env.{replacement}"
                secret = f"STALE.{replacement}.SECRET.91a0"
                path.write_text(f"PRIVATE_TOKEN={secret}\n", encoding="utf-8")
                suggestion, _ = self._suggest(path.name)
                candidate = self._single_candidate(suggestion)
                manifest_before = self.manifest_path.read_bytes()
                if replacement == "changed":
                    path.write_text("PUBLIC_URL=https://example.invalid\n", encoding="utf-8")
                else:
                    target = self.workspace / "replacement.env"
                    target.write_text(f"PRIVATE_TOKEN={secret}\n", encoding="utf-8")
                    path.unlink()
                    path.symlink_to(target)

                exit_code, _, stderr = self._approve(suggestion, candidate)
                self.assertEqual(1, exit_code)
                self.assertNotIn(secret, stderr)
                self.assertEqual(manifest_before, self.manifest_path.read_bytes())

    def test_suggest_rejects_outside_symlink_and_oversize_sources(self) -> None:
        outside_secret = "OUTSIDE.SECRET.6cd2"
        outside = self.root / ".env.outside"
        outside.write_text(f"PRIVATE_TOKEN={outside_secret}\n", encoding="utf-8")
        symlink_secret = "SYMLINK.SECRET.9ab0"
        symlink_target = self.workspace / ".env.target"
        symlink_target.write_text(f"PRIVATE_TOKEN={symlink_secret}\n", encoding="utf-8")
        (self.workspace / ".env.link").symlink_to(symlink_target)
        oversize_secret = "OVERSIZE.SECRET.0f8b"
        (self.workspace / ".env.large").write_text(
            f"PRIVATE_TOKEN={oversize_secret}\n"
            + "X" * (MAX_DISCOVERY_FILE_BYTES + 1),
            encoding="utf-8",
        )
        manifest_before = self.manifest_path.read_bytes()

        cases = (
            ("../.env.outside", outside_secret),
            (".env.link", symlink_secret),
            (".env.large", oversize_secret),
        )
        for source_path, secret in cases:
            with self.subTest(source_path=source_path):
                exit_code, payload, stderr = self._run_json(
                    *self._protect_arguments("suggest", "--path", source_path)
                )
                self.assertEqual(1, exit_code)
                self.assertEqual({}, payload)
                self.assertNotIn(secret, stderr)
                self.assertNotIn(str(outside.resolve()), stderr)
                self.assertEqual(manifest_before, self.manifest_path.read_bytes())

    @unittest.skipIf(os.name == "nt", "POSIX link and FIFO safety test")
    def test_suggest_rejects_hardlinks_directory_symlinks_and_fifos(self) -> None:
        secret = "SPECIAL.FILE.SECRET.f251"
        original = self.workspace / ".env.original"
        original.write_text(f"PRIVATE_TOKEN={secret}\n", encoding="utf-8")
        os.link(original, self.workspace / ".env.hardlink")
        real_directory = self.workspace / "real"
        real_directory.mkdir()
        (real_directory / ".env").write_text(
            f"PRIVATE_TOKEN={secret}\n",
            encoding="utf-8",
        )
        (self.workspace / "linked").symlink_to(real_directory, target_is_directory=True)
        os.mkfifo(self.workspace / ".env.pipe")

        for source_path in (".env.hardlink", "linked/.env", ".env.pipe"):
            with self.subTest(source_path=source_path):
                exit_code, payload, stderr = self._run_json(
                    *self._protect_arguments("suggest", "--path", source_path)
                )
                self.assertEqual(1, exit_code)
                self.assertEqual({}, payload)
                self.assertIn("source_not_safe", stderr)
                self.assertNotIn(secret, stderr)

    def test_legacy_invalid_duplicate_and_symlink_manifests_are_rejected(self) -> None:
        secret = "MANIFEST.REJECTION.SECRET.d733"
        (self.workspace / ".env").write_text(
            f"PRIVATE_TOKEN={secret}\n",
            encoding="utf-8",
        )
        manifests: tuple[tuple[str, bytes], ...] = (
            (
                "legacy",
                json.dumps({"schema_version": 1, "sources": []}).encode(),
            ),
            ("invalid", b"{not-json"),
            (
                "duplicate",
                json.dumps(
                    {
                        "schema_version": 2,
                        "sources": [
                            {
                                "id": "duplicate",
                                "path": ".env",
                                "type": "secretfile",
                                "sensitivity": "high",
                                "selector": {"dotenv_keys": ["PRIVATE_TOKEN"]},
                            },
                            {
                                "id": "duplicate",
                                "path": ".env",
                                "type": "secretfile",
                                "sensitivity": "high",
                                "selector": {"dotenv_keys": ["PRIVATE_TOKEN"]},
                            },
                        ],
                    }
                ).encode(),
            ),
            (
                "duplicate-json-key",
                b'{"schema_version":2,"sources":[],"sources":[]}',
            ),
        )
        for name, contents in manifests:
            with self.subTest(manifest=name):
                self.manifest_path.write_bytes(contents)
                exit_code, payload, stderr = self._run_json(
                    *self._protect_arguments("suggest", "--path", ".env")
                )
                self.assertEqual(1, exit_code)
                self.assertEqual({}, payload)
                self.assertNotIn(secret, stderr)
                self.assertEqual(contents, self.manifest_path.read_bytes())

        target = self.root / "outside-manifest.json"
        target.write_text(
            json.dumps({"schema_version": 2, "sources": []}),
            encoding="utf-8",
        )
        self.manifest_path.unlink()
        self.manifest_path.symlink_to(target)
        target_before = target.read_bytes()
        exit_code, payload, stderr = self._run_json(
            *self._protect_arguments("suggest", "--path", ".env")
        )
        self.assertEqual(1, exit_code)
        self.assertEqual({}, payload)
        self.assertNotIn(secret, stderr)
        self.assertEqual(target_before, target.read_bytes())

    def test_approval_is_atomic_and_cleans_up_a_failed_temporary_file(self) -> None:
        secret = "ATOMIC.ROLLBACK.SECRET.c431"
        (self.workspace / ".env").write_text(
            f"PRIVATE_TOKEN={secret}\n",
            encoding="utf-8",
        )
        suggestion, _ = self._suggest(".env")
        candidate = self._single_candidate(suggestion)
        manifest_before = self.manifest_path.read_bytes()

        failures = (
            ("short_write", "tooluseproxy.protected_sources.os.write", {"return_value": 0}),
            (
                "replace",
                "tooluseproxy.protected_sources.os.replace",
                {"side_effect": OSError("injected replace failure")},
            ),
        )
        for failure, target, behavior in failures:
            with self.subTest(failure=failure), patch(target, **behavior):
                exit_code, payload, stderr = self._approve(suggestion, candidate)

                self.assertEqual(1, exit_code)
                self.assertEqual({}, payload)
                self.assertNotIn(secret, stderr)
                self.assertEqual(manifest_before, self.manifest_path.read_bytes())
                leftovers = [
                    path
                    for path in self.workspace.iterdir()
                    if path.name.startswith(f".{self.manifest_path.name}.")
                    and path.name.endswith(".tmp")
                ]
                self.assertEqual([], leftovers)

    def test_approval_preserves_unknown_fields_and_existing_source_order(self) -> None:
        for suffix in ("one", "two"):
            (self.workspace / f".env.{suffix}").write_text(
                f"PRIVATE_TOKEN={suffix}.secret\n",
                encoding="utf-8",
            )
        (self.workspace / ".env.new").write_text(
            "PRIVATE_TOKEN=new.secret\n",
            encoding="utf-8",
        )
        existing_sources = [
            {
                "id": f"existing-{suffix}",
                "path": f".env.{suffix}",
                "type": "secretfile",
                "sensitivity": "high",
                "policy_tags": ["no_external"],
                "selector": {"dotenv_keys": ["PRIVATE_TOKEN"]},
                "future_source_field": {"suffix": suffix},
            }
            for suffix in ("one", "two")
        ]
        original = {
            "schema_version": 2,
            "future_top_field": {"preserve": True},
            "sources": existing_sources,
            "trailing_field": "kept",
        }
        self._write_manifest(original)

        suggestion, _ = self._suggest(".env.new")
        candidate = self._single_candidate(suggestion)
        exit_code, _, stderr = self._approve(suggestion, candidate)
        self.assertEqual(0, exit_code, stderr)

        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(list(original), list(manifest))
        self.assertEqual(original["future_top_field"], manifest["future_top_field"])
        self.assertEqual(original["trailing_field"], manifest["trailing_field"])
        self.assertEqual(existing_sources, manifest["sources"][:2])
        self.assertEqual(".env.new", manifest["sources"][2]["path"])

    def test_exact_approval_replay_is_idempotent(self) -> None:
        (self.workspace / ".env").write_text(
            "PRIVATE_TOKEN=IDEMPOTENT.SECRET.f8de\n",
            encoding="utf-8",
        )
        suggestion, _ = self._suggest(".env")
        candidate = self._single_candidate(suggestion)
        first_code, first, first_stderr = self._approve(suggestion, candidate)
        self.assertEqual(0, first_code, first_stderr)
        manifest_after_first = self.manifest_path.read_bytes()

        second_code, second, second_stderr = self._approve(suggestion, candidate)

        self.assertEqual(0, second_code, second_stderr)
        self.assertEqual("already_registered", second["status"])
        self.assertEqual(first["source_id"], second["source_id"])
        self.assertEqual(manifest_after_first, self.manifest_path.read_bytes())
        repeated_suggestion, repeated_stderr = self._suggest(".env")
        self.assertEqual("no_candidate", repeated_suggestion["status"])
        self.assertEqual(1, repeated_suggestion["already_registered_count"])
        self.assertEqual([], repeated_suggestion["candidates"])
        self.assertEqual("", repeated_stderr)

    def test_removed_approved_entry_is_proposed_again(self) -> None:
        secret = "REMOVED.ENTRY.SECRET.1c7a"
        (self.workspace / ".env").write_text(
            f"PRIVATE_TOKEN={secret}\n",
            encoding="utf-8",
        )
        first_suggestion, _ = self._suggest(".env")
        first_candidate = self._single_candidate(first_suggestion)
        first_code, _, first_stderr = self._approve(
            first_suggestion,
            first_candidate,
        )
        self.assertEqual(0, first_code, first_stderr)

        self._write_manifest({"schema_version": 2, "sources": []})
        repeated_suggestion, stderr = self._suggest(".env")
        repeated_candidate = self._single_candidate(repeated_suggestion)

        self.assertEqual(
            first_candidate["candidate_id"],
            repeated_candidate["candidate_id"],
        )
        self.assertNotEqual(
            first_candidate["candidate_revision"],
            repeated_candidate["candidate_revision"],
        )
        self.assertNotIn(secret, json.dumps(repeated_suggestion, ensure_ascii=False))
        self.assertNotIn(secret, stderr)

    def test_an_existing_same_path_registration_is_an_explicit_conflict(self) -> None:
        secret = "SAME.PATH.SECRET.834a"
        (self.workspace / ".env").write_text(
            f"PRIVATE_TOKEN={secret}\nOTHER_PASSWORD={secret}.other\n",
            encoding="utf-8",
        )
        original = {
            "schema_version": 2,
            "sources": [
                {
                    "id": "existing-env",
                    "path": ".env",
                    "type": "secretfile",
                    "sensitivity": "high",
                    "policy_tags": ["no_external"],
                    "selector": {"dotenv_keys": ["PRIVATE_TOKEN"]},
                    "owner": "user",
                }
            ],
        }
        self._write_manifest(original)
        manifest_before = self.manifest_path.read_bytes()

        exit_code, payload, stderr = self._run_json(
            *self._protect_arguments("suggest", "--path", ".env")
        )

        self.assertEqual(1, exit_code)
        self.assertEqual({}, payload)
        self.assertIn("source_path_conflict", stderr)
        self.assertNotIn(secret, stderr)
        self.assertEqual(manifest_before, self.manifest_path.read_bytes())

    def test_concurrent_approvals_detect_lost_updates_and_can_be_retried(self) -> None:
        for suffix in ("one", "two"):
            (self.workspace / f".env.{suffix}").write_text(
                f"PRIVATE_TOKEN=CONCURRENT.{suffix}.SECRET\n",
                encoding="utf-8",
            )
        suggestions: dict[str, tuple[dict[str, object], dict[str, object]]] = {}
        for suffix in ("one", "two"):
            suggestion, _ = self._suggest(f".env.{suffix}")
            suggestions[suffix] = (suggestion, self._single_candidate(suggestion))
        self.assertEqual(
            suggestions["one"][0]["manifest_sha256"],
            suggestions["two"][0]["manifest_sha256"],
        )

        processes: list[tuple[str, subprocess.Popen[str]]] = []
        for suffix, (suggestion, candidate) in suggestions.items():
            command = [
                sys.executable,
                "-m",
                "tooluseproxy",
                *self._protect_arguments(
                    "approve",
                    str(candidate["candidate_id"]),
                    "--candidate-revision",
                    str(candidate["candidate_revision"]),
                    "--expected-manifest-sha256",
                    str(suggestion["manifest_sha256"]),
                ),
            ]
            processes.append(
                (
                    suffix,
                    subprocess.Popen(
                        command,
                        cwd=REPO_ROOT,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    ),
                )
            )
        results: dict[str, tuple[int, str, str]] = {}
        for suffix, process in processes:
            stdout, stderr = process.communicate(timeout=20)
            results[suffix] = (process.returncode, stdout, stderr)

        successful = [suffix for suffix, result in results.items() if result[0] == 0]
        self.assertEqual(1, len(successful), results)
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(1, len(manifest["sources"]))
        registered_path = manifest["sources"][0]["path"]
        loser = "two" if registered_path == ".env.one" else "one"
        self.assertEqual(1, results[loser][0])

        retry_suggestion, _ = self._suggest(f".env.{loser}")
        retry_candidate = self._single_candidate(retry_suggestion)
        retry_code, retry, retry_stderr = self._approve(
            retry_suggestion,
            retry_candidate,
        )
        self.assertEqual(0, retry_code, retry_stderr)
        self.assertEqual("approved", retry["status"])
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(
            {".env.one", ".env.two"},
            {source["path"] for source in manifest["sources"]},
        )

    def test_approval_reservation_blocks_review_and_duplicate_suggestion(self) -> None:
        secret = "APPROVAL.RESERVATION.SECRET.765e"
        (self.workspace / ".env").write_text(
            f"PRIVATE_TOKEN={secret}\n",
            encoding="utf-8",
        )
        suggestion, _ = self._suggest(".env")
        candidate = self._single_candidate(suggestion)
        store = EventStore(self.data_dir / "events.db")
        workspace = resolve_workspace(
            str(self.workspace),
            str(self.workspace),
            discovered_by="test",
        )
        entered_core = threading.Event()
        release_core = threading.Event()
        result: dict[str, object] = {}
        failure: list[BaseException] = []
        suggestion_result: dict[str, object] = {}
        suggestion_failure: list[BaseException] = []
        suggestion_thread: threading.Thread | None = None
        real_approve = approve_protected_source

        def blocking_approve(*args: object, **kwargs: object):
            entered_core.set()
            if not release_core.wait(timeout=5):
                raise AssertionError("approval test did not release the core writer")
            return real_approve(*args, **kwargs)

        def run_approval() -> None:
            try:
                result.update(
                    _approve_protected_source_candidate(
                        store,
                        workspace,
                        self.workspace,
                        candidate_id=str(candidate["candidate_id"]),
                        candidate_revision=str(candidate["candidate_revision"]),
                        expected_manifest_sha256=str(suggestion["manifest_sha256"]),
                    )
                )
            except BaseException as exc:  # pragma: no cover - asserted below
                failure.append(exc)

        def run_duplicate_suggestion() -> None:
            try:
                suggestion_result.update(
                    _suggest_protected_sources(
                        store,
                        workspace,
                        self.workspace,
                        (".env",),
                    )
                )
            except BaseException as exc:  # pragma: no cover - asserted below
                suggestion_failure.append(exc)

        with patch(
            "tooluseproxy.cli.approve_protected_source",
            side_effect=blocking_approve,
        ):
            thread = threading.Thread(target=run_approval)
            thread.start()
            try:
                self.assertTrue(entered_core.wait(timeout=5))
                with self.assertRaises(_ProtectCliError) as raised:
                    _review_protected_source_candidate(
                        store,
                        workspace,
                        candidate_id=str(candidate["candidate_id"]),
                        candidate_revision=str(candidate["candidate_revision"]),
                        decision="reject",
                    )
                self.assertEqual("candidate_not_proposed", raised.exception.code)

                suggestion_thread = threading.Thread(
                    target=run_duplicate_suggestion
                )
                suggestion_thread.start()
                suggestion_thread.join(timeout=0.1)
                self.assertTrue(suggestion_thread.is_alive())
            finally:
                release_core.set()
                thread.join(timeout=5)
                if suggestion_thread is not None:
                    suggestion_thread.join(timeout=5)

        self.assertFalse(thread.is_alive())
        self.assertIsNotNone(suggestion_thread)
        assert suggestion_thread is not None
        self.assertFalse(suggestion_thread.is_alive())
        self.assertEqual([], failure)
        self.assertEqual([], suggestion_failure)
        self.assertEqual("approved", result["status"])
        self.assertEqual("no_candidate", suggestion_result["status"])
        self.assertEqual([], suggestion_result["candidates"])
        self.assertEqual(1, suggestion_result["already_registered_count"])
        self.assertNotIn(
            secret,
            json.dumps(suggestion_result, ensure_ascii=False),
        )
        stored = store.get_protected_source_candidate(str(candidate["candidate_id"]))
        self.assertIsNotNone(stored)
        assert stored is not None
        self.assertEqual("approved", stored.status)
        decisions = [
            review.decision_code
            for review in store.list_protected_source_candidate_reviews(
                stored.candidate_id
            )
        ]
        self.assertIn("approval_started", decisions)
        self.assertIn("approved", decisions)
        self.assertNotIn("rejected", decisions)

    def test_suggest_reconciles_a_crash_after_manifest_replace(self) -> None:
        secret = "FINALIZE.CRASH.RECOVERY.SECRET.982a"
        (self.workspace / ".env").write_text(
            f"PRIVATE_TOKEN={secret}\n",
            encoding="utf-8",
        )
        suggestion, _ = self._suggest(".env")
        candidate = self._single_candidate(suggestion)

        with patch.object(
            EventStore,
            "finalize_protected_source_candidate_approval",
            side_effect=sqlite3.OperationalError("injected finalize failure"),
        ):
            exit_code, payload, stderr = self._approve(suggestion, candidate)

        self.assertEqual(1, exit_code)
        self.assertEqual({}, payload)
        self.assertIn("state_unavailable", stderr)
        self.assertNotIn(secret, stderr)
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual([".env"], [entry["path"] for entry in manifest["sources"]])
        store = EventStore(self.data_dir / "events.db")
        before = store.get_protected_source_candidate(str(candidate["candidate_id"]))
        self.assertIsNotNone(before)
        assert before is not None
        self.assertEqual("approving", before.status)
        self.assertIsNotNone(before.approval_attempt_id)

        with patch(
            "tooluseproxy.protected_sources.os.fsync",
            side_effect=OSError("injected directory fsync failure"),
        ):
            blocked_code, blocked_payload, blocked_stderr = self._run_json(
                *self._protect_arguments("suggest", "--path", ".env")
            )

        self.assertEqual(1, blocked_code)
        self.assertEqual({}, blocked_payload)
        self.assertIn("manifest_durability_unknown", blocked_stderr)
        self.assertNotIn(secret, blocked_stderr)
        still_reserved = store.get_protected_source_candidate(
            str(candidate["candidate_id"])
        )
        self.assertIsNotNone(still_reserved)
        assert still_reserved is not None
        self.assertEqual("approving", still_reserved.status)

        recovered, recovered_stderr = self._suggest(".env")

        self.assertEqual("no_candidate", recovered["status"])
        self.assertEqual(1, recovered["already_registered_count"])
        self.assertEqual([], recovered["candidates"])
        self.assertEqual("", recovered_stderr)
        self.assertNotIn(secret, json.dumps(recovered, ensure_ascii=False))
        after = store.get_protected_source_candidate(str(candidate["candidate_id"]))
        self.assertIsNotNone(after)
        assert after is not None
        self.assertEqual("approved", after.status)
        self.assertIsNone(after.approval_attempt_id)
        self.assertIn(
            "reconciled_approved",
            [
                review.decision_code
                for review in store.list_protected_source_candidate_reviews(
                    after.candidate_id
                )
            ],
        )

    def test_suggest_reconciles_after_registered_secret_value_rotation(self) -> None:
        original_secret = "FINALIZE.ROTATION.OLD.SECRET.51c4"
        rotated_secret = "FINALIZE.ROTATION.NEW.SECRET.74e9"
        source_path = self.workspace / ".env"
        source_path.write_text(
            f"PRIVATE_TOKEN={original_secret}\n",
            encoding="utf-8",
        )
        suggestion, _ = self._suggest(".env")
        candidate = self._single_candidate(suggestion)

        with patch.object(
            EventStore,
            "finalize_protected_source_candidate_approval",
            side_effect=sqlite3.OperationalError("injected finalize failure"),
        ):
            exit_code, payload, stderr = self._approve(suggestion, candidate)

        self.assertEqual(1, exit_code)
        self.assertEqual({}, payload)
        self.assertIn("state_unavailable", stderr)
        source_path.write_text(
            f"PRIVATE_TOKEN={rotated_secret}\n",
            encoding="utf-8",
        )

        recovered, recovered_stderr = self._suggest(".env")

        self.assertEqual("no_candidate", recovered["status"])
        self.assertEqual(1, recovered["already_registered_count"])
        self.assertEqual("", recovered_stderr)
        rendered = json.dumps(recovered, ensure_ascii=False)
        self.assertNotIn(original_secret, rendered)
        self.assertNotIn(rotated_secret, rendered)
        store = EventStore(self.data_dir / "events.db")
        approved = store.get_protected_source_candidate(str(candidate["candidate_id"]))
        self.assertIsNotNone(approved)
        assert approved is not None
        self.assertEqual("approved", approved.status)
        self.assertIsNone(approved.approval_attempt_id)
        self.assertEqual(
            "reconciled_approved",
            store.list_protected_source_candidate_reviews(approved.candidate_id)[
                -1
            ].decision_code,
        )
        database_text, _ = self._database_text()
        self.assertNotIn(original_secret, database_text)
        self.assertNotIn(rotated_secret, database_text)

    def test_approve_retry_resumes_a_reserved_prewrite_attempt(self) -> None:
        secret = "PREWRITE.RETRY.SECRET.54c8"
        (self.workspace / ".env").write_text(
            f"PRIVATE_TOKEN={secret}\n",
            encoding="utf-8",
        )
        suggestion, _ = self._suggest(".env")
        candidate = self._single_candidate(suggestion)
        manifest_before = self.manifest_path.read_bytes()

        with patch(
            "tooluseproxy.cli.approve_protected_source",
            side_effect=OSError("injected prewrite interruption"),
        ):
            exit_code, payload, stderr = self._approve(suggestion, candidate)

        self.assertEqual(1, exit_code)
        self.assertEqual({}, payload)
        self.assertIn("state_unavailable", stderr)
        self.assertNotIn(secret, stderr)
        self.assertEqual(manifest_before, self.manifest_path.read_bytes())
        store = EventStore(self.data_dir / "events.db")
        reserved = store.get_protected_source_candidate(str(candidate["candidate_id"]))
        self.assertIsNotNone(reserved)
        assert reserved is not None
        self.assertEqual("approving", reserved.status)

        retry_code, retry, retry_stderr = self._approve(suggestion, candidate)

        self.assertEqual(0, retry_code, retry_stderr)
        self.assertEqual("approved", retry["status"])
        self.assertNotIn(secret, json.dumps(retry, ensure_ascii=False))
        approved = store.get_protected_source_candidate(str(candidate["candidate_id"]))
        self.assertIsNotNone(approved)
        assert approved is not None
        self.assertEqual("approved", approved.status)
        decisions = [
            review.decision_code
            for review in store.list_protected_source_candidate_reviews(
                approved.candidate_id
            )
        ]
        self.assertEqual(1, decisions.count("approval_started"))
        self.assertEqual(1, decisions.count("approved"))

    def test_post_replace_validation_failure_keeps_the_approval_reserved(self) -> None:
        secret = "POST.REPLACE.VALIDATION.SECRET.a13d"
        (self.workspace / ".env").write_text(
            f"PRIVATE_TOKEN={secret}\n",
            encoding="utf-8",
        )
        suggestion, _ = self._suggest(".env")
        candidate = self._single_candidate(suggestion)
        real_read_manifest = protected_source_registration._read_manifest_text
        read_count = 0

        def fail_installed_manifest_read(*args: object, **kwargs: object):
            nonlocal read_count
            read_count += 1
            if read_count == 3:
                raise ProtectedSourceRegistrationError("manifest_not_safe")
            return real_read_manifest(*args, **kwargs)

        with patch(
            "tooluseproxy.protected_sources._read_manifest_text",
            side_effect=fail_installed_manifest_read,
        ):
            exit_code, payload, stderr = self._approve(suggestion, candidate)

        self.assertEqual(1, exit_code)
        self.assertEqual({}, payload)
        self.assertIn("manifest_postcondition_failed", stderr)
        self.assertNotIn(secret, stderr)
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual([".env"], [entry["path"] for entry in manifest["sources"]])
        store = EventStore(self.data_dir / "events.db")
        reserved = store.get_protected_source_candidate(str(candidate["candidate_id"]))
        self.assertIsNotNone(reserved)
        assert reserved is not None
        self.assertEqual("approving", reserved.status)

        review_code, review_payload, review_stderr = self._review("reject", candidate)
        self.assertEqual(1, review_code)
        self.assertEqual({}, review_payload)
        self.assertIn("candidate_not_proposed", review_stderr)
        self.assertNotIn(secret, review_stderr)

        recovered, recovered_stderr = self._suggest(".env")
        self.assertEqual("no_candidate", recovered["status"])
        self.assertEqual(1, recovered["already_registered_count"])
        self.assertEqual("", recovered_stderr)
        approved = store.get_protected_source_candidate(str(candidate["candidate_id"]))
        self.assertIsNotNone(approved)
        assert approved is not None
        self.assertEqual("approved", approved.status)


if __name__ == "__main__":
    unittest.main()
