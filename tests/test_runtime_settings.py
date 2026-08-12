from __future__ import annotations

import sqlite3
import tempfile
import unittest
import json
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from hook_monitor.runtime.settings import (
    EXTERNALITY_PROTECTION_KEY,
    FILE_PAYLOAD_EXACT_ENFORCEMENT_KEY,
    FILE_PAYLOAD_SHADOW_KEY,
    PRE_TOOL_POLICY_KEY,
    RuntimeSettingsError,
    empty_workspace_runtime_settings,
    make_workspace_runtime_settings,
    parse_runtime_setting_value,
    resolve_effective_runtime_settings,
)
from hook_monitor.runtime.storage import CURRENT_SCHEMA_VERSION, EventStore
from hook_monitor.runtime.workspace import resolve_workspace
from tooluseproxy.cli import (
    SETUP_PROFILE_FILE_PAYLOAD_EXACT,
    main as tooluseproxy_main,
)


class RuntimeSettingsDomainTest(unittest.TestCase):
    def test_revision_is_deterministic_and_key_order_independent(self) -> None:
        first = make_workspace_runtime_settings(
            "workspace",
            {
                PRE_TOOL_POLICY_KEY: True,
                FILE_PAYLOAD_SHADOW_KEY: True,
            },
        )
        second = make_workspace_runtime_settings(
            "workspace",
            {
                FILE_PAYLOAD_SHADOW_KEY: True,
                PRE_TOOL_POLICY_KEY: True,
            },
        )

        self.assertEqual(first.revision, second.revision)
        self.assertEqual(first.settings, second.settings)

    def test_unknown_key_and_non_boolean_value_are_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeSettingsError, "not supported"):
            make_workspace_runtime_settings("workspace", {"unknown": True})
        with self.assertRaisesRegex(RuntimeSettingsError, "must be on or off"):
            make_workspace_runtime_settings(  # type: ignore[arg-type]
                "workspace",
                {PRE_TOOL_POLICY_KEY: 1},
            )

    def test_dependency_requires_pre_tool_policy(self) -> None:
        with self.assertRaisesRegex(
            RuntimeSettingsError,
            "pre-tool-policy must be on",
        ):
            make_workspace_runtime_settings(
                "workspace",
                {FILE_PAYLOAD_EXACT_ENFORCEMENT_KEY: True},
            )
        with self.assertRaisesRegex(
            RuntimeSettingsError,
            "pre-tool-policy must be on",
        ):
            make_workspace_runtime_settings(
                "workspace",
                {EXTERNALITY_PROTECTION_KEY: True},
            )

    def test_environment_precedence_and_invalid_value_are_explicit(self) -> None:
        state = make_workspace_runtime_settings(
            "workspace",
            {
                PRE_TOOL_POLICY_KEY: True,
                FILE_PAYLOAD_SHADOW_KEY: True,
            },
        )
        resolved = resolve_effective_runtime_settings(
            state,
            {
                "TOOLUSEPROXY_PRE_TOOL_POLICY": "off",
                "TOOLUSEPROXY_PRE_TOOL_FILE_PAYLOAD_SHADOW": "invalid",
            },
        )

        pre_tool = resolved.settings[PRE_TOOL_POLICY_KEY]
        shadow = resolved.settings[FILE_PAYLOAD_SHADOW_KEY]
        self.assertFalse(pre_tool.effective_value)
        self.assertEqual("environment", pre_tool.source)
        self.assertFalse(shadow.effective_value)
        self.assertEqual("invalid_environment", shadow.source)
        self.assertEqual("environment_value_invalid", shadow.diagnostic_code)

        judge_shadow = resolve_effective_runtime_settings(
            state,
            {"TOOLUSEPROXY_EXTERNALITY_PROTECTION": "on"},
        ).settings[EXTERNALITY_PROTECTION_KEY]
        self.assertTrue(judge_shadow.effective_value)
        self.assertEqual("environment", judge_shadow.source)

    def test_boolean_parser_is_strict(self) -> None:
        self.assertTrue(parse_runtime_setting_value("ON"))
        self.assertFalse(parse_runtime_setting_value(" no "))
        with self.assertRaises(RuntimeSettingsError):
            parse_runtime_setting_value("enabled")


class RuntimeSettingsStorageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.db_path = self.root / "events.db"
        self.store = EventStore(self.db_path)
        self.store.initialize()
        self.workspace_a_path = self.root / "workspace-a"
        self.workspace_b_path = self.root / "workspace-b"
        self.workspace_a_path.mkdir()
        self.workspace_b_path.mkdir()
        self.workspace_a = resolve_workspace(
            str(self.workspace_a_path),
            str(self.workspace_a_path),
            discovered_by="test",
        )
        self.workspace_b = resolve_workspace(
            str(self.workspace_b_path),
            str(self.workspace_b_path),
            discovered_by="test",
        )
        self.store.register_workspace(self.workspace_a)
        self.store.register_workspace(self.workspace_b)
        assert self.workspace_a.workspace_id is not None
        assert self.workspace_b.workspace_id is not None

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_schema_contains_runtime_settings_contract(self) -> None:
        self.store.require_runtime_schema()
        with sqlite3.connect(self.db_path) as conn:
            version = conn.execute("PRAGMA user_version").fetchone()
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
        self.assertEqual((CURRENT_SCHEMA_VERSION,), version)
        self.assertIn("workspace_runtime_settings", tables)
        self.assertIn("workspace_runtime_setting_changes", tables)

    def test_set_unset_cas_and_history_are_workspace_scoped(self) -> None:
        workspace_a_id = self.workspace_a.workspace_id
        workspace_b_id = self.workspace_b.workspace_id
        assert workspace_a_id is not None and workspace_b_id is not None
        initial = self.store.get_workspace_runtime_settings(workspace_a_id)

        first, first_change = self.store.update_workspace_runtime_setting(
            workspace_a_id,
            setting_key=PRE_TOOL_POLICY_KEY,
            value=True,
            expected_revision=initial.revision,
        )
        self.assertTrue(first.settings[PRE_TOOL_POLICY_KEY])
        self.assertIsNotNone(first_change)

        with self.assertRaisesRegex(RuntimeSettingsError, "run config show again"):
            self.store.update_workspace_runtime_setting(
                workspace_a_id,
                setting_key=FILE_PAYLOAD_SHADOW_KEY,
                value=True,
                expected_revision=initial.revision,
            )

        second, second_change = self.store.update_workspace_runtime_setting(
            workspace_a_id,
            setting_key=FILE_PAYLOAD_SHADOW_KEY,
            value=True,
            expected_revision=first.revision,
        )
        self.assertIsNotNone(second_change)
        self.assertEqual(
            {},
            self.store.get_workspace_runtime_settings(workspace_b_id).settings,
        )

        unchanged, no_change = self.store.update_workspace_runtime_setting(
            workspace_a_id,
            setting_key=FILE_PAYLOAD_SHADOW_KEY,
            value=True,
            expected_revision=second.revision,
        )
        self.assertEqual(second, unchanged)
        self.assertIsNone(no_change)

        with self.assertRaisesRegex(RuntimeSettingsError, "pre-tool-policy"):
            self.store.update_workspace_runtime_setting(
                workspace_a_id,
                setting_key=PRE_TOOL_POLICY_KEY,
                value=False,
                expected_revision=second.revision,
            )

        third, _ = self.store.update_workspace_runtime_setting(
            workspace_a_id,
            setting_key=FILE_PAYLOAD_SHADOW_KEY,
            value=None,
            expected_revision=second.revision,
        )
        final, _ = self.store.update_workspace_runtime_setting(
            workspace_a_id,
            setting_key=PRE_TOOL_POLICY_KEY,
            value=None,
            expected_revision=third.revision,
        )
        self.assertEqual(
            empty_workspace_runtime_settings(workspace_a_id),
            final,
        )
        history = self.store.list_workspace_runtime_setting_changes(
            workspace_a_id
        )
        self.assertEqual(4, len(history))
        self.assertEqual(
            {workspace_a_id},
            {item.workspace_id for item in history},
        )

    def test_audit_rows_are_immutable(self) -> None:
        workspace_id = self.workspace_a.workspace_id
        assert workspace_id is not None
        initial = self.store.get_workspace_runtime_settings(workspace_id)
        self.store.update_workspace_runtime_setting(
            workspace_id,
            setting_key=PRE_TOOL_POLICY_KEY,
            value=True,
            expected_revision=initial.revision,
        )

        with sqlite3.connect(self.db_path) as conn:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute(
                    "DELETE FROM workspace_runtime_setting_changes"
                )

    def test_fixed_profile_is_atomic_revisioned_and_idempotent(self) -> None:
        workspace_id = self.workspace_a.workspace_id
        assert workspace_id is not None
        initial = self.store.get_workspace_runtime_settings(workspace_id)
        expected = {
            PRE_TOOL_POLICY_KEY: True,
            FILE_PAYLOAD_SHADOW_KEY: True,
            FILE_PAYLOAD_EXACT_ENFORCEMENT_KEY: True,
        }

        applied, changes = (
            self.store.apply_workspace_runtime_settings_profile(
                self.workspace_a,
                settings=expected,
                expected_revision=initial.revision,
            )
        )

        self.assertEqual(expected, applied.settings)
        self.assertEqual(3, len(changes))
        self.assertEqual(
            {initial.revision},
            {change.previous_revision for change in changes},
        )
        self.assertEqual(
            {applied.revision},
            {change.new_revision for change in changes},
        )
        retried, retry_changes = (
            self.store.apply_workspace_runtime_settings_profile(
                self.workspace_a,
                settings=expected,
                expected_revision=initial.revision,
            )
        )
        self.assertEqual(applied, retried)
        self.assertEqual((), retry_changes)

    def test_fixed_profile_rejects_stale_non_target_revision(self) -> None:
        workspace_id = self.workspace_a.workspace_id
        assert workspace_id is not None
        initial = self.store.get_workspace_runtime_settings(workspace_id)
        partial, _ = self.store.update_workspace_runtime_setting(
            workspace_id,
            setting_key=PRE_TOOL_POLICY_KEY,
            value=True,
            expected_revision=initial.revision,
        )

        with self.assertRaisesRegex(
            RuntimeSettingsError,
            "verify the current revision",
        ):
            self.store.apply_workspace_runtime_settings_profile(
                self.workspace_a,
                settings={
                    PRE_TOOL_POLICY_KEY: True,
                    FILE_PAYLOAD_SHADOW_KEY: True,
                    FILE_PAYLOAD_EXACT_ENFORCEMENT_KEY: True,
                },
                expected_revision=initial.revision,
            )
        self.assertEqual(
            partial,
            self.store.get_workspace_runtime_settings(workspace_id),
        )

    def test_unregistered_workspace_cannot_be_changed(self) -> None:
        initial = empty_workspace_runtime_settings("not-registered")
        with self.assertRaisesRegex(RuntimeSettingsError, "not registered"):
            self.store.update_workspace_runtime_setting(
                "not-registered",
                setting_key=PRE_TOOL_POLICY_KEY,
                value=True,
                expected_revision=initial.revision,
            )


class RuntimeSettingsCliTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.workspace = self.root / "workspace"
        self.data_dir = self.root / "data"
        self.workspace.mkdir()
        exit_code, payload, _ = self._run(
            [
                "init",
                "--codex",
                "--workspace",
                str(self.workspace),
                "--data-dir",
                str(self.data_dir),
                "--json",
            ]
        )
        self.assertEqual(0, exit_code)
        self.assertEqual("initialized", payload["status"])

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _run(
        self,
        arguments: list[str],
    ) -> tuple[int, dict[str, object], str]:
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = tooluseproxy_main(arguments)
        rendered = stdout.getvalue() or stderr.getvalue()
        return exit_code, json.loads(rendered), stderr.getvalue()

    def _config_arguments(self, *arguments: str) -> list[str]:
        return [
            "config",
            *arguments,
            "--workspace",
            str(self.workspace),
            "--data-dir",
            str(self.data_dir),
            "--json",
        ]

    def test_show_set_unset_history_and_status(self) -> None:
        exit_code, shown, _ = self._run(
            self._config_arguments("show")
        )
        self.assertEqual(0, exit_code)
        revision = str(shown["settings_revision"])
        self.assertEqual(
            [
                PRE_TOOL_POLICY_KEY,
                FILE_PAYLOAD_SHADOW_KEY,
                FILE_PAYLOAD_EXACT_ENFORCEMENT_KEY,
                EXTERNALITY_PROTECTION_KEY,
            ],
            [item["key"] for item in shown["settings"]],
        )

        exit_code, updated, _ = self._run(
            self._config_arguments(
                "set",
                PRE_TOOL_POLICY_KEY,
                "on",
                "--expected-revision",
                revision,
            )
        )
        self.assertEqual(0, exit_code)
        self.assertEqual("updated", updated["status"])
        updated_revision = str(updated["settings_revision"])

        exit_code, exact, _ = self._run(
            self._config_arguments(
                "set",
                FILE_PAYLOAD_EXACT_ENFORCEMENT_KEY,
                "on",
                "--expected-revision",
                updated_revision,
            )
        )
        self.assertEqual(0, exit_code)
        self.assertEqual("updated", exact["status"])

        exit_code, stale, stderr = self._run(
            self._config_arguments(
                "unset",
                FILE_PAYLOAD_EXACT_ENFORCEMENT_KEY,
                "--expected-revision",
                revision,
            )
        )
        self.assertEqual(1, exit_code)
        self.assertEqual("settings_revision_stale", stale["error"]["code"])
        self.assertTrue(stderr)

        exit_code, history, _ = self._run(
            self._config_arguments("history", "--limit", "10")
        )
        self.assertEqual(0, exit_code)
        self.assertEqual(2, len(history["changes"]))

        exit_code, status, _ = self._run(
            [
                "status",
                "--workspace",
                str(self.workspace),
                "--data-dir",
                str(self.data_dir),
                "--json",
            ]
        )
        self.assertEqual(0, exit_code)
        self.assertTrue(status["runtime_settings"]["ok"])

    def test_dependency_and_unknown_key_return_stable_errors(self) -> None:
        _, shown, _ = self._run(self._config_arguments("show"))
        revision = str(shown["settings_revision"])

        exit_code, dependency, _ = self._run(
            self._config_arguments(
                "set",
                FILE_PAYLOAD_SHADOW_KEY,
                "on",
                "--expected-revision",
                revision,
            )
        )
        self.assertEqual(1, exit_code)
        self.assertEqual(
            "setting_dependency_invalid",
            dependency["error"]["code"],
        )

        exit_code, unknown, _ = self._run(
            self._config_arguments(
                "set",
                "unknown",
                "on",
                "--expected-revision",
                revision,
            )
        )
        self.assertEqual(1, exit_code)
        self.assertEqual("setting_key_unknown", unknown["error"]["code"])

    def test_setup_profile_apply_and_read_only_verify(self) -> None:
        fresh_workspace = self.root / "setup-workspace"
        fresh_data = self.root / "setup-data"
        fresh_workspace.mkdir()
        initial_revision = empty_workspace_runtime_settings(
            "revision-is-settings-only"
        ).revision
        setup_arguments = [
            "setup",
            "apply",
            SETUP_PROFILE_FILE_PAYLOAD_EXACT,
            "--codex",
            "--expected-revision",
            initial_revision,
            "--workspace",
            str(fresh_workspace),
            "--data-dir",
            str(fresh_data),
            "--json",
        ]

        exit_code, applied, _ = self._run(setup_arguments)

        self.assertEqual(0, exit_code)
        self.assertEqual("applied", applied["status"])
        self.assertEqual(3, len(applied["changed_keys"]))
        retry_code, retried, _ = self._run(setup_arguments)
        self.assertEqual(0, retry_code)
        self.assertEqual("already_applied", retried["status"])

        manifest = fresh_workspace / "protected_sources.json"
        database = fresh_data / "events.db"
        with sqlite3.connect(database) as conn:
            before_settings = conn.execute(
                """
                SELECT settings_revision, settings_json
                FROM workspace_runtime_settings
                """
            ).fetchall()
            before_history = conn.execute(
                """
                SELECT change_id, previous_revision, new_revision
                FROM workspace_runtime_setting_changes
                ORDER BY change_id
                """
            ).fetchall()
        before_manifest = manifest.read_bytes()
        verify_code, verified, _ = self._run(
            [
                "setup",
                "verify",
                SETUP_PROFILE_FILE_PAYLOAD_EXACT,
                "--workspace",
                str(fresh_workspace),
                "--data-dir",
                str(fresh_data),
                "--json",
            ]
        )
        with sqlite3.connect(database) as conn:
            after_settings = conn.execute(
                """
                SELECT settings_revision, settings_json
                FROM workspace_runtime_settings
                """
            ).fetchall()
            after_history = conn.execute(
                """
                SELECT change_id, previous_revision, new_revision
                FROM workspace_runtime_setting_changes
                ORDER BY change_id
                """
            ).fetchall()

        self.assertEqual(0, verify_code)
        self.assertEqual("passed", verified["status"])
        self.assertEqual(before_settings, after_settings)
        self.assertEqual(before_history, after_history)
        self.assertEqual(before_manifest, manifest.read_bytes())

    def test_setup_profile_accepts_only_empty_settings_precondition(self) -> None:
        fresh_workspace = self.root / "empty-settings-workspace"
        fresh_data = self.root / "empty-settings-data"
        fresh_workspace.mkdir()
        arguments = [
            "setup",
            "apply",
            SETUP_PROFILE_FILE_PAYLOAD_EXACT,
            "--codex",
            "--expect-empty-settings",
            "--workspace",
            str(fresh_workspace),
            "--data-dir",
            str(fresh_data),
            "--json",
        ]

        exit_code, applied, _ = self._run(arguments)

        self.assertEqual(0, exit_code)
        self.assertEqual("applied", applied["status"])
        self.assertEqual("empty_settings", applied["precondition"])
        retry_code, retried, _ = self._run(arguments)
        self.assertEqual(0, retry_code)
        self.assertEqual("already_applied", retried["status"])

        _, shown, _ = self._run(
            [
                "config",
                "show",
                "--workspace",
                str(fresh_workspace),
                "--data-dir",
                str(fresh_data),
                "--json",
            ]
        )
        revision = str(shown["settings_revision"])
        set_code, _, _ = self._run(
            [
                "config",
                "set",
                FILE_PAYLOAD_EXACT_ENFORCEMENT_KEY,
                "off",
                "--expected-revision",
                revision,
                "--workspace",
                str(fresh_workspace),
                "--data-dir",
                str(fresh_data),
                "--json",
            ]
        )
        self.assertEqual(0, set_code)

        manifest = fresh_workspace / "protected_sources.json"
        manifest.unlink()
        stale_code, stale, _ = self._run(arguments)
        self.assertEqual(1, stale_code)
        self.assertEqual("settings_revision_stale", stale["error"]["code"])
        self.assertFalse(manifest.exists())

    def test_setup_verify_allows_additive_externality_shadow_setting(self) -> None:
        fresh_workspace = self.root / "setup-additive-workspace"
        fresh_data = self.root / "setup-additive-data"
        fresh_workspace.mkdir()
        initial_revision = empty_workspace_runtime_settings(
            "revision-is-settings-only"
        ).revision
        apply_code, _, _ = self._run(
            [
                "setup",
                "apply",
                SETUP_PROFILE_FILE_PAYLOAD_EXACT,
                "--codex",
                "--expected-revision",
                initial_revision,
                "--workspace",
                str(fresh_workspace),
                "--data-dir",
                str(fresh_data),
                "--json",
            ]
        )
        self.assertEqual(0, apply_code)
        _, shown, _ = self._run(
            [
                "config",
                "show",
                "--workspace",
                str(fresh_workspace),
                "--data-dir",
                str(fresh_data),
                "--json",
            ]
        )
        set_code, _, _ = self._run(
            [
                "config",
                "set",
                EXTERNALITY_PROTECTION_KEY,
                "on",
                "--expected-revision",
                str(shown["settings_revision"]),
                "--workspace",
                str(fresh_workspace),
                "--data-dir",
                str(fresh_data),
                "--json",
            ]
        )
        self.assertEqual(0, set_code)

        verify_code, verified, _ = self._run(
            [
                "setup",
                "verify",
                SETUP_PROFILE_FILE_PAYLOAD_EXACT,
                "--workspace",
                str(fresh_workspace),
                "--data-dir",
                str(fresh_data),
                "--json",
            ]
        )

        self.assertEqual(0, verify_code)
        self.assertEqual("passed", verified["status"])

    def test_setup_profile_rolls_back_manifest_when_database_write_fails(self) -> None:
        fresh_workspace = self.root / "rollback-workspace"
        fresh_data = self.root / "rollback-data"
        fresh_workspace.mkdir()
        arguments = [
            "setup",
            "apply",
            SETUP_PROFILE_FILE_PAYLOAD_EXACT,
            "--codex",
            "--expect-empty-settings",
            "--workspace",
            str(fresh_workspace),
            "--data-dir",
            str(fresh_data),
            "--json",
        ]

        with patch.object(
            EventStore,
            "_upsert_workspace",
            side_effect=sqlite3.OperationalError("synthetic write failure"),
        ):
            exit_code, payload, _ = self._run(arguments)

        self.assertEqual(1, exit_code)
        self.assertEqual("setup_unavailable", payload["error"]["code"])
        self.assertFalse((fresh_workspace / "protected_sources.json").exists())
        with sqlite3.connect(fresh_data / "events.db") as conn:
            self.assertEqual(
                0,
                conn.execute("SELECT COUNT(*) FROM workspaces").fetchone()[0],
            )
            self.assertEqual(
                0,
                conn.execute(
                    "SELECT COUNT(*) FROM workspace_runtime_settings"
                ).fetchone()[0],
            )

    def test_setup_profile_errors_remain_structured_json(self) -> None:
        fresh_workspace = self.root / "error-workspace"
        fresh_data = self.root / "error-data"
        fresh_workspace.mkdir()
        initial_revision = empty_workspace_runtime_settings(
            "revision-is-settings-only"
        ).revision
        with patch(
            "tooluseproxy.cli._create_empty_manifest",
            side_effect=ValueError("invalid manifest"),
        ):
            apply_code, apply_payload, _ = self._run(
                [
                    "setup",
                    "apply",
                    SETUP_PROFILE_FILE_PAYLOAD_EXACT,
                    "--codex",
                    "--expected-revision",
                    initial_revision,
                    "--workspace",
                    str(fresh_workspace),
                    "--data-dir",
                    str(fresh_data),
                    "--json",
                ]
            )
        self.assertEqual(1, apply_code)
        self.assertEqual("setup_unavailable", apply_payload["error"]["code"])

        with patch(
            "tooluseproxy.cli._resolve_cli_workspace",
            side_effect=ValueError("invalid workspace"),
        ):
            verify_code, verify_payload, _ = self._run(
                [
                    "setup",
                    "verify",
                    SETUP_PROFILE_FILE_PAYLOAD_EXACT,
                    "--workspace",
                    str(fresh_workspace),
                    "--data-dir",
                    str(fresh_data),
                    "--json",
                ]
            )
        self.assertEqual(1, verify_code)
        self.assertEqual(
            "verification_unavailable",
            verify_payload["error"]["code"],
        )


if __name__ == "__main__":
    unittest.main()
