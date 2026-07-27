from __future__ import annotations

import sqlite3
import tempfile
import unittest
import json
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from hook_monitor.runtime.settings import (
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
from tooluseproxy.cli import main as tooluseproxy_main


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
            [PRE_TOOL_POLICY_KEY, FILE_PAYLOAD_SHADOW_KEY,
             FILE_PAYLOAD_EXACT_ENFORCEMENT_KEY],
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


if __name__ == "__main__":
    unittest.main()
