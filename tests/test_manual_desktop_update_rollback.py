from __future__ import annotations

import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import scripts.manual_desktop_update_rollback as update_rollback

from scripts.manual_desktop_update_rollback import (
    MARKETPLACE_NAME,
    PLUGIN_ID,
    DesktopUpdateRollbackFailure,
    _extract_tar_safely,
    _database_event_prefix_sha256,
    _inventory_delta_matches,
    _migration_backup_files,
    _old_baseline_prompt,
    _rebaseline_desktop_host_bundle,
    _rebaseline_desktop_version_only,
    _remove_managed_path,
    _validate_uninstall_plan,
    _write_update_context_and_prompt,
    inspect_marketplace_artifact,
)


class ManualDesktopUpdateRollbackTest(unittest.TestCase):
    def test_event_prefix_digest_is_stable_across_append_only_events(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database = Path(temporary_directory) / "events.db"
            with update_rollback.sqlite3.connect(database) as connection:
                connection.execute(
                    "CREATE TABLE events ("
                    "event_id TEXT, sequence_no INTEGER, payload_json TEXT)"
                )
                connection.executemany(
                    "INSERT INTO events VALUES (?, ?, ?)",
                    [("one", 1, "{}"), ("two", 2, "{}")],
                )
            before = _database_event_prefix_sha256(database, 2)

            with update_rollback.sqlite3.connect(database) as connection:
                connection.execute(
                    "INSERT INTO events VALUES (?, ?, ?)",
                    ("three", 3, "{}"),
                )

            self.assertEqual(
                before,
                _database_event_prefix_sha256(database, 2),
            )
            with update_rollback.sqlite3.connect(database) as connection:
                connection.execute(
                    "UPDATE events SET payload_json = ? WHERE event_id = ?",
                    ('{"changed":true}', "one"),
                )
            self.assertNotEqual(
                before,
                _database_event_prefix_sha256(database, 2),
            )

    def test_update_prompt_uses_short_approval_and_wait_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            state = {
                "workspace": str(root / "workspace"),
                "new_installed_plugin_root": str(root / "plugin"),
                "current_data": str(root / "data"),
                "fake_sink": str(root / "bin" / "curl"),
                "new": {"declared_version": "0.1.0-alpha.3"},
            }

            _write_update_context_and_prompt(root, state)

            prompt = (root / "desktop-update-rollback-prompt.txt").read_text()
            self.assertIn(
                "実行確認｜すること：...｜変わるもの：...｜外部通信：",
                prompt,
            )
            self.assertIn("同じ160文字以内のplain text", prompt)
            self.assertIn("tool callのjustification", prompt)
            self.assertIn("cell ID", prompt)
            self.assertIn("元commandの完了まで待って", prompt)
            self.assertIn("CLI commandを再実行せず", prompt)

    def test_migration_backup_files_excludes_sqlite_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            plugin_data = Path(temporary_directory)
            backup = plugin_data / "events.db.pre-migration-v1.bak"
            backup.write_bytes(b"database")
            (plugin_data / f"{backup.name}-shm").write_bytes(b"shm")
            (plugin_data / f"{backup.name}-wal").write_bytes(b"wal")

            self.assertEqual([backup], _migration_backup_files(plugin_data))

    def test_checkpoint_new_probe_cli_dispatches_to_function(self) -> None:
        root = Path("/tmp/desktop-update-new-probe")
        payload = {"schema_version": 1, "status": "new_hook_probe_passed"}

        with (
            patch.object(
                sys,
                "argv",
                [
                    "manual_desktop_update_rollback.py",
                    "checkpoint-new-probe",
                    "--root",
                    str(root),
                ],
            ),
            patch.object(
                update_rollback,
                "checkpoint_new_probe",
                return_value=payload,
            ) as checkpoint,
            patch("builtins.print") as output,
        ):
            result = update_rollback.main()

        self.assertEqual(0, result)
        checkpoint.assert_called_once_with(root)
        output.assert_called_once_with(json.dumps(payload, sort_keys=True))

    def test_desktop_host_rebaseline_allows_app_bundle_drift_only(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            marketplace = Path(temporary_directory).resolve()
            plugin = {
                "pluginId": PLUGIN_ID,
                "name": "tooluseproxy",
            }
            before = {
                "codex_cli_version": "codex 1",
                "desktop_version": "desktop-old",
                "desktop_codex_version": "desktop-codex-old",
                "installed_plugin_ids": [],
                "marketplace_names": [MARKETPLACE_NAME],
                "marketplaces": [
                    {"name": MARKETPLACE_NAME, "root": str(marketplace)}
                ],
                "plugins": [],
            }
            current = {
                **before,
                "desktop_version": "desktop-new",
                "desktop_codex_version": "desktop-codex-new",
                "installed_plugin_ids": [PLUGIN_ID],
                "plugins": [plugin],
            }

            rebased = _rebaseline_desktop_host_bundle(
                before,
                current,
                plugin_expected=True,
                marketplace_root=marketplace,
            )

            self.assertIsNotNone(rebased)
            assert rebased is not None
            self.assertEqual("desktop-new", rebased["desktop_version"])
            self.assertEqual(
                "desktop-codex-new",
                rebased["desktop_codex_version"],
            )
            self.assertEqual("desktop-old", before["desktop_version"])

            incompatible = {**current, "codex_cli_version": "codex 2"}
            self.assertIsNone(
                _rebaseline_desktop_host_bundle(
                    before,
                    incompatible,
                    plugin_expected=True,
                    marketplace_root=marketplace,
                )
            )

    def test_desktop_version_rebaseline_allows_only_app_version_drift(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            marketplace = Path(temporary_directory).resolve()
            before = {
                "codex_cli_version": "codex 1",
                "desktop_version": "desktop-old",
                "desktop_codex_version": "desktop-codex 1",
                "installed_plugin_ids": [],
                "marketplace_names": [MARKETPLACE_NAME],
                "marketplaces": [
                    {"name": MARKETPLACE_NAME, "root": str(marketplace)}
                ],
                "plugins": [],
            }
            current = {
                **before,
                "desktop_version": "desktop-new",
            }

            rebased = _rebaseline_desktop_version_only(
                before,
                current,
                plugin_expected=False,
                marketplace_root=marketplace,
            )

            self.assertIsNotNone(rebased)
            assert rebased is not None
            self.assertEqual("desktop-new", rebased["desktop_version"])
            self.assertEqual("desktop-old", before["desktop_version"])

            incompatible = {
                **current,
                "desktop_codex_version": "desktop-codex 2",
            }
            self.assertIsNone(
                _rebaseline_desktop_version_only(
                    before,
                    incompatible,
                    plugin_expected=False,
                    marketplace_root=marketplace,
                )
            )

    def test_checkpoint_baseline_cli_dispatches_to_function(self) -> None:
        root = Path("/tmp/desktop-update-baseline")
        payload = {"schema_version": 1, "status": "baseline_initialized"}

        with (
            patch.object(
                sys,
                "argv",
                [
                    "manual_desktop_update_rollback.py",
                    "checkpoint-baseline",
                    "--root",
                    str(root),
                ],
            ),
            patch.object(
                update_rollback,
                "checkpoint_baseline",
                return_value=payload,
            ) as checkpoint,
            patch("builtins.print") as output,
        ):
            result = update_rollback.main()

        self.assertEqual(0, result)
        checkpoint.assert_called_once_with(root)
        output.assert_called_once_with(json.dumps(payload, sort_keys=True))

    def test_old_baseline_prompt_requires_scoped_escalation(self) -> None:
        command = 'sh "/plugin/hooks/run_cli.sh" init --data-dir "/data"'

        prompt = _old_baseline_prompt(command)

        self.assertIn("通常のsandboxで先に試さない", prompt)
        self.assertIn("この1コマンドだけ、sandbox外での実行許可", prompt)
        self.assertIn("操作:", prompt)
        self.assertIn("目的:", prompt)
        self.assertIn("変更:", prompt)
        self.assertIn("通信:", prompt)
        self.assertIn("拒否条件:", prompt)
        self.assertIn(command, prompt)
        self.assertIn("trueを1回だけ", prompt)

    def test_inspect_marketplace_binds_all_artifact_identities(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            marketplace = self._marketplace(root, version="0.1.0-alpha.1")
            artifact = root / "old-source.tar"
            artifact.write_bytes(b"immutable old artifact")

            identity = inspect_marketplace_artifact(
                role="old",
                marketplace=marketplace,
                source_commit="2" * 40,
                source_artifact=artifact,
                expected_version="0.1.0-alpha.1",
            )

            self.assertEqual("old", identity.role)
            self.assertEqual("0.1.0-alpha.1", identity.declared_version)
            self.assertEqual("0.1.0a1", identity.python_version)
            self.assertEqual(MARKETPLACE_NAME, identity.marketplace)
            self.assertEqual(PLUGIN_ID, identity.plugin_id)
            self.assertEqual(64, len(identity.source_artifact_sha256))
            self.assertEqual(64, len(identity.plugin_tree_sha256))
            self.assertEqual(64, len(identity.hook_definition_sha256))
            self.assertEqual(64, len(identity.launcher_sha256))

    def test_inspect_marketplace_rejects_version_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            marketplace = self._marketplace(root, version="0.1.0-alpha.1")
            artifact = root / "artifact"
            artifact.write_bytes(b"artifact")
            with self.assertRaisesRegex(
                DesktopUpdateRollbackFailure,
                "plugin_version_invalid",
            ):
                inspect_marketplace_artifact(
                    role="new",
                    marketplace=marketplace,
                    source_commit="c" * 40,
                    source_artifact=artifact,
                    expected_version="0.1.0-alpha.3",
                )

    def test_tar_extractor_rejects_parent_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            archive = root / "source.tar"
            payload = root / "payload"
            payload.write_text("escape", encoding="utf-8")
            with tarfile.open(archive, "w") as handle:
                handle.add(payload, arcname="../escape")
            destination = root / "destination"
            destination.mkdir()
            with self.assertRaisesRegex(
                DesktopUpdateRollbackFailure,
                "archive_path_invalid",
            ):
                _extract_tar_safely(archive, destination)
            self.assertFalse((root / "escape").exists())

    def test_inventory_delta_preserves_unrelated_plugin_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            marketplace = root / "marketplace"
            marketplace.mkdir()
            baseline_plugin = {
                "pluginId": "other@market",
                "name": "other",
                "marketplaceName": "market",
                "version": "1.0.0",
                "enabled": True,
                "source": {"source": "local", "path": "/other"},
            }
            before = {
                "codex_cli_version": "codex 1",
                "desktop_version": "1",
                "desktop_codex_version": "codex 1",
                "installed_plugin_ids": ["other@market"],
                "marketplace_names": ["market"],
                "plugins": [baseline_plugin],
            }
            current = {
                **before,
                "installed_plugin_ids": [
                    "other@market",
                    "tooluseproxy@tooluseproxy-desktop-update",
                ],
                "marketplace_names": [
                    "market",
                    "tooluseproxy-desktop-update",
                ],
                "plugins": [
                    {**baseline_plugin, "version": "1.0.1"},
                    {
                        "pluginId": "tooluseproxy@tooluseproxy-desktop-update",
                        "name": "tooluseproxy",
                    },
                ],
                "marketplaces": [
                    {
                        "name": "tooluseproxy-desktop-update",
                        "root": str(marketplace),
                    }
                ],
            }
            self.assertTrue(
                _inventory_delta_matches(
                    before,
                    current,
                    plugin_expected=True,
                    marketplace_root=marketplace,
                )
            )
            current["plugins"][0]["enabled"] = False
            self.assertFalse(
                _inventory_delta_matches(
                    before,
                    current,
                    plugin_expected=True,
                    marketplace_root=marketplace,
                )
            )

    def test_uninstall_plan_is_bound_to_exact_data_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            data_dir = Path(temporary_directory).resolve() / "data"
            payload = {
                "status": "review_required",
                "review_required": True,
                "action": "delete_managed_data",
                "data_dir": str(data_dir),
                "managed_entry_count": 4,
                "managed_file_count": 3,
                "managed_bytes": 100,
                "unmanaged_entry_count": 0,
                "confirmation_token": "a" * 64,
            }
            self.assertEqual(
                "a" * 64,
                _validate_uninstall_plan(
                    payload,
                    data_dir=data_dir,
                )["confirmation_token"],
            )
            payload["data_dir"] = str(data_dir.parent / "other")
            with self.assertRaisesRegex(
                DesktopUpdateRollbackFailure,
                "uninstall_plan_invalid",
            ):
                _validate_uninstall_plan(payload, data_dir=data_dir)

    def test_cleanup_path_cannot_escape_run_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve() / "run"
            root.mkdir()
            outside = root.parent / "outside"
            outside.mkdir()
            with self.assertRaisesRegex(
                DesktopUpdateRollbackFailure,
                "cleanup_path_invalid",
            ):
                _remove_managed_path(outside, root=root)
            self.assertTrue(outside.is_dir())

    def _marketplace(self, root: Path, *, version: str) -> Path:
        marketplace = root / "marketplace"
        plugin = marketplace / "tooluseproxy"
        (marketplace / ".agents" / "plugins").mkdir(parents=True)
        (plugin / ".codex-plugin").mkdir(parents=True)
        (plugin / "hooks").mkdir()
        (plugin / "tooluseproxy").mkdir()
        (marketplace / ".agents" / "plugins" / "marketplace.json").write_text(
            json.dumps(
                {
                    "name": MARKETPLACE_NAME,
                    "plugins": [
                        {
                            "name": "tooluseproxy",
                            "source": {
                                "source": "local",
                                "path": "./tooluseproxy",
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        (plugin / ".codex-plugin" / "plugin.json").write_text(
            json.dumps({"name": "tooluseproxy", "version": version}),
            encoding="utf-8",
        )
        python_version = version.replace("-alpha.", "a")
        (plugin / "tooluseproxy" / "__init__.py").write_text(
            f'__version__ = "{python_version}"\n',
            encoding="utf-8",
        )
        (plugin / "hooks" / "hooks.json").write_text(
            '{"hooks": {}}\n',
            encoding="utf-8",
        )
        (plugin / "hooks" / "run_hook.sh").write_text(
            "#!/bin/sh\nexit 0\n",
            encoding="utf-8",
        )
        return marketplace


if __name__ == "__main__":
    unittest.main()
