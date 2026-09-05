from __future__ import annotations

import functools
import http.server
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_COMMIT = "22974427ab62e55a00d21af164d8fc837cb5e8b7"
BASELINE_PLUGIN_VERSION = "0.1.0-alpha.1"
STALE_ALPHA8_COMMIT = "4f771d0099e60957cebaa35125fb53a0fc62af4f"
STALE_ALPHA8_VERSION = "0.1.0-alpha.8"
CURRENT_PLUGIN_VERSION = "0.1.0-alpha.13"
CURRENT_PYTHON_VERSION = "0.1.0a13"
UPDATE_REF = "public-alpha-test"


class _QuietRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        del format, args


@unittest.skipUnless(
    shutil.which("codex") and shutil.which("git"),
    "Codex CLI and Git are required for marketplace upgrade rehearsal",
)
class CodexMarketplaceUpgradeTest(unittest.TestCase):
    def test_same_named_stale_alpha8_is_replaced_by_alpha11(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="tooluseproxy-stale-alpha8-upgrade-"
        ) as temporary_directory:
            root = Path(temporary_directory)
            bare_repository = root / "tooluseproxy-marketplace.git"
            codex_home = root / "codex-home"
            home = root / "home"
            codex_home.mkdir()
            home.mkdir()
            self._run(
                ["git", "clone", "--quiet", "--bare", str(REPO_ROOT), str(bare_repository)]
            )
            self._move_update_ref(bare_repository, STALE_ALPHA8_COMMIT)
            handler = functools.partial(_QuietRequestHandler, directory=str(root))
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            try:
                environment = {
                    **os.environ,
                    "CODEX_HOME": str(codex_home),
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_TERMINAL_PROMPT": "0",
                    "HOME": str(home),
                    "NO_COLOR": "1",
                }
                marketplace_url = (
                    f"http://127.0.0.1:{server.server_address[1]}/"
                    f"{bare_repository.name}"
                )
                self._run_json(
                    [
                        "codex",
                        "plugin",
                        "marketplace",
                        "add",
                        marketplace_url,
                        "--ref",
                        UPDATE_REF,
                        "--json",
                    ],
                    env=environment,
                )
                installed = self._run_json(
                    [
                        "codex",
                        "plugin",
                        "add",
                        "tooluseproxy@tooluseproxy",
                        "--json",
                    ],
                    env=environment,
                )
                self.assertEqual(STALE_ALPHA8_VERSION, installed["version"])
                stale_root = Path(installed["installedPath"])
                stale_hooks = json.loads(
                    (stale_root / "hooks" / "hooks.json").read_text(encoding="utf-8")
                )
                self.assertEqual(3, len(stale_hooks["hooks"]))
                data_directory = (
                    codex_home / "plugins" / "data" / "tooluseproxy-tooluseproxy"
                )
                data_directory.mkdir(parents=True)
                retained = data_directory / "retained.marker"
                retained.write_text("retained", encoding="utf-8")

                self._move_update_ref(bare_repository, "HEAD")
                upgraded = self._run_json(
                    [
                        "codex",
                        "plugin",
                        "marketplace",
                        "upgrade",
                        "tooluseproxy",
                        "--json",
                    ],
                    env=environment,
                )
                self.assertEqual([], upgraded["errors"])
                plugins = self._run_json(
                    ["codex", "plugin", "list", "--json"],
                    env=environment,
                )
                self.assertEqual(CURRENT_PLUGIN_VERSION, plugins["installed"][0]["version"])
                current_root = Path(plugins["installed"][0]["source"]["path"])
                current_hooks = json.loads(
                    (current_root / "hooks" / "hooks.json").read_text(encoding="utf-8")
                )
                self.assertEqual(
                    {
                        "SessionStart",
                        "SubagentStart",
                        "PreToolUse",
                        "PostToolUse",
                        "Stop",
                    },
                    set(current_hooks["hooks"]),
                )
                self.assertFalse(stale_root.exists())
                self.assertEqual("retained", retained.read_text(encoding="utf-8"))
            finally:
                server.shutdown()
                server.server_close()
                server_thread.join(timeout=5)

    def test_marketplace_upgrade_replaces_plugin_and_preserves_managed_data(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="tooluseproxy-marketplace-upgrade-"
        ) as temporary_directory:
            root = Path(temporary_directory)
            bare_repository = root / "tooluseproxy-marketplace.git"
            codex_home = root / "codex-home"
            home = root / "home"
            workspace = root / "workspace"
            data_directory = root / "plugin-data"
            codex_home.mkdir()
            home.mkdir()
            workspace.mkdir()

            self._run(
                ["git", "clone", "--quiet", "--bare", str(REPO_ROOT), str(bare_repository)]
            )
            self._move_update_ref(bare_repository, BASELINE_COMMIT)

            handler = functools.partial(
                _QuietRequestHandler,
                directory=str(root),
            )
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            try:
                port = server.server_address[1]
                marketplace_url = (
                    f"http://127.0.0.1:{port}/{bare_repository.name}"
                )
                environment = {
                    **os.environ,
                    "CODEX_HOME": str(codex_home),
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_TERMINAL_PROMPT": "0",
                    "HOME": str(home),
                    "NO_COLOR": "1",
                }

                added = self._run_json(
                    [
                        "codex",
                        "plugin",
                        "marketplace",
                        "add",
                        marketplace_url,
                        "--ref",
                        UPDATE_REF,
                        "--json",
                    ],
                    env=environment,
                )
                self.assertEqual("tooluseproxy", added["marketplaceName"])
                installed = self._run_json(
                    [
                        "codex",
                        "plugin",
                        "add",
                        "tooluseproxy@tooluseproxy",
                        "--json",
                    ],
                    env=environment,
                )
                self.assertEqual(BASELINE_PLUGIN_VERSION, installed["version"])
                baseline_root = Path(installed["installedPath"])
                baseline_cli = baseline_root / "hooks" / "run_cli.sh"
                initialized = self._run_json(
                    [
                        "sh",
                        str(baseline_cli),
                        "init",
                        "--codex",
                        "--workspace",
                        str(workspace),
                        "--data-dir",
                        str(data_directory),
                        "--json",
                    ],
                    cwd=workspace,
                    env=environment,
                )
                self.assertEqual("0.1.0a1", initialized["version"])
                database = data_directory / "events.db"
                self.assertTrue(database.is_file())

                self._move_update_ref(bare_repository, "HEAD")
                upgraded = self._run_json(
                    [
                        "codex",
                        "plugin",
                        "marketplace",
                        "upgrade",
                        "tooluseproxy",
                        "--json",
                    ],
                    env=environment,
                )
                self.assertEqual(["tooluseproxy"], upgraded["selectedMarketplaces"])
                self.assertEqual([], upgraded["errors"])

                plugins = self._run_json(
                    ["codex", "plugin", "list", "--json"],
                    env=environment,
                )
                self.assertEqual(1, len(plugins["installed"]))
                self.assertEqual(
                    CURRENT_PLUGIN_VERSION,
                    plugins["installed"][0]["version"],
                )
                current_root = (
                    codex_home
                    / "plugins"
                    / "cache"
                    / "tooluseproxy"
                    / "tooluseproxy"
                    / CURRENT_PLUGIN_VERSION
                )
                self.assertTrue(current_root.is_dir())
                self.assertFalse(baseline_root.exists())
                self.assertTrue(database.is_file())

                current_cli = current_root / "hooks" / "run_cli.sh"
                migrated = self._run_json(
                    [
                        "sh",
                        str(current_cli),
                        "init",
                        "--codex",
                        "--workspace",
                        str(workspace),
                        "--data-dir",
                        str(data_directory),
                        "--json",
                    ],
                    cwd=workspace,
                    env=environment,
                )
                self.assertEqual(CURRENT_PYTHON_VERSION, migrated["version"])
                self.assertIsInstance(migrated["migration_backup"], str)
                status_result = self._run(
                    [
                        "sh",
                        str(current_cli),
                        "status",
                        "--workspace",
                        str(workspace),
                        "--data-dir",
                        str(data_directory),
                        "--json",
                    ],
                    cwd=workspace,
                    env=environment,
                    expected_returncodes=(1,),
                )
                status = json.loads(status_result.stdout)
                self.assertEqual("inactive", status["status"])
                self.assertEqual(CURRENT_PYTHON_VERSION, status["version"])
            finally:
                server.shutdown()
                server.server_close()
                server_thread.join(timeout=5)

    def _move_update_ref(self, bare_repository: Path, revision: str) -> None:
        self._run(
            [
                "git",
                f"--git-dir={bare_repository}",
                "branch",
                "-f",
                UPDATE_REF,
                revision,
            ]
        )
        self._run(
            ["git", f"--git-dir={bare_repository}", "update-server-info"]
        )

    def _run_json(
        self,
        command: list[str],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        result = self._run(command, cwd=cwd, env=env)
        payload = json.loads(result.stdout)
        self.assertIsInstance(payload, dict)
        return payload

    def _run(
        self,
        command: list[str],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        expected_returncodes: tuple[int, ...] = (0,),
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            command,
            cwd=cwd or REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertIn(
            result.returncode,
            expected_returncodes,
            f"{' '.join(command)}\n{result.stdout}\n{result.stderr}",
        )
        return result


if __name__ == "__main__":
    unittest.main()
