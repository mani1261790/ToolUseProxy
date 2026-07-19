from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BUILDER = REPO_ROOT / "scripts" / "build_plugin_bundle.py"
FORBIDDEN_PARTS = {
    ".git",
    ".github",
    ".pytest_cache",
    ".ruff_cache",
    ".tooluseproxy",
    ".venv",
    "__pycache__",
    "docs",
    "scripts",
    "tests",
}


def _build_bundle(outdir: Path) -> Path:
    subprocess.run(
        [sys.executable, str(BUILDER), "--outdir", str(outdir)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    artifacts = list(outdir.glob("tooluseproxy-plugin-*.zip"))
    if len(artifacts) != 1:
        raise AssertionError(f"expected one Plugin artifact, found {artifacts}")
    return artifacts[0]


class PluginArtifactTest(unittest.TestCase):
    def test_bundle_has_a_minimal_marketplace_and_runtime_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact = _build_bundle(Path(temporary_directory))
            with zipfile.ZipFile(artifact) as archive:
                names = archive.namelist()
                marketplace = json.loads(
                    archive.read(".agents/plugins/marketplace.json").decode("utf-8")
                )

            self.assertEqual(sorted(names), names)
            self.assertEqual(len(names), len(set(names)))
            self.assertEqual(
                {"source": "local", "path": "./tooluseproxy"},
                marketplace["plugins"][0]["source"],
            )
            self.assertIn("PRIVACY.md", names)
            self.assertIn("QUICKSTART.md", names)
            self.assertIn("README.en.md", names)
            self.assertIn("README.md", names)
            self.assertIn("SUPPORT.md", names)
            self.assertIn("tooluseproxy/.codex-plugin/plugin.json", names)
            self.assertIn("tooluseproxy/hooks/hooks.json", names)
            self.assertIn("tooluseproxy/hooks/run_cli.sh", names)
            self.assertIn("tooluseproxy/hooks/run_hook.sh", names)
            self.assertIn("tooluseproxy/skills/tooluseproxy-setup/SKILL.md", names)
            self.assertIn("tooluseproxy/tooluseproxy/__main__.py", names)
            self.assertIn("tooluseproxy/hook_monitor/runtime/runner.py", names)
            self.assertNotIn("tooluseproxy/hooks/monitor_pre_tool.py", names)
            self.assertNotIn("tooluseproxy/hooks/monitor_post_tool.py", names)
            self.assertNotIn("tooluseproxy/hooks/monitor_stop.py", names)
            self.assertFalse(
                [name for name in names if name.startswith("tooluseproxy/hook_monitor/evaluation/")]
            )
            for name in names:
                parts = set(Path(name).parts)
                self.assertFalse(parts & FORBIDDEN_PARTS, name)
                self.assertFalse(name.endswith((".pyc", ".pyo", ".DS_Store")), name)
                self.assertFalse(name.endswith(".db"), name)

    def test_bundle_bytes_are_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            first = _build_bundle(root / "first")
            second = _build_bundle(root / "second")
            self.assertEqual(
                hashlib.sha256(first.read_bytes()).digest(),
                hashlib.sha256(second.read_bytes()).digest(),
            )

    @unittest.skipIf(os.name == "nt", "POSIX launcher test")
    def test_extracted_bundle_runs_outside_the_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            artifact = _build_bundle(root / "dist")
            extracted = root / "extracted marketplace"
            with zipfile.ZipFile(artifact) as archive:
                manifest = json.loads(
                    archive.read("tooluseproxy/.codex-plugin/plugin.json").decode("utf-8")
                )
                archive.extractall(extracted)

            plugin_root = extracted / "tooluseproxy"
            workspace = root / "workspace"
            data_dir = root / "plugin data"
            workspace.mkdir()
            environment = {
                **os.environ,
                "PLUGIN_ROOT": str(plugin_root),
                "PLUGIN_DATA": str(data_dir),
                "TOOLUSEPROXY_PYTHON": sys.executable,
            }
            environment.pop("PYTHONPATH", None)
            launcher = plugin_root / "hooks" / "run_cli.sh"

            version = subprocess.run(
                ["sh", str(launcher), "--version"],
                cwd=workspace,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn(
                f"tooluseproxy {manifest['version'].replace('-alpha.', 'a')}",
                version.stdout,
            )
            subprocess.run(
                [
                    "sh",
                    str(launcher),
                    "init",
                    "--codex",
                    "--workspace",
                    str(workspace),
                    "--data-dir",
                    str(data_dir),
                ],
                cwd=workspace,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
            status = subprocess.run(
                [
                    "sh",
                    str(launcher),
                    "status",
                    "--workspace",
                    str(workspace),
                    "--data-dir",
                    str(data_dir),
                    "--json",
                ],
                cwd=workspace,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual("active", json.loads(status.stdout)["status"])
            hook = subprocess.run(
                ["sh", str(plugin_root / "hooks" / "run_hook.sh"), "pre-tool-use"],
                cwd=workspace,
                env=environment,
                input=json.dumps(
                    {
                        "hook_event_name": "PreToolUse",
                        "session_id": "clean-bundle-session",
                        "turn_id": "clean-bundle-turn",
                        "tool_use_id": "clean-bundle-call",
                        "tool_name": "Bash",
                        "tool_input": {"command": "printf public"},
                        "cwd": str(workspace),
                    }
                ),
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual("", hook.stdout)
            with sqlite3.connect(data_dir / "events.db") as connection:
                self.assertEqual(
                    1,
                    connection.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                )

    @unittest.skipUnless(
        shutil.which("codex")
        and os.environ.get("TOOLUSEPROXY_RUN_CODEX_PLUGIN_TEST") == "1",
        "set TOOLUSEPROXY_RUN_CODEX_PLUGIN_TEST=1 for local Codex installation",
    )
    def test_codex_installs_only_the_bundled_plugin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            artifact = _build_bundle(root / "dist")
            marketplace_root = root / "marketplace"
            with zipfile.ZipFile(artifact) as archive:
                expected_installed_files = {
                    Path(name).relative_to("tooluseproxy")
                    for name in archive.namelist()
                    if name.startswith("tooluseproxy/")
                }
                archive.extractall(marketplace_root)
            codex_home = root / "codex-home"
            codex_home.mkdir()
            environment = {**os.environ, "CODEX_HOME": str(codex_home)}
            codex = shutil.which("codex")
            assert codex is not None

            subprocess.run(
                [codex, "plugin", "marketplace", "add", str(marketplace_root), "--json"],
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
            installed = subprocess.run(
                [codex, "plugin", "add", "tooluseproxy@tooluseproxy", "--json"],
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
            installed_path = Path(json.loads(installed.stdout)["installedPath"])
            installed_files = [path for path in installed_path.rglob("*") if path.is_file()]
            self.assertTrue(installed_files)
            self.assertEqual(
                expected_installed_files,
                {path.relative_to(installed_path) for path in installed_files},
            )
            for path in installed_files:
                relative = path.relative_to(installed_path)
                self.assertFalse(set(relative.parts) & FORBIDDEN_PARTS, str(relative))
            self.assertFalse((installed_path / ".agents").exists())
            self.assertFalse((installed_path / "PRIVACY.md").exists())
            self.assertFalse((installed_path / "QUICKSTART.md").exists())
            self.assertFalse((installed_path / "README.en.md").exists())
            self.assertFalse((installed_path / "README.md").exists())
            self.assertFalse((installed_path / "SUPPORT.md").exists())
            self.assertTrue((installed_path / "tooluseproxy" / "__main__.py").is_file())


if __name__ == "__main__":
    unittest.main()
