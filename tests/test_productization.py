from __future__ import annotations

import io
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
import venv
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from hook_monitor.runtime.storage import EventStore
from tooluseproxy import __version__
from tooluseproxy.cli import main as cli_main
from tooluseproxy.paths import (
    PathConfigurationError,
    default_user_data_dir,
    resolve_runtime_paths,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


class RuntimePathsTest(unittest.TestCase):
    def test_explicit_and_environment_precedence_is_stable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            environment = {
                "TOOLUSEPROXY_DB_PATH": str(root / "environment.db"),
                "TOOLUSEPROXY_DATA_DIR": str(root / "environment-data"),
                "PLUGIN_DATA": str(root / "plugin-data"),
            }
            explicit = resolve_runtime_paths(
                db_path=root / "explicit.db",
                environ=environment,
            )
            environment_db = resolve_runtime_paths(environ=environment)
            data_environment = dict(environment)
            data_environment.pop("TOOLUSEPROXY_DB_PATH")
            environment_data = resolve_runtime_paths(environ=data_environment)
            plugin_environment = {"PLUGIN_DATA": str(root / "plugin-data")}
            plugin_data = resolve_runtime_paths(environ=plugin_environment)

            self.assertEqual(root / "explicit.db", explicit.db_path)
            self.assertEqual("explicit_db", explicit.source)
            self.assertEqual(root / "environment.db", environment_db.db_path)
            self.assertEqual("environment_db", environment_db.source)
            self.assertEqual(
                root / "environment-data" / "events.db",
                environment_data.db_path,
            )
            self.assertEqual(
                root / "plugin-data" / "events.db",
                plugin_data.db_path,
            )

    def test_explicit_db_and_data_dir_are_rejected_together(self) -> None:
        with self.assertRaises(PathConfigurationError):
            resolve_runtime_paths(db_path="one.db", data_dir="data")

    def test_platform_defaults_do_not_depend_on_repository_layout(self) -> None:
        home = Path("/users/example")
        self.assertEqual(
            home / "Library" / "Application Support" / "ToolUseProxy",
            default_user_data_dir(environ={}, platform="darwin", home=home),
        )
        self.assertEqual(
            home / ".local" / "state" / "tooluseproxy",
            default_user_data_dir(environ={}, platform="linux", home=home),
        )
        self.assertEqual(
            Path("/state") / "tooluseproxy",
            default_user_data_dir(
                environ={"XDG_STATE_HOME": "/state"},
                platform="linux",
                home=home,
            ),
        )


class ProductCliTest(unittest.TestCase):
    def test_codex_init_rejects_an_unknown_plugin_data_directory(self) -> None:
        stderr = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), redirect_stderr(stderr):
            exit_code = cli_main(["init", "--codex"])
        self.assertEqual(1, exit_code)
        self.assertIn("Plugin data directory is unknown", stderr.getvalue())

    def test_codex_init_rejects_a_data_directory_split_from_plugin_data(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workspace = root / "workspace"
            workspace.mkdir()
            stderr = io.StringIO()
            with patch.dict(
                os.environ,
                {"PLUGIN_DATA": str(root / "plugin-data")},
                clear=True,
            ), redirect_stderr(stderr):
                exit_code = cli_main(
                    [
                        "init",
                        "--codex",
                        "--workspace",
                        str(workspace),
                        "--data-dir",
                        str(root / "different-data"),
                    ]
                )
            self.assertEqual(1, exit_code)
            self.assertIn("does not match", stderr.getvalue())
            self.assertFalse((root / "different-data").exists())

    def test_init_doctor_and_status_share_one_database(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workspace = root / "workspace with space 日本語"
            data_dir = root / "runtime data"
            workspace.mkdir()

            init_stdout = io.StringIO()
            with redirect_stdout(init_stdout):
                exit_code = cli_main(
                    [
                        "init",
                        "--codex",
                        "--workspace",
                        str(workspace),
                        "--data-dir",
                        str(data_dir),
                        "--json",
                    ]
                )
            self.assertEqual(0, exit_code)
            initialized = json.loads(init_stdout.getvalue())
            self.assertEqual(str(data_dir / "events.db"), initialized["db_path"])
            self.assertTrue(initialized["manifest_created"])
            self.assertEqual(
                {"schema_version": 1, "sources": []},
                json.loads((workspace / "protected_sources.json").read_text()),
            )
            if os.name == "posix":
                self.assertEqual(0o700, stat.S_IMODE(data_dir.stat().st_mode))
                self.assertEqual(
                    0o600,
                    stat.S_IMODE((data_dir / "events.db").stat().st_mode),
                )
                self.assertEqual(
                    0o600,
                    stat.S_IMODE(
                        (workspace / "protected_sources.json").stat().st_mode
                    ),
                )

            for command in ("doctor", "status"):
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    exit_code = cli_main(
                        [
                            command,
                            "--workspace",
                            str(workspace),
                            "--data-dir",
                            str(data_dir),
                            "--json",
                        ]
                    )
                self.assertEqual(0, exit_code, stdout.getvalue())
                payload = json.loads(stdout.getvalue())
                self.assertEqual(str(data_dir / "events.db"), payload["db_path"])

            with sqlite3.connect(data_dir / "events.db") as conn:
                registered = conn.execute(
                    "SELECT canonical_root FROM workspaces"
                ).fetchall()
                schema_version = conn.execute("PRAGMA user_version").fetchone()[0]
            self.assertEqual([(str(workspace.resolve()),)], registered)
            self.assertEqual(1, schema_version)

            nested = workspace / "nested" / "directory"
            nested.mkdir(parents=True)
            store = EventStore(data_dir / "events.db")
            self.assertEqual(
                str(workspace.resolve()),
                store.find_registered_workspace_root(str(nested)),
            )

    def test_init_does_not_replace_an_existing_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workspace = root / "workspace"
            workspace.mkdir()
            manifest = workspace / "protected_sources.json"
            original = {
                "sources": [
                    {
                        "id": "private",
                        "path": "private.txt",
                        "type": "file",
                        "sensitivity": "private",
                    }
                ]
            }
            (workspace / "private.txt").write_text("secret", encoding="utf-8")
            manifest.write_text(json.dumps(original), encoding="utf-8")

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = cli_main(
                    [
                        "init",
                        "--workspace",
                        str(workspace),
                        "--data-dir",
                        str(root / "data"),
                        "--json",
                    ]
                )
            self.assertEqual(0, exit_code)
            self.assertFalse(json.loads(stdout.getvalue())["manifest_created"])
            self.assertEqual(original, json.loads(manifest.read_text()))

    def test_init_does_not_replace_a_manifest_created_concurrently(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workspace = root / "workspace"
            workspace.mkdir()
            manifest = workspace / "protected_sources.json"
            concurrent = {"schema_version": 1, "sources": []}
            real_link = os.link

            def create_competing_manifest(source: object, destination: object) -> None:
                manifest.write_text(json.dumps(concurrent), encoding="utf-8")
                real_link(source, destination)

            stdout = io.StringIO()
            with patch(
                "tooluseproxy.cli.os.link",
                side_effect=create_competing_manifest,
            ), redirect_stdout(stdout):
                exit_code = cli_main(
                    [
                        "init",
                        "--workspace",
                        str(workspace),
                        "--data-dir",
                        str(root / "data"),
                        "--json",
                    ]
                )

            self.assertEqual(0, exit_code)
            self.assertFalse(json.loads(stdout.getvalue())["manifest_created"])
            self.assertEqual(concurrent, json.loads(manifest.read_text()))

    @unittest.skipUnless(os.name == "posix", "POSIX permission diagnostic")
    def test_doctor_rejects_a_group_readable_existing_data_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workspace = root / "workspace"
            data_dir = root / "data"
            workspace.mkdir()
            data_dir.mkdir()
            data_dir.chmod(0o750)

            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    0,
                    cli_main(
                        [
                            "init",
                            "--workspace",
                            str(workspace),
                            "--data-dir",
                            str(data_dir),
                            "--json",
                        ]
                    ),
                )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = cli_main(
                    [
                        "doctor",
                        "--workspace",
                        str(workspace),
                        "--data-dir",
                        str(data_dir),
                        "--json",
                    ]
                )

            self.assertEqual(1, exit_code)
            payload = json.loads(stdout.getvalue())
            permission_check = next(
                check
                for check in payload["checks"]
                if check["name"] == "data_directory_permissions"
            )
            self.assertFalse(permission_check["ok"])
            self.assertIn("chmod 700", permission_check["detail"])

    def test_database_import_uses_a_distinct_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workspace = root / "workspace"
            workspace.mkdir()
            source = root / "legacy.db"
            with sqlite3.connect(source) as conn:
                conn.execute("CREATE TABLE legacy_marker (value TEXT NOT NULL)")
                conn.execute("INSERT INTO legacy_marker VALUES ('preserved')")

            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = cli_main(
                    [
                        "init",
                        "--workspace",
                        str(workspace),
                        "--data-dir",
                        str(root / "data"),
                        "--import-db",
                        str(source),
                        "--json",
                    ]
                )
            self.assertEqual(0, exit_code, stderr.getvalue())
            with sqlite3.connect(root / "data" / "events.db") as conn:
                value = conn.execute("SELECT value FROM legacy_marker").fetchone()
            self.assertEqual(("preserved",), value)
            if os.name == "posix":
                self.assertEqual(
                    0o600,
                    stat.S_IMODE((root / "data" / "events.db").stat().st_mode),
                )

    def test_database_import_rejects_a_newer_schema_without_a_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workspace = root / "workspace"
            workspace.mkdir()
            source = root / "future.db"
            with sqlite3.connect(source) as conn:
                conn.execute("CREATE TABLE future_data (value TEXT NOT NULL)")
                conn.execute("INSERT INTO future_data VALUES ('preserved')")
                conn.execute("PRAGMA user_version = 99")

            destination = root / "data" / "events.db"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                exit_code = cli_main(
                    [
                        "init",
                        "--workspace",
                        str(workspace),
                        "--data-dir",
                        str(root / "data"),
                        "--import-db",
                        str(source),
                    ]
                )

            self.assertEqual(1, exit_code)
            self.assertIn("newer than runtime", stderr.getvalue())
            self.assertFalse(destination.exists())
            with sqlite3.connect(source) as conn:
                self.assertEqual(99, conn.execute("PRAGMA user_version").fetchone()[0])
                self.assertEqual(
                    ("preserved",),
                    conn.execute("SELECT value FROM future_data").fetchone(),
                )

    def test_init_backs_up_an_older_schema_before_upgrade(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workspace = root / "workspace"
            data_dir = root / "data"
            workspace.mkdir()
            store = EventStore(data_dir / "events.db")
            store.initialize()
            with sqlite3.connect(store.db_path) as conn:
                conn.execute("CREATE TABLE migration_marker (value TEXT NOT NULL)")
                conn.execute("INSERT INTO migration_marker VALUES ('before-upgrade')")
                conn.execute("PRAGMA user_version = 0")

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = cli_main(
                    [
                        "init",
                        "--workspace",
                        str(workspace),
                        "--data-dir",
                        str(data_dir),
                        "--json",
                    ]
                )
            self.assertEqual(0, exit_code)
            backup = Path(json.loads(stdout.getvalue())["migration_backup"])
            self.assertTrue(backup.is_file())
            if os.name == "posix":
                self.assertEqual(0o600, stat.S_IMODE(backup.stat().st_mode))
            with sqlite3.connect(backup) as conn:
                self.assertEqual(0, conn.execute("PRAGMA user_version").fetchone()[0])
                self.assertEqual(
                    ("before-upgrade",),
                    conn.execute("SELECT value FROM migration_marker").fetchone(),
                )
            with sqlite3.connect(store.db_path) as conn:
                self.assertEqual(1, conn.execute("PRAGMA user_version").fetchone()[0])

    def test_init_backs_up_an_incomplete_current_schema_before_repair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workspace = root / "workspace"
            data_dir = root / "data"
            workspace.mkdir()
            data_dir.mkdir()
            db_path = data_dir / "events.db"
            with sqlite3.connect(db_path) as conn:
                conn.execute("CREATE TABLE preserved (value TEXT NOT NULL)")
                conn.execute("INSERT INTO preserved VALUES ('before-repair')")
                conn.execute("PRAGMA user_version = 1")

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = cli_main(
                    [
                        "init",
                        "--codex",
                        "--workspace",
                        str(workspace),
                        "--data-dir",
                        str(data_dir),
                        "--json",
                    ]
                )

            self.assertEqual(0, exit_code)
            backup = Path(json.loads(stdout.getvalue())["migration_backup"])
            self.assertTrue(backup.is_file())
            with sqlite3.connect(backup) as conn:
                self.assertEqual(
                    ("before-repair",),
                    conn.execute("SELECT value FROM preserved").fetchone(),
                )
            EventStore(db_path).require_runtime_schema()

    def test_init_rejects_a_newer_schema_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workspace = root / "workspace"
            data_dir = root / "data"
            workspace.mkdir()
            data_dir.mkdir()
            db_path = data_dir / "events.db"
            with sqlite3.connect(db_path) as conn:
                conn.execute("CREATE TABLE future_data (value TEXT NOT NULL)")
                conn.execute("INSERT INTO future_data VALUES ('preserved')")
                conn.execute("PRAGMA user_version = 99")

            stderr = io.StringIO()
            with redirect_stderr(stderr):
                exit_code = cli_main(
                    [
                        "init",
                        "--workspace",
                        str(workspace),
                        "--data-dir",
                        str(data_dir),
                    ]
                )
            self.assertEqual(1, exit_code)
            self.assertIn("newer than runtime", stderr.getvalue())
            with sqlite3.connect(db_path) as conn:
                self.assertEqual(99, conn.execute("PRAGMA user_version").fetchone()[0])
                self.assertEqual(
                    ("preserved",),
                    conn.execute("SELECT value FROM future_data").fetchone(),
                )

    def test_product_hook_does_not_create_an_uninitialized_database(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            data_dir = root / "data"
            payload = {
                "hook_event_name": "PreToolUse",
                "session_id": "session",
                "turn_id": "turn",
                "tool_use_id": "call",
                "tool_name": "Bash",
                "tool_input": {"command": "printf public"},
                "cwd": str(root),
            }
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tooluseproxy",
                    "hook",
                    "pre-tool-use",
                    "--data-dir",
                    str(data_dir),
                ],
                cwd=REPO_ROOT,
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual("", result.stdout)
            self.assertIn("database_missing", result.stderr)
            self.assertFalse((data_dir / "events.db").exists())

    def test_product_hook_fails_open_before_using_an_incomplete_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            data_dir = root / "data"
            data_dir.mkdir()
            db_path = data_dir / "events.db"
            with sqlite3.connect(db_path) as conn:
                conn.execute("CREATE TABLE workspaces (workspace_id TEXT PRIMARY KEY)")
                conn.execute("CREATE TABLE events (event_id TEXT PRIMARY KEY)")
                conn.execute("CREATE TABLE analysis_state (key TEXT PRIMARY KEY)")
                conn.execute("PRAGMA user_version = 1")
            before = db_path.read_bytes()
            payload = {
                "hook_event_name": "PreToolUse",
                "session_id": "session",
                "turn_id": "turn",
                "tool_use_id": "call",
                "tool_name": "Bash",
                "tool_input": {"command": "printf public"},
                "cwd": str(root),
            }

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tooluseproxy",
                    "hook",
                    "pre-tool-use",
                    "--data-dir",
                    str(data_dir),
                ],
                cwd=REPO_ROOT,
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                check=True,
            )

            self.assertEqual("", result.stdout)
            self.assertIn("schema_incomplete", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertEqual(before, db_path.read_bytes())

    def test_status_rejects_an_unregistered_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            registered = root / "registered"
            unregistered = root / "unregistered"
            data_dir = root / "data"
            registered.mkdir()
            unregistered.mkdir()
            for workspace in (registered, unregistered):
                (workspace / "protected_sources.json").write_text(
                    json.dumps({"schema_version": 1, "sources": []}),
                    encoding="utf-8",
                )
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    0,
                    cli_main(
                        [
                            "init",
                            "--codex",
                            "--workspace",
                            str(registered),
                            "--data-dir",
                            str(data_dir),
                            "--json",
                        ]
                    ),
                )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = cli_main(
                    [
                        "status",
                        "--workspace",
                        str(unregistered),
                        "--data-dir",
                        str(data_dir),
                        "--json",
                    ]
                )

            self.assertEqual(1, exit_code)
            payload = json.loads(stdout.getvalue())
            self.assertEqual("inactive", payload["status"])
            self.assertFalse(payload["workspace_registration"]["ok"])

    def test_product_hook_uses_the_registered_root_from_a_nested_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workspace = root / "workspace"
            nested = workspace / "nested" / "directory"
            data_dir = root / "data"
            nested.mkdir(parents=True)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    0,
                    cli_main(
                        [
                            "init",
                            "--codex",
                            "--workspace",
                            str(workspace),
                            "--data-dir",
                            str(data_dir),
                            "--json",
                        ]
                    ),
                )
            payload = {
                "hook_event_name": "PreToolUse",
                "session_id": "nested-session",
                "turn_id": "nested-turn",
                "tool_use_id": "nested-call",
                "tool_name": "Bash",
                "tool_input": {"command": "printf public"},
                "cwd": str(nested),
            }

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tooluseproxy",
                    "hook",
                    "pre-tool-use",
                    "--data-dir",
                    str(data_dir),
                ],
                cwd=REPO_ROOT,
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                check=True,
            )

            with sqlite3.connect(data_dir / "events.db") as conn:
                recorded = conn.execute(
                    "SELECT workspace_root, workspace_source FROM events"
                ).fetchone()
            self.assertEqual(
                (str(workspace.resolve()), "registered_root"),
                recorded,
            )


class PluginBundleTest(unittest.TestCase):
    def test_plugin_manifest_and_hook_commands_are_relocatable(self) -> None:
        manifest = json.loads(
            (REPO_ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8")
        )
        hooks = json.loads(
            (REPO_ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8")
        )

        self.assertEqual("tooluseproxy", manifest["name"])
        self.assertEqual(__version__, manifest["version"].replace("-alpha.", "a"))
        self.assertNotIn("hooks", manifest)
        rendered_hooks = json.dumps(hooks)
        self.assertIn("PLUGIN_ROOT", rendered_hooks)
        self.assertNotIn(str(REPO_ROOT), rendered_hooks)

    @unittest.skipIf(os.name == "nt", "POSIX launcher test")
    def test_relocated_plugin_uses_plugin_data_without_checkout_imports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            plugin_root = root / "installed plugin"
            plugin_root.mkdir()
            for directory in (".codex-plugin", "hook_monitor", "hooks", "skills", "tooluseproxy"):
                shutil.copytree(
                    REPO_ROOT / directory,
                    plugin_root / directory,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
                )
            shutil.copy2(
                REPO_ROOT / "tooluseproxy_plugin.py",
                plugin_root / "tooluseproxy_plugin.py",
            )
            workspace = root / "workspace with space"
            workspace.mkdir()
            data_dir = root / "plugin data"
            environment = dict(os.environ)
            environment.update(
                {
                    "PLUGIN_ROOT": str(plugin_root),
                    "PLUGIN_DATA": str(data_dir),
                    "TOOLUSEPROXY_PYTHON": sys.executable,
                }
            )
            environment.pop("PYTHONPATH", None)
            hook_launcher = plugin_root / "hooks" / "run_hook.sh"
            cli_launcher = plugin_root / "hooks" / "run_cli.sh"
            payload = {
                "hook_event_name": "PreToolUse",
                "session_id": "plugin-session",
                "turn_id": "plugin-turn",
                "tool_use_id": "plugin-call",
                "tool_name": "Bash",
                "tool_input": {"command": "printf public"},
                "cwd": str(workspace),
            }

            inactive = subprocess.run(
                ["sh", str(hook_launcher), "pre-tool-use"],
                cwd=workspace,
                env=environment,
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn("database_missing", inactive.stderr)
            self.assertIn(str(cli_launcher), inactive.stderr)
            self.assertIn(str(data_dir), inactive.stderr)
            self.assertFalse((data_dir / "events.db").exists())

            initialized = subprocess.run(
                [
                    "sh",
                    str(cli_launcher),
                    "init",
                    "--codex",
                    "--workspace",
                    str(workspace),
                    "--data-dir",
                    str(data_dir),
                    "--json",
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual("initialized", json.loads(initialized.stdout)["status"])
            doctor = subprocess.run(
                [
                    "sh",
                    str(cli_launcher),
                    "doctor",
                    "--workspace",
                    str(workspace),
                    "--data-dir",
                    str(data_dir),
                    "--json",
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=True,
            )
            doctor_payload = json.loads(doctor.stdout)
            self.assertEqual("ok", doctor_payload["status"])
            self.assertTrue(
                next(
                    check
                    for check in doctor_payload["checks"]
                    if check["name"] == "plugin_environment"
                )["ok"]
            )

            active = subprocess.run(
                ["sh", str(hook_launcher), "pre-tool-use"],
                cwd=workspace,
                env=environment,
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual("", active.stdout)
            self.assertEqual("", active.stderr)
            post_payload = {
                **payload,
                "hook_event_name": "PostToolUse",
                "tool_response": {"output": "public"},
            }
            post = subprocess.run(
                ["sh", str(hook_launcher), "post-tool-use"],
                cwd=workspace,
                env=environment,
                input=json.dumps(post_payload),
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual("", post.stdout)
            self.assertEqual("", post.stderr)
            stop = subprocess.run(
                ["sh", str(hook_launcher), "stop"],
                cwd=workspace,
                env=environment,
                input=json.dumps(
                    {
                        "hook_event_name": "Stop",
                        "session_id": "plugin-session",
                        "turn_id": "plugin-turn",
                        "stop_hook_active": False,
                        "cwd": str(workspace),
                        "last_assistant_message": "Public final answer.",
                    }
                ),
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual("", stop.stdout)
            self.assertEqual("", stop.stderr)
            with sqlite3.connect(data_dir / "events.db") as conn:
                row = conn.execute(
                    "SELECT workspace_root, workspace_source FROM events"
                    " WHERE phase = 'pre_tool_use'"
                ).fetchone()
                phases = conn.execute(
                    "SELECT phase FROM events ORDER BY sequence_no"
                ).fetchall()
            self.assertEqual((str(workspace.resolve()), "hook_cwd"), row)
            self.assertEqual(
                [("pre_tool_use",), ("post_tool_use",), ("stop",)],
                phases,
            )

    @unittest.skipIf(os.name == "nt", "POSIX launcher test")
    def test_plugin_hook_fails_open_when_python_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            data_dir = Path(temporary_directory) / "plugin-data"
            environment = {
                "PATH": "",
                "PLUGIN_ROOT": str(REPO_ROOT),
                "PLUGIN_DATA": str(data_dir),
            }
            result = subprocess.run(
                ["/bin/sh", str(REPO_ROOT / "hooks" / "run_hook.sh"), "stop"],
                env=environment,
                input="{}",
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual("", result.stdout)
            self.assertIn("python_missing", result.stderr)
            self.assertFalse((data_dir / "events.db").exists())

    @unittest.skipIf(os.name == "nt", "POSIX launcher test")
    def test_plugin_hook_fails_open_when_payload_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workspace = root / "workspace"
            data_dir = root / "plugin-data"
            workspace.mkdir()
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    0,
                    cli_main(
                        [
                            "init",
                            "--workspace",
                            str(workspace),
                            "--data-dir",
                            str(data_dir),
                        ]
                    ),
                )
            environment = {
                **os.environ,
                "PLUGIN_ROOT": str(REPO_ROOT),
                "PLUGIN_DATA": str(data_dir),
                "TOOLUSEPROXY_PYTHON": sys.executable,
            }
            result = subprocess.run(
                ["sh", str(REPO_ROOT / "hooks" / "run_hook.sh"), "stop"],
                cwd=workspace,
                env=environment,
                input="not-json",
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, result.returncode)
            with sqlite3.connect(data_dir / "events.db") as conn:
                self.assertEqual(
                    0,
                    conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                )

    @unittest.skipUnless(
        shutil.which("codex")
        and os.environ.get("TOOLUSEPROXY_RUN_CODEX_PLUGIN_TEST") == "1",
        "set TOOLUSEPROXY_RUN_CODEX_PLUGIN_TEST=1 for local Codex installation",
    )
    def test_codex_cli_installs_the_plugin_from_an_isolated_marketplace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            codex_home = root / "codex-home"
            codex_home.mkdir()
            environment = {**os.environ, "CODEX_HOME": str(codex_home)}
            codex = shutil.which("codex")
            assert codex is not None

            subprocess.run(
                [
                    codex,
                    "plugin",
                    "marketplace",
                    "add",
                    str(REPO_ROOT),
                    "--json",
                ],
                env=environment,
                capture_output=True,
                text=True,
                check=True,
            )
            installed = subprocess.run(
                [
                    codex,
                    "plugin",
                    "add",
                    "tooluseproxy@tooluseproxy",
                    "--json",
                ],
                env=environment,
                capture_output=True,
                text=True,
                check=True,
            )
            payload = json.loads(installed.stdout)
            installed_path = Path(payload["installedPath"])
            self.assertTrue((installed_path / ".codex-plugin" / "plugin.json").is_file())
            self.assertTrue((installed_path / "hooks" / "hooks.json").is_file())
            marketplace = json.loads(
                (REPO_ROOT / ".agents" / "plugins" / "marketplace.json").read_text(
                    encoding="utf-8"
                )
            )
            source = marketplace["plugins"][0]["source"]
            self.assertEqual({"source": "local", "path": "./"}, source)

            workspace = root / "workspace"
            plugin_data = root / "plugin-data"
            workspace.mkdir()
            plugin_environment = {
                **environment,
                "PLUGIN_ROOT": str(installed_path),
                "PLUGIN_DATA": str(plugin_data),
                "TOOLUSEPROXY_PYTHON": sys.executable,
            }
            plugin_environment.pop("PYTHONPATH", None)
            subprocess.run(
                [
                    "sh",
                    str(installed_path / "hooks" / "run_cli.sh"),
                    "init",
                    "--codex",
                    "--workspace",
                    str(workspace),
                    "--data-dir",
                    str(plugin_data),
                ],
                cwd=workspace,
                env=plugin_environment,
                capture_output=True,
                text=True,
                check=True,
            )
            subprocess.run(
                [
                    "sh",
                    str(installed_path / "hooks" / "run_hook.sh"),
                    "pre-tool-use",
                ],
                cwd=workspace,
                env=plugin_environment,
                input=json.dumps(
                    {
                        "hook_event_name": "PreToolUse",
                        "session_id": "installed-plugin-session",
                        "turn_id": "installed-plugin-turn",
                        "tool_use_id": "installed-plugin-call",
                        "tool_name": "Bash",
                        "tool_input": {"command": "printf public"},
                        "cwd": str(workspace),
                    }
                ),
                capture_output=True,
                text=True,
                check=True,
            )
            with sqlite3.connect(plugin_data / "events.db") as conn:
                self.assertEqual(
                    1,
                    conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                )
            doctor = subprocess.run(
                [codex, "doctor", "--json"],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            doctor_payload = json.loads(doctor.stdout)
            self.assertEqual(
                "ok",
                doctor_payload["checks"]["config.load"]["status"],
            )
            self.assertNotIn("invalid hook", (doctor.stdout + doctor.stderr).casefold())


@unittest.skipUnless(sys.version_info >= (3, 11), "package metadata requires Python 3.11+")
class WheelInstallationTest(unittest.TestCase):
    def test_wheel_runs_outside_checkout_without_pythonpath(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            dist = root / "dist"
            subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts" / "build_package.py"),
                    "--outdir",
                    str(dist),
                ],
                cwd=REPO_ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            wheel = next(dist.glob("tooluseproxy-*.whl"))
            with zipfile.ZipFile(wheel) as archive:
                names = archive.namelist()
            self.assertFalse(
                [
                    name
                    for name in names
                    if name.startswith("build/")
                    or name.endswith(".DS_Store")
                    or "__pycache__" in name
                ]
            )
            self.assertFalse([name for name in names if name.startswith("scripts/")])
            environment = root / "venv"
            venv.EnvBuilder(with_pip=True).create(environment)
            python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            subprocess.run(
                [
                    str(python),
                    "-m",
                    "pip",
                    "install",
                    "--no-deps",
                    str(wheel),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            outside = root / "outside checkout 日本語"
            outside.mkdir()
            clean_environment = dict(os.environ)
            clean_environment.pop("PYTHONPATH", None)
            version = subprocess.run(
                [str(python), "-m", "tooluseproxy", "--version"],
                cwd=outside,
                env=clean_environment,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("tooluseproxy 0.1.0a1", version.stdout)
            trace_help = subprocess.run(
                [str(python), "-m", "tooluseproxy", "trace", "--help"],
                cwd=outside,
                env=clean_environment,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("Show source lineage", trace_help.stdout)

            data_dir = root / "installed-runtime"
            initialize = subprocess.run(
                [
                    str(python),
                    "-m",
                    "tooluseproxy",
                    "init",
                    "--codex",
                    "--workspace",
                    str(outside),
                    "--data-dir",
                    str(data_dir),
                    "--json",
                ],
                cwd=outside,
                env=clean_environment,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual("initialized", json.loads(initialize.stdout)["status"])
            db_path = data_dir / "events.db"
            payload = {
                "hook_event_name": "PreToolUse",
                "session_id": "installed-session",
                "turn_id": "installed-turn",
                "tool_use_id": "installed-call",
                "tool_name": "Bash",
                "tool_input": {"command": "printf public"},
                "cwd": str(outside),
            }
            hook = subprocess.run(
                [
                    str(python),
                    "-m",
                    "tooluseproxy",
                    "hook",
                    "pre-tool-use",
                    "--data-dir",
                    str(data_dir),
                ],
                cwd=outside,
                env=clean_environment,
                input=json.dumps(payload),
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual("", hook.stdout)
            with sqlite3.connect(db_path) as conn:
                count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            self.assertEqual(1, count)


if __name__ == "__main__":
    unittest.main()
