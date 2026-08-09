from __future__ import annotations

import hashlib
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

from hook_monitor.runtime.source_config import CURRENT_MANIFEST_SCHEMA_VERSION
from hook_monitor.runtime.storage import CURRENT_SCHEMA_VERSION, EventStore
from tooluseproxy import __version__
from tooluseproxy.cli import main as cli_main
from tooluseproxy.paths import (
    CODEX_PLUGIN_ROOT_ENV,
    PathConfigurationError,
    default_user_data_dir,
    resolve_runtime_paths,
)
from tooluseproxy.protected_sources import LEGACY_DETECTOR_VERSION


REPO_ROOT = Path(__file__).resolve().parents[1]


def _rewrite_candidate_detector_version(
    database_path: Path,
    candidate_id: str,
    detector_version: str,
) -> None:
    with sqlite3.connect(database_path) as conn:
        row = conn.execute(
            """
            SELECT workspace_id, relative_path, source_sha256,
                   proposed_source_json
            FROM protected_source_candidates
            WHERE candidate_id = ?
            """,
            (candidate_id,),
        ).fetchone()
        if row is None:
            raise AssertionError("candidate upgrade fixture is missing")
        workspace_id, relative_path, source_sha256, proposed_source_json = row
        suppression_fingerprint = hashlib.sha256(
            json.dumps(
                {
                    "detector_version": detector_version,
                    "workspace_id": workspace_id,
                    "path": relative_path,
                    "source_sha256": source_sha256,
                    "proposed_source": json.loads(proposed_source_json),
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        conn.execute(
            """
            UPDATE protected_source_candidates
            SET detector_version = ?, suppression_fingerprint = ?
            WHERE candidate_id = ?
            """,
            (detector_version, suppression_fingerprint, candidate_id),
        )


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

    def test_installed_codex_plugin_resolves_official_data_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            codex_home = root / "codex-home"
            plugin_root = (
                codex_home
                / "plugins"
                / "cache"
                / "tooluseproxy"
                / "tooluseproxy"
                / "0.1.0-alpha.6"
            )
            manifest_dir = plugin_root / ".codex-plugin"
            manifest_dir.mkdir(parents=True)
            (manifest_dir / "plugin.json").write_text(
                json.dumps({"name": "tooluseproxy", "version": "0.1.0-alpha.6"}),
                encoding="utf-8",
            )

            paths = resolve_runtime_paths(
                environ={
                    "CODEX_HOME": str(codex_home),
                    CODEX_PLUGIN_ROOT_ENV: str(plugin_root),
                }
            )

            self.assertEqual("codex_plugin_store", paths.source)
            self.assertEqual(
                codex_home.resolve()
                / "plugins"
                / "data"
                / "tooluseproxy-tooluseproxy"
                / "events.db",
                paths.db_path,
            )

    def test_codex_plugin_resolver_rejects_unverified_or_mismatched_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            codex_home = root / "codex-home"
            outside = root / "copied-plugin"
            manifest_dir = outside / ".codex-plugin"
            manifest_dir.mkdir(parents=True)
            (manifest_dir / "plugin.json").write_text(
                json.dumps({"name": "tooluseproxy"}),
                encoding="utf-8",
            )
            with self.assertRaises(PathConfigurationError):
                resolve_runtime_paths(
                    environ={
                        "CODEX_HOME": str(codex_home),
                        CODEX_PLUGIN_ROOT_ENV: str(outside),
                    }
                )

            installed = (
                codex_home / "plugins" / "cache" / "market" / "plugin" / "1.0"
            )
            installed_manifest = installed / ".codex-plugin"
            installed_manifest.mkdir(parents=True)
            (installed_manifest / "plugin.json").write_text(
                json.dumps({"name": "different"}),
                encoding="utf-8",
            )
            with self.assertRaises(PathConfigurationError):
                resolve_runtime_paths(
                    environ={
                        "CODEX_HOME": str(codex_home),
                        CODEX_PLUGIN_ROOT_ENV: str(installed),
                    }
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
                {
                    "schema_version": CURRENT_MANIFEST_SCHEMA_VERSION,
                    "sources": [],
                },
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
            self.assertEqual(CURRENT_SCHEMA_VERSION, schema_version)

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

    def test_doctor_validates_selector_resolution_without_exposing_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workspace = root / "workspace"
            data_dir = root / "data"
            workspace.mkdir()
            secret = "C.DOCTOR.SELECTOR.VALUE"
            (workspace / ".env").write_text(
                f"PRIVATE_TOKEN={secret}\n",
                encoding="utf-8",
            )

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
            (workspace / "protected_sources.json").write_text(
                json.dumps(
                    {
                        "schema_version": CURRENT_MANIFEST_SCHEMA_VERSION,
                        "sources": [
                            {
                                "id": "private-env",
                                "path": ".env",
                                "type": "secretfile",
                                "sensitivity": "high",
                                "policy_tags": ["no_external"],
                                "selector": {
                                    "dotenv_keys": ["MISSING_TOKEN"]
                                },
                            }
                        ],
                    }
                ),
                encoding="utf-8",
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

            report = json.loads(stdout.getvalue())
            protected = next(
                check
                for check in report["checks"]
                if check["name"] == "protected_sources"
            )
            self.assertEqual(1, exit_code)
            self.assertEqual("needs_attention", report["status"])
            self.assertFalse(protected["ok"])
            self.assertIn("SourceConfigError", protected["detail"])
            self.assertNotIn(secret, stdout.getvalue())

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
                self.assertEqual(
                    CURRENT_SCHEMA_VERSION,
                    conn.execute("PRAGMA user_version").fetchone()[0],
                )

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
                conn.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION}")

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
            output = json.loads(result.stdout)
            self.assertEqual(
                "PreToolUse",
                output["hookSpecificOutput"]["hookEventName"],
            )
            self.assertIn(
                "database_missing",
                output["hookSpecificOutput"]["additionalContext"],
            )
            self.assertEqual("", result.stderr)
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
                conn.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION}")
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

            output = json.loads(result.stdout)
            self.assertEqual(
                "PreToolUse",
                output["hookSpecificOutput"]["hookEventName"],
            )
            self.assertIn(
                "schema_incomplete",
                output["hookSpecificOutput"]["additionalContext"],
            )
            self.assertNotIn("Traceback", result.stdout)
            self.assertEqual("", result.stderr)
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
        self.assertEqual("Apache-2.0", manifest["license"])
        self.assertNotIn("hooks", manifest)
        self.assertEqual(
            (
                "ToolUseProxy checks tool inputs before execution, records tool "
                "results locally, and reviews final responses for protected content. "
                "These hooks do not use the network."
            ),
            hooks["description"],
        )
        rendered_hooks = json.dumps(hooks)
        self.assertIn("PLUGIN_ROOT", rendered_hooks)
        self.assertNotIn(str(REPO_ROOT), rendered_hooks)

    @unittest.skipIf(os.name == "nt", "POSIX launcher test")
    def test_codex_store_install_supports_normal_setup_without_data_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            codex_home = root / "codex-home"
            plugin_root = (
                codex_home
                / "plugins"
                / "cache"
                / "tooluseproxy"
                / "tooluseproxy"
                / "0.1.0-alpha.6"
            )
            plugin_root.mkdir(parents=True)
            for directory in (".codex-plugin", "hook_monitor", "hooks", "tooluseproxy"):
                shutil.copytree(
                    REPO_ROOT / directory,
                    plugin_root / directory,
                    dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
                )
            shutil.copy2(
                REPO_ROOT / "tooluseproxy_plugin.py",
                plugin_root / "tooluseproxy_plugin.py",
            )
            workspace = root / "research-project"
            workspace.mkdir()
            source = workspace / "docs" / "private-plan.md"
            source.parent.mkdir()
            private_text = "ISOLATED.NORMAL.SETUP.SECRET.81f4"
            source.write_text(private_text, encoding="utf-8")
            launcher = plugin_root / "hooks" / "run_cli.sh"
            environment = dict(os.environ)
            for name in (
                "PLUGIN_DATA",
                "PLUGIN_ROOT",
                "PYTHONPATH",
                "TOOLUSEPROXY_DATA_DIR",
                "TOOLUSEPROXY_DB_PATH",
            ):
                environment.pop(name, None)
            environment.update(
                {
                    "CODEX_HOME": str(codex_home),
                    "TOOLUSEPROXY_PYTHON": sys.executable,
                }
            )

            applied = subprocess.run(
                [
                    "sh",
                    str(launcher),
                    "setup",
                    "apply",
                    "file-payload-exact",
                    "--codex",
                    "--expect-empty-settings",
                    "--workspace",
                    str(workspace),
                    "--json",
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=True,
            )
            applied_payload = json.loads(applied.stdout)
            self.assertEqual("applied", applied_payload["status"])
            self.assertEqual("codex_plugin_store", applied_payload["path_source"])
            data_dir = (
                codex_home
                / "plugins"
                / "data"
                / "tooluseproxy-tooluseproxy"
            )
            self.assertEqual(str(data_dir.resolve()), applied_payload["data_dir"])

            verified = subprocess.run(
                [
                    "sh",
                    str(launcher),
                    "setup",
                    "verify",
                    "file-payload-exact",
                    "--workspace",
                    str(workspace),
                    "--json",
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual("passed", json.loads(verified.stdout)["status"])

            suggested = subprocess.run(
                [
                    "sh",
                    str(launcher),
                    "protect",
                    "suggest",
                    "--path",
                    "docs/private-plan.md",
                    "--whole-file",
                    "--workspace",
                    str(workspace),
                    "--json",
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=True,
            )
            suggestion = json.loads(suggested.stdout)
            self.assertEqual("review_required", suggestion["status"])
            self.assertNotIn(private_text, suggested.stdout + suggested.stderr)
            candidate = suggestion["candidates"][0]
            self.assertEqual("docs/private-plan.md", candidate["path"])
            self.assertNotIn("selector", candidate["proposed_source"])
            self.assertTrue((data_dir / "events.db").is_file())

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
            legacy_secret = "RELOCATED.LEGACY.SECRET.6c42"
            legacy_metadata = "RELOCATED.MIGRATION.METADATA.31ad"
            legacy_source = {
                "id": "legacy-env",
                "path": ".env.legacy",
                "type": "secretfile",
                "sensitivity": "high",
                "policy_tags": ["no_external"],
                "future_source_field": {"preserved": True},
            }
            (workspace / ".env.legacy").write_text(
                f"LEGACY_TOKEN={legacy_secret}\n",
                encoding="utf-8",
            )
            legacy_manifest = workspace / "protected_sources.json"
            legacy_manifest_before = (
                json.dumps(
                    {
                        "sources": [legacy_source],
                        "future_top_field": {"value": legacy_metadata},
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            legacy_manifest.write_bytes(legacy_manifest_before)
            legacy_manifest.chmod(0o600)
            data_dir = workspace / ".tooluseproxy data"
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
            self.assertNotIn("PYTHONPATH", environment)
            self.assertTrue(cli_launcher.is_absolute())
            self.assertFalse(plugin_root.is_relative_to(REPO_ROOT))
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
            inactive_output = json.loads(inactive.stdout)
            inactive_context = inactive_output["hookSpecificOutput"][
                "additionalContext"
            ]
            self.assertEqual(
                "PreToolUse",
                inactive_output["hookSpecificOutput"]["hookEventName"],
            )
            self.assertIn("database_missing", inactive_context)
            self.assertIn(str(cli_launcher), inactive_context)
            self.assertIn(str(data_dir), inactive_context)
            self.assertEqual("", inactive.stderr)
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
            initialized_payload = json.loads(initialized.stdout)
            self.assertEqual("initialized", initialized_payload["status"])
            self.assertFalse(initialized_payload["manifest_created"])

            legacy_status = subprocess.run(
                [
                    "sh",
                    str(cli_launcher),
                    "status",
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
            legacy_status_payload = json.loads(legacy_status.stdout)
            self.assertEqual("active", legacy_status_payload["status"])
            self.assertTrue(
                legacy_status_payload["protected_sources"]["runtime_readable"]
            )
            self.assertFalse(
                legacy_status_payload["protected_sources"]["registration_writable"]
            )
            self.assertTrue(
                legacy_status_payload["protected_sources"]["migration_required"]
            )

            registration_secret = "RELOCATED.PLUGIN.SECRET.9d31"
            decoy_secret = "RELOCATED.EXCLUDED.SECRET.61b7"
            registered_json = workspace / "config" / "runtime.json"
            registered_json.parent.mkdir()
            registered_json.write_text(
                json.dumps(
                    {
                        "private_token": registration_secret,
                        "public_mode": "demo",
                    }
                ),
                encoding="utf-8",
            )
            dependency_decoy = workspace / "node_modules" / "package" / "runtime.json"
            dependency_decoy.parent.mkdir(parents=True)
            dependency_decoy.write_text(
                json.dumps({"private_token": decoy_secret}),
                encoding="utf-8",
            )
            data_decoy = data_dir / "runtime.json"
            data_decoy.write_text(
                json.dumps({"private_token": decoy_secret}),
                encoding="utf-8",
            )

            legacy_scan = subprocess.run(
                [
                    "sh",
                    str(cli_launcher),
                    "protect",
                    "scan",
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
                check=False,
            )
            self.assertEqual(1, legacy_scan.returncode)
            self.assertEqual("", legacy_scan.stdout)
            self.assertEqual(
                "manifest_schema_legacy",
                json.loads(legacy_scan.stderr)["error"]["code"],
            )
            self.assertNotIn(
                registration_secret,
                legacy_scan.stdout + legacy_scan.stderr,
            )
            self.assertNotIn(decoy_secret, legacy_scan.stdout + legacy_scan.stderr)
            with sqlite3.connect(data_dir / "events.db") as conn:
                self.assertEqual(
                    0,
                    conn.execute(
                        "SELECT COUNT(*) FROM protected_source_candidates"
                    ).fetchone()[0],
                )

            migration_plan = subprocess.run(
                [
                    "sh",
                    str(cli_launcher),
                    "protect",
                    "migrate",
                    "plan",
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
            migration_plan_payload = json.loads(migration_plan.stdout)
            self.assertEqual("review_required", migration_plan_payload["status"])
            self.assertEqual(1, migration_plan_payload["source_count"])
            self.assertTrue(migration_plan_payload["schema_version_was_omitted"])
            self.assertFalse(
                migration_plan_payload["sources_field_will_be_added"]
            )
            self.assertEqual(0, migration_plan_payload["selector_changes"])
            self.assertEqual(
                hashlib.sha256(legacy_manifest_before).hexdigest(),
                migration_plan_payload["manifest_sha256"],
            )
            self.assertEqual(legacy_manifest_before, legacy_manifest.read_bytes())
            self.assertNotIn(
                legacy_secret,
                migration_plan.stdout + migration_plan.stderr,
            )
            self.assertNotIn(
                legacy_metadata,
                migration_plan.stdout + migration_plan.stderr,
            )
            migration_backup = (
                data_dir / migration_plan_payload["backup_relative_path"]
            )
            self.assertFalse(migration_backup.exists())

            migration_apply = subprocess.run(
                [
                    "sh",
                    str(cli_launcher),
                    "protect",
                    "migrate",
                    "apply",
                    "--migration-revision",
                    migration_plan_payload["migration_revision"],
                    "--expected-manifest-sha256",
                    migration_plan_payload["manifest_sha256"],
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
            migration_apply_payload = json.loads(migration_apply.stdout)
            self.assertEqual("migrated", migration_apply_payload["status"])
            self.assertEqual(
                migration_plan_payload["result_manifest_sha256"],
                migration_apply_payload["manifest_sha256"],
            )
            self.assertNotIn(
                legacy_secret,
                migration_apply.stdout + migration_apply.stderr,
            )
            self.assertNotIn(
                legacy_metadata,
                migration_apply.stdout + migration_apply.stderr,
            )
            self.assertEqual(legacy_manifest_before, migration_backup.read_bytes())
            self.assertEqual(
                0o600,
                stat.S_IMODE(migration_backup.stat().st_mode),
            )
            migrated_manifest = json.loads(
                legacy_manifest.read_text(encoding="utf-8")
            )
            self.assertEqual(2, migrated_manifest["schema_version"])
            self.assertEqual([legacy_source], migrated_manifest["sources"])
            self.assertEqual(
                {"value": legacy_metadata},
                migrated_manifest["future_top_field"],
            )

            manifest_before_scan = legacy_manifest.read_bytes()
            suggestion = subprocess.run(
                [
                    "sh",
                    str(cli_launcher),
                    "protect",
                    "scan",
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
            suggestion_payload = json.loads(suggestion.stdout)
            self.assertEqual("review_required", suggestion_payload["status"])
            self.assertTrue(suggestion_payload["scan_complete"])
            self.assertEqual("one_at_a_time", suggestion_payload["approval_mode"])
            self.assertTrue(
                suggestion_payload["rescan_required_after_manifest_change"]
            )
            self.assertEqual(0, suggestion_payload["remaining_candidate_count"])
            self.assertTrue(suggestion_payload["continuation_required"])
            self.assertEqual(1, len(suggestion_payload["candidates"]))
            candidate = suggestion_payload["candidates"][0]
            self.assertIs(candidate["review_required"], True)
            self.assertEqual("config/runtime.json", candidate["path"])
            self.assertEqual(
                {"json_pointers": ["/private_token"]},
                candidate["proposed_source"]["selector"],
            )
            self.assertEqual(manifest_before_scan, legacy_manifest.read_bytes())
            self.assertNotIn(
                registration_secret,
                suggestion.stdout + suggestion.stderr,
            )
            self.assertNotIn(decoy_secret, suggestion.stdout + suggestion.stderr)
            self.assertNotIn(
                str(workspace.resolve()),
                suggestion.stdout + suggestion.stderr,
            )

            approval = subprocess.run(
                [
                    "sh",
                    str(cli_launcher),
                    "protect",
                    "approve",
                    candidate["candidate_id"],
                    "--candidate-revision",
                    candidate["candidate_revision"],
                    "--expected-manifest-sha256",
                    suggestion_payload["manifest_sha256"],
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
                check=False,
            )
            self.assertEqual(0, approval.returncode, approval.stderr)
            approval_payload = json.loads(approval.stdout)
            self.assertEqual("approved", approval_payload["status"])
            self.assertNotIn(
                registration_secret,
                approval.stdout + approval.stderr,
            )
            protected_manifest = json.loads(
                (workspace / "protected_sources.json").read_text(encoding="utf-8")
            )
            self.assertEqual(legacy_source, protected_manifest["sources"][0])
            self.assertEqual(
                {"value": legacy_metadata},
                protected_manifest["future_top_field"],
            )
            registered_source = next(
                source
                for source in protected_manifest["sources"]
                if source["path"] == "config/runtime.json"
            )
            self.assertEqual("secretfile", registered_source["type"])
            self.assertEqual(
                {"json_pointers": ["/private_token"]},
                registered_source["selector"],
            )
            candidate_database_check = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import sqlite3,sys; "
                        "connection=sqlite3.connect(sys.argv[1]); "
                        "dump='\\n'.join(connection.iterdump()); "
                        "connection.close(); "
                        "print('present' if sys.argv[2] in dump else 'absent')"
                    ),
                    str(data_dir / "events.db"),
                    registration_secret,
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual("absent", candidate_database_check.stdout.strip())
            _rewrite_candidate_detector_version(
                data_dir / "events.db",
                str(candidate["candidate_id"]),
                LEGACY_DETECTOR_VERSION,
            )
            with sqlite3.connect(data_dir / "events.db") as conn:
                legacy_candidate = conn.execute(
                    """
                    SELECT detector_version, status
                    FROM protected_source_candidates
                    WHERE candidate_id = ?
                    """,
                    (candidate["candidate_id"],),
                ).fetchone()
                legacy_review_count = conn.execute(
                    """
                    SELECT COUNT(*)
                    FROM protected_source_candidate_reviews
                    WHERE candidate_id = ?
                    """,
                    (candidate["candidate_id"],),
                ).fetchone()[0]
            self.assertEqual(
                (LEGACY_DETECTOR_VERSION, "approved"),
                legacy_candidate,
            )

            repeated_scan = subprocess.run(
                [
                    "sh",
                    str(cli_launcher),
                    "protect",
                    "scan",
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
            repeated_scan_payload = json.loads(repeated_scan.stdout)
            self.assertEqual("no_candidate", repeated_scan_payload["status"])
            self.assertEqual([], repeated_scan_payload["candidates"])
            self.assertTrue(repeated_scan_payload["scan_complete"])
            self.assertFalse(repeated_scan_payload["continuation_required"])
            self.assertGreaterEqual(
                repeated_scan_payload["already_registered_count"],
                2,
            )
            self.assertNotIn(
                registration_secret,
                repeated_scan.stdout + repeated_scan.stderr,
            )
            self.assertNotIn(
                decoy_secret,
                repeated_scan.stdout + repeated_scan.stderr,
            )

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
            status = subprocess.run(
                [
                    "sh",
                    str(cli_launcher),
                    "status",
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
            self.assertEqual("active", json.loads(status.stdout)["status"])
            self.assertNotIn(
                registration_secret,
                status.stdout + status.stderr,
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
                runtime_source = conn.execute(
                    """
                    SELECT source_id, selector_json
                    FROM protected_sources
                    WHERE path = 'config/runtime.json'
                    """
                ).fetchone()
                legacy_runtime_source = conn.execute(
                    """
                    SELECT source_id, selector_json
                    FROM protected_sources
                    WHERE path = '.env.legacy'
                    """
                ).fetchone()
                source_chunk_count = conn.execute(
                    """
                    SELECT COUNT(*)
                    FROM source_chunks
                    WHERE source_id = ?
                    """,
                    (runtime_source[0],),
                ).fetchone()[0]
                legacy_chunk_count = conn.execute(
                    """
                    SELECT COUNT(*)
                    FROM source_chunks
                    WHERE source_id = ?
                    """,
                    (legacy_runtime_source[0],),
                ).fetchone()[0]
                runtime_analysis = conn.execute(
                    """
                    SELECT config_json, completed_at
                    FROM analysis_runs
                    WHERE session_id = 'plugin-session'
                    ORDER BY started_at DESC, rowid DESC
                    LIMIT 1
                    """
                ).fetchone()
                final_legacy_candidate = conn.execute(
                    """
                    SELECT detector_version, status
                    FROM protected_source_candidates
                    WHERE candidate_id = ?
                    """,
                    (candidate["candidate_id"],),
                ).fetchone()
                final_legacy_review_count = conn.execute(
                    """
                    SELECT COUNT(*)
                    FROM protected_source_candidate_reviews
                    WHERE candidate_id = ?
                    """,
                    (candidate["candidate_id"],),
                ).fetchone()[0]
            self.assertEqual((str(workspace.resolve()), "hook_cwd"), row)
            self.assertEqual(
                [("pre_tool_use",), ("post_tool_use",), ("stop",)],
                phases,
            )
            self.assertEqual(
                {"json_pointers": ["/private_token"]},
                json.loads(runtime_source[1]),
            )
            self.assertEqual(1, source_chunk_count)
            self.assertIsNone(json.loads(legacy_runtime_source[1]))
            self.assertEqual(1, legacy_chunk_count)
            self.assertEqual(
                (LEGACY_DETECTOR_VERSION, "approved"),
                final_legacy_candidate,
            )
            self.assertEqual(legacy_review_count, final_legacy_review_count)
            self.assertEqual(
                "session-full",
                json.loads(runtime_analysis[0])["runtime_reanalysis"],
            )
            self.assertIsNotNone(runtime_analysis[1])

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
            output = json.loads(result.stdout)
            self.assertEqual(
                {
                    "systemMessage": (
                        "Python 3.11または3.12が見つからないため、"
                        "ToolUseProxyの保護機能は動作していません。"
                        "（技術情報: python_missing）"
                    )
                },
                output,
            )
            self.assertEqual("", result.stderr)
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
    @unittest.skipIf(os.name == "nt", "protected-source migration is POSIX-only")
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
                    "--sdist",
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
            self.assertEqual(f"tooluseproxy {__version__}", version.stdout.strip())
            trace_help = subprocess.run(
                [str(python), "-m", "tooluseproxy", "trace", "--help"],
                cwd=outside,
                env=clean_environment,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("Show source lineage", trace_help.stdout)

            chunk_workspace = root / "installed-chunking"
            chunk_workspace.mkdir()
            (chunk_workspace / ".env").write_text(
                "PRIVATE_TOKEN=C.INSTALLED.VALUE\nPUBLIC_MODE=demo\n",
                encoding="utf-8",
            )
            (chunk_workspace / "protected_sources.json").write_text(
                json.dumps(
                    {
                        "schema_version": CURRENT_MANIFEST_SCHEMA_VERSION,
                        "sources": [
                            {
                                "id": "installed-env",
                                "path": ".env",
                                "type": "secretfile",
                                "sensitivity": "high",
                                "policy_tags": ["no_external"],
                                "selector": {
                                    "dotenv_keys": ["PRIVATE_TOKEN"]
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            installed_chunks = subprocess.run(
                [
                    str(python),
                    "-c",
                    (
                        "import json; from pathlib import Path; "
                        "from hook_monitor.analysis.source_index import "
                        "load_sources_and_chunks; "
                        "_, chunks = load_sources_and_chunks(Path.cwd()); "
                        "print(json.dumps([chunk.text for chunk in chunks]))"
                    ),
                ],
                cwd=chunk_workspace,
                env=clean_environment,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                ["C.INSTALLED.VALUE"],
                json.loads(installed_chunks.stdout),
            )

            legacy_secret = "WHEEL.LEGACY.SECRET.8a51"
            legacy_metadata = "WHEEL.MIGRATION.METADATA.54ce"
            legacy_source = {
                "id": "wheel-legacy-env",
                "path": ".env.legacy",
                "type": "secretfile",
                "sensitivity": "high",
                "policy_tags": ["no_external"],
                "future_source_field": {"preserved": True},
            }
            (outside / ".env.legacy").write_text(
                f"LEGACY_TOKEN={legacy_secret}\n",
                encoding="utf-8",
            )
            legacy_manifest = outside / "protected_sources.json"
            legacy_manifest_before = (
                json.dumps(
                    {
                        "sources": [legacy_source],
                        "future_top_field": {"value": legacy_metadata},
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            legacy_manifest.write_bytes(legacy_manifest_before)
            legacy_manifest.chmod(0o600)
            data_dir = outside / ".tooluseproxy data"
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
            initialize_payload = json.loads(initialize.stdout)
            self.assertEqual("initialized", initialize_payload["status"])
            self.assertFalse(initialize_payload["manifest_created"])
            db_path = data_dir / "events.db"

            installed_secret = "INSTALLED.REGISTRATION.SECRET.7b2e"
            decoy_secret = "INSTALLED.EXCLUDED.SECRET.30f1"
            installed_json = outside / "config" / "runtime.json"
            installed_json.parent.mkdir()
            installed_json.write_text(
                json.dumps(
                    {
                        "private_token": installed_secret,
                        "public_mode": "demo",
                    }
                ),
                encoding="utf-8",
            )
            dependency_decoy = outside / "node_modules" / "package" / "runtime.json"
            dependency_decoy.parent.mkdir(parents=True)
            dependency_decoy.write_text(
                json.dumps({"private_token": decoy_secret}),
                encoding="utf-8",
            )
            (data_dir / "runtime.json").write_text(
                json.dumps({"private_token": decoy_secret}),
                encoding="utf-8",
            )

            legacy_scan = subprocess.run(
                [
                    str(python),
                    "-m",
                    "tooluseproxy",
                    "protect",
                    "scan",
                    "--workspace",
                    str(outside),
                    "--data-dir",
                    str(data_dir),
                    "--json",
                ],
                cwd=outside,
                env=clean_environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(1, legacy_scan.returncode)
            self.assertEqual("", legacy_scan.stdout)
            self.assertEqual(
                "manifest_schema_legacy",
                json.loads(legacy_scan.stderr)["error"]["code"],
            )
            self.assertNotIn(
                installed_secret,
                legacy_scan.stdout + legacy_scan.stderr,
            )
            self.assertNotIn(decoy_secret, legacy_scan.stdout + legacy_scan.stderr)
            with sqlite3.connect(db_path) as conn:
                self.assertEqual(
                    0,
                    conn.execute(
                        "SELECT COUNT(*) FROM protected_source_candidates"
                    ).fetchone()[0],
                )

            migration_plan = subprocess.run(
                [
                    str(python),
                    "-m",
                    "tooluseproxy",
                    "protect",
                    "migrate",
                    "plan",
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
            migration_plan_payload = json.loads(migration_plan.stdout)
            self.assertEqual("review_required", migration_plan_payload["status"])
            self.assertEqual(1, migration_plan_payload["source_count"])
            self.assertTrue(migration_plan_payload["schema_version_was_omitted"])
            self.assertFalse(
                migration_plan_payload["sources_field_will_be_added"]
            )
            self.assertEqual(0, migration_plan_payload["selector_changes"])
            self.assertEqual(
                hashlib.sha256(legacy_manifest_before).hexdigest(),
                migration_plan_payload["manifest_sha256"],
            )
            self.assertEqual(legacy_manifest_before, legacy_manifest.read_bytes())
            self.assertNotIn(
                legacy_secret,
                migration_plan.stdout + migration_plan.stderr,
            )
            self.assertNotIn(
                legacy_metadata,
                migration_plan.stdout + migration_plan.stderr,
            )
            migration_backup = (
                data_dir / migration_plan_payload["backup_relative_path"]
            )
            self.assertFalse(migration_backup.exists())

            migration_apply = subprocess.run(
                [
                    str(python),
                    "-m",
                    "tooluseproxy",
                    "protect",
                    "migrate",
                    "apply",
                    "--migration-revision",
                    migration_plan_payload["migration_revision"],
                    "--expected-manifest-sha256",
                    migration_plan_payload["manifest_sha256"],
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
            migration_apply_payload = json.loads(migration_apply.stdout)
            self.assertEqual("migrated", migration_apply_payload["status"])
            self.assertEqual(
                migration_plan_payload["result_manifest_sha256"],
                migration_apply_payload["manifest_sha256"],
            )
            self.assertNotIn(
                legacy_secret,
                migration_apply.stdout + migration_apply.stderr,
            )
            self.assertNotIn(
                legacy_metadata,
                migration_apply.stdout + migration_apply.stderr,
            )
            self.assertEqual(legacy_manifest_before, migration_backup.read_bytes())
            self.assertEqual(
                0o600,
                stat.S_IMODE(migration_backup.stat().st_mode),
            )
            migrated_manifest = json.loads(
                legacy_manifest.read_text(encoding="utf-8")
            )
            self.assertEqual(2, migrated_manifest["schema_version"])
            self.assertEqual([legacy_source], migrated_manifest["sources"])
            self.assertEqual(
                {"value": legacy_metadata},
                migrated_manifest["future_top_field"],
            )

            manifest_before_scan = legacy_manifest.read_bytes()
            suggestion = subprocess.run(
                [
                    str(python),
                    "-m",
                    "tooluseproxy",
                    "protect",
                    "scan",
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
            suggestion_payload = json.loads(suggestion.stdout)
            self.assertEqual("review_required", suggestion_payload["status"])
            self.assertTrue(suggestion_payload["scan_complete"])
            self.assertEqual("one_at_a_time", suggestion_payload["approval_mode"])
            self.assertEqual(0, suggestion_payload["remaining_candidate_count"])
            self.assertTrue(suggestion_payload["continuation_required"])
            self.assertNotIn(installed_secret, suggestion.stdout + suggestion.stderr)
            self.assertNotIn(decoy_secret, suggestion.stdout + suggestion.stderr)
            self.assertNotIn(
                str(outside.resolve()),
                suggestion.stdout + suggestion.stderr,
            )
            self.assertEqual(manifest_before_scan, legacy_manifest.read_bytes())
            installed_candidate = suggestion_payload["candidates"][0]
            self.assertEqual("config/runtime.json", installed_candidate["path"])
            self.assertEqual(
                {"json_pointers": ["/private_token"]},
                installed_candidate["proposed_source"]["selector"],
            )
            approval = subprocess.run(
                [
                    str(python),
                    "-m",
                    "tooluseproxy",
                    "protect",
                    "approve",
                    installed_candidate["candidate_id"],
                    "--candidate-revision",
                    installed_candidate["candidate_revision"],
                    "--expected-manifest-sha256",
                    suggestion_payload["manifest_sha256"],
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
            self.assertEqual("approved", json.loads(approval.stdout)["status"])
            self.assertNotIn(installed_secret, approval.stdout + approval.stderr)
            registered_manifest = json.loads(
                legacy_manifest.read_text(encoding="utf-8")
            )
            self.assertEqual(legacy_source, registered_manifest["sources"][0])
            self.assertEqual(
                {"value": legacy_metadata},
                registered_manifest["future_top_field"],
            )
            repeated_scan = subprocess.run(
                [
                    str(python),
                    "-m",
                    "tooluseproxy",
                    "protect",
                    "scan",
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
            repeated_scan_payload = json.loads(repeated_scan.stdout)
            self.assertEqual("no_candidate", repeated_scan_payload["status"])
            self.assertEqual([], repeated_scan_payload["candidates"])
            self.assertTrue(repeated_scan_payload["scan_complete"])
            self.assertFalse(repeated_scan_payload["continuation_required"])
            self.assertGreaterEqual(
                repeated_scan_payload["already_registered_count"],
                2,
            )
            self.assertNotIn(
                installed_secret,
                repeated_scan.stdout + repeated_scan.stderr,
            )
            self.assertNotIn(
                decoy_secret,
                repeated_scan.stdout + repeated_scan.stderr,
            )
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
            post = subprocess.run(
                [
                    str(python),
                    "-m",
                    "tooluseproxy",
                    "hook",
                    "post-tool-use",
                    "--data-dir",
                    str(data_dir),
                ],
                cwd=outside,
                env=clean_environment,
                input=json.dumps(
                    {
                        **payload,
                        "hook_event_name": "PostToolUse",
                        "tool_response": {"output": "public"},
                    }
                ),
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual("", post.stdout)
            stop = subprocess.run(
                [
                    str(python),
                    "-m",
                    "tooluseproxy",
                    "hook",
                    "stop",
                    "--data-dir",
                    str(data_dir),
                ],
                cwd=outside,
                env=clean_environment,
                input=json.dumps(
                    {
                        "hook_event_name": "Stop",
                        "session_id": "installed-session",
                        "turn_id": "installed-turn",
                        "stop_hook_active": False,
                        "cwd": str(outside),
                        "last_assistant_message": "Public final answer.",
                    }
                ),
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual("", stop.stdout)
            with sqlite3.connect(db_path) as conn:
                count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                runtime_sources = conn.execute(
                    """
                    SELECT path, source_id, selector_json
                    FROM protected_sources
                    WHERE path IN ('.env.legacy', 'config/runtime.json')
                    ORDER BY path
                    """
                ).fetchall()
                chunk_counts = {
                    path: conn.execute(
                        "SELECT COUNT(*) FROM source_chunks WHERE source_id = ?",
                        (source_id,),
                    ).fetchone()[0]
                    for path, source_id, _ in runtime_sources
                }
                runtime_analysis = conn.execute(
                    """
                    SELECT config_json, completed_at
                    FROM analysis_runs
                    WHERE session_id = 'installed-session'
                    ORDER BY started_at DESC, rowid DESC
                    LIMIT 1
                    """
                ).fetchone()
            self.assertEqual(3, count)
            self.assertEqual(
                [".env.legacy", "config/runtime.json"],
                [path for path, _, _ in runtime_sources],
            )
            selectors = {
                path: json.loads(selector_json)
                for path, _, selector_json in runtime_sources
            }
            self.assertEqual(
                {"json_pointers": ["/private_token"]},
                selectors["config/runtime.json"],
            )
            self.assertIsNone(selectors[".env.legacy"])
            self.assertEqual(
                {".env.legacy": 1, "config/runtime.json": 1},
                chunk_counts,
            )
            self.assertEqual(
                "session-full",
                json.loads(runtime_analysis[0])["runtime_reanalysis"],
            )
            self.assertIsNotNone(runtime_analysis[1])


if __name__ == "__main__":
    unittest.main()
