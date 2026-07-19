from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_LAUNCHER = REPO_ROOT / "hooks" / "run_cli.sh"
HOOK_LAUNCHER = REPO_ROOT / "hooks" / "run_hook.sh"


class WindowsLauncherPythonContractTest(unittest.TestCase):
    def test_windows_launchers_try_both_supported_minor_versions(self) -> None:
        for relative_path in ("hooks/run_cli.cmd", "hooks/run_hook.cmd"):
            with self.subTest(relative_path=relative_path):
                content = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
                python_312 = content.index("py -3.12")
                python_311 = content.index("py -3.11")
                self.assertLess(python_312, python_311)
                self.assertNotIn("py -3.13", content)


@unittest.skipIf(os.name == "nt", "POSIX launcher contract")
class PosixLauncherPythonContractTest(unittest.TestCase):
    def test_explicit_unsupported_python_is_never_used(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            marker = root / "unsupported-python-invoked"
            fake_python = root / "python-3.13"
            fake_python.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"-c\" ]; then\n"
                "  case \"$2\" in\n"
                "    *\"sys.version_info >= (3, 13)\"*) exit 1 ;;\n"
                "    *) exit 0 ;;\n"
                "  esac\n"
                "fi\n"
                f"printf 'invoked\\n' > {marker}\n",
                encoding="utf-8",
            )
            fake_python.chmod(0o700)
            environment = {
                "PATH": str(root),
                "PLUGIN_ROOT": str(REPO_ROOT),
                "PLUGIN_DATA": str(root / "plugin-data"),
                "TOOLUSEPROXY_PYTHON": str(fake_python),
            }

            cli = subprocess.run(
                ["/bin/sh", str(CLI_LAUNCHER), "--version"],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            hook = subprocess.run(
                ["/bin/sh", str(HOOK_LAUNCHER), "pre-tool-use"],
                cwd=root,
                env=environment,
                input="{}",
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(1, cli.returncode)
            self.assertIn("Python 3.11 or 3.12 is required", cli.stderr)
            self.assertEqual(0, hook.returncode)
            self.assertIn("Python 3.11 or 3.12 is required", hook.stderr)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
