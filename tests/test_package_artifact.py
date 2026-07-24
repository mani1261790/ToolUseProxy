from __future__ import annotations

import email.parser
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path, PurePosixPath


REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_BUILDER = REPO_ROOT / "scripts" / "build_package.py"
SDIST_ROOT_FILES = {
    PurePosixPath("LICENSE"),
    PurePosixPath("MANIFEST.in"),
    PurePosixPath("PKG-INFO"),
    PurePosixPath("PRIVACY.md"),
    PurePosixPath("QUICKSTART.md"),
    PurePosixPath("README.en.md"),
    PurePosixPath("README.md"),
    PurePosixPath("SECURITY.md"),
    PurePosixPath("SUPPORT.md"),
    PurePosixPath("pyproject.toml"),
    PurePosixPath("setup.cfg"),
}
EGG_INFO_FILES = {
    "PKG-INFO",
    "SOURCES.txt",
    "dependency_links.txt",
    "entry_points.txt",
    "requires.txt",
    "top_level.txt",
}
DIST_INFO_FILES = {
    "METADATA",
    "RECORD",
    "WHEEL",
    "entry_points.txt",
    "top_level.txt",
}
RUNTIME_PACKAGE_ROOTS = {"hook_monitor", "tooluseproxy"}
HOOK_MONITOR_RUNTIME_DIRECTORIES = {"analysis", "cli", "policy", "runtime"}
FORBIDDEN_PARTS = {
    ".agents",
    ".codex-plugin",
    ".git",
    ".github",
    ".pytest_cache",
    ".ruff_cache",
    ".tooluseproxy",
    ".venv",
    "__pycache__",
    "docs",
    "evaluation",
    "fixtures",
    "hooks",
    "scripts",
    "skills",
    "tests",
}


def _build_artifacts(outdir: Path) -> tuple[Path, Path]:
    subprocess.run(
        [sys.executable, str(PACKAGE_BUILDER), "--outdir", str(outdir), "--sdist"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    sdists = list(outdir.glob("tooluseproxy-*.tar.gz"))
    wheels = list(outdir.glob("tooluseproxy-*.whl"))
    if len(sdists) != 1 or len(wheels) != 1:
        raise AssertionError(f"expected one sdist and wheel, found {sdists=} {wheels=}")
    return sdists[0], wheels[0]


def _assert_no_forbidden_path(test: unittest.TestCase, path: PurePosixPath) -> None:
    test.assertFalse(set(path.parts) & FORBIDDEN_PARTS, str(path))
    test.assertFalse(path.name.endswith((".db", ".pyc", ".pyo", ".DS_Store")), str(path))


def _is_runtime_python_file(path: PurePosixPath) -> bool:
    if path.suffix != ".py" or not path.parts:
        return False
    if path.parts[0] == "tooluseproxy":
        return True
    if path.parts[0] != "hook_monitor":
        return False
    return len(path.parts) == 2 or path.parts[1] in HOOK_MONITOR_RUNTIME_DIRECTORIES


class PackageArtifactTest(unittest.TestCase):
    def test_package_artifact_bytes_are_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            first_sdist, first_wheel = _build_artifacts(root / "first")
            second_sdist, second_wheel = _build_artifacts(root / "second")
            self.assertEqual(first_sdist.read_bytes(), second_sdist.read_bytes())
            self.assertEqual(first_wheel.read_bytes(), second_wheel.read_bytes())

    def test_sdist_and_wheel_follow_the_runtime_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            sdist, wheel = _build_artifacts(Path(temporary_directory))

            with tarfile.open(sdist, mode="r:gz") as archive:
                members = [member for member in archive.getmembers() if member.isfile()]
                roots = {PurePosixPath(member.name).parts[0] for member in members}
                self.assertEqual(1, len(roots))
                sdist_root = roots.pop()
                sdist_paths = [
                    PurePosixPath(*PurePosixPath(member.name).parts[1:]) for member in members
                ]
                for path in sdist_paths:
                    _assert_no_forbidden_path(self, path)
                    if path in SDIST_ROOT_FILES or _is_runtime_python_file(path):
                        continue
                    if len(path.parts) == 2 and path.parts[0].endswith(".egg-info"):
                        self.assertIn(path.name, EGG_INFO_FILES, str(path))
                        continue
                    self.fail(f"unexpected sdist file: {path}")
                sources_member = next(
                    member
                    for member in members
                    if member.name == f"{sdist_root}/tooluseproxy.egg-info/SOURCES.txt"
                )
                sources = archive.extractfile(sources_member)
                assert sources is not None
                sources_text = sources.read().decode("utf-8")

            for forbidden in FORBIDDEN_PARTS:
                self.assertNotIn(f"{forbidden}/", sources_text)

            with zipfile.ZipFile(wheel) as archive:
                wheel_paths = [PurePosixPath(name) for name in archive.namelist()]
                metadata_path = next(path for path in wheel_paths if path.name == "METADATA")
                metadata = email.parser.BytesParser().parsebytes(archive.read(str(metadata_path)))
                for path in wheel_paths:
                    _assert_no_forbidden_path(self, path)
                    if _is_runtime_python_file(path):
                        continue
                    if len(path.parts) == 2 and path.parts[0].endswith(".dist-info"):
                        self.assertIn(path.name, DIST_INFO_FILES, str(path))
                        continue
                    if (
                        len(path.parts) == 3
                        and path.parts[0].endswith(".dist-info")
                        and path.parts[1] == "licenses"
                    ):
                        self.assertEqual("LICENSE", path.name)
                        continue
                    self.fail(f"unexpected wheel file: {path}")

            self.assertEqual({">=3.11", "<3.13"}, set(metadata["Requires-Python"].split(",")))
            self.assertEqual("Apache-2.0", metadata["License-Expression"])
            self.assertTrue(any(path.parts[0] == "hook_monitor" for path in wheel_paths))
            self.assertTrue(any(path.parts[0] == "tooluseproxy" for path in wheel_paths))


if __name__ == "__main__":
    unittest.main()
