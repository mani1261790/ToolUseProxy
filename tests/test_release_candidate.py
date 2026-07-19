from __future__ import annotations

import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BUILDER = REPO_ROOT / "scripts" / "build_release_candidate.py"


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(BUILDER), *arguments],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _write_json(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _resign_candidate(candidate: Path, artifact: Path) -> None:
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    manifest_path = candidate / "release-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = next(item for item in manifest["artifacts"] if item["filename"] == artifact.name)
    entry["sha256"] = digest
    entry["size"] = artifact.stat().st_size
    _write_json(manifest_path, manifest)

    sbom_path = candidate / manifest["sbom"]["filename"]
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    component = next(item for item in sbom["components"] if item["name"] == artifact.name)
    component["hashes"][0]["content"] = digest
    _write_json(sbom_path, sbom)

    checksum_path = candidate / "SHA256SUMS"
    targets = sorted(path for path in candidate.iterdir() if path.name != checksum_path.name)
    checksum_path.write_text(
        "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in targets),
        encoding="ascii",
    )


def _append_zip_member(artifact: Path, info: zipfile.ZipInfo, content: bytes) -> None:
    temporary = artifact.with_name(f".{artifact.name}.unsafe")
    with zipfile.ZipFile(artifact) as source, zipfile.ZipFile(
        temporary,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
    ) as destination:
        for source_info in source.infolist():
            destination.writestr(source_info, source.read(source_info))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            destination.writestr(info, content)
    temporary.replace(artifact)


def _append_sdist_symlink(artifact: Path) -> None:
    temporary = artifact.with_name(f".{artifact.name}.unsafe")
    with tarfile.open(artifact, mode="r:gz") as source, tarfile.open(
        temporary,
        mode="w:gz",
    ) as destination:
        members = source.getmembers()
        for member in members:
            extracted = source.extractfile(member) if member.isfile() else None
            destination.addfile(member, extracted)
        root = members[0].name.split("/", 1)[0]
        link = tarfile.TarInfo(f"{root}/unsafe-link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        link.mode = 0o777
        destination.addfile(link, io.BytesIO())
    temporary.replace(artifact)


class ReleaseCandidateTest(unittest.TestCase):
    def test_candidate_is_reproducible_complete_and_self_verifying(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            first = root / "first"
            second = root / "second"
            first_result = _run("--outdir", str(first))
            second_result = _run("--outdir", str(second))
            self.assertEqual(0, first_result.returncode, first_result.stderr)
            self.assertEqual(0, second_result.returncode, second_result.stderr)

            first_files = {path.name: path.read_bytes() for path in first.iterdir()}
            second_files = {path.name: path.read_bytes() for path in second.iterdir()}
            self.assertEqual(first_files, second_files)
            self.assertEqual(7, len(first_files))

            manifest = json.loads(first_files["release-manifest.json"])
            self.assertEqual(1, manifest["schema_version"])
            self.assertEqual("candidate", manifest["status"])
            self.assertEqual(3, len(manifest["artifacts"]))
            license_present = (REPO_ROOT / "LICENSE").is_file()
            self.assertEqual(license_present, manifest["gates"]["license_present"])
            self.assertEqual(
                license_present and not manifest["source"]["dirty"],
                manifest["gates"]["artifact_set_eligible"],
            )
            self.assertNotIn(str(REPO_ROOT), first_files["release-manifest.json"].decode())

            checksum_lines = first_files["SHA256SUMS"].decode("ascii").splitlines()
            checksums = {line[66:]: line[:64] for line in checksum_lines}
            self.assertEqual(set(first_files) - {"SHA256SUMS"}, set(checksums))
            for filename, expected in checksums.items():
                self.assertEqual(expected, hashlib.sha256(first_files[filename]).hexdigest())

            sbom_name = manifest["sbom"]["filename"]
            sbom = json.loads(first_files[sbom_name])
            self.assertEqual("CycloneDX", sbom["bomFormat"])
            self.assertEqual("1.7", sbom["specVersion"])
            self.assertEqual(3, len(sbom["components"]))

            verified = _run("--verify", str(first))
            self.assertEqual(0, verified.returncode, verified.stderr)
            verified_payload = json.loads(verified.stdout)
            self.assertEqual("verified", verified_payload["status"])
            self.assertEqual(3, verified_payload["artifact_count"])
            self.assertEqual(6, verified_payload["checked_file_count"])
            self.assertGreater(verified_payload["checked_archive_member_count"], 0)

    def test_verifier_rejects_tampering_and_unexpected_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate = Path(temporary_directory) / "candidate"
            built = _run("--outdir", str(candidate))
            self.assertEqual(0, built.returncode, built.stderr)
            artifact = next(candidate.glob("*.whl"))
            artifact.write_bytes(artifact.read_bytes() + b"tampered")
            rejected = _run("--verify", str(candidate))
            self.assertEqual(1, rejected.returncode)
            self.assertIn("checksum mismatch", rejected.stderr)

            artifact.write_bytes(artifact.read_bytes()[:-8])
            (candidate / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
            rejected = _run("--verify", str(candidate))
            self.assertEqual(1, rejected.returncode)
            self.assertIn("missing or unexpected", rejected.stderr)

    def test_verifier_rejects_unsafe_zip_members_after_valid_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            original = root / "original"
            built = _run("--outdir", str(original))
            self.assertEqual(0, built.returncode, built.stderr)

            cases = (
                ("path", "../outside", 0o100644, "unsafe member path"),
                ("symlink", "tooluseproxy/unsafe-link", 0o120777, "non-regular member"),
                ("permissions", "tooluseproxy/unsafe.txt", 0o100666, "dangerous member permissions"),
                ("executable", "tooluseproxy/unsafe.py", 0o100755, "unexpected executable"),
                ("duplicate", "README.md", 0o100644, "duplicate member paths"),
            )
            for label, name, mode, message in cases:
                with self.subTest(label=label):
                    candidate = root / label
                    shutil.copytree(original, candidate)
                    artifact = next(candidate.glob("tooluseproxy-plugin-*.zip"))
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = mode << 16
                    _append_zip_member(artifact, info, b"unsafe\n")
                    _resign_candidate(candidate, artifact)

                    rejected = _run("--verify", str(candidate))
                    self.assertEqual(1, rejected.returncode, rejected.stdout)
                    self.assertIn(message, rejected.stderr)

    def test_verifier_rejects_sdist_links_after_valid_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate = Path(temporary_directory) / "candidate"
            built = _run("--outdir", str(candidate))
            self.assertEqual(0, built.returncode, built.stderr)
            artifact = next(candidate.glob("*.tar.gz"))
            _append_sdist_symlink(artifact)
            _resign_candidate(candidate, artifact)

            rejected = _run("--verify", str(candidate))
            self.assertEqual(1, rejected.returncode, rejected.stdout)
            self.assertIn("non-regular member", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
