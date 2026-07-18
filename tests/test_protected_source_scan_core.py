from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from tooluseproxy import protected_sources as protected_source_module
from tooluseproxy.protected_sources import (
    DEFAULT_PROTECTED_SOURCE_SCAN_LIMITS,
    MANIFEST_FILENAME,
    ProtectedSourceRegistrationError,
    ProtectedSourceScanLimits,
    scan_protected_sources,
    suggest_protected_source,
)


class ProtectedSourceScanCoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary_directory.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self._write_manifest({"schema_version": 2, "sources": []})

    def tearDown(self) -> None:
        self._temporary_directory.cleanup()

    @property
    def manifest_path(self) -> Path:
        return self.workspace / MANIFEST_FILENAME

    def _write_manifest(self, payload: dict[str, object]) -> None:
        self.manifest_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def _write_secret(self, relative_path: str, value: str | None = None) -> Path:
        path = self.workspace / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        secret = value or f"SECRET.{relative_path}.value"
        if path.name.casefold().endswith(".json"):
            path.write_text(json.dumps({"private_token": secret}), encoding="utf-8")
        else:
            path.write_text(f"PRIVATE_TOKEN={secret}\n", encoding="utf-8")
        return path

    @staticmethod
    def _limits(**overrides: int) -> ProtectedSourceScanLimits:
        return replace(DEFAULT_PROTECTED_SOURCE_SCAN_LIMITS, **overrides)

    @staticmethod
    def _public_shape(candidate: object) -> tuple[object, ...]:
        return (
            candidate.relative_path,
            candidate.reason_codes,
            candidate.confidence,
            candidate.proposed_source,
            candidate.already_registered,
        )

    def test_scan_is_deterministic_and_applies_fixed_and_explicit_exclusions(
        self,
    ) -> None:
        for relative_path in (
            "z.json",
            "node_modules/package/credentials.json",
            "a/.env",
            ".git/private.json",
            ".cache/private.json",
            ".tooluseproxy/internal.json",
            "build/generated.json",
            "private-skip/credentials.json",
        ):
            self._write_secret(relative_path)
        (self.workspace / "m.json").write_text(
            json.dumps({"public_url": "https://example.invalid"}),
            encoding="utf-8",
        )

        first = scan_protected_sources(
            self.workspace,
            "deterministic-workspace",
            excluded_relative_paths=("private-skip",),
        )
        second = scan_protected_sources(
            self.workspace,
            "deterministic-workspace",
            excluded_relative_paths=("private-skip",),
        )

        self.assertTrue(first.scan_complete)
        self.assertEqual(
            ["a/.env", "z.json"],
            [candidate.relative_path for candidate in first.candidates],
        )
        self.assertEqual(
            [self._public_shape(candidate) for candidate in first.candidates],
            [self._public_shape(candidate) for candidate in second.candidates],
        )
        skipped = dict(first.skipped_counts)
        self.assertGreaterEqual(skipped["excluded_directory"], 4)
        self.assertEqual(1, skipped["excluded_path"])
        self.assertEqual(1, skipped["no_secret_selector"])

    def test_explicit_exclusion_identity_is_independent_of_lexical_matching(self) -> None:
        self._write_secret(
            "runtime-data/manifest-backups/legacy.json",
            "IDENTITY.EXCLUSION.SECRET.3d20",
        )

        with patch.object(
            protected_source_module,
            "_scan_path_is_excluded",
            return_value=False,
        ):
            result = scan_protected_sources(
                self.workspace,
                "identity-exclusion-workspace",
                excluded_relative_paths=("runtime-data",),
            )

        self.assertTrue(result.scan_complete)
        self.assertEqual((), result.candidates)
        self.assertEqual(1, dict(result.skipped_counts)["excluded_path"])

    def test_depth_file_eligible_and_total_byte_limits_are_exact(self) -> None:
        self._write_secret("depth/.env.allowed")
        self._write_secret("depth/deeper/.env.omitted")
        depth = scan_protected_sources(
            self.workspace,
            "depth-workspace",
            limits=self._limits(max_depth=2),
        )
        self.assertEqual(
            ["depth/.env.allowed"],
            [candidate.relative_path for candidate in depth.candidates],
        )
        self.assertFalse(depth.scan_complete)
        self.assertIn("depth_limit", depth.truncation_reasons)

        for child in self.workspace.iterdir():
            if child.name != MANIFEST_FILENAME:
                if child.is_dir():
                    for nested in sorted(child.rglob("*"), reverse=True):
                        if nested.is_file() or nested.is_symlink():
                            nested.unlink()
                        else:
                            nested.rmdir()
                    child.rmdir()
                else:
                    child.unlink()
        (self.workspace / "a.txt").write_text("ordinary", encoding="utf-8")
        self._write_secret("b/.env")
        files = scan_protected_sources(
            self.workspace,
            "file-limit-workspace",
            limits=self._limits(max_files=1),
        )
        self.assertEqual((), files.candidates)
        self.assertIn("file_limit", files.truncation_reasons)

        (self.workspace / "a.txt").unlink()
        for path in sorted((self.workspace / "b").rglob("*"), reverse=True):
            path.unlink()
        (self.workspace / "b").rmdir()
        first_path = self._write_secret(".env.a", "A" * 32)
        self._write_secret(".env.b", "B" * 32)
        eligible = scan_protected_sources(
            self.workspace,
            "eligible-limit-workspace",
            limits=self._limits(max_eligible_files=1),
        )
        self.assertEqual([".env.a"], [item.relative_path for item in eligible.candidates])
        self.assertIn("eligible_file_limit", eligible.truncation_reasons)

        total = scan_protected_sources(
            self.workspace,
            "byte-limit-workspace",
            limits=self._limits(max_total_read_bytes=first_path.stat().st_size),
        )
        self.assertEqual([".env.a"], [item.relative_path for item in total.candidates])
        self.assertEqual(first_path.stat().st_size, total.inspected_bytes)
        self.assertIn("total_read_bytes_limit", total.truncation_reasons)

    def test_entry_limit_discards_every_candidate(self) -> None:
        self._write_secret(".env.a")
        self._write_secret(".env.b")

        result = scan_protected_sources(
            self.workspace,
            "entry-limit-workspace",
            limits=self._limits(max_entries=2),
        )

        self.assertFalse(result.scan_complete)
        self.assertEqual((), result.candidates)
        self.assertEqual(0, result.public_candidate_bytes)
        self.assertEqual(2, result.entries_seen)
        self.assertIn("entry_limit", result.truncation_reasons)

    def test_candidate_and_public_metadata_limits_are_bounded(self) -> None:
        for suffix in ("a", "b", "c"):
            self._write_secret(f".env.{suffix}", suffix.upper() * 8)

        candidate_limited = scan_protected_sources(
            self.workspace,
            "candidate-limit-workspace",
            limits=self._limits(max_candidates=1),
        )
        self.assertEqual(3, candidate_limited.detected_candidate_count)
        self.assertEqual(1, len(candidate_limited.candidates))
        self.assertIn("candidate_limit", candidate_limited.truncation_reasons)

        one = scan_protected_sources(
            self.workspace,
            "metadata-limit-workspace",
            limits=self._limits(max_candidates=1),
        )
        metadata_limited = scan_protected_sources(
            self.workspace,
            "metadata-limit-workspace",
            limits=self._limits(
                max_public_metadata_bytes=one.public_candidate_bytes,
            ),
        )
        self.assertEqual(1, len(metadata_limited.candidates))
        self.assertLessEqual(
            metadata_limited.public_candidate_bytes,
            metadata_limited.candidates
            and one.public_candidate_bytes,
        )
        self.assertIn("public_metadata_limit", metadata_limited.truncation_reasons)

    @unittest.skipIf(os.name == "nt", "POSIX file-kind safety test")
    def test_scan_skips_symlinks_hardlinks_and_fifos_without_reading_them(self) -> None:
        safe = self._write_secret(".env.safe", "SAFE.SCANNER.SECRET")
        outside = self.root / ".env.outside"
        outside.write_text("PRIVATE_TOKEN=OUTSIDE.SCANNER.SECRET\n", encoding="utf-8")
        (self.workspace / ".env.link").symlink_to(outside)
        real_directory = self.workspace / "real-directory"
        real_directory.mkdir()
        self._write_secret("real-directory/.env.hidden")
        (self.workspace / "linked-directory").symlink_to(
            real_directory,
            target_is_directory=True,
        )
        original = self._write_secret(".env.original", "HARDLINK.SCANNER.SECRET")
        os.link(original, self.workspace / ".env.hardlink")
        os.mkfifo(self.workspace / ".env.pipe")

        result = scan_protected_sources(self.workspace, "safe-kind-workspace")

        self.assertEqual(
            [safe.name, "real-directory/.env.hidden"],
            [item.relative_path for item in result.candidates],
        )
        skipped = dict(result.skipped_counts)
        self.assertEqual(2, skipped["symlink"])
        self.assertEqual(2, skipped["hardlink"])
        self.assertEqual(1, skipped["non_regular"])
        rendered = repr(result)
        self.assertNotIn("OUTSIDE.SCANNER.SECRET", rendered)
        self.assertNotIn("HARDLINK.SCANNER.SECRET", rendered)

    def test_legacy_manifest_fails_before_any_candidate_source_read(self) -> None:
        self._write_secret(".env", "LEGACY.BEFORE.READ.SECRET")
        self._write_manifest({"schema_version": 1, "sources": []})

        with patch.object(
            protected_source_module,
            "_read_scan_source_text",
            wraps=protected_source_module._read_scan_source_text,
        ) as source_reader:
            with self.assertRaises(ProtectedSourceRegistrationError) as raised:
                scan_protected_sources(self.workspace, "legacy-workspace")

        self.assertEqual("manifest_schema_legacy", raised.exception.code)
        source_reader.assert_not_called()
        self.assertNotIn("LEGACY.BEFORE.READ.SECRET", str(raised.exception))

    def test_manifest_change_after_classification_discards_the_scan(self) -> None:
        self._write_secret(".env", "MANIFEST.RACE.SCANNER.SECRET")
        real_scan_directory = protected_source_module._scan_protected_source_directory

        def mutate_manifest_after_scan(*args: object, **kwargs: object) -> None:
            real_scan_directory(*args, **kwargs)
            payload = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            payload["external_change"] = True
            self._write_manifest(payload)

        with patch.object(
            protected_source_module,
            "_scan_protected_source_directory",
            side_effect=mutate_manifest_after_scan,
        ):
            with self.assertRaises(ProtectedSourceRegistrationError) as raised:
                scan_protected_sources(self.workspace, "manifest-race-workspace")

        self.assertEqual("manifest_conflict", raised.exception.code)
        self.assertNotIn("MANIFEST.RACE.SCANNER.SECRET", str(raised.exception))

    def test_changed_source_is_value_free_and_marks_scan_incomplete(self) -> None:
        source = self._write_secret(".env", "SOURCE.RACE.SCANNER.SECRET")
        real_reader = protected_source_module._read_scan_source_text

        def replace_before_read(*args: object, **kwargs: object):
            source.write_text("PRIVATE_TOKEN=ROTATED.SCANNER.SECRET\n", encoding="utf-8")
            return real_reader(*args, **kwargs)

        with patch.object(
            protected_source_module,
            "_read_scan_source_text",
            side_effect=replace_before_read,
        ):
            result = scan_protected_sources(self.workspace, "source-race-workspace")

        self.assertFalse(result.scan_complete)
        self.assertEqual((), result.candidates)
        self.assertIn("source_changed", result.truncation_reasons)
        rendered = repr(result)
        self.assertNotIn("SOURCE.RACE.SCANNER.SECRET", rendered)
        self.assertNotIn("ROTATED.SCANNER.SECRET", rendered)

    def test_explicit_suggestion_and_scan_share_the_exact_candidate_contract(self) -> None:
        self._write_secret("config/credentials.json", "PARITY.SCANNER.SECRET")

        explicit = suggest_protected_source(
            self.workspace,
            "config/credentials.json",
            workspace_id="parity-workspace",
        )
        scanned = scan_protected_sources(self.workspace, "parity-workspace")

        self.assertEqual(1, len(scanned.candidates))
        candidate = scanned.candidates[0]
        self.assertEqual(self._public_shape(explicit), self._public_shape(candidate))
        self.assertEqual(explicit.suppression_fingerprint, candidate.suppression_fingerprint)

    def test_already_registered_source_is_counted_without_being_returned(self) -> None:
        self._write_secret(".env", "REGISTERED.SCANNER.SECRET")
        self._write_manifest(
            {
                "schema_version": 2,
                "sources": [
                    {
                        "id": "legacy_selectorless_env",
                        "path": ".env",
                        "type": "secretfile",
                        "sensitivity": "high",
                        "policy_tags": ["no_external"],
                    }
                ],
            }
        )

        result = scan_protected_sources(self.workspace, "registered-workspace")

        self.assertTrue(result.scan_complete)
        self.assertEqual((), result.candidates)
        self.assertEqual(1, result.already_registered_count)

    def test_parse_failures_are_value_free_and_no_selector_is_not_incomplete(self) -> None:
        invalid_secret = "INVALID.JSON.SCANNER.SECRET"
        (self.workspace / "invalid.json").write_text(
            '{"private_token": "' + invalid_secret,
            encoding="utf-8",
        )
        (self.workspace / ".env.public").write_text(
            "PUBLIC_URL=https://example.invalid\n",
            encoding="utf-8",
        )
        excluded_secret = "EXCLUDED.PATH.SCANNER.SECRET"
        self._write_secret("do-not-show/credentials.json", excluded_secret)

        result = scan_protected_sources(
            self.workspace,
            "privacy-workspace",
            excluded_relative_paths=("do-not-show",),
        )

        self.assertFalse(result.scan_complete)
        self.assertEqual((), result.candidates)
        skipped = dict(result.skipped_counts)
        self.assertEqual(1, skipped["source_not_parseable"])
        self.assertEqual(1, skipped["no_secret_selector"])
        rendered = repr(result)
        self.assertNotIn(invalid_secret, rendered)
        self.assertNotIn(excluded_secret, rendered)
        self.assertNotIn("do-not-show", rendered)
        source_digest = hashlib.sha256(
            (self.workspace / "invalid.json").read_bytes()
        ).hexdigest()
        self.assertNotIn(source_digest, rendered)

    def test_invalid_or_raised_scan_limits_are_rejected(self) -> None:
        invalid_limits = (
            self._limits(max_depth=0),
            self._limits(
                max_entries=DEFAULT_PROTECTED_SOURCE_SCAN_LIMITS.max_entries + 1
            ),
        )
        for limits in invalid_limits:
            with self.subTest(limits=limits):
                with self.assertRaises(ProtectedSourceRegistrationError) as raised:
                    scan_protected_sources(
                        self.workspace,
                        "invalid-limit-workspace",
                        limits=limits,
                    )
                self.assertEqual("scan_limits_invalid", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
