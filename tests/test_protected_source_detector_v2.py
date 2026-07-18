from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from tooluseproxy.protected_sources import (
    DETECTOR_VERSION,
    LEGACY_DETECTOR_VERSION,
    ProtectedSourceCandidate,
    ProtectedSourceRegistrationError,
    approve_protected_source,
    ignore_protected_source_candidate,
    reject_protected_source_candidate,
    suggest_protected_source,
)


class ProtectedSourceDetectorV2Test(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.workspace = Path(self._temporary_directory.name) / "workspace"
        self.workspace.mkdir()
        self.manifest_path.write_text(
            '{"schema_version":2,"sources":[]}\n',
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self._temporary_directory.cleanup()

    @property
    def manifest_path(self) -> Path:
        return self.workspace / "protected_sources.json"

    def _write(self, relative_path: str, content: str) -> Path:
        path = self.workspace / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def _suggest(self, relative_path: str) -> ProtectedSourceCandidate:
        return suggest_protected_source(
            self.workspace,
            relative_path,
            workspace_id="detector-v2-test",
        )

    @staticmethod
    def _selector(candidate: ProtectedSourceCandidate) -> list[str]:
        selector = candidate.proposed_source["selector"]
        assert isinstance(selector, dict)
        values = next(iter(selector.values()))
        assert isinstance(values, list)
        return values

    def _assert_no_candidate(self, relative_path: str, content: str) -> None:
        self._write(relative_path, content)
        with self.assertRaises(ProtectedSourceRegistrationError) as raised:
            self._suggest(relative_path)
        self.assertEqual("no_secret_selector", raised.exception.code)

    def test_mixed_dotenv_omits_definitive_placeholders_and_references(self) -> None:
        canary = "MIXED.DOTENV.REAL.7f29"
        self._write(
            ".env.mixed",
            "\n".join(
                (
                    f"REAL_TOKEN={canary}",
                    "SHELL_TOKEN=${DEV_SECRET_REF}",
                    "BARE_TOKEN=$VALIDATION_VAULT_REF",
                    "MUSTACHE_TOKEN={{ secret_ref }}",
                    "ANGLE_TOKEN=<replace-me>",
                    "SET_TOKEN=__SET_ME__",
                    "MASKED_TOKEN=********",
                    "WITHHELD_TOKEN=[withheld]",
                    "VAULT_TOKEN=vault://apps/service/token",
                    "SSM_TOKEN=arn:aws:ssm:ap-northeast-1:123:parameter/app",
                    "AWS_TOKEN=aws-secretsmanager://apps/service/token",
                    "GCP_TOKEN=projects/example/secrets/app/versions/latest",
                    "",
                )
            ),
        )

        candidate = self._suggest(".env.mixed")

        self.assertEqual(["REAL_TOKEN"], self._selector(candidate))
        self.assertEqual(DETECTOR_VERSION, candidate.detector_version)
        rendered = repr(candidate)
        self.assertNotIn(canary, rendered)
        self.assertNotIn(candidate.source_binding.sha256, rendered)

    def test_weak_placeholder_requires_a_placeholder_like_basename(self) -> None:
        self._assert_no_candidate(
            ".env.example",
            "PRIVATE_TOKEN=sample-dev-token\n",
        )
        self._assert_no_candidate(
            "tests/fixtures/dummy-01.json",
            json.dumps({"token": "sample-validation-token"}),
        )
        self._assert_no_candidate(
            "config/defaults.json",
            json.dumps({"token": "fake-token"}),
        )

        self._write(
            "tests/fixtures/live/.env",
            "PRIVATE_TOKEN=sample-live-token\n",
        )
        fixture_live = self._suggest("tests/fixtures/live/.env")
        self.assertEqual(["PRIVATE_TOKEN"], self._selector(fixture_live))

        self._write("config/runtime.json", json.dumps({"token": "dummy-live-token"}))
        runtime = self._suggest("config/runtime.json")
        self.assertEqual(["/token"], self._selector(runtime))

    def test_example_and_fixture_paths_do_not_veto_real_values(self) -> None:
        value = "opaque-production-credential-9d7c"
        for relative_path, content, expected in (
            (".env.example", f"PRIVATE_TOKEN={value}\n", ["PRIVATE_TOKEN"]),
            (
                "tests/fixtures/live/config.json",
                json.dumps({"clientSecret": value}),
                ["/clientSecret"],
            ),
            (
                "cookbook/reference.json",
                json.dumps({"private_key": value}),
                ["/private_key"],
            ),
        ):
            with self.subTest(relative_path=relative_path):
                self._write(relative_path, content)
                self.assertEqual(expected, self._selector(self._suggest(relative_path)))

    def test_protocol_and_reference_metadata_require_matching_value_semantics(
        self,
    ) -> None:
        payload = {
            "metadata": {
                "auth": "oauth2",
                "authScheme": "OAuth2",
                "auth_method": "OpenID",
                "authorizationScheme": "OpenID",
                "token_type": "Bearer",
                "tokenMode": "DPoP",
                "auth_mode": "private_key_jwt",
                "private_key_algorithm": "Ed25519",
                "private_key_path": "key.pem",
                "secret_name": "prod-key",
                "secret_version": "v3",
                "auth_url": "https://auth.example.invalid/token",
                "token_scope": "read:all write:all",
            },
            "live": {
                "auth": "Bearer-live-d-8a10",
                "token_type": "opaque-nonenum-v-7b91",
                "access_key_id": "synthetic-access-id-7c20",
                "access_key": "Digest",
                "api_key": "Basic",
                "app_credential": "access",
                "authorization": "opaque-authorization-value-219e",
                "client_secret": "jwt",
                "password": "password",
                "service_secret": "Bearer",
            },
        }
        self._write("config/auth.json", json.dumps(payload))

        candidate = self._suggest("config/auth.json")

        self.assertEqual(
            [
                "/live/access_key",
                "/live/access_key_id",
                "/live/api_key",
                "/live/app_credential",
                "/live/auth",
                "/live/authorization",
                "/live/client_secret",
                "/live/password",
                "/live/service_secret",
                "/live/token_type",
            ],
            self._selector(candidate),
        )

    def test_exact_metadata_and_placeholder_checks_preserve_prefixed_values(self) -> None:
        self._write(
            ".env.hard-positive",
            "\n".join(
                (
                    "AUTH_TOKEN=Bearer-live-d-1234",
                    "PRIVATE_TOKEN=replace-resistant-d-5678",
                    "ACCESS_TOKEN=configure-resistant-v-9012",
                    "BEARER_TOKEN=DPoP-live-v-3456",
                    "",
                )
            ),
        )

        candidate = self._suggest(".env.hard-positive")

        self.assertEqual(
            ["ACCESS_TOKEN", "AUTH_TOKEN", "BEARER_TOKEN", "PRIVATE_TOKEN"],
            self._selector(candidate),
        )

    def test_nfkc_camel_acronym_and_separator_key_normalization(self) -> None:
        value = "normalization-secret-70b2"
        self._write(
            "config/normalized.json",
            json.dumps(
                {
                    "clientSecret": value,
                    "APIKey": value,
                    "X-APIKey": value,
                    "ｐｒｉｖａｔｅ＿ｋｅｙ": value,
                    "private/token": value,
                },
                ensure_ascii=False,
            ),
        )

        candidate = self._suggest("config/normalized.json")

        self.assertEqual(
            [
                "/APIKey",
                "/X-APIKey",
                "/clientSecret",
                "/private~1token",
                "/ｐｒｉｖａｔｅ＿ｋｅｙ",
            ],
            self._selector(candidate),
        )

    def test_source_id_derivation_remains_in_the_v1_domain(self) -> None:
        relative_path = ".env.stable-id"
        self._write(relative_path, "PRIVATE_TOKEN=stable-id-secret-36ef\n")

        candidate = self._suggest(relative_path)

        identity = f"{LEGACY_DETECTOR_VERSION}\0{relative_path}".encode("utf-8")
        expected = (
            "protected_env_stable_id_"
            + hashlib.sha256(identity).hexdigest()[:16]
        )
        self.assertEqual(expected, candidate.proposed_source["id"])

    def test_old_proposed_candidates_and_review_operations_fail_closed(self) -> None:
        self._write(".env.stale", "PRIVATE_TOKEN=stale-candidate-secret-4d80\n")
        current = self._suggest(".env.stale")
        legacy_proposed = replace(
            current,
            candidate_id="a" * 32,
            detector_version=LEGACY_DETECTOR_VERSION,
            status="proposed",
        )

        for legacy in (legacy_proposed, self._storage_record(legacy_proposed)):
            with self.subTest(kind=type(legacy).__name__):
                with self.assertRaises(ProtectedSourceRegistrationError) as raised:
                    approve_protected_source(
                        self.workspace,
                        legacy,
                        candidate_revision=current.candidate_revision,
                    )
                self.assertEqual("candidate_detector_stale", raised.exception.code)

        legacy_approving = replace(legacy_proposed, status="approving")
        for review in (
            reject_protected_source_candidate,
            ignore_protected_source_candidate,
        ):
            for legacy in (
                legacy_proposed,
                self._storage_record(legacy_proposed),
                legacy_approving,
                self._storage_record(legacy_approving),
            ):
                with self.subTest(
                    review=review.__name__,
                    kind=type(legacy).__name__,
                ):
                    with self.assertRaises(
                        ProtectedSourceRegistrationError
                    ) as raised:
                        review(
                            legacy,
                            candidate_revision=current.candidate_revision,
                        )
                    self.assertEqual(
                        "candidate_detector_stale",
                        raised.exception.code,
                    )

        unknown = replace(
            legacy_approving,
            detector_version="protected-source-candidate-v999",
        )
        with self.assertRaises(ProtectedSourceRegistrationError) as raised:
            approve_protected_source(
                self.workspace,
                unknown,
                candidate_revision=current.candidate_revision,
            )
        self.assertEqual("candidate_detector_stale", raised.exception.code)
        with self.assertRaises(ProtectedSourceRegistrationError) as raised:
            approve_protected_source(
                self.workspace,
                self._storage_record(unknown),
                candidate_revision=current.candidate_revision,
            )
        self.assertEqual("candidate_detector_stale", raised.exception.code)

    def test_old_approving_candidate_uses_v1_logic_for_exact_recovery(self) -> None:
        self._write(
            ".env.legacy-recovery",
            "AUTH=oauth2\n"
            "APIKey=v2-only-normalized-secret-3b92\n"
            "PRIVATE_TOKEN=legacy-real-secret-8d31\n",
        )
        current = self._suggest(".env.legacy-recovery")
        legacy_source = dict(current.proposed_source)
        legacy_source["selector"] = {
            "dotenv_keys": ["AUTH", "PRIVATE_TOKEN"],
        }
        legacy = replace(
            current,
            candidate_id="b" * 32,
            proposed_source=legacy_source,
            detector_version=LEGACY_DETECTOR_VERSION,
            status="approving",
        )

        first = approve_protected_source(
            self.workspace,
            legacy,
            candidate_revision=current.candidate_revision,
            expected_manifest_sha256=current.manifest_sha256,
        )
        recovered = approve_protected_source(
            self.workspace,
            self._storage_record(legacy),
            candidate_revision=current.candidate_revision,
            expected_manifest_sha256=current.manifest_sha256,
        )
        legacy_approved = replace(legacy, status="approved")
        approved_recovered = approve_protected_source(
            self.workspace,
            self._storage_record(legacy_approved),
            candidate_revision=current.candidate_revision,
            expected_manifest_sha256=current.manifest_sha256,
        )

        self.assertEqual("approved", first.status)
        self.assertEqual("already_registered", recovered.status)
        self.assertEqual("already_registered", approved_recovered.status)
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(
            {"dotenv_keys": ["AUTH", "PRIVATE_TOKEN"]},
            manifest["sources"][0]["selector"],
        )

    def test_public_surfaces_never_include_value_or_value_hash(self) -> None:
        placeholder = "PRIVATE.PLACEHOLDER.CANARY.26a9"
        real = "PRIVATE.REAL.CANARY.43bd"
        self._write(
            "privacy.json",
            json.dumps(
                {
                    "auth": "oauth2",
                    "client_secret": real,
                    "token_ref": f"vault://{placeholder}",
                }
            ),
        )
        candidate = self._suggest("privacy.json").with_candidate_id("c" * 32)
        surfaces = (
            repr(candidate),
            json.dumps(candidate.to_public_payload(), sort_keys=True),
            " ".join(candidate.reason_codes),
        )

        for surface in surfaces:
            self.assertNotIn(placeholder, surface)
            self.assertNotIn(real, surface)
            self.assertNotIn(hashlib.sha256(placeholder.encode()).hexdigest(), surface)
            self.assertNotIn(hashlib.sha256(real.encode()).hexdigest(), surface)
            self.assertNotIn(candidate.source_binding.sha256, surface)

        self._assert_no_candidate(
            ".env.private-error",
            f"PRIVATE_TOKEN=<${placeholder}>\n",
        )
        try:
            self._suggest(".env.private-error")
        except ProtectedSourceRegistrationError as error:
            rendered_error = repr(error)
        else:  # pragma: no cover - guarded by _assert_no_candidate
            self.fail("placeholder source unexpectedly produced a candidate")
        self.assertNotIn(placeholder, rendered_error)
        self.assertNotIn(hashlib.sha256(placeholder.encode()).hexdigest(), rendered_error)

    @staticmethod
    def _storage_record(candidate: ProtectedSourceCandidate) -> dict[str, object]:
        record = candidate.to_storage_record()
        record.update(
            {
                "candidate_id": candidate.candidate_id,
                "status": candidate.status,
            }
        )
        return record


if __name__ == "__main__":
    unittest.main()
