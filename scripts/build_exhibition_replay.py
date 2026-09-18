"""Export only fixed, value-free exhibition fields from the synthetic Plugin demo."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def export_replay(evidence: object) -> dict:
    if not isinstance(evidence, dict):
        raise ValueError("demo evidence must be an object")
    checks = evidence.get("checks")
    if (evidence.get("status") != "passed"
            or evidence.get("demo_kind") != "automated_phase_a_preview"
            or not isinstance(checks, dict)
            or checks.get("public_call_allowed") is not True
            or checks.get("protected_call_denied") is not True
            or checks.get("raw_value_exposure") is not False
            or type(checks.get("external_side_effect_count")) is not int
            or checks["external_side_effect_count"] != 0):
        raise ValueError("required synthetic demo evidence is missing")
    version, digest = evidence.get("plugin_version"), evidence.get("artifact_sha256")
    if (not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+-alpha\.\d+", version)
            or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
        raise ValueError("invalid artifact identity")
    # Never copy reports, tool arguments, source text, local paths or free-form
    # diagnostics. All display strings below are authored for the exhibition.
    return {
        "schema": 1, "mode": "synthetic_replay", "version": version, "artifact": digest,
        "source": "scripts/demo_plugin.py", "receiver": "not_observed",
        "scenarios": [
            {"id": "protected", "title": "保護情報が外へ向かう操作を、実行前に停止する。",
             "source": "保護対象の情報", "verdict": "停止", "tone": "blocked",
             "kind": "固定人工試験の判定", "proof": "人工試験で停止判定を確認",
             "steps": [
                 ["情報の出所", "保護対象として登録された人工情報", "情報の内容は表示しません。固定試験で用意した人工情報を、保護対象として扱います。"],
                 ["ツールへの入力", "Shellから外部へ送る操作", "読み取った情報を含む送信操作がShellへの入力になる経路を、説明用に再構成しています。"],
                 ["送信前に停止", "操作の実行前に停止を判定", "固定人工試験で、保護情報を含む操作に停止判定が返ったことを確認しています。実環境での遮断成功の証明ではありません。"],
                 ["受信の証拠を確認", "外部の受信結果は未観測", "この固定試験には受信側の記録がありません。判定が停止でも、外部が受信しなかったという観測結果には置き換えません。"],
             ]},
            {"id": "public", "title": "公開情報を扱う通常の操作は、そのまま許可する。",
             "source": "公開してよい情報", "verdict": "許可", "tone": "allowed",
             "kind": "固定人工試験の判定", "proof": "人工試験で許可判定を確認",
             "steps": [
                 ["情報の出所", "公開してよい人工情報", "固定試験で用意した公開情報の例です。実利用の文章や認証情報は含まれていません。"],
                 ["ツールへの入力", "通常の外部送信操作", "公開情報をShellの送信操作へ渡す経路を、説明用に再構成しています。"],
                 ["通常操作を許可", "操作の実行前に許可を判定", "固定人工試験で、公開情報の通常操作が許可されたことを確認しています。展示の再生時に実際の送信は行いません。"],
                 ["受信の証拠を確認", "許可と配信完了は別の結果", "操作が許可されても、相手に届いたとは限りません。受信側の観測証拠がないため、受信結果は未観測と表示します。"],
             ]},
            {"id": "unknown", "title": "証拠が足りなければ、不明のまま区別する。",
             "source": "分類が確定していない情報", "verdict": "不明", "tone": "unknown",
             "kind": "説明用の人工例（試験結果ではありません）", "proof": "判定証拠なし・説明用",
             "steps": [
                 ["情報の出所", "情報の性質が未確定", "不明という表示を説明するための人工例です。実際に観測した試験結果ではありません。"],
                 ["ツールへの入力", "移動先の証拠が足りない", "情報の由来や送信先を確定する材料が不足している場合を表しています。"],
                 ["判定を確定しない", "許可・停止へ推測で置き換えない", "観測されていない判定は不明と表示します。この例は実際のHookの実行結果ではありません。"],
                 ["受信の証拠を確認", "受信も未観測", "判定の不明と、受信側の未観測を別々に表示します。成功・失敗のどちらも推測しません。"],
             ]},
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    data = export_replay(json.loads(args.evidence.read_text(encoding="utf-8")))
    args.output.write_text("window.EXHIBITION_REPLAY = " + json.dumps(
        data, ensure_ascii=False, indent=2,
    ) + ";\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
