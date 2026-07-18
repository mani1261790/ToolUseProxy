# Similarity evaluation dataset v1

このディレクトリは、ToolUseProxy の類似度改善を production の閾値変更より先に測るための固定 corpus です。

- **pairs.jsonl**: artifact 間と protected source → artifact の pair 正解ラベル
- **scenarios.jsonl**: source → artifact chain → sink の到達性と policy action の正解ラベル
- **manifest.json**: schema version、dataset version、構成ファイル

すべて手作業の synthetic data で、provenance=synthetic を必須とします。実ファイル、環境変数、外部サービス、remote embedding を読みません。長い共通 marker は 5-gram の交絡要因になるため評価本文には使わず、loader が既知の実credential形式を拒否します。

## ラベル

- **should_link**: text だけを証拠に情報伝播 edge を張るのが妥当か。意味が逆転した文や、値が異なるtemplateは「派生の可能性」ではなく「textだけでedgeを張る十分性」を false とする
- **should_reach_sink**: direct edge の本数によらず source lineage が sink に到達すべきか
- **expected_action**: finding がない場合を allow とみなした最終 action
- **observe_only**: baseline には表示するが release gate や閾値調整には使わない研究ケース

artifact_flow は現行 runtime と同じ minimum length 8、source_binding は 4 で評価します。候補検索 recall、pair classification、lineage reachability、policy action は混ぜずに集計します。

## split の運用

development は方式・閾値を検討するための split です。validation は同じリポジトリから読めるため blind / sealed holdout ではなく、実装案を development で確定した後の比較用です。case を追加・修正した場合は dataset version を更新し、baseline report に corpus digest を記録します。真の holdout が必要な場合はリポジトリ外で管理します。

## v1 の既知の限界

- corpus は synthetic であり、実秘密を収集した代表標本ではありません。
- candidate limit 50 / 200 の境界動作は runner の決定的 unit test で検証します。v1 corpus の recall は小さいpoolでの lexical eligibility であり、順位性能やcap負荷の代表値ではありません。
- E2E scenario は source chunk と artifact fragment を直接構築するため、dotenv / JSON の実chunkingとadapter extractionは後続corpusで測ります。
- semantic paraphrase は local lexical baseline の研究用で observe_only=true です。Hook runtime の network 利用を許可するラベルではありません。
