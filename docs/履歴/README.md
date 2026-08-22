# 履歴資料

このdirectoryには、当時の判断、実験結果、移行経緯を再現するために残す文書を置きます。現行の仕様、保証、優先順位を判断するときの正本ではありません。

現在の入口:

- [研究目的と検知モデル](../研究/現行研究方針.md)
- [現在の実装タスク](../運用/実装タスク.md)
- [現行アーキテクチャ](../設計/アーキテクチャ.md)
- [ドキュメント索引](../索引.md)

## 収録資料

- [Network egress観測とAudit改善計画](調査/NetworkEgress観測とAudit改善計画.md)
  - Codex network proxy / app-server / OTLPをproduction境界へ使えるか調べた過程
  - OTLPは実行後かつtool単位join不能のためproduction不採用、というnegative resultを保存
- [実装タスク計画（2026-08-10時点）](運用/実装タスク-2026-08-10.md)
  - Plugin alpha、Desktop Phase B、network probe、Externality Judgeへ至る詳細な時系列
  - 現行の短い実装タスクへ置き換える前のsnapshot

## 扱い方

- 履歴文書の「次に行う」「正本」「現在」は、文書作成当時の意味として読む
- 現行文書から履歴へは、過去の根拠やnegative resultを確認する場合だけlinkする
- 新しい仕様から履歴文書へ逆参照して、古い方針を現行要件へ戻さない
- 履歴文書自体は事実誤認や壊れたlinkの修正を除き、現在形へ書き換えない
