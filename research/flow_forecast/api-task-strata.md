# 閉じたAPI実行の課題別・道具別集計

MessageAPIとTicketAPIの固定source、保存した状態・呼び出し・受信結果を再検証し、
比較レポートへ `task-api/…` と `tool-api/…` の層別成績を追加する。
各モデルの全体評価で凍結した閾値をそのまま使い、APIごとの再調整はしない。

これらは完了した継続枝を後から分類する説明用ラベルであり、Prefixや予測器へ渡さない。
同じ枝は複数APIに属するため、API別件数の合計は全体件数ではない。
分母と重みは従来の関連群方式を保つ。実行を拒否されたAPIはdispatch済みに数えない。
`generalization.closed_api_tasks` はpartitionごとの観測API/課題名と証拠の有無を示す。
名前がtrainになかっただけでは独立性や未使用性を証明しない。F02の受入判定は不変。

新しいMessage/Ticket collectionは、公開source本文をローカル監査記録にも保存する。
既存sealは変更しない。source本文のない旧記録や未対応課題は `task-api/missing-evidence`。
対応する記録ではroot/design binding、元captureの枝、checked契約、collection封印を照合し、
矛盾があれば評価を拒否する。holdoutでは初回開封予約後に監査を読み、途中失敗も開封を消費する。

## 実記録による確認（2026-09-20）

既存の人工Message/Ticket各2captureと介入記録から新しいcollectionを作成した。
`/private/tmp/tooluseproxy-204-api-strata-message-v1` と
`/private/tmp/tooluseproxy-204-api-strata-ticket-v1`。新しいモデル呼出・trialは0。
元のデータとsplitは維持し、Messageは1関連群/train、Ticketは1関連群/calibration。
それぞれ4APIのdispatch証拠を検証した。2rootsは独立2群を意味しない。

Messageのprepare/train評価を実行し、各モデルの層別成績と共通閾値を確認した。
結果は `inconclusive_do_not_adopt`。testは空であり、新たに受入可能となった独立群は0。
Ticketはtrainなしのため比較モデルの学習は行わない。
封印識別と集計は `results/api-task-strata-20260920.json` に保存。
未使用課題・道具・モデルの本評価、独立データ量、固定モデル版・費用証拠は#204の残件。

## 学習診断とtest証拠の区別

`--partition train` の評価数・性能は `scored_partition_metrics` に保存し、
受入判定の `test_*` とtest性能指標には流用しない（null/未評価）。
モデル別の診断値と部品除去の詳細は残すが、学習試験の値で一般化・部品除去の
受入条件を満たさない。test区分がデータ中に存在するだけでも評価済みとは扱わない。
課題分類 `unknown` は新しい課題名ではない。train/testの課題分類に不明があれば、
課題間一般化の受入条件は未確認とし、そのprefix数をレポートに残す。

2026-09-20に既存Message collectionの凍結計画を再評価した。
学習診断の正例1群と行数は保存され、受入側test件数はnull、判定は
`inconclusive_do_not_adopt`。新しいモデル呼出・trial・独立群は0。
旧レポートやsealed collectionは書き換えていない。
