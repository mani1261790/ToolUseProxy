# BFCL Ticket APIの隔離参照実行（#204）

固定commit `6ea57973c7a6097fd7c5915698c54c17c5b1b6c8` のTicketAPIをSHA-256で照合し、
全体を変更せずにDocker内で実行する。公開元の実装はホストでimportしない。
上流runner・対話データ・実利用DBは使わず、3件の人工ticketを初期状態にする。
[公開元・利用条件の監査](bfcl-source-audit.md)を前提とする。

一覧の所有者/状態filter、他所有者のID指定取得とresolve、未対応fieldの更新拒否、
priority=0へのeditの計6ケースについて、返り値と更新後の状態を事前の期待値と比較する。
一覧には所有者filterがあるが、ID指定取得・resolveにはない。editはpriority=0を受理する。
これらは固定版の模擬APIの挙動であり、実サービスの認証やアクセス制御の保証にはしない。

各ケースは新しいnetwork-none・非特権・read-only containerで実行する。
初期状態設定とAPI呼出しをそれぞれ1試行として先に予約し、合計12試行。
上限20試行・180秒（指定可能な最大1,800秒）・1GiBで、次バッチへの自動延長は行わない。
個々の実行は既存の10秒timeoutとfinallyでの対象container削除を使う。
全体時間と容量は各工程の前後で検査する方式で、全工程の厳密なOS強制deadlineではない。

```sh
python -m research.flow_forecast.bfcl_ticket_reference \
  --repository ISOLATED_CHECKOUT --source PINNED_TICKET_API.py \
  --output NEW_ARTIFACT_DIRECTORY --seconds 180
```

2026-09-19の明示1バッチは、12試行（API呼出し6回）、6.468964084秒、
report前47,987 bytesで完了。6件すべての返り値・更新後状態が一致した。
予約・実行script・観測・reportのhash対応も再確認した。
[実測記録](results/bfcl-ticket-reference-20260919.json)に版・image・hashを保存する。

新しいモデル呼出し0、採用独立群0。6ケースを6独立課題とは数えない。
外部receiver、ToolUseProxyの判定、生成モデル証跡、未使用holdoutにはまだ接続していない。
次はこの状態遷移をToolCallの実I/Oと隔離receiverへ接続する。
