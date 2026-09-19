# ローカルTicket生成の有限試験

`python -m research.flow_forecast.ollama_ticket_generation --output NEW_DIRECTORY`
は既存の `qwen3:8b` に人工Ticket課題を1回だけ渡す開発用経路。
モデル取得・変更、ホスト道具の実行、再試行は行わない。出力先は新規に限る。
現在のCodex生成receiptや評価collectionへの投入経路とは未接続。

要求と実装hashを先に保存し、固定loopbackの `/api/tags` と `/api/version`、
1回の `/api/generate`、同じ識別情報の再取得を行う。各HTTP応答は1MiB以内、
親プロセスが全体60秒を制限する。HTTPの失敗は追従・再試行しない。
モデル出力は最大256tokens、文脈4096tokens、構造化JSON、thinking無効。
モデルの保存済み設定は編集しない。サーバー側の通常のモデル滞在設定を使う。

親がtimeoutでクライアントを終了しても、サーバー側の推論停止までは証明できない。
失敗時の実呼出数が観測できなければnullとし、事前予約1回を保持する。
モデルdigestとサーバー版が前後一致しても、その間に使われた重みの独立した証明や
不変性の保証ではない。`resolved_model_verified=false` を維持する。
費用も未計測なのでnull。ローカル実行を電力・ハードウェア費用0とは扱わない。
F02の予測器RSS上限と、この生成モデルのメモリ使用量は別物であり、後者は未測定。

公式API仕様: [モデル一覧](https://docs.ollama.com/api/tags)、
[生成](https://docs.ollama.com/api/generate)。

## 2026-09-20 JSTの実測

- 実装commit: `5e8dc88`。保存先: `/private/tmp/tooluseproxy-204-ollama-ticket-generation-v1`。
- 生成要求1回、27,597ms。モデル `qwen3:8b`、Ollama `0.34.2`。
- manifest digestは前後とも `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`。
- 入力316tokens、出力37tokens。サーバー報告の総時間27,085,452,167ns、
  ロード21,324,506,250ns。クライアント計測とは区別する。
- 返答は `status=refused` と `operations=[resolve,query,send]` が矛盾。
  既存のPlan契約が拒否し、trialは0。再生成はしていない。
- 応答原本と前後識別情報を保存済み。成功した準備計画、生成receipt、
  独立評価データとしては採用していない。採用独立群は引き続き0。

この試験はローカル経路が返答を得られることと、不正な計画を実行しないことの確認。
固定モデル版の受入、520独立群、未使用holdout、費用、有効性は未達のまま。
