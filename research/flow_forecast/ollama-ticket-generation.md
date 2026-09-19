# ローカルTicket生成の有限試験

`python -m research.flow_forecast.ollama_ticket_generation --output NEW_DIRECTORY`
は既存の `qwen3:8b` に人工Ticket課題を1回だけ渡す開発用経路。
モデル取得・変更、ホスト道具の実行、再試行は行わない。出力先は新規に限る。
下記のprovider経路では既存の準備・費用集計・収集データへ接続する。
この単独probeの保存物を後から有効な準備計画に変換する機能はない。

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

## 既存の収集経路への接続

```sh
python -m research.flow_forecast.generated_ticket prepare \
  --provider ollama --model qwen3:8b --output NEW_PREPARED_DIRECTORY
```

共通の事前予約を書いてから同じ有限workerを1回だけ呼び、応答原本を保存する。
有効な計画だけ `generated-plan.json` を作成し、既存の `collect` へ渡せる。
prepare成功後のcollectは別の明示的バッチであり、prepareから自動では開始しない。
不正な計画はexecution receiptと消費量を残し、prepared計画やtrialを作らない。

receipt schema 3は固定loopback、要求hash、観測hash、前後manifest・サーバー版、
生成計画hashを記録する。汎用のモデル識別子規則は緩めず、
`ollama-qwen3-8b` とOllamaの要求名 `qwen3:8b` の対応を明示する。
既存のCodex/API receipt schema 1/2は維持する。
サーバーがcache token数を省略した場合、cache=0とせずreceiptのusageをnullにする。

準備計画の再読込は保存した応答原本からreceiptを再構成して一致を確認する。
Ticket captureは生成計画をtrial前のintentへ固定し、collection読込時には
生成計画・branch・関連群との対応を検証する。モデル別集計には要求aliasと
観測されたローカル識別情報を別々に載せ、固定重みが確認済みとは扱わない。

### 接続後の実測

実装commit `090edd8cff3bc2518abe8ed44471cf840be08377` で1回だけ実行。
`/private/tmp/tooluseproxy-204-ollama-ticket-prepared-v1` に原本を保存した。
先の単独probeから独立した接続確認バッチであり、同じ人工課題の開発用反復。
新しい独立群や未使用評価には加算しない。

生成は25,377msで終了し、入力316/出力37/cache0tokensを共通費用集計へ記録。
返答は再びrefusedと操作一覧が矛盾したため `invalid_model_proposal` で拒否した。
生成要求1・失敗1・trial0。再生成はしていない。金銭費用はnullのまま。
モデルmanifestとサーバー版は単独probeと同じだった。

保存済みの事前予約、実装、要求、応答原本、execution receipt、費用集計を再照合した。
再照合時の新規モデル呼出しは0。
[機械可読記録](results/ollama-ticket-receipts-20260920.json)に結果を記載。
有効なローカル生成計画から実Docker trialまでの実測は未達であり、
この実測時点でのcollection接続の成功証拠はfixture試験に限られていた。


## 提案・拒否の形式を分離した実生成（2026-09-20）

従来のJSON Schemaは、Plan.parseが拒否する「status=refusedかつoperationsが非空」も
許していた。Ollama要求revision 2は提案/拒否のoneOfに分け、拒否はoperations=[]、
export=publicとする。提案の順序・内容を正解へ書き換えたり、拒否を禁止したりしない。
実行不能な提案と正しい拒否は引き続きprepareで止まり、消費量を残す。
OllamaのformatへのSchema指定は[公式文書](https://docs.ollama.com/capabilities/structured-outputs)に従う。

旧revision 1の要求は再構成可能なまま保持する。新workerは観測へrevision 2を記録し、
receiptのrequest hashへ結び付ける。新しい実行で旧workerの無版応答は受理しない。
過去の失敗応答原本から旧execution receiptが同一に再構成できることも実確認した。

実装64f1162593cba483d07bedbcb9fba642a8c2d3e8で明示的な生成1回を実施した。
約37.185秒、input316/output38/cache0でpropose・resolve/query/send・publicを得た。
別の明示バッチは18試行・19.0766秒・report前118297bytes。observe/enforceの両方で
公開結果が実受信され、課題完了、保護マーカー到達なし。記録した6個のcontainer/networkは撤去済み。

既存介入との結合、checked collection封印、生成receiptと実枝の対応、個別APIを再検証した。
1既知関連群・3prefix・6branch、生成receipt1件。今回の機械的splitはtestのみでtrainがなく、
比較prepareはno_fixed_distribution_training_rootsで終了した。割当てをやり直していない。
既知課題の開発用実行であり、testという名前を未使用性の証明とは扱わない。
採用独立群0、resolved_model_verified=false、金銭費用/価格根拠はnullのまま。
実Hook/PostToolUse、未使用課題での性能、独立群数の受入には未到達。

原本は `/private/tmp/tooluseproxy-204-ollama-ticket-union-{prepared,capture,collection}-v1`。
[実測記録](results/ollama-ticket-plan-union-20260920.json)に識別hash、usage、状態を保存した。
再生成・自動延長は行っていない。過去の失敗2回も成功扱いに変更しない。
