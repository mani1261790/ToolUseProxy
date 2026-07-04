# 実装タスク計画

この文書は、ToolUseProxy の次に実装する内容を整理するための作業計画です。

現在の研究フェーズは第1段階「情報流を追跡可能にする」です。したがって、次に優先するのは漏えい判定や遮断ではなく、記録済みの情報流グラフを人間が確認し、source から後続 node までの経路を説明できる状態にすることです。

## 現在の到達点

実装済みの基盤は次の通りです。

- Codex Hooks から `PreToolUse` / `PostToolUse` の payload を受け取る
- Hook payload を event、artifact、artifact fragment として SQLite に保存する
- artifact fragment 間の exact、substring、shingle 類似度から情報流 edge を作る
- protected source を後から graph へ binding する
- source binding を起点に lineage を伝播する
- Filesystem adapter により、ファイル read/write を resource version 経由の edge として表現する

未実装の大きな部分は、graph を人間が確認するための導線、外部 sink の構造化、漏えい検知、介入です。

## グラフ設計の前提

情報流グラフは有向グラフとして扱います。

理由は、情報流には「どこから来て、どこへ行ったか」という向きがあるためです。たとえば次の2つは意味が異なります。

```text
.env -> tool_output -> search_query
search_query -> tool_output -> .env
```

無向グラフにすると、source、経由点、sink の区別が失われ、漏えい検知の根拠を説明できなくなります。

この graph は広い意味ではナレッジグラフと呼べますが、研究上は `information-flow graph` または `provenance graph` と呼ぶ方が正確です。目的は一般的な知識表現ではなく、観測された tool I/O の由来と伝播経路を追跡することだからです。

現時点では動的ナレッジグラフとして複雑な更新モデルを作る必要はありません。event と edge を時系列で保存し、再解析によって lineage を更新できれば、第1段階の MVP として十分です。

## 次に実装すること

### 1. 情報流経路を表示する CLI

最優先で実装します。

目的は、DB に保存された `lineage_assignments` と edge を使って、ある node がどの protected source から来た可能性があるのかを人間が確認できるようにすることです。

作るもの:

- `scripts/trace_lineage.py`
- node ID を指定して source までの経路を逆向きに表示する機能
- source ID を指定して下流 node を一覧する機能
- edge の relation、method、score、reason を表示する機能
- artifact fragment の短い preview を表示する機能

完了条件:

- source から resource version、tool output、tool input までの経路を表示できる
- 分岐した情報流を別々の経路として確認できる
- source と無関係な node は経路なしとして表示される

### 2. 情報流グラフの export

次に実装します。

目的は、情報流グラフを目視できる形に変換し、研究報告やデバッグで使えるようにすることです。

作るもの:

- `scripts/export_graph.py`
- Graphviz DOT 出力
- Mermaid 出力
- JSON 出力
- source lineage に含まれる node だけを出すオプション
- session、tool、source、sink候補で絞り込むオプション

完了条件:

- GitHub Markdown 上で Mermaid graph として確認できる
- Graphviz で画像化できる DOT を出力できる
- source 由来の経路と孤立 node を見分けられる

### 3. Search adapter

可視化の次に実装します。

目的は、web search query を外部送信候補として graph 上に表現することです。この時点ではまだ漏えい判定はしません。

作るもの:

- `hook_monitor/analysis/adapters/search.py`
- search query fragment を sink candidate として扱う edge または node metadata
- tool 名や semantic role から search query を認識する処理
- Search adapter の説明を `docs/adapters.md` に追記

完了条件:

- protected source 由来の情報が search query に到達した場合、lineage として辿れる
- search query が外部 sink 候補として graph export に表示される
- local README 書き込みと external search を graph 上で区別できる

### 4. sink 分類

Search adapter の後に実装します。

目的は、第2段階の漏えい検知に進む前に、tool input/output がどの種類の出口なのかを分類できるようにすることです。

想定する sink 種別:

- `local_file_write`
- `external_search`
- `external_post`
- `external_api_call`
- `local_log_write`
- `final_answer`

作るもの:

- sink 分類用の model または table
- adapter から sink 種別を付与する仕組み
- graph export で sink 種別を色やlabelに反映する機能

完了条件:

- 同じ source lineage でも、local write と external search を区別できる
- 第2段階で「source lineage が external sink に到達したか」を判定できる準備ができている

### 5. 最小の漏えい検知

ここから第2段階に入ります。

目的は、情報流グラフを使って、指定 source 由来の情報が外部 sink に到達したかを判定することです。

作るもの:

- `scripts/detect_leaks.py`
- source lineage と sink 分類を使った最小判定
- 判定理由の保存
- false positive / false negative の実験ログ形式

完了条件:

- `.env -> search query` のような危険経路を検知できる
- `private.py -> local README` のような許可したい経路を区別できる
- 判定結果に source、経由 edge、sink、score、reason が含まれる

### 6. Stop / warn / redact の設計

検知が動いてから着手します。

目的は、Codex Hooks の `PreToolUse` や将来の proxy 層で、危険な tool use に介入することです。

作るもの:

- policy engine
- `allow` / `warn` / `redact` / `block` の判断
- PreToolUse での block 応答
- redact 後の tool input 生成
- ブロック理由のログ

完了条件:

- external sink に source lineage が到達する場合に block または warn できる
- local write など許可すべき操作を過剰に止めない
- 介入理由を人間が trace graph で確認できる

## 次セッションの推奨作業

次セッションでは、次の順で実装します。

1. `scripts/trace_lineage.py` を作る
2. `scripts/export_graph.py` で Mermaid または DOT を出す
3. 可視化結果を使って、現在の Filesystem adapter の edge が人間に理解できるか確認する

この3つができると、第1段階の「情報流を追跡可能にする」が研究報告しやすい形になります。その後で Search adapter を実装し、外部流出候補までの経路を観測します。

