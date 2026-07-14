# Hook Setup

このリポジトリには、Codex の `PreToolUse` / `PostToolUse` / `Stop` に接続するための最小スクリプトを置いています。

## 参考

- Hooks の全体像をつかむための動画: [YouTube](https://www.youtube.com/watch?v=03CfGf9iw_U)

## Hooks の構造

Codex の Hooks は、Codex 本体に組み込まれた拡張機構です。
「あるタイミングで、外部コマンドを呼ぶ」ためのイベントシステムだと考えると分かりやすいです。

階層は次の通りです。

```text
Codex 本体
  └─ Codex Hooks
       └─ Hook event
            ├─ UserPromptSubmit
            ├─ PreToolUse
            ├─ PostToolUse
            └─ Stop
                 └─ matcher
                      └─ hook handler
                           └─ 作成する監視プログラム
```

- `Hook event` は「いつ発火するか」を表します
- `matcher` は「どの tool に対して発火するか」を絞る条件です
- `hook handler` は実際に呼ばれるコマンドです

この研究で作るのは、Hooks そのものではありません。
Codex Hooks の設定と、そこから呼び出される監視プログラムです。

## この研究での役割分担

- `PreToolUse` は、tool 実行前の入力を観測する
- `PostToolUse` は、tool 実行後の出力を記録する
- `UserPromptSubmit` は、最初のユーザー入力に秘密情報が混ざっていないかを見る候補
- `Stop` は、最終応答に漏えいがないかを見る候補

この4つの観測点を使って、秘密情報源から tool input / tool output / 最終応答までの流れを追跡します。

## 設定イメージ

たとえば、設定は概念的には次のようになります。

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /Users/mani/Developer/ToolUseProxy/hooks/monitor_pre_tool.py"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /Users/mani/Developer/ToolUseProxy/hooks/monitor_post_tool.py"
          }
        ]
      }
    ],
    "Stop": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /Users/mani/Developer/ToolUseProxy/hooks/monitor_stop.py"
          }
        ]
      }
    ]
  }
}
```

`PreToolUse`、`PostToolUse`、`Stop` は Codex が用意している既存イベントです。
このリポジトリで実装するのは、そこから呼び出される `monitor_pre_tool.py`、`monitor_post_tool.py`、`monitor_stop.py` の中身です。

## 置いてあるもの

- `hooks/monitor_pre_tool.py`
- `hooks/monitor_post_tool.py`
- `hooks/monitor_stop.py`

いずれも stdin のHook payloadを受け取り、event、artifact、artifact fragmentをローカルSQLiteへ記録します。

`PostToolUse`は記録だけを行います。`Stop`は最終応答の`final_answer` sinkを評価します。`PreToolUse`は既定では記録だけですが、`TOOLUSEPROXY_PRE_TOOL_POLICY=1`を設定すると、実payloadを確認済みの`Bash`だけを実行前に評価します。

## 使い方

Codex の GUI か設定ファイルで、次の command を指定します。

- `PreToolUse` -> `python3 /Users/mani/Developer/ToolUseProxy/hooks/monitor_pre_tool.py`
- `PostToolUse` -> `python3 /Users/mani/Developer/ToolUseProxy/hooks/monitor_post_tool.py`
- `Stop` -> `python3 /Users/mani/Developer/ToolUseProxy/hooks/monitor_stop.py`

この段階の目的は、hook から I/O を受け取り、後から情報流を再解析できる観測ログを残すことです。加えて `Stop` では、最終応答をユーザーへ出す直前の確認点として `continue_review` を返す最小接続を行います。

## 実装構造

`hooks/monitor_pre_tool.py` と `hooks/monitor_post_tool.py` は入口だけです。
実際の記録処理は `hook_monitor/` に分けています。

```text
hooks/
  monitor_pre_tool.py
  monitor_post_tool.py
  monitor_stop.py

hook_monitor/
  runtime/
    models.py
    ids.py
    normalize.py
    parser.py
    fragments.py
    storage.py
    source_config.py
    runner.py
    incremental_analysis.py
    policy_audit.py
    pre_tool_policy.py
    stop_policy.py
  analysis/
    adapters/
      base.py
      common.py
      filesystem.py
      registry.py
    chunking.py
    similarity.py
    graph.py
    lineage.py
    source_index.py
```

まず、記録の単位を2つに分けています。

- `event`
  - hook が1回発火した記録です
  - たとえば「この `PreToolUse` はいつ、どの session / turn / tool で起きたか」を持ちます
- `artifact`
  - その event から比較対象として抜き出した文字列です
  - たとえば `tool_input` や `tool_response` がここに入ります

つまり、

- `event` = 時系列で追いたい単位
- `artifact` = 類似度を計算したい単位

です。

## どの順で動くか

処理の流れは次の通りです。

1. `monitor_pre_tool.py` / `monitor_post_tool.py` / `monitor_stop.py` が hook の stdin を受ける
2. `hook_monitor/runtime/runner.py` が共通処理を呼ぶ
3. `hook_monitor/runtime/parser.py` が JSON payload を読む
4. `hook_monitor/runtime/parser.py` が event を内部形式に正規化する
5. `hook_monitor/runtime/parser.py` が `tool_input` / `tool_response` / `final_answer` から artifact を作る
6. `hook_monitor/runtime/storage.py` が SQLite に保存する
7. 有効な`PreToolUse`または`Stop`ではsession差分解析を更新する
8. `pre_tool_policy.py`または`stop_policy.py`が現在eventのsinkだけを評価し、stdout JSONへ変換する

短く書くと、こうです。

```text
Codex
  -> hooks/monitor_pre_tool.py or hooks/monitor_post_tool.py or hooks/monitor_stop.py
  -> hook_monitor/runtime/runner.py
  -> hook_monitor/runtime/parser.py
  -> hook_monitor/runtime/storage.py
  -> .tooluseproxy/events.db
  -> PreToolUse: hook_monitor/runtime/pre_tool_policy.py
  -> Stop: hook_monitor/runtime/stop_policy.py
```

## Stop hook の policy 接続

`Stop` hookでは、最終応答をまず通常のeventとして保存し、その後に同じSQLite DBから次の処理を実行します。判断対象にするのは、今回の `Stop` event から作られた `final_answer` sink だけです。過去の最終応答に漏えい候補が残っていても、現在の最終応答がcleanなら block しません。

実CodexのStop payloadでは、最終回答本文は`last_assistant_message`、既にStop hookから継続されたturnかどうかは`stop_hook_active`に入ります。runtimeは`last_assistant_message`を`final_answer` artifactへ正規化し、`stop_hook_active`をeventへ保存します。旧形式の`final_answer`、`response`、`assistant_response`、`message`も互換入力として扱います。

```json
{
  "hook_event_name": "Stop",
  "session_id": "...",
  "turn_id": "...",
  "stop_hook_active": false,
  "last_assistant_message": "assistant response"
}
```

```text
Stop payload
  -> final_answer artifact
  -> codex_final_answer adapter
  -> sink_candidate(final_answer)
  -> lineage propagation
  -> LeakFinding
  -> PolicyDecision(continue_review)
  -> PolicyExplanation
  -> Codex Hook stdout JSON
```

StopとPreToolUseは同じruntime graph detector versionを使います。初回、detector変更、source manifest変更、cursor不整合時だけ同一sessionを`session-full`で再構築し、通常は未処理sequenceだけを`session-incremental`で追加します。source manifestが変わらない場合、protected source本文は再読込しません。

source設定は、`protected_sources.json` が存在する場合はその内容を優先します。空の `sources` は「保護対象なし」として扱い、DBに古いsource定義が残っていてもfallbackしません。`protected_sources.json` が存在しない場合だけ、既存DBのsource定義へfallbackします。

Stop hook が返す `reason` は、source、sink、score、severity、trace command、次の修正指示を含む短い説明です。説明には raw protected text や final answer の本文は含めません。

Stop hook が実際に介入した場合は、`policy_decisions` table に判断を保存します。保存された判断は次のコマンドで確認できます。

```bash
python3 /Users/mani/Developer/ToolUseProxy/scripts/list_policy_decisions.py
python3 /Users/mani/Developer/ToolUseProxy/scripts/trace_lineage.py --decision <decision_id>
```

Stop policy 接続は環境変数で無効化できます。

```bash
TOOLUSEPROXY_STOP_POLICY=0 python3 /Users/mani/Developer/ToolUseProxy/hooks/monitor_stop.py
```

## PreToolUse hook の policy 接続

PreToolUse policyはopt-inです。Hook commandに次の環境変数を追加します。

```text
TOOLUSEPROXY_PRE_TOOL_POLICY=1 python3 /Users/mani/Developer/ToolUseProxy/hooks/monitor_pre_tool.py
```

対象は正規化後のtool名が`bash`である実payloadだけです。現在eventの`event_id`、`sequence_no`、`tool_use_id`、`adapter: bash`が一致するexternal sinkだけを評価します。

- critical: `permissionDecision: deny`
- high: `additionalContext`を返して実行継続
- medium以下またはfindingなし: stdoutなしで実行継続
- session ID欠落、policy無効、解析例外: fail-open

未サポートの`permissionDecision: ask`と`continue: false`には依存しません。Hook内ではSQLite、静的adapter、indexed lexical candidate、差分lineageだけを使い、network、embedding、全DB再解析は行いません。

現時点のsource設定基準はToolUseProxy repository rootです。複数workspaceを同じDBで分離するsource ID / cursor schemaは別作業とします。

## 各ファイルの役割

- `hooks/monitor_pre_tool.py`
  - `PreToolUse` 用の薄い entrypoint です
  - `run_hook("pre_tool_use")`を呼び、opt-in時はBash external sinkを評価します
- `hooks/monitor_post_tool.py`
  - `PostToolUse` 用の薄い entrypoint です
  - `run_hook("post_tool_use")` を呼ぶだけです
- `hooks/monitor_stop.py`
  - `Stop` 用の薄い entrypoint です
  - `run_hook("stop")` を呼び、記録後に `final_answer` の policy 評価を実行します
- `hook_monitor/runtime/models.py`
  - 内部で扱う「記録の型」を定義します
  - `NormalizedEvent` は event 用です
  - `ArtifactRecord` は artifact 用です
  - ここで「1件の event は何を持つか」「1件の artifact は何を持つか」を固定します
- `hook_monitor/runtime/ids.py`
  - `event_id` と `artifact_id` を生成します
  - `event_id` は `events` テーブルの主キーとして使います
  - `artifact_id` は `artifacts` テーブルの主キーとして使います
  - `artifacts.event_id` で「この artifact はどの event 由来か」をひも付けます
  - 後で情報流グラフを作るときも、この ID で参照します
- `hook_monitor/runtime/normalize.py`
  - payload の内容を比較しやすい形に整えます
  - いまは文字列化、空白の正規化、小文字化だけです
  - embedding を使う場合も、前段でこうした整形をしておくのは有効です
  - ただし embedding 自体は別の層として足す想定です
- `hook_monitor/runtime/parser.py`
  - stdin から来た JSON payload を解釈します
  - `normalize_event()` が hook payload を event に変換します
  - `build_artifacts()` が phase ごとに `tool_input` / `tool_response` / `final_answer` を抽出します
- `hook_monitor/runtime/fragments.py`
  - artifact全体とJSON内の値を比較用fragmentへ分割します
  - `query`、`path`、`content`、`stdout`などのsemantic roleを付けます
- `hook_monitor/runtime/storage.py`
  - SQLite への保存を担当します
  - `events` テーブルと `artifacts` テーブルを初期化し、記録します
  - `events` は時系列の箱です
  - `artifacts` は比較対象テキストの箱です
- `hook_monitor/runtime/source_config.py`
  - 保護対象 source の設定ファイルを読みます
  - `.env` や `private.py` を「守るべき source」として定義する入口です
- `hook_monitor/runtime/runner.py`
  - 全体の実行順序をまとめる orchestrator です
  - `read stdin -> parse -> normalize -> build artifacts -> store` を順番に実行します
- `hook_monitor/analysis/chunking.py`
  - 保護対象 source を chunk に分割します
  - `.py` は関数や class 単位、テキストは段落単位で分割します
- `hook_monitor/analysis/adapters/`
  - tool固有のJSONを共通のresourceとedgeへ変換します
  - Filesystem read/write、Search、Bash、MCP、Codex最終応答に対応しています
  - 詳細は [アダプター.md](../設計/アダプター.md) にまとめています
- `hook_monitor/analysis/similarity.py`
  - 任意の2つの文字列の比較を担当します
  - `exact -> substring -> shingle_jaccard -> embedding_cosine` の順で評価します
- `hook_monitor/analysis/graph.py`
  - sourceとは独立にartifact fragment間のedgeを構築します
  - source chunkを既存グラフへ接続するbinding edgeも作ります
- `hook_monitor/analysis/lineage.py`
  - source bindingからedgeをたどり、各nodeへの最良経路を計算します
- `hook_monitor/analysis/source_index.py`
  - source 定義を読み、chunk 化した一覧を作ります
  - offline な再解析や lineage 再構築で使います

## DB の考え方

保存先はローカルの SQLite ファイルです。

- `.tooluseproxy/events.db`

中には主に次のテーブルがあります。

- `events`
  - hook が1回発火した記録を入れます
  - `phase`, `session_id`, `turn_id`, `tool_use_id`, `tool_name` などを持ちます
- `artifacts`
  - その event から取り出した `tool_input` / `tool_output` を入れます
  - `event_id` で元の event にぶら下がります
- `artifact_fragments`
  - artifact内のquery、path、content、stdoutなどを比較単位として保存します
- `information_flow_edges`
  - source設定とは独立したartifact fragment間の情報流候補を保存します
- `resource_versions`
  - Filesystem adapterが再構成したファイルのversionを保存します
- `source_binding_edges`
  - protected sourceとartifactグラフの接続点を解析runごとに保存します
- `lineage_assignments`
  - sourceから各nodeへ到達する最良経路を保存します

イメージとしては、

- `events` = 時系列ログ
- `artifacts` = 類似度計算の材料

です。

## 保護対象 source の定義

何を守るべきかは、hook の I/O だけでは決まりません。
先に「このファイルは秘密情報源である」と設定しておく必要があります。

このリポジトリでは、その定義を `protected_sources.json` のような設定ファイルで持つ想定です。
サンプルは [protected_sources.example.json](/Users/mani/Developer/ToolUseProxy/protected_sources.example.json) に置いてあります。

```json
{
  "sources": [
    {
      "id": "env_main",
      "path": ".env",
      "type": "secretfile",
      "sensitivity": "high",
      "policy_tags": ["no_external", "no_search"]
    }
  ]
}
```

ここで定義した source を起点にして、後続の artifact にどこまで流れたかを追います。

## embedding や cos 類似度はどこに入るか

embedding を使って自然言語をベクトル化し、cos 類似度を取る方針はもちろん可能です。

ただし、今の段階ではまだ入れていません。
理由は、研究の順番としてまず

1. event と artifact を壊れず保存する
2. どの artifact 同士を比較するか決める
3. その上で exact match / substring / n-gram / embedding を比較する

の順で進めたいからです。

将来的には、たとえば `embeddings.py` や `similarity.py` を追加して、

- `artifact_fragments` のテキストをベクトル化する
- fragment 同士の cos 類似度を計算する
- その結果を `information_flow_edges` に保存する

という形に伸ばせます。

## 現在の比較器

現在の実装では、artifact fragment同士、およびsource chunkとartifact fragmentの比較を段階的に行います。

1. `exact`
2. `substring`
3. `shingle_jaccard`
4. `embedding_cosine` を将来追加

これは、速度の速い手法で候補をなるべく拾い、その後で意味的な類似度を足す方が実用的だからです。

- `exact`
  - `.env` の値や完全一致の断片に強い
- `substring`
  - source の一部がそのまま後続 artifact に混ざる場合に強い
- `shingle_jaccard`
  - 少し崩れたコピーや近似的な再利用を拾いやすい
- `embedding_cosine`
  - 要約や言い換えの検出に向くが、コストは高い

## 再解析コマンド

保護対象 source は後から追加・変更される前提なので、過去のログに対して再解析できる必要があります。

そのために、source 設定と `events.db` を使ってartifactグラフとlineageを再構築するコマンドを用意しています。

- `python3 /Users/mani/Developer/ToolUseProxy/scripts/rebuild_lineage.py`

このコマンドは次を行います。

1. 過去artifactからfragmentを補完する
2. source非依存のartifact間グラフを構築または再利用する
3. `protected_sources.json` を読み、sourceをchunkに分割する
4. source chunkをartifactグラフへ接続する
5. sourceからのlineageを計算する

詳細な設計は [情報流追跡.md](../設計/情報流追跡.md) にまとめています。

## なぜ分けているか

この構造にしている理由は、研究の次の段階で差し替えやすくするためです。特に `runtime` と `analysis` を分けることで、hook 実行時の本番経路と、後から何度も回せる再解析経路を切り分けています。

- hook 実行時の記録経路を変えたいなら `hook_monitor/runtime/`
- 類似度計算や source 追跡を変えたいなら `hook_monitor/analysis/`
- 情報流エッジを強化したいなら `analysis` 側に拡張を足す

つまり、いまの `hook_monitor/` は「記録の骨格」です。
まだ漏えい検知や stop 判定までは入れず、まず event と artifact を壊れず保存するところに絞っています。

## この研究の位置づけ

ざっくり言うと、

- `Codex Hooks` = 差し込み口
- `PreToolUse` / `PostToolUse` = 差し込めるタイミング
- `hooks.json` = どのタイミングで何を呼ぶかの配線図
- `monitor_pre_tool.py` / `monitor_post_tool.py` = 監視プログラム
- 情報流追跡・漏えい検知・Stop 機構 = この研究の成果

つまり、この研究は「Codex Hooks を観測点として使い、tool use の I/O を外部で追跡・記録・判定する」ことを狙っています。
