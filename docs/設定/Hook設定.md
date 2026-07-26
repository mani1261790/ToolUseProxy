# Hook Setup

このリポジトリには、Codex の `PreToolUse` / `PostToolUse` / `Stop` に接続するための最小スクリプトを置いています。

新規導入では、ユーザー固有の絶対pathをHook定義へ書かないCodex Plugin方式を推奨します。Pluginはrepository rootの`.codex-plugin/plugin.json`から読み込まれ、既定の`hooks/hooks.json`を使います。Hook commandは`PLUGIN_ROOT`、SQLiteは`PLUGIN_DATA`を参照します。install、trust、初期化の手順は[Plugin導入](Plugin導入.md)を参照してください。

以下の`.codex/hooks.json`方式は、Pluginを使わない既存の研究・開発環境向けのmanual設定です。

## 参考

- 公式仕様: [Codex Hooks](https://learn.chatgpt.com/docs/hooks.md)
- Hooks の全体像をつかむための補助動画: [YouTube](https://www.youtube.com/watch?v=03CfGf9iw_U)

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
- `PostToolUse` は、tool 実行後の出力とoperation outcomeを記録し、成功を確認できた変更だけをsnapshot候補にする
- `UserPromptSubmit` は、最初のユーザー入力に秘密情報が混ざっていないかを見る候補
- `Stop` は、最終応答に漏えいがないかを見る候補

この4つの観測点を使って、秘密情報源から tool input / tool output / 最終応答までの流れを追跡します。

## 設定イメージ

project単位では、trustedなrepositoryの`.codex/hooks.json`へ次のように設定します。operation抽出とsnapshot captureの対象である`Bash`と`apply_patch`を同じmatcherで観測します。

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^(Bash|apply_patch)$",
        "hooks": [
          {
            "type": "command",
            "command": "TOOLUSEPROXY_WORKSPACE_ROOT=/absolute/path/to/workspace python3 /absolute/path/to/ToolUseProxy/hooks/monitor_pre_tool.py",
            "timeout": 5
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "^(Bash|apply_patch)$",
        "hooks": [
          {
            "type": "command",
            "command": "TOOLUSEPROXY_WORKSPACE_ROOT=/absolute/path/to/workspace python3 /absolute/path/to/ToolUseProxy/hooks/monitor_post_tool.py",
            "timeout": 5
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "TOOLUSEPROXY_WORKSPACE_ROOT=/absolute/path/to/workspace python3 /absolute/path/to/ToolUseProxy/hooks/monitor_stop.py",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

`PreToolUse`、`PostToolUse`、`Stop` は Codex が用意している既存イベントです。
このリポジトリで実装するのは、そこから呼び出される `monitor_pre_tool.py`、`monitor_post_tool.py`、`monitor_stop.py` の中身です。

`matcher`は正規表現です。`PreToolUse`と`PostToolUse`ではtool名に適用されますが、`Stop`ではmatcherがサポートされないため省略します。MCPも観測する場合は、対象serverを絞った`^mcp__<server>__.*$`などのmatcher groupを追加します。Codexはtimeoutを省略すると600秒を使用するため、この軽量Hookでは明示的に5秒へ制限します。commandはsessionの`cwd`で実行され、複数のmatching command hookは並行起動されます。project-local Hookは実行前に定義内容をtrustする必要があります。

## 置いてあるもの

- `hooks/monitor_pre_tool.py`
- `hooks/monitor_post_tool.py`
- `hooks/monitor_stop.py`

いずれも stdin のHook payloadを受け取り、event、artifact、artifact fragmentをローカルSQLiteへ記録します。`PreToolUse`では静的なfile operationも抽出し、`PostToolUse`ではoperation outcomeとbounded resource snapshotを記録します。

`PostToolUse`はtool responseを三値のoutcomeへ分類し、成功を確認できた`apply_patch`またはBash writeだけをsnapshot候補にします。`Stop`は最終応答の`final_answer` sinkを評価します。`PreToolUse`は既定では記録だけですが、`TOOLUSEPROXY_PRE_TOOL_POLICY=1`を設定すると、実payloadを確認済みの`Bash`を実行前に評価します。MCPはさらに`TOOLUSEPROXY_PRE_TOOL_MCP_POLICY=1`を設定した場合だけ評価します。

file-backedな`curl --data-binary @relative-file`には、POSIXでcomponent-safeに実行前snapshotを読むresolverと、解決値を返さないpayload evidence契約があります。opt-inのshadow modeではallow / denyを変えずに観測し、別の明示opt-inではevaluated exact / exact-substringだけを実行前denyへ接続します。file-backed operandは既存graph上では引き続き`coarse_fallback`であり、no-matchやunsupportedを保護済みとは扱いません。resolver内部のpath race、Hook後にtarget toolがfileを再読込するTOCTOU、値非保持契約は[Sink payload evidenceの設計](../設計/SinkPayloadEvidence.md)を参照してください。

## 使い方

Codex の GUI か設定ファイルで、次の command を指定します。`/absolute/path/to/workspace`は保護対象projectの絶対pathへ置き換えます。

- `PreToolUse` -> `TOOLUSEPROXY_WORKSPACE_ROOT=/absolute/path/to/workspace python3 /absolute/path/to/ToolUseProxy/hooks/monitor_pre_tool.py`
- `PostToolUse` -> `TOOLUSEPROXY_WORKSPACE_ROOT=/absolute/path/to/workspace python3 /absolute/path/to/ToolUseProxy/hooks/monitor_post_tool.py`
- `Stop` -> `TOOLUSEPROXY_WORKSPACE_ROOT=/absolute/path/to/workspace python3 /absolute/path/to/ToolUseProxy/hooks/monitor_stop.py`

### workspace identity

`TOOLUSEPROXY_WORKSPACE_ROOT`の指定を推奨します。rootは既存の絶対directoryで、root自身がsymlinkではなく、Hook payloadの`cwd`がその配下にある必要があります。canonical rootのSHA-256から安定した`workspace_id`を作り、lexical rootと実行時cwdも別fieldで監査保存します。rootを指定しない場合はHook payloadの`cwd`自体をworkspace rootとして扱うため、同じrepositoryでもsubdirectoryごとに別workspaceになり得ます。

明示rootの検証に失敗したeventはraw evidenceとして保存しますが、snapshot取得とruntime policy評価はfail-openで省略します。workspaceを推測するための親directory走査やGit探索は行いません。

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
    operations.py
    tool_outcome.py
    snapshot_capture.py
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

記録の単位は、raw Hook payloadから実ファイルの状態まで段階的に分けています。

- `event`
  - hook が1回発火した記録です
  - たとえば「この `PreToolUse` はいつ、どの session / turn / tool で起きたか」を持ちます
- `artifact`
  - その event から比較対象として抜き出した文字列です
  - たとえば `tool_input` や `tool_response` がここに入ります
- `artifact fragment`
  - artifactを比較・解釈する単位へ分割したものです
  - payload由来fragmentに加え、`operation_container`、`operation_added`、`operation_removed`、`operation_control`、`bash_segment`を区別します
- `tool operation`
  - `PreToolUse`の入力から静的に確定できたfile操作です
  - adapter、operation index/kind、source/target path、Bash segment/connector、対応fragmentを持ちます
- `tool operation outcome`
  - あるPost eventが各operationを`succeeded` / `failed` / `unknown`のどれと判断したかを保存する履歴です
- `resource snapshot`
  - 成功を確認できたPost後に、operationから静的に確定したpathだけをbounded captureした証拠です
  - 本文、hash、取得status、workspace境界、所要時間を別fieldで保持します

つまり、

- `event` = 時系列で追いたい単位
- `artifact` = 類似度を計算したい単位
- `operation` = tool call内のfile操作を分離する単位
- `snapshot` = 実行後のresource状態を確認する単位

です。

## どの順で動くか

処理の流れは次の通りです。

1. `monitor_pre_tool.py` / `monitor_post_tool.py` / `monitor_stop.py` が hook の stdin を受ける
2. `hook_monitor/runtime/runner.py` が共通処理を呼ぶ
3. `hook_monitor/runtime/parser.py` が JSON payload を読む
4. `hook_monitor/runtime/parser.py` が event を内部形式に正規化する
5. `hook_monitor/runtime/parser.py` が `tool_input` / `tool_response` / `final_answer` から artifact を作る
6. `PreToolUse`では`operations.py`がapply_patchのfile operationまたはBashの静的segment operationを抽出する
7. `PostToolUse`では、保存済みPre operationのownerを検証し、`tool_outcome.py`が実行結果を三値へ分類する
8. outcomeが`succeeded`の場合だけ、`snapshot_capture.py`が変更対象pathをbounded captureする
9. `storage.py`がPost event、outcome、snapshotを同じtransactionでSQLiteへ保存する
10. 有効な`PreToolUse`または`Stop`では、現在eventと同じworkspace・sessionの未処理Post evidenceだけを差分解析する
11. `pre_tool_policy.py`または`stop_policy.py`が現在eventのsinkだけを評価し、stdout JSONへ変換する

短く書くと、こうです。

```text
Codex
  -> hooks/monitor_pre_tool.py or hooks/monitor_post_tool.py or hooks/monitor_stop.py
  -> hook_monitor/runtime/runner.py
  -> hook_monitor/runtime/parser.py
  -> PreToolUse: hook_monitor/runtime/operations.py
  -> PostToolUse: hook_monitor/runtime/tool_outcome.py
                  hook_monitor/runtime/snapshot_capture.py
  -> hook_monitor/runtime/storage.py
  -> PLUGIN_DATA/events.db or configured user data/events.db
  -> PreToolUse: hook_monitor/runtime/pre_tool_policy.py
  -> Stop: hook_monitor/runtime/stop_policy.py
```

## PostToolUseのoperation outcomeとsnapshot

snapshotの目的は、patch文字列やshell commandをファイル本文の代用品にせず、tool実行後に実在するresourceの状態を確認することです。PreToolUseでは実行前遮断のlatencyを増やさないためsnapshotを取得しません。`PreToolUse`で静的operationだけを保存し、同じsession / tool use / tool名 / workspaceの`PostToolUse`で成功を確認できた場合だけcaptureします。

outcomeは次の三値です。

- `succeeded`
  - structuredな`exit_code: 0`または成功flagを確認した
  - `apply_patch`では実Codex互換の`Done!` / `success` markerも採用する
- `failed`
  - structuredなnon-zero exit codeまたは明示的な失敗flagを確認した
- `unknown`
  - statusを確定できない、owner contextが一致しない、またはstructured statusが不正

Bash stdoutはcommand自身が自由に生成できるため、本文中の`Exit code: 0`などをstatusとして信用しません。Codex CLI `0.142.5` / `gpt-5.5`の実Hookでは、成功したno-output Bashと失敗した`false`のどちらも`tool_response: ""`として届きました。そのため現在のHook contractでは両方を`unknown / success_unconfirmed`として保存し、Bash snapshotは取得しません。静的Bash segment operation自体はPreToolUseで保存されます。structured statusを含むsynthetic payloadとbenchmarkではsnapshot経路を検証しています。

### capture対象と境界

- workspace全体は走査せず、operationから静的に確定できたpathだけを扱う
- workspace rootにはvalidated `TOOLUSEPROXY_WORKSPACE_ROOT`を使い、未指定時だけPreToolUse `cwd`をrootとする
- Post側のsession、tool use、tool名、workspaceがPre ownerと一致しなければcaptureしない
- lexical pathがroot外なら`outside_workspace`とする
- workspace root、中間directory、対象fileのsymlinkをfollowせず`symlink_rejected`とする
- regular fileだけを読み、device、FIFO、directoryなどは`non_regular`とする
- 読み始めと終了時のdevice、inode、size、mtime、ctimeを比較し、変化した場合は`unstable_file`としてhashを採用しない
- binary fileは本文を保存せず、上限内で全体を読めた場合だけ`binary_hash_only`としてSHA-256を保存する

moveではsourceが消えたこととtargetの現在内容を別snapshotで確認します。deleteではsourceの不在を確認できた場合だけ`deleted` tombstoneを作ります。overwriteは古いresource lineageを引き継がず、appendは`updated_from`で以前のresourceを引き継ぎます。同じtool callで同じpathを複数回書く場合は最終writerだけをcaptureし、先行operationを`superseded_by_later_operation`とします。`&&` / `||`は各segmentが実行されたかをPost全体のstatusから確定できないため`execution_unknown`、pipeを含み最終writerが曖昧な場合は`ambiguous_final_writer`としてresourceを断定しません。

### 上限

| 環境変数 | 既定値 | hard cap / 許容値 |
|---|---:|---:|
| `TOOLUSEPROXY_SNAPSHOT_MAX_FILE_BYTES` | 256 KiB | 4 MiB |
| `TOOLUSEPROXY_SNAPSHOT_MAX_TOOL_BYTES` | 1 MiB | 16 MiB |
| `TOOLUSEPROXY_SNAPSHOT_MAX_PATHS` | 32 | 128 |
| `TOOLUSEPROXY_SNAPSHOT_TIME_BUDGET_MS` | 250 ms | 1000 ms |
| `TOOLUSEPROXY_SNAPSHOT_PLAINTEXT` | `0` | `0` / `1`相当のboolean |

不正値または0以下は既定値へ戻し、hard capを超える値はcapへ丸めます。内部のsnapshot record上限はpath上限の2倍です。operationまたはsnapshot specがこのrecord上限を最初から超える場合はcapture全体を省略し、hashless解析へfallbackします。個別処理中にfile上限、tool call合計byte上限、path数、時間budgetのいずれかへ達した場合は、`file_too_large`、`tool_total_limit`、`path_limit`、`time_budget_exhausted`などのstatusを監査証拠として残します。

### 本文、hash、失敗時のfallback

既定の`TOOLUSEPROXY_SNAPSHOT_PLAINTEXT=0`では、UTF-8 textでも`body_text`を保存せず`captured_hash_only`にします。opt-in時だけ`captured_text`として本文を保存します。binary本文はopt-inでも保存しません。同じpathの取得結果を再利用する場合も、重複本文を保存せず`cached_hash_only`にします。

`content_sha256`は、上限内のファイル全体を安定して読み切った場合だけ計算します。apply_patch文字列やBash segmentのhashをfile content hashとして代用しません。capture全体の例外はHookをfail-openにし、outcome evidenceへ例外型だけを追記します。path単位の失敗は`capture_status`と`error_code`を保存し、可能な場合はhashless resource versionへfallbackします。ただし、delete tombstoneは不在を確認した場合だけ作り、`execution_unknown`と`ambiguous_final_writer`はmaterializeしません。

snapshotの自動retentionやpruneはまだ実装していないため、recordはDBを削除または明示的に整理するまで残ります。SQLite自体も暗号化しません。snapshot本文をoffにしても、raw Hook payload、artifact、operation fragmentにはtool input/outputが平文で保存され得ます。さらにcompleted offline runの`analysis_node_snapshots.metadata_json`はcontent-addressedですが暗号化・匿名化ではなく、artifact fragmentやsource chunkのtextを過去run再現用に保持します。live sourceを削除しても過去run snapshotは自動pruneされません。DBを外部へ共有せず、OSのfile permissionとdisk encryptionで保護してください。

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

StopとPreToolUseは同じruntime graph detector versionを使います。cursorの主keyは`(workspace_id, session_id)`です。初回、detector変更、workspace単位のsource manifest変更、cursor不整合時だけ同じworkspace・sessionを`session-full`で再構築し、通常は未処理sequenceだけを`session-incremental`で追加します。detectorとsource manifestがともに変わらない場合、protected source本文は再読込しません。detector変更時はchunking規則も変わり得るため、同じmanifestでもsource chunksを再生成します。duplicate Postやcursor更新前の部分保存により、delta operationが既存resource versionへ再度当たる場合も、重複versionやcycleを避けるため同じworkspace・sessionだけを`session-full`で再構築します。runtime Hookが全DB再解析へ戻ることはありません。

source設定は、canonical workspace rootの`protected_sources.json`が存在する場合はその内容を優先します。空の`sources`は「保護対象なし」として扱い、DBに古いsource定義が残っていてもfallbackしません。設定fileが存在しない場合だけ、同じworkspaceのDB catalogへfallbackし、別workspaceやglobal catalogは参照しません。

Stop hook が返す `reason` は、source、sink、score、severity、trace command、次の修正指示を含む短い説明です。説明には raw protected text や final answer の本文は含めません。

Stop hook が実際に介入した場合は、`policy_decisions` table に判断を保存します。保存された判断は次のコマンドで確認できます。

```bash
python3 /absolute/path/to/ToolUseProxy/scripts/list_policy_decisions.py
python3 /absolute/path/to/ToolUseProxy/scripts/trace_lineage.py --decision "$DECISION_ID"
```

Stop policy 接続は環境変数で無効化できます。

```bash
TOOLUSEPROXY_STOP_POLICY=0 python3 /absolute/path/to/ToolUseProxy/hooks/monitor_stop.py
```

## PreToolUse hook の policy 接続

PreToolUse policyはopt-inです。Hook commandに次の環境変数を追加します。

```text
TOOLUSEPROXY_PRE_TOOL_POLICY=1 python3 /absolute/path/to/ToolUseProxy/hooks/monitor_pre_tool.py
```

この設定で対象になるのは、実payloadを確認済みの`Bash`です。MCPも対象にする場合は、影響範囲を明示するために二つ目のopt-inを追加します。

```text
TOOLUSEPROXY_PRE_TOOL_POLICY=1 TOOLUSEPROXY_PRE_TOOL_MCP_POLICY=1 python3 /absolute/path/to/ToolUseProxy/hooks/monitor_pre_tool.py
```

### Bash curl送信値の静的抽出

直接実行される`curl`では、`-d VALUE`、`-dVALUE`と、`--data`、`--data-ascii`、`--data-binary`、`--data-raw`、`--data-urlencode`、`--json`、`--form-string`のseparated / `=`形式をsegment単位で静的解析します。複数operandの順序は保ちますが最終bodyは合成しません。operand全体とprotected source chunkのraw valueが完全一致した場合だけscore 1.0のbindingを作ります。

shell変数、command substitution、glob / brace / tilde展開、body以外のdynamic option / operand、dynamic redirection、unknown option arity、file-backedな`@file` / `@-`、空値、上限超過があれば、そのsegmentの抽出値をすべて破棄して`coarse_fallback`にします。ただし`--data-raw @literal`と`--form-string name=@literal`はcurlが`@`をliteralとして扱うためstaticです。`--data-urlencode`もfile formだけをfallbackにします。fallbackでもexternal sinkと従来のsegment-to-sink / path / pipe evidenceは残しますが、未知のruntime値を秘密値とは仮定しません。

この抽出はshell、subprocess、networkを実行せず、fileも読みません。上限は1 segmentあたり32値、1値32 KiB、合計128 KiBです。projection値を追加fragment、DB row、評価report本文へ複製しません。

### File-backed payload shadow

production PreToolUseで値なしの観測だけを有効にするには、Bash policyとshadowの二つをopt-inにします。

```text
TOOLUSEPROXY_PRE_TOOL_POLICY=1 TOOLUSEPROXY_PRE_TOOL_FILE_PAYLOAD_SHADOW=1 python3 /absolute/path/to/ToolUseProxy/hooks/monitor_pre_tool.py
```

対象はcurrent eventの`curl`による`external_http_request`だけです。解析runが実際に使用したactive source chunksを同じcall内で比較し、DBを後から広く再検索しません。static literalは既存graphの担当なのでshadow rowを作らず、`resolved_file`とfile resolutionへ進めなかった`coarse_fallback`だけを記録します。

shadow rowにはresolution / comparison status、値なしreason、snapshot semantics、value数とpayload byte数のbucket、exact / exact substring / none、match件数、処理時間、現在policyとshadow判断の差だけを保存します。payload本文、payload由来hash、raw command、file path、source chunk IDはshadow tableへ複製しません。同一event / sink / segment / evidence versionの再実行では最初の観測を保持し、policy結果などの不一致があれば上書きしません。

schema drift、SQLite lock、resolver例外、保存失敗はshadow専用の例外境界で破棄します。現在policyのHook出力を先に確定するため、shadowの失敗が既存denyを弱めたり、allowを新しいdenyへ変えたりすることはありません。現在は`would_block`も観測値にすぎず、実行を止めません。

集約レポートは次のcommandで確認できます。event ID、sink ID、source IDなどのdurable identityはreportへ出しません。

```bash
python3 scripts/report_sink_payload_shadow.py \
  --db /absolute/path/to/events.db
```

このresolverが取得するのは実行前のfile snapshotです。Hook完了後にfileが変わるTOCTOUを解消せず、実際にcurlが送ったbytesも証明しません。したがって、既存graphではfile-backed operandを引き続き`coarse_fallback`として扱い、no-matchを送信の安全証明とは表示しません。

### File-backed payload exact-only enforcement

TUIで検証済みのexact evidenceだけを実行前denyへ接続する場合は、Bash policyとenforcementを明示opt-inにします。既定値は無効です。

```text
TOOLUSEPROXY_PRE_TOOL_POLICY=1 TOOLUSEPROXY_PRE_TOOL_FILE_PAYLOAD_EXACT_ENFORCEMENT=1 python3 /absolute/path/to/ToolUseProxy/hooks/monitor_pre_tool.py
```

対象はcurrent Bash eventの`curl --data-binary @relative-file`です。`resolution_status`と`comparison_status`がともに`evaluated`、extractionが`resolved_file`、snapshotが`pre_execution_file_snapshot`であり、active source chunkとの`resolved_payload_exact`または`resolved_payload_exact_substring`がある場合だけcritical blockを返します。一般的なshingle、token equivalent、embedding / semantic類似はこのdenyへ接続しません。

public no-match、unsupported、上限超過、resolver例外は新しいdenyを作らず、先に確定したlineage policyのallow / warn / blockを維持します。exact evidence確定後に監査保存だけが失敗した場合は外部side effectを許可せずdenyを維持します。shadow flagも同時に有効化した場合は同じ一回のfile snapshot比較から値なし観測を保存し、payloadを二重に読みません。

denyは「file-backed external payloadにprotected contentが見つかった」と説明し、参照fileから保護内容を除くかpublic payloadを選ぶよう案内します。ただし実行前snapshotとcurlが後で読むbytesの一致は証明しないため、TOCTOUの制限は残ります。既定有効化は別のgo / no-go判断です。

MCP Hookのmatcherは、たとえば`^mcp__.*$`、または対象を絞った`^mcp__github__.*$`を使用します。実CodexのMCP payloadは`tool_name: mcp__<server>__<tool>`で、`tool_input`にはMCP toolへ渡すraw argumentsが入ります。adapterが外部送信と分類するwrite-like toolだけがsinkとなり、read-only toolは記録して通過させます。MCP tool名はUTF-8で4 KiBを上限とし、超過時はartifact / sinkをmaterializeする前に`tool_name_bytes_exceeded`でdenyします。tool名自体が1 MiBのraw read上限を跨いで後続`cwd`を読めない場合も、明示`TOOLUSEPROXY_WORKSPACE_ROOT`が有効ならそのrootだけを早期deny scopeとして検証します。

現在eventの`event_id`、`sequence_no`、`tool_use_id`、adapter種別が一致するexternal sinkだけを評価します。過去eventの未解消findingを理由に現在の呼出しを止めません。

MCPでcritical blockが確定した場合は、`detect_leaks()`が現在callへ返した全critical findingをそのままredaction preview plannerへ渡します。source本文はfindingが参照するworkspace-owned source chunk IDだけを32件以下で取得し、workspace全体をplanner用に再読込しません。bounded envelope内のeligible / rejected planと全targetは本文なしのhash-only監査として1 transactionでimmutableに保存します。新規insertでは完了runのcurrent-call sink / critical lineage / source evidenceからpure planner結果を再構成し、metadataと全targetが完全一致した場合だけ保存します。source取得、planner、保存が失敗しても、すでに生成したdenyをそのまま返します。previewはHook stdoutへ`updatedInput`を追加せず、runtime rewriteを行いません。

`prepare_redaction_enforcement()`はfuture renderer用のstorage APIです。eligible previewを再証明し、`enforce / eligible` plan、target exact clone、全findingのBLOCK-to-REDACT decision linkを同じtransactionで保存します。prepare専用connectionだけでSQLite foreign key enforcementを有効化し、commit前にplan / target / linkを再読込します。現行runnerとHook設定はこのAPIを呼びません。`enforce / eligible`は監査準備済みを表すだけで、stdout生成済みの`rendered`や実行許可ではありません。新しい環境変数やoperator設定もありません。

redaction audit schemaのdriftは初期化時に検出し、推測修復せずauditだけを無効化します。audit用のsource read / plan writeはSQLiteの`busy_timeout` 10 msでfail-fastし、lockやschema driftによる失敗もpreviewの例外境界内に留めます。replay対象は最大64 sink、識別子4 KiB、sink metadata 64 KiB / row、512 KiB / callでbyte制限し、重いread検証中はwriter lockを保持しません。そのためcore policyが確定したdenyは弱まりません。

event保存時は、実際に`events.payload_json`へ入れるJSONを1回だけserialize / UTF-8 encodeし、byte数とpayload SHA-256を物理的に分離した`event_payload_metadata`へ同じtransactionで保存します。redaction対象になり得るPre / Postには、4 KiB以下のidentityから作るcall-scope SHA-256と`sequence_no`も保存します。1 MiB以下のPostだけはobserver version、bounded status、profile / registry version、canonical input byte数・SHA-256、structure SHA-256を追加し、本文は複製しません。row全体のmetadata SHA-256でfield driftを検出し、同一event replayは最初のrecord-time observationをimmutableに維持します。既存eventはHook初期化中に本文を全走査しないためbackfillしません。sidecar insert / observerだけが失敗した場合はauditを無効化し、core event / artifact保存と既存denyを維持します。schema driftは推測修復しません。

Post event本体を保存した後、runnerはdormantなredaction confirmationを独立したfail-soft境界で呼びます。対象は将来rendererが保存する`mode = enforce AND status = rendered`の単一planだけで、現行preview / prepared eligible planは候補hashと一致しても遷移しません。enforce planの全immutable列とbounded target集合がstorageで再証明済みeligible previewのexact cloneであること、全decision link、完了analysis run、current profile / registry versionが一致することを要求します。exact Pre call scopeを先に検索し、candidateがなければ同じcoarse identityのnarrow Pre sidecarを最大32件だけ確認して、欠損・破損をsilentに無視せず未確認にします。候補が1件だけある場合にcurrent Post、所有Pre、同scopeの最小sequence Postをsidecarから検証します。confirmation SQLは`events` tableを一切読みません。Post metadata欠落は`post_payload_bytes_unavailable`、Pre scope metadata欠落は`pre_scope_metadata_unavailable`、integrity不一致は`post_payload_metadata_invalid`、1 MiB超過は`post_payload_bytes_exceeded`として未確認にします。`post_input_stable`かつfile inputなしのprofileについて、record時に32 KiB / 32 fields / depth 8以内で得たcanonical full-input hashを比較します。一致は`post_confirmed`、boundedなhash不一致は`post_mismatch`、oversize・profile drift・曖昧候補は未確認のままです。terminal replayとcompare-and-setの前にも全linkを再証明します。10 msの短いaudit read transactionを使い、実際に終端状態へ進める1 rowだけwriterへupgradeします。失敗しても記録済みPost eventをrollbackせず、stdoutやinput本文を出しません。現行runtimeは`rendered` planも`updatedInput`も生成しないためproductionではno-opです。

- critical: `permissionDecision: deny`
- high: `additionalContext`を返して実行継続
- medium以下またはfindingなし: stdoutなしで実行継続
- session ID欠落、policy無効、解析例外: fail-open

未サポートの`permissionDecision: ask`と`continue: false`には依存しません。Hook内ではSQLite、静的adapter、indexed lexical candidate、差分lineageだけを使い、network、embedding、全DB再解析は行いません。

preview auditのretentionは所有するPreToolUse eventのscopeに合わせます。次のcommandはdry-runで件数だけを返し、`--execute`を追加した場合だけ削除します。

```bash
python3 scripts/cleanup_redaction_audits.py \
  --db .tooluseproxy/events.db \
  --workspace-root /absolute/path/to/workspace \
  --before 2026-08-01T00:00:00Z
```

SQLiteのforeign key enforcementはprepare専用transaction以外のリポジトリ全体で現在offです。cleanupは`ON DELETE CASCADE`に依存せず、同じtransaction内で`redaction_decision_links`、`redaction_targets`、`redaction_plans`の順に明示削除します。dry-run / executeのJSONは3種類の件数を返します。

native Web SearchはCodex CLI `0.142.5`で`matcher: "*"`を使ってもPreToolUse / PostToolUseに現れなかったため、実行前遮断へは接続していません。Search adapterはsynthetic / imported eventのoffline解析用に残します。

source manifestの基準directoryはeventのcanonical workspace rootです。`protected_sources.json`の相対pathとoperationの相対pathはこのrootに閉じ、実行時cwdはBashなどの相対pathを解決するために別途使います。event、artifact、operation、snapshot、protected source、source chunk、cursor、resource、sink、edge、analysis runは`workspace_id`で分離されます。同じ`session_id`や同じsource設定上の`id`が別workspaceに存在しても混線させません。

## 各ファイルの役割

- `hooks/monitor_pre_tool.py`
  - `PreToolUse` 用の薄い entrypoint です
  - `run_hook("pre_tool_use")`を呼び、opt-in時はBashとMCPのexternal sinkを評価します
- `hooks/monitor_post_tool.py`
  - `PostToolUse` 用の薄い entrypoint です
  - `run_hook("post_tool_use")`を呼び、runner側でoutcome分類と成功時snapshot captureを実行します
- `hooks/monitor_stop.py`
  - `Stop` 用の薄い entrypoint です
  - `run_hook("stop")` を呼び、記録後に `final_answer` の policy 評価を実行します
- `hook_monitor/runtime/models.py`
  - 内部で扱う「記録の型」を定義します
  - `NormalizedEvent` は event 用です
  - `ArtifactRecord` は artifact 用です
  - `ToolOperation`、`ResourceSnapshot`、`ResourceVersion`もここで固定します
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
  - artifact全体とJSON内のscalar value、tool inputのJSON object keyをfragmentへ分割します
  - `query`、`path`、`content`、`stdout`などのsemantic roleを付けます
- `hook_monitor/runtime/operations.py`
  - PreToolUseのapply_patchをfile operationへ、Bashを静的segment operationへ分解します
  - operation固有fragmentと安定したoperation IDを作ります
- `hook_monitor/runtime/tool_outcome.py`
  - PostToolUse responseを`succeeded` / `failed` / `unknown`へ分類します
  - Bashの自由なstdout本文を実行statusとして信用しません
- `hook_monitor/runtime/snapshot_capture.py`
  - 成功Postに対応する静的pathだけを、workspace・byte・path数・時間上限内で取得します
  - symlinkや非regular fileを拒否し、hash-onlyを既定にします
- `hook_monitor/runtime/redaction_audit.py`
  - preview planをplaintext本文なしのstored modelへ変換します
  - eligible / rejected planとfinding単位の全targetを保存します
- `hook_monitor/policy/redaction_decision.py`
  - findingのBLOCK decisionを検証し、versionedなderived REDACT decision identityを決定論的に作ります
  - Hook outputは生成せず、dormant decision linkのidentityだけを担当します
- `hook_monitor/runtime/redaction_confirmation.py`
  - stable profileのbounded Post inputをcanonical hashで照合します
  - file input、profile drift、unbounded inputを未確認のままにします
- `hook_monitor/runtime/storage.py`
  - SQLite への保存を担当します
  - event、artifact、operation、outcome、snapshot、redaction auditと解析結果tableを初期化し、記録します
  - Post event、operation outcome、resource snapshotを同じtransactionで保存します
- `hook_monitor/runtime/source_config.py`
  - 保護対象 source の設定ファイルを読みます
  - `.env` や `private.py` を「守るべき source」として定義する入口です
- `hook_monitor/runtime/runner.py`
  - 全体の実行順序をまとめる orchestrator です
  - MCP policy有効時は`bounded prefix read -> top-level tool/workspace scope -> real MCP raw gate -> parse -> normalize -> bounded input preflight`を先に行います。ready workspaceのreal MCPだけをraw JSON 1 MiB / depth 64 / numeric token 128 charsで制限し、超過したwriteはdeny、read-only / unsinked / workspace未確定は空stdoutで早期bypassします。既知の非MCP toolは従来経路を維持し、Hook JSONはUTF-8・BOMなしだけを受理します
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

- Plugin: `PLUGIN_DATA/events.db`
- 明示指定: `TOOLUSEPROXY_DB_PATH`または`TOOLUSEPROXY_DATA_DIR/events.db`
- package既定: OSごとのuser data directory配下の`events.db`

repository内の旧`.tooluseproxy/events.db`は自動探索しません。移行する場合は、元DBを残したまま`tooluseproxy init --import-db .tooluseproxy/events.db`を明示的に実行します。

中には主に次のテーブルがあります。

- `workspaces`
  - canonical rootから作ったworkspace identityと、検出方法を保存します
- `events`
  - hook が1回発火した記録を入れます
  - `phase`, `workspace_id`, `session_id`, `turn_id`, `tool_use_id`, `tool_name` などを持ちます
- `artifacts`
  - その event から取り出した `tool_input` / `tool_output` を入れます
  - `event_id` で元の event にぶら下がります
- `artifact_fragments`
  - artifact内のquery、path、content、stdoutとoperation由来fragmentを比較・監査単位として保存します
- `tool_operations`
  - PreToolUseから静的に抽出したfile operation、path、segment、connector、対応fragmentを保存します
- `tool_operation_outcomes`
  - `(post_event_id, operation_id)`単位でPostの三値outcomeと根拠を保存します
- `resource_snapshots`
  - operation、workspace、path role、resource state、capture status、byte数、SHA-256、任意本文、error、durationを保存します
- `information_flow_edges`
  - source設定とは独立したartifact fragment間の情報流候補を保存します
- `resource_versions`
  - Filesystem adapterが再構成したファイルのversionを保存します
  - operation ID/index、snapshot ID、resource stateにより実行証拠と接続します
- `source_binding_edges`
  - protected sourceとartifactグラフの接続点を解析runごとに保存します
- `protected_source_candidates`
  - agentが明示pathから作ったvalue-freeなsource提案、内部再検証用hash/stat、`approving`を含む現在statusを保存します
- `protected_source_candidate_reviews`
  - proposed / approving / approved / rejected / ignored / staleの遷移とapproval started / releasedを本文なしのappend-only監査として保存します
- `lineage_assignments`
  - sourceから各nodeへ到達する最良経路を保存します
- `analysis_cursors`
  - `(workspace_id, session_id)`ごとのruntime差分位置とdetector/source digestを保存します
- `analysis_node_snapshots` / `analysis_run_nodes`
  - completed offline runが参照したnode metadataをcontent-addressedに保存し、runへ固定します
- `redaction_plans` / `redaction_targets`
  - current MCP callのeligible / rejected previewと全finding targetをhash-onlyで保存します
- `redaction_decision_links`
  - preview BLOCK decisionと将来REDACT identityのfinding単位linkを本文なしで保存します

イメージとしては、

- `events` = 時系列ログ
- `artifacts` = 類似度計算の材料

です。

## 保護対象 source の定義

何を守るべきかは、hook の I/O だけでは決まりません。
先に「このファイルは秘密情報源である」と設定しておく必要があります。

このリポジトリでは、その定義を `protected_sources.json` のような設定ファイルで持つ想定です。
サンプルは [protected_sources.example.json](../../protected_sources.example.json) に置いてあります。

```json
{
  "schema_version": 2,
  "sources": [
    {
      "id": "env_main",
      "path": ".env",
      "type": "secretfile",
      "sensitivity": "high",
      "policy_tags": ["no_external", "no_search"],
      "selector": {
        "dotenv_keys": ["SERVICE_TOKEN"]
      }
    }
  ]
}
```

ここで定義したsourceを、canonical workspace rootを基準に解決します。DB上のsource identityはworkspace namespaceを含むため、別workspaceで同じ`id`を使っても同一sourceにはなりません。ここで定義したsourceを起点にして、同じworkspace内の後続artifactにどこまで流れたかを追います。

`type: secretfile`では、`.env` / `.env.*`のdecoded非空valueと、JSON object / array内の非空string valueを比較単位にします。key、comment、quoteや`export` wrapper、JSON container、非string scalarはsource chunkにしません。selectorを省略したlegacy sourceでは、解釈できないdotenv構文や不正JSONをparagraph単位へ戻し、parser失敗によって保護本文を捨てません。

manifest schema v2では、`selector`でcontent比較へ使う値を限定できます。`.env` / `.env.*`はcase-sensitiveな`dotenv_keys`、JSONはRFC 6901の`json_pointers`を使います。`selector`内はどちらか一方だけ、配列は非空・重複なしで指定します。JSON Pointerは非空string valueへexactに解決される必要があります。selectorのkey / pointerが消えた、非stringになった、またはsourceをparseできない場合はwhole-fileへ黙って戻らず設定エラーになります。`tooluseproxy doctor`はsource本文を表示せず、この解決まで検査します。

selector省略時は従来どおり全decoded string valueを保護します。schema省略またはschema v1の既存manifestもselectorなしのlegacy形式として読み続けます。`doctor` / `status`はこの状態をruntime-readableとして扱いながら、`registration_writable: false`と`migration_required: true`を返し、新しいsource登録だけが明示migrationを必要とすることを区別します。

selectorが限定するのはdirect content-bindingです。登録pathそのものをRead、copy、`cat ... | curl`、または意味を証明できないtransformへ渡した場合、fileがselected secretを内包するためpath-based taintは保守的に維持します。public siblingのliteralを直接送るだけなら保護対象にしませんが、protected file全体を経由した操作をpublicとは推定しません。

legacy manifestで新しいsourceを登録する前に、coding agentは`sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect migrate plan --workspace <workspace-root> --data-dir <PLUGIN_DATA> --json`を実行します。planはvalue-freeで、schema宣言、source数、`sources`追加の要否、formatting policy、data directory配下のbackup名、入力・結果manifest SHA-256、opaque migration revisionだけを示し、manifestやunknown fieldの値を表示しません。agentは既存entry、selector、保護semanticsを変えずにschema宣言だけをv2へ変更し、`sources`欠損時だけ意味的に等価な空配列を補うこと、元bytesのprivate exact-byte backupを作ること、UTF-8・2-space indent・LFへ正規化することを説明し、exact planへの明示承認を得ます。承認後だけ`protect migrate apply --migration-revision <revision> --expected-manifest-sha256 <sha256>`を実行します。apply後も既存source entry、source配列とkeyの相対順序、unknown field、selectorなしの保護範囲を保持します。JSON commentやduplicate keyを緩く解釈しません。

migration plan後にmanifestが変わればapplyせず、agentは新しいplanを示して再承認を得ます。途中停止時は同じrevisionとmanifest SHA-256で再試行します。migrationもworkspace lockで協調writerを直列化しますが、同一UIDの非協調的なeditorとの最終再検証から置換、またはdurability再確認から完了確定までの競合は保証外です。migrationはPOSIX（macOS/Linux）のみ対応し、`init`やHookから暗黙には実行しません。migration承認は後続source登録の承認を兼ねません。

coding agentがmanifestを直接編集する代わりに、schema v2へ明示移行した後のPluginでは`sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect scan --workspace <workspace-root> --data-dir <PLUGIN_DATA> --json`を明示的に実行できます。`scan`はVCS、依存関係、virtual environment、build / cache、runtime dataなどを除外し、深さ、entry数、file数、総read bytes、candidate数の固定上限内でworkspaceをoffline探索します。`.env` / `.env.*` / JSONのsecretらしいfield名に一致した非空stringだけをdotenv key / JSON Pointerとして候補化し、stableな相対path順で次の1件だけを提示します。sourceとmanifestは変更しませんが、local runtime DBにはvalue-freeな候補・review監査と内部再検証用のsource hash/statを保存します。raw valueと本文previewはstdout、stderr、候補row、review rowのいずれにも残さず、source hashとabsolute pathは外向きoutputやreviewには出しません。

`scan_complete: false`は固定上限で探索が部分結果になったことを表すため、agentは候補なしと言い切らず、到達した上限reasonと未探索範囲が残ることを説明します。候補は1件ずつ明示承認し、approveによってmanifest hashが変わった後は残りの旧revision / hashを使わず、必ずscanを再実行して次の提案へ新しい承認を得ます。ユーザーまたはagentが既にpathを特定した場合は、従来の`protect suggest --path <relative-path> --json`をfallbackとして使えます。`init`、PreToolUse、PostToolUse、Stopはこのworkspace scanを暗黙実行しません。

Plugin更新でprotected-source detector versionが変わった場合も、更新前の`proposed`候補のID / opaque revisionは再利用しません。旧proposalへのapprove、reject、ignoreはcandidateやreviewを変更する前にvalue-freeな`candidate_detector_stale`で終了します。agentは`protect scan`を再実行し、現在versionが作った新しいcandidate IDとrevisionを提示して改めて承認を得ます。旧versionのreject / ignoreは新versionの候補を抑止しません。すでにmanifestへ登録されたapproved sourceは更新後も維持し、detector変更だけを理由にentryやselectorを自動変更しません。更新前に開始した`approving`または完了した`approved`へのexact approve再試行だけは、途中停止のdurability recoveryとして扱います。Hookはこの候補互換処理やscanを暗黙実行しません。

`scan`と`suggest`はmanifestを変更しません。agentは提案entryをユーザーへ示し、明示承認後にだけ`protect approve`へ保存済みcandidate ID、opaque revision、提案時manifest SHA-256を渡します。approveはworkspace lockを取得してからDB上の候補を`proposed`から`approving`へ予約し、sourceのstat・content hash・selector解決とexpected manifest hashの楽観的な事前条件を再検証します。lockはmanifest更新後のDB確定または安全なreleaseまで保持するため、同時のreject / ignore / approveが異なる状態を確定しません。途中停止や一時的なstate errorでは、同じcandidate ID、opaque revision、manifest SHA-256のapprove入力を再実行します。exact登録の回復はdirectory fsyncと再検証に成功した後だけDBをapprovedへ進めます。workspace lockで直列化するのはToolUseProxyの協調writer同士です。POSIX filesystemには同一UIDの非協調editorも含めたportableなcontent compare-and-swapがないため、filesystemの最終再検証からatomic replaceまで、またはdurability再確認からDB確定までの競合を含むfilesystem / DB横断の直列化は保証外です。この登録workflowは現在POSIX（macOS/Linux）対応で、Windowsでは`protect scan / suggest / approve / reject / ignore`を未対応とします。候補作成と再検証で検出したsourceまたはmanifestの変更は登録せず、新しいscanまたはsuggestを要求します。

候補のSQLite rowにはpath、selector、固定rule、confidence、内部再検証用hash/statだけを保持し、secret本文は保持しません。`reject` / `ignore`は同一file内容・detector versionの候補を再提示しないためのvalue-free監査です。schema省略またはschema v1のlegacy manifestはruntime互換を維持し、明示的な`protect migrate plan` / `apply`が完了するまで新しいentryを登録しません。登録済みmanifestは次のanalysisでsource digest差分として検出され、そのworkspace / sessionをfull rebuildします。

直接実行される`curl`の静的body optionでは、送信operandとselected secret valueが完全一致した場合だけ、command全体の長さに影響されないcritical bindingを作ります。shell変数やcommand substitutionは展開せず、unknown option、`@file` / `@-`、上限超過を含むsegmentは値単位の証明をせず従来のsegment-level evidenceへ戻します。抽出値は追加の永続rowや評価reportへ保存しません。

JSONの例:

```json
{
  "schema_version": 2,
  "sources": [
    {
      "id": "service_credentials",
      "path": "config/secrets.json",
      "type": "secretfile",
      "sensitivity": "high",
      "policy_tags": ["no_external"],
      "selector": {
        "json_pointers": ["/private/token", "/accounts/0/key"]
      }
    }
  ]
}
```

## 類似度profile v2

現在は`similarity-profile-v2`を使い、artifact fragment同士、およびsource chunkとartifact fragmentをboundedかつdeterministicに比較します。比較は次の順です。

1. raw text hashまたはcanonical representationの`exact`
2. 内容衝突とlow-signal containmentを棄却する`substring`
3. 明示した少数のaliasだけを扱う`token_equivalent`
4. deterministic conflict guardを通過した`shingle_jaccard`
5. backendが明示的に渡された場合だけ`embedding_cosine`

canonicalizationはNFKC、1回だけのpercent decode、JSON escape、identifier separatorを固定段数・固定byte上限内で扱います。上限を超えた本文はraw exact以外をfail closedにし、短いlow-information phrase、否定や条件が衝突する表現、一般的な数値phraseを近似一致へ昇格しません。

source bindingでは、長く多様な英字だけの単一tokenをwrapper内でsubstring一致させる場合に限り、secretfile selectorが明示したsecurity fieldの値であることも要求します。selectorなし、または通常項目を選んだだけの値はこのalpha-only heuristicで結びません。exact一致とartifact fragment同士の比較には影響しません。

候補探索ではcanonical / raw exactをlexical上限の外で先に保持し、残りをbounded feature indexからcoverageとoverlapの二つの順位で取得します。artifactは50件、sourceは200件を上限とし、full rebuildとsession incrementalで同じranking helperを使います。

`embedding_cosine`のinterfaceは比較器に残していますが、現在のHook runtimeはembedding backend、network、remote serviceを使いません。意味的な言い換えは研究gapとして評価corpusへ残しています。固定corpus、promotion基準、full / incremental parity、privacy invariantは[類似度評価](../運用/類似度評価.md)を参照してください。

## 再解析コマンド

保護対象 source は後から追加・変更される前提なので、過去のログに対して再解析できる必要があります。

そのために、source 設定と `events.db` を使ってartifactグラフとlineageを再構築するコマンドを用意しています。

```bash
python3 /absolute/path/to/ToolUseProxy/scripts/rebuild_lineage.py \
  --db /absolute/path/to/events.db \
  --workspace-root /absolute/path/to/workspace
```

このコマンドは次を行います。

1. 過去artifactからfragmentを補完する
2. selected workspaceの入力revisionを固定してartifact、operation、snapshotを読む
3. source非依存のartifact間グラフをメモリ上で構築または再利用する
4. `protected_sources.json` を読み、sourceをchunkに分割する
5. source chunkをartifactグラフへ接続し、sourceからのlineageをメモリ上で計算する
6. source設定の存在状態とcatalog fingerprintをpublish直前に再確認する
7. 入力revision、直前run、graph stateをCASし、live derived stateとcompleted run snapshotを1 transactionでpublishする

途中でvalidation、CAS、保存、completionのいずれかが失敗した場合は全transactionをrollbackし、旧live derived rows/stateと旧latest completed runを維持します。重いrevision読込はdeferred WAL snapshotで行い、その間のHook writerを塞ぎません。writer競合はbounded retryします。このatomic publish APIはoffline CLI専用であり、PreToolUse / PostToolUse / StopのHook経路からは呼びません。

詳細な設計は [情報流追跡.md](../設計/情報流追跡.md) にまとめています。

## なぜ分けているか

この構造にしている理由は、研究の次の段階で差し替えやすくするためです。特に `runtime` と `analysis` を分けることで、hook 実行時の本番経路と、後から何度も回せる再解析経路を切り分けています。

- hook 実行時の記録経路を変えたいなら `hook_monitor/runtime/`
- 類似度計算や source 追跡を変えたいなら `hook_monitor/analysis/`
- Bash curl送信値の静的抽出を変えたいなら `hook_monitor/analysis/bash_submission.py`
- 情報流エッジを強化したいなら `analysis` 側に拡張を足す

現在の`hook_monitor/`は記録の骨格に加え、workspace・session差分graph、漏えい検知、Stop継続、Bash/MCP PreToolUse deny、operation単位lineage、PostToolUse snapshot、複数workspace分離、offline run snapshotとatomic publish、MCP exact profileと全scalar value / JSON key sink coverageまでを接続しています。PermissionRequestは実payloadとdeny / allowを評価しましたが、PreToolUseの代替にならず、payloadにstableなcall IDがなく、`allow`が通常承認を自動通過させるため、production Hookには設定しません。将来接続する場合もdeny-onlyの独立adapterとし、判断なしは空stdoutでCodex本来の承認へ委ねます。redactはblockを維持するpure preview planner、immutableなhash-only audit、future renderer向けのdormant decision linkage、rendered planだけを対象にしたPost confirmationまでDBへ追加しました。runnerはprepare APIやrendererを呼ばず、Hook stdoutは従来のdenyのままで`updatedInput`をrenderしません。複数rewrite競合のgateが解消するまでproduction Hookへruntime rewriteを追加しません。詳細は [Redact設計](../設計/Redact.md) を参照してください。

## この研究の位置づけ

ざっくり言うと、

- `Codex Hooks` = 差し込み口
- `PreToolUse` / `PostToolUse` = 差し込めるタイミング
- `hooks.json` = どのタイミングで何を呼ぶかの配線図
- `monitor_pre_tool.py` / `monitor_post_tool.py` = 監視プログラム
- 情報流追跡・漏えい検知・Stop 機構 = この研究の成果

つまり、この研究は「Codex Hooks を観測点として使い、tool use の I/O を外部で追跡・記録・判定する」ことを狙っています。
