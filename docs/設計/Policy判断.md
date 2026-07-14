# Policy判断

Policy判断は、漏えい検知で得た finding を、実行時にどう扱うかという判断へ変換する層です。

```text
LeakFinding
  -> PolicyDecision
  -> Codex Hook output
```

この層は、Codex の既存の許可UIを作り直すものではありません。Codex の許可機構は「この操作を実行してよいか」を扱います。ToolUseProxy の policy 判断は「この情報がこの宛先へ流れてよいか」を扱います。

```text
Codex permission:
  Can this action run?

ToolUseProxy policy:
  Can this source lineage flow to this sink?
```

## 層の分離

Policy判断は、次の2層に分けます。

```text
共通層:
  LeakFinding
  PolicyDecision
  PolicyEngine

Codex接続層:
  Codex hook stdout JSON
  PreToolUse / PermissionRequest / PostToolUse / Stop の返却形式
```

共通層は、Codex以外の実行環境でも使える判断モデルです。Codex接続層は、Codex Hooks の現在の仕様へ合わせる adapter です。

## Codex既存許可との違い

Codex の既存許可は、tool use や権限要求の種類を見ます。

```text
git push を実行してよいか
curl を実行してよいか
ファイルを書き換えてよいか
ネットワークアクセスしてよいか
```

ToolUseProxy は、操作だけでなく、その操作に流れ込んでいる情報の由来を見ます。

```text
private-source
  -> artifact_fragment
  -> sink_candidate(external_http_request)
  -> LeakFinding
  -> PolicyDecision(block)
```

同じ `curl` でも、protected source 由来の情報が含まれない場合は許可でき、protected source 由来の情報が外部へ送られる場合は止める、という判断ができます。

## PolicyDecision model

最小実装では、次のactionを使います。

```python
@dataclass(frozen=True)
class PolicyDecision:
    decision_id: str
    action: str
    severity: str
    finding_id: str
    sink_type: str
    source_node_kind: str
    source_node_id: str
    sink_node_id: str
    path_score: float
    hook_event: str | None
    reason: str
```

action:

- `allow`
  - findingはあるが介入しない
- `warn`
  - Codexに警告や追加contextを渡す
- `redact`
  - tool inputを書き換える
- `block`
  - tool実行や承認要求を拒否する
- `continue_review`
  - `Stop` 後に追加確認ターンを促す

## 初期ルール

最初は設定ファイルではなく、固定ルールで実装します。ルールを安定させてから設定化します。

```text
external_message
external_http_request
external_git_publish
external_package_publish
external_deploy
  critical -> block
  high     -> warn

external_search
external_api_call
external_file_transfer
  critical -> block
  high     -> warn

final_answer
  critical -> continue_review
  high     -> warn

medium / low
  -> allow
```

`redact` は初期実装では判断modelだけに置きます。安全なredactは tool input の構造ごとに異なるため、Bash、MCP、apply_patch などの個別対応が必要です。

## Codex Hookとの対応

Codex Hook では、eventごとに返せる制御が異なります。

```text
PreToolUse
  block -> permissionDecision: deny
  warn  -> additionalContext
  redact -> permissionDecision: allow + updatedInput

PermissionRequest
  block -> decision.behavior: deny
  allow -> 通常承認へ委ねるため空stdout

PostToolUse
  warn -> additionalContext
  block -> tool resultをhook feedbackに置き換える

Stop
  continue_review -> decision: block
  warn -> systemMessage
```

Codex の `PreToolUse` では `permissionDecision: "ask"` は現在の安定した返却形として使いません。ユーザー確認に委ねたい場合は、まず `warn` として追加contextを出し、Codex本来の承認フローへ委ねます。

`PermissionRequest`の`decision.behavior: allow`は、policy上の`allow`を記録するだけではなく、guardian / userの通常承認を省略してtool実行を承認します。ToolUseProxyはDLP判断を権限付与へ昇格させないため、`behavior: allow`を返しません。criticalな追加漏えい根拠がある場合だけ`deny`を返し、それ以外は空stdoutで通常承認へ戻すのが安全な契約です。ただし現時点では、PermissionRequest自体をruntimeへ接続していません。

PermissionRequestはPreToolUseの後、Codexが承認を必要とした場合だけ発火します。payloadには`tool_use_id`がなく、cached / auto-approved / `approval_policy=never`の呼び出しでは発火しません。現在のexternal sinkはより早いPreToolUseで評価でき、generic接続は解析と監査を二重化する一方でcoverageを増やさないため、接続を見送りました。PreToolUseで観測できない実漏えい経路とstableな相関・permission fieldが確認できた場合だけ、deny-onlyの独立adapterとして再評価します。

`Stop` の `decision: "block"` は最終応答を単純に拒否するものではなく、Codexに追加ターンを継続させる動きです。そのため、最終応答の漏えい候補は `continue_review` として扱います。

現在は `hook_monitor/policy/codex_output.py` で、`PolicyDecision` を Codex Hook の stdout JSON へ変換します。Hookに返す文面は、`hook_monitor/policy/explanation.py` の `PolicyExplanation` で組み立てます。

```python
select_strongest_decision(decisions, "PreToolUse")
render_codex_hook_output(decision, "PreToolUse")
```

`PolicyExplanation` は、判断そのものではなく人間に見せる説明です。説明には次を含めます。

- 何が起きたか
- source node
- sink type
- score / severity
- `trace_lineage.py` で根拠経路を確認する command
- 次にどう直すべきか

説明には raw artifact text、protected source text、tool input の生値、final answer の生値は含めません。Hook stdout は漏えいを止めるための出力なので、説明自体が再漏えい経路にならないようにします。

Stop hook の `reason` は、たとえば次のようになります。

```text
Protected source content appears in the final answer. Revise the final answer to remove protected details, then continue.
Source: source_chunk:private-source:0; Sink: final_answer; Score: 0.97; Severity: critical
Trace: python3 scripts/trace_lineage.py --db .tooluseproxy/events.db --analysis-run <analysis_run_id> --node sink_candidate:<id>
```

Stop hook runtimeで `block` / `warn` / `continue_review` を返した場合は、同じ判断を `policy_decisions` tableへ保存します。これにより、Codexに返した短い説明が流れた後でも、あとからdecision idで判断を確認できます。

保存する情報:

- decision id / finding id / analysis run id
- hook event / action / severity
- source node / sink candidate
- sink type / score
- user message / technical summary
- trace command
- path summary

保存しない情報:

- raw artifact text
- protected source text
- tool input raw value
- final answer raw value

保存済みdecisionは次のCLIで確認します。

```bash
python3 scripts/list_policy_decisions.py
python3 scripts/list_policy_decisions.py --format json
python3 scripts/list_policy_decisions.py --decision <decision_id>
python3 scripts/trace_lineage.py --decision "$DECISION_ID"
```

複数decisionがある場合は、次の優先順で最も強いdecisionを選びます。

```text
block
continue_review
redact
warn
allow
```

同じactionの場合は、`path_score` が高いdecisionを優先します。

## 最小CLI

実行時hookに直結する前に、offlineで判断結果を確認します。現在は `scripts/evaluate_policy.py` を実装しています。

```bash
python3 scripts/evaluate_policy.py --workspace-root "$PWD" --latest
python3 scripts/evaluate_policy.py --workspace-root "$PWD" --latest --include-final-answer
python3 scripts/evaluate_policy.py --analysis-run "$ANALYSIS_RUN_ID" --format json
python3 scripts/evaluate_policy.py --analysis-run "$ANALYSIS_RUN_ID" --hook-output PreToolUse
python3 scripts/evaluate_policy.py --analysis-run "$ANALYSIS_RUN_ID" --include-final-answer --hook-output Stop
```

`--analysis-run ID`と`--workspace-root PATH --latest`は排他的です。後者は指定workspaceのcompleted offline runだけを選び、global latestやruntime runへfallbackしません。

text output:

```text
analysis_run_id=...
decisions=1

[BLOCK] external_http_request severity=critical score=0.94
source: source_chunk:private-source:0
sink: sink_candidate:<id>
reason: critical source lineage reached external_http_request
hook_event: PreToolUse
trace: python3 scripts/trace_lineage.py --analysis-run <analysis_run_id> --node sink_candidate:<id>
```

JSON output:

```json
{
  "analysis_run": {
    "analysis_run_id": "..."
  },
  "summary": {
    "decisions": 1
  },
  "decisions": [
    {
      "decision_id": "...",
      "action": "block",
      "finding_id": "...",
      "severity": "critical",
      "reason": "critical source lineage reached external_http_request",
      "hook_event": "PreToolUse"
    }
  ]
}
```

## 実装順序

実装済み:

- `hook_monitor/policy/models.py`
- `hook_monitor/policy/engine.py`
- `hook_monitor/policy/codex_output.py`
- `hook_monitor/policy/explanation.py`
- `hook_monitor/runtime/stop_policy.py`
- `scripts/evaluate_policy.py`
- `scripts/list_policy_decisions.py`
- `LeakFinding` から `PolicyDecision` への変換
- `PolicyDecision` から `PolicyExplanation` への説明生成
- Stop hook が返したpolicy decisionのDB保存
- `Stop` hook から `final_answer` の `continue_review` を返す最小接続
- Stop hook では現在の `Stop` event 由来の `final_answer` sink だけを判断対象にする
- text / JSON output
- policy decision のテスト

実Hookへ接続済みの範囲:

1. Bash external sinkを`PreToolUse`の`permissionDecision: deny`へ接続
2. 実CodexのMCP tool名とraw argumentsをadapterへ接続
3. 二段階opt-inでMCP external sinkを`PreToolUse` denyへ接続

operation単位fragment、snapshot capture、複数workspaceのsource/cursor/resource分離は実装済みです。`PermissionRequest`は公式source、実payload、deny / allow E2Eを検証し、汎用runtime接続を追加しないと判断しました。次はtool別`updatedInput`を使うredactについて、構造を壊さず安全に書き換えられる条件を定義します。

Stop hook内の解析はsession差分更新へ移行済みです。初回または解析条件変更時は`session-full`、通常時は`session-incremental`としてanalysis runへ記録します。Hook内ではlocal DB、static adapter、indexed lexical候補、差分lineageだけを扱い、embeddingやnetwork accessは行いません。

## 完了条件

- `detect_leaks.py` のfindingをpolicy decisionへ変換できる
- `external_*` と `final_answer` で異なるactionを返せる
- text / JSON outputで判断理由を確認できる
- `block` 判断の根拠を `trace_lineage.py` で確認できる
- Codex Hookへ接続する前にofflineで誤判定を評価できる
- `PolicyDecision` をCodex Hook stdout JSONへ変換できる
- `Stop` hook が final answer sink の critical finding を `decision: block` として返せる
- Hook reason が source / sink / score / severity / trace command を含む
- Hook reason に raw protected text を含めない
- 保存済みdecisionをCLIで一覧・単体表示できる
- 保存済みdecisionから `trace_lineage.py` で根拠経路を確認できる

## 非対象

初期実装では次を扱いません。

- policy rule の設定ファイル化
- finding DB table への保存
- 実行時hook内での外部APIやembeddingを使う重い再解析
- Bash / MCP / apply_patch の安全なredact実装
- ユーザー確認UIの再実装
