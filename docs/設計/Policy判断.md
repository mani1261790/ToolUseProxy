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
  allow -> decision.behavior: allow

PostToolUse
  warn -> additionalContext
  block -> tool resultをhook feedbackに置き換える

Stop
  continue_review -> decision: block
  warn -> systemMessage
```

Codex の `PreToolUse` では `permissionDecision: "ask"` は現在の安定した返却形として使いません。ユーザー確認に委ねたい場合は、まず `warn` として追加contextを出し、実行時の通常の承認フローや後続の `PermissionRequest` に接続します。

`Stop` の `decision: "block"` は最終応答を単純に拒否するものではなく、Codexに追加ターンを継続させる動きです。そのため、最終応答の漏えい候補は `continue_review` として扱います。

現在は `hook_monitor/policy/codex_output.py` で、`PolicyDecision` を Codex Hook の stdout JSON へ変換します。

```python
select_strongest_decision(decisions, "PreToolUse")
render_codex_hook_output(decision, "PreToolUse")
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
python3 scripts/evaluate_policy.py --latest
python3 scripts/evaluate_policy.py --latest --include-final-answer
python3 scripts/evaluate_policy.py --format json
python3 scripts/evaluate_policy.py --latest --hook-output PreToolUse
python3 scripts/evaluate_policy.py --latest --include-final-answer --hook-output Stop
```

text output:

```text
analysis_run_id=...
decisions=1

[BLOCK] external_http_request severity=critical score=0.94
source: source_chunk:private-source:0
sink: sink_candidate:<id>
reason: critical source lineage reached external_http_request
hook_event: PreToolUse
trace: python3 scripts/trace_lineage.py --node sink_candidate:<id>
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
- `scripts/evaluate_policy.py`
- `LeakFinding` から `PolicyDecision` への変換
- text / JSON output
- policy decision のテスト

次に実装すること:

1. Hook runtime から `codex_output.py` を呼び出す
2. `PreToolUse` / `PermissionRequest` / `Stop` の実Hookで動作確認する
3. redact用のtool別 `updatedInput` 生成を設計する

## 完了条件

- `detect_leaks.py` のfindingをpolicy decisionへ変換できる
- `external_*` と `final_answer` で異なるactionを返せる
- text / JSON outputで判断理由を確認できる
- `block` 判断の根拠を `trace_lineage.py` で確認できる
- Codex Hookへ接続する前にofflineで誤判定を評価できる
- `PolicyDecision` をCodex Hook stdout JSONへ変換できる

## 非対象

初期実装では次を扱いません。

- policy rule の設定ファイル化
- finding DB table への保存
- policy decision DB table への保存
- 実行時hook内での重い再解析
- Bash / MCP / apply_patch の安全なredact実装
- ユーザー確認UIの再実装
