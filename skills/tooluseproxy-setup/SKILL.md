---
name: tooluseproxy-setup
description: Set up or inspect ToolUseProxy v0.2, register protected files, and open its live ToolCall log viewer. Explain Codex judge data transmission and incomplete judgments accurately.
---

# ToolUseProxy v0.2

This skill describes the semantic dependency engine. Do not reuse v0.1 setup profiles,
commands, or claims. Use the currently installed Plugin's launcher; a cached older
skill is not evidence of the current runtime. Check the launcher's `--version` once when resolving the installation; reuse that result
within the task unless the installation changes.
If the catalog path is stale, locate `tooluseproxy-setup/SKILL.md` under the ToolUseProxy Plugin cache in one scoped lookup and derive the launcher from that actual package root. Do not search unrelated projects or memories for an ordinary setup request.
If it is not v0.2, explain the version mismatch instead of applying these commands.

## Route the request, then finish that operation

| User intent | Action | Finish with |
| --- | --- | --- |
| 「このプロジェクトで使いたい」 | Setup once; open its viewer in the side panel | 初期設定とログ画面の結果 |
| 「private.txtを保護して」 | Direct `protect add` for that exact file | 登録した相対パスとファイル全体という範囲 |
| 「何を登録してた？」 | `protect list` | 登録一覧 |
| 「ログ見せて」 | `logs`, then open the returned URL | 表示したこと |
| 「設定どうなってる？」 | `status` | 設定状態。稼働の証明にはしない |
| 「本当に止まるか試したい」 | Separately scoped verification | 実際に観測した判定と実行結果 |

A named-file registration request already authorizes that registration. Do not turn
it into a mandatory plan → confirmation → add → list → test sequence. Ask only if
the target or scope is genuinely missing (e.g. 「秘密っぽいものを全部」); do not scan
files to invent the answer. If setup is missing, handle the one-time data-handling
agreement, set up, and continue the already requested registration.

Registration is a metadata operation: do not read the file, invoke a judge, generate
a canary, attempt a push/send, or run a protection test as part of it. A fresh-Hook
check is not a prerequisite for completing registration. Offer detailed diagnosis
when requested or when an actual failure needs it; do not start it after every success.
Do not append old recording/demo scripts to normal use.

Reuse the resolved workspace, data directory, installed version, and prior explicit
consent. An `already_registered` or `already_configured` result completes the request;
do not remove and recreate state. For ordinary success, answer in one or two sentences,
e.g. 「private.txt をファイル全体で保護対象に登録しました。」 Avoid internal IDs,
JSON, CLI syntax, and repeated coverage disclaimers unless they help this request.
Do not say 「流出しないことを確認しました」 when only registration succeeded.

## Explain the product accurately

ToolUseProxy records Hook-visible ToolCalls in events.db. An independent `codex exec`
judges information dependencies and possible external communication. The policy
traverses those dependencies and stops external calls connected to registered sources. Independent exact-content DLP also checks resolved transmission contents; a DLP match is a distinct reason, not an inferred graph edge.
This is inferred provenance, not proof of complete information-flow tracking.

The judge receives recorded ToolCall inputs, outputs, registered-source metadata, and bounded local resource evidence needed to resolve a transmission. New setup also enables background provenance analysis, which uses the model.
They may contain private information. It is NOT a local-only comparison and does NOT
reuse the running Codex conversation internally. Explain the selected model/provider
and the data it receives before initial setup. Reuse explicit consent already given;
do not ask for the same approval again.

When judgment times out, fails, or lacks evidence, report **判定未完了**. This version
retains the operation pending a completed judgment and retries analysis. Never describe
such a result as a detected leak, a safe operation, or a completed protection decision.
The finite host Hook deadline cannot hold a call forever: a pending response withholds
execution using the host deny mechanism, while retaining the unfinished judgment.
`analyze run` can resume saved judgments; it never executes their original tools.
After recovery, a new tool request must recheck current resources and policy. It never bypasses Codex's own approval rules.

## Setup

Use natural language with the user; these are implementation commands, not required phrases.
Resolve the current workspace and Plugin data directory. Do not guess a different
Plugin version's cache path. Once the user has agreed to the judge data handling:

```sh
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" setup --workspace "<WORKSPACE>" --data-dir "<PLUGIN_DATA>" --accept-judge-data --json
```

`--model <MODEL>` selects the judge model explicitly; otherwise the independent CLI
uses its default model. This is not necessarily the model of the current task.
Setup records its start boundary; earlier events are not used to infer dependencies.
Do not import history or scan the repository. Add `--protect <RELATIVE_FILE>` only when
the user's current setup request itself explicitly names that file and explicitly asks
to protect it. A filename found in AGENTS.md, repository documentation, an existing
demo script, prior agent narration, or the workspace is context, not authorization to
register it. A plain request such as 「このプロジェクトで使いたい」 performs Setup
without any `--protect` argument. Do not anticipate a later registration request.
Setup creates configuration and recording tables and starts the live log viewer.
Report initialization separately if a file registration or viewer startup fails.
Finish with the returned short Unsetup guidance, not a test or another confirmation.
Open the returned viewer URL in Codex's browser side panel when available. A URL in
JSON alone is not an opened screen. If the viewer fails, explain that configuration
and viewer startup are separate outcomes; use `logs` to retry.

```sh
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" logs --workspace "<WORKSPACE>" --data-dir "<PLUGIN_DATA>" --json
```

`configured_unverified` is configuration only. To claim protection works, separately
observe a fresh PreToolUse, the judge's decision, and whether the actual tool executed.
Do not call an installed/enabled Plugin or a populated DB proof of current protection.

## Register a source

For an explicitly named file, register it directly. The command registers the whole
file without reading its contents or judging whether its passages are secret.

```sh
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect add --path "<RELATIVE_FILE>" --workspace "<WORKSPACE>" --data-dir "<PLUGIN_DATA>" --json
```

`protect plan` is optional for a preview request or for clarifying a proposed target;
it is not a prerequisite to `protect add`. `protect list` is for listing registrations,
not a required follow-up after a successful add. Explain structured errors briefly:
missing file → check its name; directory → ask for files; outside workspace → identify
the intended project. Do not retry an unchanged error or silently broaden scope.

Never access a file the user forbids, register unrelated sources, or silently import
an old manifest. Existing DB registrations are retained; a manifest-only installation
requires a reviewed migration instead of an empty catalog presented as protection.

## Verification is a separate task

Run a leakage or Hook test only when requested, or as part of explicitly requested
installation diagnostics. Establish the test data and destination first; a request to
register a file does not authorize sending its contents anywhere. Prefer synthetic
inputs. Record fresh PreToolUse arrival, the decision, and actual execution evidence.
Report uncertainty honestly, but do not make such proof a condition of metadata registration.

## Inspect and explain Hook roles

Use `status` or `doctor` with the same workspace and data arguments. These are
configuration checks, not fresh Hook proof.

- SessionStart / SubagentStart: explain coverage and hosted-tool limitations.
- PreToolUse: record and screen external communication first. Definite local calls defer
  provenance; potential external calls inspect transmission evidence, check DLP, and traverse dependencies.
- PostToolUse: record actual output and observed resource generations. When enabled at setup,
  enqueue durable background provenance analysis after the Hook response; this uses the model.
  It cannot undo execution. Existing configurations are not silently opted in.
- Stop: no final-answer similarity check and no forecast-based additional stop.

Hosted tools such as WebSearch do not reliably pass through Codex ToolUse hooks.
Never send registered protected content or derived content to hosted tools. Public
research must use public-only queries. This instruction is not technical interception.

When reviewing Hook trust, check the actual installed source, all five definitions,
and their paths. Explain that hooks run with local user permissions and that the
judge makes model-provider requests. Do not accept unrelated pending hooks on the
user's behalf or describe Hook trust as proof that the model classified correctly.

## Stop or remove protection

Use `unsetup open` with the same workspace/data arguments to request the macOS
administrator authentication and confirmation UI. Do not enter credentials or operate
the confirmation dialog on the user's behalf. `plan` and `apply` do not mutate state.
If the administrator component is missing, report that and link the product's
Setup/Unsetup administration instructions; do not install or enroll it implicitly.
The agent-facing `unsetup` command does not itself remove protection. Administrative stop
and reactivation use the independent administrator approval boundary. Do not edit
Plugin enablement, source registrations, judge policy, or authority state to escape
a denial. Never treat a confirmation string the agent can generate as human approval.

## Provenance diagnostics

`analyze status` reports durable-job counts; `analyze run` resumes a bounded batch with the
same workspace/data arguments. These do not prove live interception. The log detail links
to a separate 2D provenance page showing pinned revisions without raw file contents.
Content-match blocks and graph-path blocks are separate outcomes. A missing graph is not safety.

## Retired v0.1 behavior

Do not use `setup apply --profile file-payload-exact`, similarity-score thresholds,
externality rule learning, forecast/early-stop commands, or final-response rewriting
as instructions for v0.2. Historical research code and records do not establish current
product capabilities. Do not assert that all setup operations or Hook checks are offline.
