---
name: tooluseproxy-setup
description: Set up or inspect ToolUseProxy v0.2, register protected files, and open its live ToolCall log viewer. Explain Codex judge data transmission and incomplete judgments accurately.
---

# ToolUseProxy v0.2

This skill describes the semantic dependency engine. Do not reuse v0.1 setup profiles,
commands, or claims. Use the currently installed Plugin's launcher; a cached older
skill is not evidence of the current runtime. Check the launcher's `--version` first.
If it is not v0.2, explain the version mismatch instead of applying these commands.

## Explain the product accurately

ToolUseProxy records Hook-visible ToolCalls in events.db. An independent `codex exec`
judges information dependencies and possible external communication. The policy
traverses those dependencies and stops external calls connected to registered sources.
This is inferred provenance, not proof of complete information-flow tracking.

The judge receives recorded ToolCall inputs, outputs, and registered-source metadata.
They may contain private information. It is NOT a local-only comparison and does NOT
reuse the running Codex conversation internally. Explain the selected model/provider
and the data it receives before initial setup. Reuse explicit consent already given;
do not ask for the same approval again.

When judgment times out, fails, or lacks evidence, report **判定未完了**. This version
warns and continues. Never describe such a result as a detected leak, a safe operation,
or an automatic protection success. It never bypasses Codex's own approval rules.

## Setup

Use natural language with the user; these are implementation commands, not required phrases.
Resolve the current workspace and Plugin data directory. Do not guess a different
Plugin version's cache path. Once the user has agreed to the judge data handling:

```sh
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" setup --workspace "<WORKSPACE>" --data-dir "<PLUGIN_DATA>" --accept-judge-data --json
```

`--model <MODEL>` selects the judge model explicitly; otherwise the independent CLI
uses its default model. This is not necessarily the model of the current task.
Setup creates configuration and recording tables and starts the live log viewer.
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

First show exactly which file and scope will be registered. The v0.2 command below
registers the whole file. It does not read its contents or guess which passages are secret.

```sh
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect plan --path "<RELATIVE_FILE>" --workspace "<WORKSPACE>" --data-dir "<PLUGIN_DATA>" --json
```

After the user authorizes that exact source (including authorization already in the
conversation), use the same arguments with `protect add` instead of `protect plan`.
`protect list` lists the registrations. Never scan or open a file the user forbids
accessing. Do not register unrelated sources or silently import an old manifest.
Existing DB registrations are retained; a manifest-only installation requires a
reviewed migration rather than creating an empty catalog and claiming protection.

## Inspect and explain Hook roles

Use `status` or `doctor` with the same workspace and data arguments. These are
configuration checks, not fresh Hook proof.

- SessionStart / SubagentStart: explain coverage and hosted-tool limitations.
- PreToolUse: record the pending call, judge dependencies/externality, then traverse.
- PostToolUse: record actual output and update the node. Cannot undo execution.
- Stop: no final-answer similarity check and no forecast-based additional stop.

Hosted tools such as WebSearch do not reliably pass through Codex ToolUse hooks.
Never send registered protected content or derived content to hosted tools. Public
research must use public-only queries. This instruction is not technical interception.

When reviewing Hook trust, check the actual installed source, all five definitions,
and their paths. Explain that hooks run with local user permissions and that the
judge makes model-provider requests. Do not accept unrelated pending hooks on the
user's behalf or describe Hook trust as proof that the model classified correctly.

## Stop or remove protection

The agent-facing `unsetup` command does not remove protection. Administrative stop
and reactivation use the independent administrator approval boundary. Do not edit
Plugin enablement, source registrations, judge policy, or authority state to escape
a denial. Never treat a confirmation string the agent can generate as human approval.

## Retired v0.1 behavior

Do not use `setup apply --profile file-payload-exact`, similarity-score thresholds,
externality rule learning, forecast/early-stop commands, or final-response rewriting
as instructions for v0.2. Historical research code and records do not establish current
product capabilities. Do not assert that all setup operations or Hook checks are offline.
