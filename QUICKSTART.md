# ToolUseProxy five-minute quickstart

This quickstart uses a local development checkout. Public releases will use an immutable tag or artifact; do not treat a mutable remote branch as a trusted distribution source.

After a public pre-release exists, add the repository marketplace with an immutable
release ref:

```bash
codex plugin marketplace add mani1261790/ToolUseProxy --ref <release-tag>
codex plugin add tooluseproxy@tooluseproxy
```

Do not use this remote command until the repository is public and the named tag exists.

## 1. Prerequisites

- macOS or Linux
- Python 3.11 or 3.12
- Codex CLI with Plugin support

Review [support and known limitations](SUPPORT.md) and [privacy and retention](PRIVACY.md). ToolUseProxy stores local audit data that may contain plaintext code, commands, responses, and protected-source chunks.
The source and distribution artifacts are licensed under the [Apache License 2.0](LICENSE).

## 2. Optional 30-second preview

The preview builds a clean Plugin artifact and runs a synthetic Phase A lifecycle without real network calls:

```bash
python3.11 scripts/demo_plugin.py
```

It does not replace manual Hook trust or actual-tool Phase B testing.

## 3. Install the local Plugin

From the checkout root:

```bash
codex plugin marketplace add "$PWD"
codex plugin add tooluseproxy@tooluseproxy
```

Start a new Codex task in the workspace you want to monitor. Review the exact Hook definition shown by Codex and trust it only if the Plugin source and version are the ones you intended to install. ToolUseProxy does not bypass this review.

## 4. Initialize and diagnose

Ask the coding agent:

> Use the ToolUseProxy setup skill. Initialize ToolUseProxy for this workspace, run doctor and status, and explain any failure without showing protected values.

The Plugin provides the exact `PLUGIN_ROOT` and `PLUGIN_DATA` paths at runtime. The equivalent commands are:

```bash
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" init --codex --data-dir "<PLUGIN_DATA>"
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" doctor --workspace "$PWD" --data-dir "<PLUGIN_DATA>"
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" status --workspace "$PWD" --data-dir "<PLUGIN_DATA>"
```

`status: active` confirms runtime initialization. It does not mean every sensitive file has been discovered or registered.

## 5. Review one protected-source proposal

Ask the agent:

> Scan for one protected-source candidate. Show only the relative path, reason codes, confidence, and proposed selector. Wait for my explicit approve, reject, or ignore decision.

The agent runs bounded offline `protect scan`. It must not display source values, source hashes, file previews, or absolute paths. Approval is one candidate at a time. After an approval changes the manifest hash, the agent must scan again before presenting another proposal.

Do not approve a proposal you do not understand. `init`, setup permission, or permission to edit another file does not approve a protected source.

## 6. Confirm status and retention

After an explicit approval, ask the agent to run `status` again. The approved source becomes active for the next analysis run in that workspace.

PreToolUse blocking remains off by default; the quickstart does not silently enable enforcement. Use the full [Plugin onboarding guide](https://github.com/mani1261790/ToolUseProxy/blob/main/docs/%E8%A8%AD%E5%AE%9A/Plugin%E5%B0%8E%E5%85%A5.md) before enabling it.

To remove Plugin code:

```bash
codex plugin remove tooluseproxy@tooluseproxy
codex plugin marketplace remove tooluseproxy
```

Removal retains local SQLite data. Deleting managed data is a separate `uninstall plan` and exact-confirmation operation described in the [Plugin onboarding guide](https://github.com/mani1261790/ToolUseProxy/blob/main/docs/%E8%A8%AD%E5%AE%9A/Plugin%E5%B0%8E%E5%85%A5.md#disable--uninstall).
