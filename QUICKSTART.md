# ToolUseProxy five-minute quickstart

This quickstart installs the published public alpha from the protected
`public-alpha` release channel. Do not substitute the mutable development
branch `main`. Changes merged after the latest release are not available from
`public-alpha` until a new verified release is promoted.

## 1. Prerequisites

- macOS or Linux
- Python 3.11 or 3.12
- Codex CLI or Codex Desktop with Plugin support

Review [support and known limitations](SUPPORT.md) and [privacy and retention](PRIVACY.md). ToolUseProxy stores local audit data that may contain plaintext code, commands, responses, and protected-source chunks.
The source and distribution artifacts are licensed under the [Apache License 2.0](LICENSE).

## 2. Optional 30-second preview

The preview builds a clean Plugin artifact and runs a synthetic Phase A lifecycle without real network calls:

```bash
python3.11 scripts/demo_plugin.py
```

It does not replace manual Hook trust or actual-tool Phase B testing.

## 3. Install the public Plugin

Add the public-alpha release channel and install ToolUseProxy:

```bash
codex plugin marketplace add mani1261790/ToolUseProxy --ref public-alpha
codex plugin add tooluseproxy@tooluseproxy
```

The marketplace and Plugin are installed once for the Codex environment, not
once per project. You can then use the same Plugin in multiple projects. Each
workspace keeps separate initialization, protected-source registration,
runtime settings, and audit data, so run the bundled setup skill when you first
use a new workspace.

Start a new Codex task in the workspace you want to monitor. Review the exact Hook definition shown by Codex and trust it only if the Plugin source and version are the ones you intended to install. ToolUseProxy does not bypass this review.

For a reproducible version pin, use `--ref v0.1.0-alpha.4` instead. A pinned
tag does not advance to a future version.

For development from a checkout, replace the first command with
`codex plugin marketplace add "$PWD"`. Do not use a mutable remote branch as a
trusted distribution source.

Before using a checkout build in a real project, confirm that no other
ToolUseProxy Plugin is enabled. Two ToolUseProxy installations can register the
same Hooks and make both behavior and audit evidence ambiguous. Keep existing
Plugin data unless you separately review and approve an `uninstall plan`.

## 4. Initialize and diagnose

Ask the coding agent:

> Use the ToolUseProxy setup skill. Initialize ToolUseProxy for this workspace, run doctor and status, and explain any failure without showing protected values.

Follow the setup skill bundled with the installed Plugin. A newer build may
group initialization and the three protected runtime settings into one atomic
profile application, followed by one read-only verification. Approval is still
limited to those exact commands; it is not a reusable permission prefix.

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

## 6. Confirm status, updates, and retention

After an explicit approval, ask the agent to run `status` again. The approved source becomes active for the next analysis run in that workspace.

PreToolUse blocking remains off by default; the quickstart does not silently enable enforcement. Use the full [Plugin onboarding guide](https://github.com/mani1261790/ToolUseProxy/blob/main/docs/%E8%A8%AD%E5%AE%9A/Plugin%E5%B0%8E%E5%85%A5.md) before enabling it.

Runtime policy settings can be stored per workspace in `PLUGIN_DATA` with
revision-checked `config show`, `config set`, and `config unset` commands.
Environment variables remain compatible overrides. See the
[workspace runtime settings guide](docs/%E8%A8%AD%E5%AE%9A/Runtime%E8%A8%AD%E5%AE%9A.md)
for the exact keys, dependencies, and audit behavior.

Updates from `public-alpha` are explicit:

```bash
codex plugin marketplace upgrade tooluseproxy
codex plugin list --json
```

After an update, review changed Hook definitions, start a new Codex task, and
run the verification requested by the installed setup skill. Run initialization
only if the installed skill reports that setup or schema migration is required.
The CLI update path and the Codex Desktop install, update, backup rollback,
direct Remove, Hook trust, public allow, and protected pre-execution block have
been verified on macOS. This does not establish Linux or Windows Desktop
support.

## 7. Use it in a real project carefully

Start with one low-risk project and one intentionally selected protected source.
Do not begin with production credentials, customer data, signing keys, or a
workspace where a fail-open event would be costly. Confirm these checkpoints in
order:

1. only one ToolUseProxy Plugin is enabled;
2. all three Hook definitions are reviewed and trusted;
3. setup and read-only verification succeed;
4. one harmless public operation completes normally;
5. one synthetic protected value is blocked before the external operation;
6. normal project work continues without unexpected blocks;
7. Plugin removal retains data unless a separate uninstall is approved.

Stop the trial if setup or verification fails, a Hook becomes `modified` or
`untrusted`, an unexpected second ToolUseProxy Plugin is active, a public
operation is blocked, or a protected value reaches an external side effect.
Do not work around a failure by granting a broad reusable permission.

Use the [real-project dogfood checklist](docs/%E9%81%8B%E7%94%A8/Plugin%E3%83%89%E3%83%83%E3%82%B0%E3%83%95%E3%83%BC%E3%83%89.md#%E5%AE%9Fproject%E3%81%A7%E3%81%AEself-dogfood) and the
[GitHub dogfood report template](.github/ISSUE_TEMPLATE/dogfood-report.md).
Reports must not include source values, raw Hook payloads, SQLite databases,
access tokens, or absolute user paths.

## 8. Remove the Plugin

To remove Plugin code:

```bash
codex plugin remove tooluseproxy@tooluseproxy
codex plugin marketplace remove tooluseproxy
```

Removal retains local SQLite data. Deleting managed data is a separate `uninstall plan` and exact-confirmation operation described in the [Plugin onboarding guide](https://github.com/mani1261790/ToolUseProxy/blob/main/docs/%E8%A8%AD%E5%AE%9A/Plugin%E5%B0%8E%E5%85%A5.md#disable--uninstall).
