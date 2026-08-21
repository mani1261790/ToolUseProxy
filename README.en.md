# ToolUseProxy

ToolUseProxy is a local-first research implementation for tracing information flow through Codex tool calls and reviewing high-confidence leaks before they leave the workspace.

This project is a research and development outcome of [SecHack365](https://sechack365.nict.go.jp/).

The current release candidate is `0.1.0-alpha.8`. It adds conservative, opt-in externality protection while keeping LLM classification outside Hooks and requiring human review before any local allow rule is created. The public channel remains on alpha.7 until the alpha.8 fresh Desktop gate passes. It is not a complete DLP system.

ToolUseProxy is licensed under the [Apache License 2.0](LICENSE).

## What it does

- Records Codex `PreToolUse`, `PostToolUse`, and `Stop` events in local SQLite storage.
- Builds lineage from user-approved protected sources to tool inputs and final answers.
- Suggests `.env` and JSON protected-source entries without displaying their values.
- Requires explicit approval before changing `protected_sources.json`.
- Checks every Hook-visible local tool and can deny protected information flow before execution when opt-in enforcement is enabled.
- Stores allowlisted boolean runtime policy settings per workspace with revision-checked updates and value-free audit history.
- Hooks stay local and use no remote embedding or ToolUseProxy telemetry. The experimental Externality Judge queues only value-free structural summaries locally. A first-seen unknown call is denied only when protected lineage reaches it; public-only calls continue. An explicitly run worker starts a new isolated, ephemeral Codex session for each job. ToolUseProxy does not call the OpenAI API directly or accept an API key. A revision-bound human review is required before an exact local rule can remove the conservative unknown sink.

## Install the Plugin

For normal alpha use, install from the protected `public-alpha` release channel:

```bash
codex plugin marketplace add mani1261790/ToolUseProxy --ref public-alpha
codex plugin add tooluseproxy@tooluseproxy
```

Install the marketplace and Plugin once per Codex environment, then use the
same Plugin across multiple projects. Initialization, protected-source
registration, runtime settings, and audit data remain workspace-scoped, so run
the bundled setup skill when you first use each workspace.

Updates are explicit, not automatic:

```bash
codex plugin marketplace upgrade tooluseproxy
codex plugin list --json
```

Use the immutable `v0.1.0-alpha.7` tag instead of `public-alpha` when reproducible version pinning matters. A pinned tag does not move when the marketplace is upgraded. Review the exact Hook definitions after installation or an update before trusting them. A changed matcher, command, or source invalidates the earlier trust decision; a Hook with `trustStatus: modified` must be reviewed again. Then follow the [Japanese five-minute quickstart](QUICKSTART.md) to initialize ToolUseProxy and review protected-source proposals in batches of up to ten. The CLI update path is tested.

On Codex Desktop for macOS, Plugin installation, review and trust of the earlier three-Hook definition, `PreToolUse` / `PostToolUse` / `Stop` delivery, public allow, and the pre-execution block of a file-backed protected payload have been verified. The August 9 runs also covered alpha.1-to-alpha.3 data migration, backup rollback, direct Remove without Disable, saved-task revalidation, and a fresh atomic setup-profile run. The fresh run passed with two command approvals, one public side effect, zero protected side effects, one exact block, and zero raw protected-value exposures. The current five-Hook candidate, which adds `SessionStart` and `SubagentStart`, still requires a fresh Desktop run. Desktop task history records local shell calls as `exec_command`, while the canonical Hook matcher name is `Bash`; value-free markers, the Hook database, stable definition hashes, and task records remain the evidence boundary. Linux and Windows Desktop are not established by this result.

## Try the synthetic preview

Run the automated, synthetic preview from a checkout:

```bash
python3.11 scripts/demo_plugin.py
```

The preview does not replace manual Hook review or an actual Codex task.

## Important boundaries

- PreToolUse enforcement is off by default.
- Internal failures and unknown schemas generally fail open.
- Local SQLite data can contain plaintext Hook payloads and protected-source chunks.
- Removing the Plugin does not delete local audit data.
- Protected-source onboarding and manifest migration are supported on macOS and Linux for this alpha, not Windows.
- Hosted Web Search does not appear in the current `PreToolUse` / `PostToolUse` Hook surface, so ToolUseProxy cannot observe or technically block it before execution. `SessionStart` and `SubagentStart` Hooks add developer context instructing Codex never to send protected or derived content through hosted tools, but this is a mitigation rather than an enforcement boundary.
- Additional input sent to a running process through `write_stdin` does not trigger another `PreToolUse`, and specialized Codex tool paths may bypass Hooks; neither boundary is claimed as protected.
- The Externality Judge is experimental, off by default, and not part of the normal setup profile. LLM classification runs outside Hooks, never auto-promotes a rule, and cannot weaken an existing block. Its provider-specific processing and retention boundary is documented in [privacy and retention](PRIVACY.md).

Read [support and known limitations](SUPPORT.md), [privacy and retention](PRIVACY.md), [private vulnerability reporting](SECURITY.md), and the [Japanese project documentation](README.md) before using the alpha.
