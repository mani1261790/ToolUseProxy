# ToolUseProxy

ToolUseProxy is a local-first research implementation for tracing information flow through Codex tool calls and reviewing high-confidence leaks before they leave the workspace.

The current version is `0.1.0-alpha.3`. It is not a complete DLP system and is not yet a published release.

## What it does

- Records Codex `PreToolUse`, `PostToolUse`, and `Stop` events in local SQLite storage.
- Builds lineage from user-approved protected sources to tool inputs and final answers.
- Suggests `.env` and JSON protected-source entries without displaying their values.
- Requires explicit approval before changing `protected_sources.json`.
- Can deny high-confidence Bash or MCP disclosures when opt-in enforcement is enabled.
- Uses no Hook-time network service, remote embedding, or ToolUseProxy telemetry.

## Try it

Run the automated, synthetic preview from a checkout:

```bash
python3.11 scripts/demo_plugin.py
```

For local Plugin installation and first protected-source registration, follow the [five-minute quickstart](QUICKSTART.md).

## Important boundaries

- PreToolUse enforcement is off by default.
- Internal failures and unknown schemas generally fail open.
- Local SQLite data can contain plaintext Hook payloads and protected-source chunks.
- Removing the Plugin does not delete local audit data.
- Protected-source onboarding and manifest migration are supported on macOS and Linux for this alpha, not Windows.

Read [support and known limitations](SUPPORT.md), [privacy and retention](PRIVACY.md), and the [Japanese project documentation](README.md) before using the alpha.
