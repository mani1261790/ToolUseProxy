---
name: tooluseproxy-setup
description: Set up, diagnose, or inspect the ToolUseProxy Codex Plugin for the current workspace. Use for ToolUseProxy init, doctor, status, plugin Hook trust, database-path, or protected_sources.json onboarding tasks.
---

# ToolUseProxy setup

Use this workflow only when the user asks to set up or diagnose ToolUseProxy. Never add a protected source without showing the proposed entry and receiving explicit user approval.

1. Confirm that the current directory is the intended workspace root.
2. Confirm that the ToolUseProxy Plugin Hook definition has been reviewed and trusted in Codex. Do not bypass Hook trust.
3. Run the Plugin CLI through `hooks/run_cli.sh` on macOS/Linux or `hooks\run_cli.cmd` on Windows. Resolve the Plugin root from this skill's location; it is two directories above `skills/tooluseproxy-setup`.
4. Initialize the same writable directory used by the Hook:

   ```text
   hooks/run_cli.sh init --codex --workspace <workspace-root> --data-dir <PLUGIN_DATA>
   ```

   If `PLUGIN_DATA` is not available in the current shell, use the exact data directory printed by the Plugin Hook's `database_missing` diagnostic. Do not guess a cache path.
5. Run `doctor` with the same `--workspace` and `--data-dir` values. Stop and explain every failing check before enabling stronger policy gates.
6. Treat the generated `protected_sources.json` as an empty, user-owned manifest. Preserve an existing valid manifest byte-for-byte; do not auto-populate it.
7. Use `status` to verify the database, canonical workspace registration, and protected-source manifest all resolve to the same workspace.

The default onboarding boundary records tool activity and reviews final responses. PreToolUse blocking and MCP blocking remain explicit opt-ins; do not silently enable them.
