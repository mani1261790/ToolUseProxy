---
name: tooluseproxy-setup
description: Set up, diagnose, or inspect the ToolUseProxy Codex Plugin for the current workspace. Use for ToolUseProxy init, doctor, status, plugin Hook trust, database-path, or protected_sources.json onboarding tasks.
---

# ToolUseProxy setup

Use this workflow only when the user asks to set up or diagnose ToolUseProxy. Never add a protected source without showing the proposed entry and receiving explicit user approval.

1. Confirm that the current directory is the intended workspace root.
2. Confirm that the ToolUseProxy Plugin Hook definition has been reviewed and trusted in Codex. Do not bypass Hook trust.
3. Resolve the absolute Plugin root from this skill's location; it is two directories above `skills/tooluseproxy-setup`. On macOS/Linux, run every command through `sh "<PLUGIN_ROOT>/hooks/run_cli.sh"`. The general Windows launcher is `<PLUGIN_ROOT>\hooks\run_cli.cmd`, but the entire protected-source registration workflow is not supported on Windows yet.
4. Initialize the same writable directory used by the Hook:

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" init --codex --workspace <workspace-root> --data-dir <PLUGIN_DATA>
   ```

   If `PLUGIN_DATA` is not available in the current shell, use the exact data directory printed by the Plugin Hook's `database_missing` diagnostic. Do not guess a cache path.
5. Run `doctor` with the same `--workspace` and `--data-dir` values. Stop and explain every failing check before enabling stronger policy gates.
6. Treat the generated `protected_sources.json` as a user-owned manifest. Never edit it directly on the user's behalf. For a user-identified `.env`, `.env.*`, or JSON file, create a value-free proposal with:

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect suggest --path <workspace-relative-path> --workspace <workspace-root> --data-dir <PLUGIN_DATA> --json
   ```

   `suggest` is read-only for the source and manifest, but it writes a value-free candidate, review audit, and an internal source hash/stat to the local runtime database. Show the returned relative path, reason codes, confidence, and proposed source entry. Never show or repeat source values, source hashes, or file previews.
7. Wait for explicit user approval of that exact proposal. Approval is not implied by setup, diagnosis, a prior request to inspect the file, or permission to edit other project files. After approval, pass the unchanged opaque revision and manifest hash returned by `suggest`:

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect approve <candidate-id> --candidate-revision <opaque-revision> --expected-manifest-sha256 <manifest-sha256> --workspace <workspace-root> --data-dir <PLUGIN_DATA> --json
   ```

   Approval holds the workspace lock from the candidate reservation through manifest I/O and DB finalize/release. The expected manifest hash is an optimistic precondition; the lock serializes cooperating ToolUseProxy writers but does not exclude a same-UID non-cooperating editor. Filesystem/DB serialization is therefore not guaranteed across either the final validation-to-replace window or the durability-revalidation-to-DB-finalize window. For an interruption or transient state failure, retry the exact same approve command and unchanged candidate ID, opaque revision, and manifest hash. Exact-entry recovery re-fsyncs the workspace directory and revalidates the source and manifest before finalizing. If approval reports that the source or manifest changed, run `suggest` again and present the new proposal. Do not weaken the comparison or retry with an edited proposal. Use `protect reject` or `protect ignore` to persist a user's negative decision. Run the whole `protect suggest / approve / reject / ignore` workflow only on POSIX (macOS/Linux); it is not supported on Windows yet.

   If the manifest omits `schema_version` or uses schema v1, stop: the writer does not implicitly upgrade it, and an automatic v1-to-v2 migration CLI is not implemented. Do not edit the user-owned legacy manifest on the user's behalf.
8. Use `status` to verify the database, canonical workspace registration, and protected-source manifest all resolve to the same workspace.

The default onboarding boundary records tool activity and reviews final responses. PreToolUse blocking and MCP blocking remain explicit opt-ins; do not silently enable them.
