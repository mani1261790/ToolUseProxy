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
5. Run `doctor` and `status` with the same `--workspace` and `--data-dir` values. Stop and explain every failing check before enabling stronger policy gates. A legacy manifest may remain runtime-readable and active while reporting `registration_writable: false` and `migration_required: true`.
6. Treat the generated `protected_sources.json` as a user-owned manifest. Never edit it directly on the user's behalf. If `status` reports that schema is omitted or v1, create a value-free migration plan on POSIX:

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect migrate plan --workspace <workspace-root> --data-dir <PLUGIN_DATA> --json
   ```

   Show the user the from/to schema, source count, whether a missing `sources` field will be added, formatting policy, private backup name, and preservation guarantees. Never show the manifest body, unknown-field values, source values, or previews. Explain that migration preserves existing entries, source order, existing key order, unknown fields, selectors, and protection semantics while changing the schema declaration and, only when `sources` is missing, adding the semantically equivalent empty list. It infers no selectors. It stores an exact-byte private backup under the data directory and normalizes the installed manifest to UTF-8, 2-space indentation, LF, and a trailing newline. Strict JSON does not support comments; do not strip comments or accept duplicate keys.

   Wait for explicit user approval of that exact migration plan. Setup approval, permission to edit another file, or a request to register a source does not approve migration. After approval, pass the unchanged revision and input manifest hash returned by the plan:

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect migrate apply --migration-revision <migration-revision> --expected-manifest-sha256 <manifest-sha256> --workspace <workspace-root> --data-dir <PLUGIN_DATA> --json
   ```

   The apply command accepts no replacement JSON. If the manifest changed, run `protect migrate plan` again, present the new plan, and obtain new approval. For an interruption or durability-unknown result, retry the exact same apply command. The workspace lock serializes cooperating ToolUseProxy writers, but not a same-UID non-cooperating editor; filesystem updates are not guaranteed to be serialized across the final validation-to-replace or durability-revalidation-to-completion windows. Run migration only on POSIX (macOS/Linux); it is unsupported on Windows. Migration approval never approves a later protected-source proposal.
7. For a user-identified `.env`, `.env.*`, or JSON file, create a separate value-free source proposal with:

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect suggest --path <workspace-relative-path> --workspace <workspace-root> --data-dir <PLUGIN_DATA> --json
   ```

   `suggest` is read-only for the source and manifest, but it writes a value-free candidate, review audit, and an internal source hash/stat to the local runtime database. Show the returned relative path, reason codes, confidence, and proposed source entry. Never show or repeat source values, source hashes, or file previews.
8. Wait for explicit user approval of that exact source proposal. Approval is not implied by setup, diagnosis, manifest migration, a prior request to inspect the file, or permission to edit other project files. After approval, pass the unchanged opaque revision and manifest hash returned by `suggest`:

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect approve <candidate-id> --candidate-revision <opaque-revision> --expected-manifest-sha256 <manifest-sha256> --workspace <workspace-root> --data-dir <PLUGIN_DATA> --json
   ```

   Approval holds the workspace lock from the candidate reservation through manifest I/O and DB finalize/release. The expected manifest hash is an optimistic precondition; the lock serializes cooperating ToolUseProxy writers but does not exclude a same-UID non-cooperating editor. Filesystem/DB serialization is therefore not guaranteed across either the final validation-to-replace window or the durability-revalidation-to-DB-finalize window. For an interruption or transient state failure, retry the exact same approve command and unchanged candidate ID, opaque revision, and manifest hash. Exact-entry recovery re-fsyncs the workspace directory and revalidates the source and manifest before finalizing. If approval reports that the source or manifest changed, run `suggest` again and present the new proposal. Do not weaken the comparison or retry with an edited proposal. Use `protect reject` or `protect ignore` to persist a user's negative decision. Run the whole `protect suggest / approve / reject / ignore` workflow only on POSIX (macOS/Linux); it is not supported on Windows yet.

9. Use `status` to verify the database, canonical workspace registration, schema v2 manifest, and protected sources all resolve to the same workspace.

The default onboarding boundary records tool activity and reviews final responses. PreToolUse blocking and MCP blocking remain explicit opt-ins; do not silently enable them.
