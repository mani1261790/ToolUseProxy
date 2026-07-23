---
name: tooluseproxy-setup
description: Set up, diagnose, inspect, or explicitly uninstall the ToolUseProxy Codex Plugin for the current workspace. Use for ToolUseProxy init, doctor, status, plugin Hook trust, database-path, protected_sources.json onboarding, or managed-data removal tasks.
---

# ToolUseProxy setup

Use this workflow only when the user asks to set up, diagnose, or uninstall ToolUseProxy. Never add a protected source or delete local data without showing the exact value-free plan and receiving explicit user approval.

Before asking the user to trust ToolUseProxy Hooks, explain all three roles in
plain language:

- `PreToolUse`: toolを実行する前に、Bash、file edit、MCPへ渡す内容を確認し、
  protected contentの外部送信を実行前に止める。
- `PostToolUse`: toolを実行した後に、入力と結果をlocal DBへ記録する。すでに
  実行されたtoolを取り消すものではない。
- `Stop`: 最終回答を返す前に、protected contentが残っていないか確認し、必要なら
  回答を作り直させる。

Explain that command Hooks run outside the Codex sandbox with the user's local
permissions. ToolUseProxy's Hook implementation writes to its local data
directory and does not make network requests, but the user must still verify
the source is `Plugin - tooluseproxy@tooluseproxy`, exactly three ToolUseProxy
Hooks are present, and every ToolUseProxy command points inside the expected
installed Plugin root. In an isolated manual Phase B harness, those three must
be the only pending Hooks. Outside that harness, if unrelated Hooks are also
pending, do not use `Trust all`; review the three ToolUseProxy entries
individually. Explain that trust applies to the exact definitions currently
shown and changed definitions require review again. If any ToolUseProxy source,
count, or path differs, tell the user not to trust and stop setup.

Before requesting permission to run any `run_cli.sh` or `run_cli.cmd` command,
explain the operation in plain language. The explanation must let a person
decide without parsing the installed Plugin path or the raw shell command.
Use these five labels:

- `目的`: what the operation accomplishes
- `読むもの`: which local configuration or source scope it reads
- `変更するもの`: which local files or database state it may write, or `なし`
- `外部通信`: `なし` unless the operation truly requires it
- `元に戻せるか`: how to reverse or review the change

Do not use implementation terms such as revision, manifest hash, Hook data
directory, or opaque token as the primary permission explanation. Those terms
may follow as technical detail. If a command combines multiple read-only
checks after one local initialization, say so explicitly.

Immediately before the permission prompt, add one final sentence explaining
that the long `sh ...` text Codex shows is the exact installed Plugin command,
not an additional operation. State whether the described action is safe to
approve, or what mismatch would make the user reject it. Do not ask the user
to infer the purpose from the command text. In Japanese, say:
`承認画面に出る長い sh ... は、説明済みの操作をinstalled Pluginから実行する
ための正確なpathです。追加の処理ではありません。`

1. Confirm that the current directory is the intended workspace root.
2. Confirm that the ToolUseProxy Plugin Hook definition has been reviewed and trusted in Codex. Do not bypass Hook trust.
3. If the workspace belongs to a manual Phase B harness and the prompt names a
   mode `0600` `phase-b-context.json`, read that exact file first. Use only its
   `workspace`, `plugin_root`, `plugin_data`, and `test_sink` paths. Do not use
   `ps`, inspect parent-process environments, or broadly search outside the
   workspace to rediscover those paths. If the context conflicts with the
   current workspace or a Hook diagnostic, stop and explain the mismatch.
   Otherwise, resolve the absolute Plugin root from this skill's location; it
   is two directories above `skills/tooluseproxy-setup`. On macOS/Linux, run
   every command through `sh "<PLUGIN_ROOT>/hooks/run_cli.sh"`. The general
   Windows launcher is `<PLUGIN_ROOT>\hooks\run_cli.cmd`, but the entire
   protected-source registration workflow is not supported on Windows yet.
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
7. After schema v2 and `registration_writable: true` are confirmed, explicitly run the bounded offline scanner:

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect scan --workspace <workspace-root> --data-dir <PLUGIN_DATA> --json
   ```

   The scanner is read-only for source files and the manifest, performs no network access, and uses fixed limits for traversal depth, entries, supported files, total bytes, and candidates. It excludes VCS, dependencies, virtual environments, build/cache directories, symlinks, and ToolUseProxy runtime data. It writes only a value-free candidate/review audit plus internal source hash/stat to the local runtime database and returns at most one review candidate in stable relative-path order. Show the relative path, reason codes, confidence, proposed source entry, and scan completeness. Never show or repeat source values, source hashes, absolute paths, or file previews. If `scan_complete` is false, explain the reached limit reasons and that unscanned scope remains; never report that no protected source exists.

   Before showing the exact JSON proposal, translate it into this five-line
   review card:

   - `守るファイル`: show only the workspace-relative path.
   - `守る範囲`: explain selectors as scope, not syntax. For `dotenv_keys`,
     say that only the values of the named settings are selected, not every
     value in the file. For `json_pointers`, identify the selected JSON fields
     without showing their values. If there is no selector, say that the file
     content is selected.
   - `止める場面`: explain in ordinary language that attempts to include the
     selected content in external sending or search can be stopped before the
     tool runs.
   - `承認すると変わるもの`: explain that one entry is added to
     `protected_sources.json`; the source file itself is not changed.
   - `承認しない場合`: explain that nothing is registered or changed. Briefly
     offer reject for a reviewed non-secret and ignore when the user does not
     want the same content proposed again by the current detector.

   After the card, copy the CLI result's proposed source object verbatim as the
   exact value-free JSON proposal. Do not reconstruct it from memory, rename
   keys, change singular/plural forms, change arrays or objects, add or remove
   fields, or normalize its contents. In particular, preserve `selector`
   exactly; never rewrite it as `selectors`. If the exact object is no longer
   available, stop and rerun the same bounded discovery command instead of
   presenting a reconstructed proposal. Follow the JSON with reason codes,
   confidence, and scan completeness as technical detail. First ask whether
   the user understands what content is selected and what approval changes.
   If the answer is no or uncertain, explain again and do not request approval.
   Ask for explicit approve, reject, or ignore only after the explanation is
   understood.
8. If the user or agent already knows one `.env`, `.env.*`, or JSON path, or needs to propose a file outside the bounded scanner's policy, use the explicit-path fallback:

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect suggest --path <workspace-relative-path> --workspace <workspace-root> --data-dir <PLUGIN_DATA> --json
   ```

   `suggest` has the same source/manifest read-only and value-free output/storage boundary as `scan`, but it evaluates only the requested path.
9. Wait for explicit user approval of that exact source proposal. Approval is not implied by setup, diagnosis, manifest migration, running a scan, a prior request to inspect the file, or permission to edit other project files. After approval, pass the unchanged opaque revision and manifest hash returned by `scan` or `suggest`:

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect approve <candidate-id> --candidate-revision <opaque-revision> --expected-manifest-sha256 <manifest-sha256> --workspace <workspace-root> --data-dir <PLUGIN_DATA> --json
   ```

   Approval holds the workspace lock from the candidate reservation through manifest I/O and DB finalize/release. The expected manifest hash is an optimistic precondition; the lock serializes cooperating ToolUseProxy writers but does not exclude a same-UID non-cooperating editor. Filesystem/DB serialization is therefore not guaranteed across either the final validation-to-replace window or the durability-revalidation-to-DB-finalize window. For an interruption or transient state failure, retry the exact same approve command and unchanged candidate ID, opaque revision, and manifest hash. Exact-entry recovery re-fsyncs the workspace directory and revalidates the source and manifest before finalizing. One approval changes the manifest hash, so never use another candidate's old scan revision/hash afterward. Run `protect scan` again, show the refreshed next proposal, and obtain a separate explicit approval. If an explicit-path approval reports that the source or manifest changed, run `suggest` again and present the new proposal. Do not weaken the comparison or retry with an edited proposal. Use `protect reject` or `protect ignore` to persist a user's negative decision.

   After a Plugin update, never reuse a pending candidate ID, opaque revision, or approval command created by an older protected-source detector. If approve, reject, or ignore returns `candidate_detector_stale`, treat it as a version boundary rather than a transient error: do not retry the cached command, run `protect scan`, present the current detector's new proposal, and obtain new explicit approval. Old reject/ignore decisions do not suppress a new detector version. Already-approved manifest entries remain registered. Only an exact retry for a candidate already in `approving` or `approved` may cross the version boundary to recover an interrupted durable approval.

   Run the whole `protect scan / suggest / approve / reject / ignore` workflow only on POSIX (macOS/Linux); it is not supported on Windows yet. Neither `init` nor a Hook runs the scanner implicitly.

10. Use `status` to verify the database, canonical workspace registration, schema v2 manifest, and protected sources all resolve to the same workspace. `status: active` means runtime health, not that a complete scan ran or that every sensitive file is registered.

11. If the user asks to uninstall, remove or disable the Plugin first so new Hook writes stop. Data retention is the default; Plugin or package removal never approves data deletion. If the user also asks to delete local data, run a non-mutating plan from an installed package or the exact release artifact being removed:

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" uninstall plan --data-dir <PLUGIN_DATA> --json
   ```

   Show the selected data directory, managed file count, managed byte count, unmanaged top-level entry count, and that all workspaces sharing the database will be affected. Never inspect or reveal stored payloads. Wait for explicit approval of that exact deletion plan. Then pass the unchanged opaque confirmation token:

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" uninstall apply --data-dir <PLUGIN_DATA> --confirmation-token <confirmation-token> --json
   ```

   Do not infer approval from a request to remove Plugin code, uninstall a Python package, clear a different cache, or approve a protected source. If managed data changes after review, `apply` rejects the stale token; create and present a new plan. The command deletes only the ToolUseProxy database / SQLite sidecars, migration backups, and manifest backups. It retains unknown entries, workspace manifests, protected source files, symlink targets, filesystem snapshots, and external backups. It does not provide secure erase.

The default onboarding boundary records tool activity and reviews final responses. PreToolUse blocking and MCP blocking remain explicit opt-ins; do not silently enable them.
