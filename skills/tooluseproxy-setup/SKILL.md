---
name: tooluseproxy-setup
description: Set up, diagnose, inspect, or explicitly uninstall the ToolUseProxy Codex Plugin for the current workspace. Use for ToolUseProxy init, doctor, status, plugin Hook trust, database-path, protected_sources.json onboarding, or managed-data removal tasks.
---

# ToolUseProxy setup

Use this workflow only when the user asks to set up, diagnose, or uninstall ToolUseProxy. Never add a protected source or delete local data without showing the exact value-free plan and receiving explicit user approval.

## User-facing language contract

Infer the user's intent from natural language. Never require or compare against
an exact phrase. The user must not need to know the skill name, CLI subcommands,
storage layout, or English decision words. The following are copyable examples,
not trigger strings:

- `ToolUseProxyをこのプロジェクトで使えるようにして`
- `守った方がよいファイルを探して`
- `ToolUseProxyが動いているか確認して`
- `ToolUseProxyをこのプロジェクトから外して`

Do not ask the user to restate a request using `setup skill`, `init`, `doctor`,
`status`, `scan`, `selector`, `approve`, `reject`, or `ignore`. Those are
implementation details for the agent. Accept clear paraphrases, different levels
of detail and politeness, and short follow-up requests whose intent is clear from
the conversation. Never ask the user to repeat one of the examples verbatim.

When setup starts, lead with:

`このプロジェクトでToolUseProxyを使えるようにします。初期設定と安全確認のため、通常は確認画面が2回出ます。どちらも外部通信は行いません。`

When setup succeeds, lead with:

`準備できました。このプロジェクトではToolUseProxyが動作しています。保護するファイルはまだ自動登録されていません。続けて、守るファイルを探すよう自然な言葉で依頼できます（例：「守った方がよいファイルを探して」）。`

When setup or verification fails, lead with:

`準備できませんでした。ToolUseProxyの保護機能はこのプロジェクトでは有効になっていません。ここで停止し、原因と安全なやり直し方を説明します。`

Technical status codes and raw JSON may follow under `技術情報`, but never use
them as the primary explanation and never require the user to interpret them.

ToolUseProxy cannot technically intercept hosted tools such as `WebSearch`
because Codex does not send them through `PreToolUse` or `PostToolUse`. A
`SessionStart` and `SubagentStart` Hooks supply a developer-context safety
boundary instead. Never
put registered protected content, or content derived from it, into a hosted
tool. Build hosted-tool queries only from public information. If protected and
public information cannot be separated confidently, do not call the hosted
tool; explain the limitation to the user. Do not describe this context rule as
pre-execution enforcement or complete DLP.

Never describe an installed/enabled Plugin or trusted Hooks as active
protection. Protection is active for the current workspace only after the
fixed setup application and read-only verification both pass. If the database
is missing, say plainly that the Plugin is installed but this workspace is not
protected yet. Do not present protected-source registration plans before that
gate passes.

If the request contains a version-specific skill link for an older Plugin
cache entry, do not treat the removed cache directory as a product failure and
do not search for replacement cache paths. Use this skill only when it is the
current active skill supplied by Codex, explain that a Plugin update requires a
new task, and never ask the user to copy an absolute skill path.

Before asking the user to trust ToolUseProxy Hooks, explain all five roles in
plain language:

- `SessionStart`: session開始時に、Hookで遮断できないhosted toolへprotected
  contentを渡さない安全境界をCodexへ伝える。これは技術的遮断ではない。
- `SubagentStart`: subagentにも同じhosted tool境界を伝える。これは技術的
  遮断ではない。
- `PreToolUse`: Hookから見えるローカルtoolを実行する前に、その入力を確認し、
  protected contentの外部送信を実行前に止める。
- `PostToolUse`: toolを実行した後に、入力と結果をlocal DBへ記録する。すでに
  実行されたtoolを取り消すものではない。
- `Stop`: 最終回答を返す前に、protected contentが残っていないか確認し、必要なら
  回答を作り直させる。

Explain that command Hooks run outside the Codex sandbox with the user's local
permissions. ToolUseProxy's Hook implementation writes to its local data
directory and does not make network requests, but the user must still verify
the Plugin source, exactly five ToolUseProxy Hooks, and every ToolUseProxy
command path. For a normal installation, the expected source is
`Plugin - tooluseproxy@tooluseproxy`. If a manual Phase B context declares
`expected_plugin_id`, use `Plugin - <expected_plugin_id>` instead; never replace
that context-specific ID with the normal installation ID. Every command must
point inside the expected installed Plugin root. In an isolated manual Phase B
harness, those five must be the only pending Hooks. Outside that harness, if
unrelated Hooks are also pending, do not use `Trust all`; review the three
ToolUseProxy entries individually. Explain that trust applies to the exact
definitions currently shown and changed definitions require review again. If
any ToolUseProxy source, count, or path differs, tell the user not to trust and
stop setup.

Before requesting permission to run any `run_cli.sh` or `run_cli.cmd` command,
explain the operation in plain language. The explanation must let a person
decide without parsing the installed Plugin path or the raw shell command, and
without remembering an earlier guide or explanation. Repeat a self-contained
permission summary immediately before every permission request. Build the
summary from the exact command arguments that will be submitted.

Assume the Codex approval surface renders plain text, exposes Markdown syntax
literally, and may collapse every newline. Therefore the summary must be one
short physical paragraph of at most 160 Unicode characters. Never use Markdown
headings, emphasis, bullets, tables, code spans, or fenced blocks in it. In
particular, do not emit `#`, `*`, backticks, or a leading `-`.

Use these plain-text delimiters in this exact order:

`ToolUseProxyの操作確認｜行うこと：...｜変更されるもの：...｜外部通信：...｜確認が必要な理由：...｜この内容で実行してよいですか？`

Keep every field in ordinary language. Use `ありません` for no state change
or no network. End with the direct question exactly as shown. Do not tell the
user to approve or reject, and do not describe an internal permission rule.

Do not list absolute paths in the summary. Name the workspace briefly and say
that the submitted arguments were checked against the approved context file.
The raw command remains available separately for technical review.

Pass exactly the same short paragraph as the tool call's approval
`justification`; do not put a second, longer explanation in the approval UI.
For common operations, follow these models and adapt only the project name or
whether state changes:

- fixed setup profile apply: `ToolUseProxyの操作確認｜行うこと：このプロジェクトの保護を有効にします｜変更されるもの：初期設定と、保護ファイルの外部送信を実行前に止める設定｜外部通信：ありません｜確認が必要な理由：プロジェクト外の専用保存領域へ設定を保存するためです｜この内容で実行してよいですか？`
- fixed setup profile verify: `ToolUseProxyの操作確認｜行うこと：設定が正しく有効か確認します｜変更されるもの：ありません｜外部通信：ありません｜確認が必要な理由：プロジェクト外の専用保存領域を読み取るためです｜この内容で実行してよいですか？`
- init: `ToolUseProxyの操作確認｜行うこと：このプロジェクトで利用を開始します｜変更されるもの：初期設定と記録用DB｜外部通信：ありません｜確認が必要な理由：プロジェクト外の専用保存領域を使うためです｜この内容で実行してよいですか？`
- doctor/status/config show: `ToolUseProxyの操作確認｜行うこと：このプロジェクトで正しく動くか確認します｜変更されるもの：ありません｜外部通信：ありません｜確認が必要な理由：専用保存領域の状態を読み取るためです｜この内容で実行してよいですか？`
- config set: `ToolUseProxyの操作確認｜行うこと：表示した保護設定を変更します｜変更されるもの：このプロジェクトの設定1件｜外部通信：ありません｜確認が必要な理由：専用保存領域へ設定を保存するためです｜この内容で実行してよいですか？`
- protected-source scan: `ToolUseProxyの操作確認｜行うこと：守った方がよいファイルを探します｜変更されるもの：候補を確認した記録だけ｜外部通信：ありません｜確認が必要な理由：プロジェクト外の専用保存領域へ確認結果を記録するためです｜この内容で実行してよいですか？`
- protected-source batch review: `ToolUseProxyの操作確認｜行うこと：表示した候補への選択をまとめて反映します｜変更されるもの：選んだ保護対象と見送った記録｜外部通信：ありません｜確認が必要な理由：専用保存領域へ選択結果を保存するためです｜この内容で実行してよいですか？`
- protected-source migration plan: `ToolUseProxyの操作確認｜行うこと：保護対象リストを安全に更新できるか確認します｜変更されるもの：ありません｜外部通信：ありません｜確認が必要な理由：プロジェクト外の専用保存領域を読み取るためです｜この内容で実行してよいですか？`
- protected-source migration apply: `ToolUseProxyの操作確認｜行うこと：保護対象リストを新しい形式へ更新します｜変更されるもの：リストの形式と専用保存領域のバックアップ｜外部通信：ありません｜確認が必要な理由：更新前の状態を安全に保存するためです｜この内容で実行してよいですか？`
- removal without data deletion: `ToolUseProxyの操作確認｜行うこと：このプロジェクトでの利用を止めます｜変更されるもの：Pluginの有効状態だけ｜外部通信：ありません｜確認が必要な理由：新しい記録を止めるためです｜この内容で実行してよいですか？`
- managed-data deletion: `ToolUseProxyの操作確認｜行うこと：表示したToolUseProxyデータを削除します｜変更されるもの：表示した管理対象データ｜外部通信：ありません｜確認が必要な理由：削除すると元に戻せないためです｜この内容で実行してよいですか？`

Do not use implementation terms such as revision, manifest hash, Hook data
directory, or opaque token as the primary permission explanation. Those terms
may follow as technical detail. If a command combines multiple read-only
checks after one local initialization, say so explicitly.

Never use memory-dependent references such as `説明済み`, `上記の操作`, or
`先ほどの説明` in the permission summary. Before submitting the tool call,
verify that the long `sh ...`
display uses the expected installed Plugin launcher, exact subcommand,
workspace, and data directory, and contains no unmentioned command. State that
verification in the summary. Tell the user to reject if the command differs from
the named operation or scope. The user must not need to understand the long
shell command to decide.

If a `run_cli.sh` or `run_cli.cmd` command must read or write `PLUGIN_DATA`
outside the current sandbox's writable roots, do not first try the command with
ordinary sandbox permissions. Request the host's explicit, one-command
out-of-sandbox approval for that exact command. On an `exec_command` interface
that exposes `sandbox_permissions`, set it to `require_escalated` and provide a
short plain-language justification consistent with the permission summary.
Do not treat Full Access as a prerequisite and do not use it merely to avoid a
per-command decision.

For a normal marketplace installation only, a surface may explicitly report
that per-command approval is disabled while its current filesystem permission
profile already grants access to the installed Plugin data directory. That is
not a permission failure and must not make the user copy an internal command
into a terminal. A clear request to enable ToolUseProxy or protect files
authorizes only the fixed normal setup profile needed for that request. Show the
same short, self-contained summary in conversation, then run the exact setup
command with the permissions already selected by the user. Run the read-only
verification next. Do not claim that an approval UI was shown; report its actual
count as zero. This is not permission escalation and does not authorize an
arbitrary profile, source approval, migration, uninstall, or data deletion.

If the current surface offers no per-command escalation and no explicit current
permission profile that grants the required path, stop before execution. Explain
the missing capability in ordinary language, but do not make copying a long
internal command the normal recovery path. Never retry an `Operation not permitted`
result with a broader command, different path, or silently enlarged permission.
Manual Phase B runs keep their context-specific per-command
escalation requirement and never use this normal-installation fallback.

If the command tool reports that the process is still running and returns a
continuation or cell ID, use only the host-provided wait/resume operation with
that exact ID until the original command completes. Waiting is not a second CLI
command and must not trigger a new approval. Do not rerun the CLI command, and
do not report missing initial output as a command failure.

1. Confirm that the current directory is the intended workspace root.
2. Confirm that the ToolUseProxy Plugin Hook definition has been reviewed and trusted in Codex. Do not bypass Hook trust.
3. If the workspace belongs to a manual Phase B harness and the prompt names a
   mode `0600` `phase-b-context.json`, read that exact file first. Use only its
   `workspace`, `plugin_root`, `plugin_data`, and `test_sink` as filesystem
   paths. Use `expected_plugin_id`, `expected_plugin_version`, `setup_skill`,
   and `surface` only as identity and workflow metadata. Do not use `ps`,
   inspect parent-process environments, or broadly search outside the workspace
   to rediscover those paths. If the context conflicts with the current
   workspace or a Hook diagnostic, stop and explain the mismatch.
   Otherwise, resolve the absolute Plugin root from this skill's location; it
   is two directories above `skills/tooluseproxy-setup`. On macOS/Linux, run
   every command through `sh "<PLUGIN_ROOT>/hooks/run_cli.sh"`. The general
   Windows launcher is `<PLUGIN_ROOT>\hooks\run_cli.cmd`, but the entire
   protected-source registration workflow is not supported on Windows yet.
   If the context declares `surface: codex_cli_tui`, report the result only for
   the Codex CLI TUI. Do not infer Codex Desktop/GUI support from that run.
4. Initialize the same writable directory used by the Hook:

   If an approved manual workflow supplies an exact `file-payload-exact`
   setup-profile command and expected revision, use that one command instead
   of separate `init` and three `config set` commands. The profile is fixed to
   `pre-tool-policy`, `file-payload-shadow`, and
   `file-payload-exact-enforcement` all enabled; it accepts no arbitrary
   settings object. It does not enable the experimental
   `externality-protection` setting or select a remote provider. Do not
   substitute another profile or revision.

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" setup apply file-payload-exact --codex --expected-revision <expected-revision> --workspace <workspace-root> --data-dir <PLUGIN_DATA> --json
   ```

   Follow it with the exact read-only combined verification when the workflow
   supplies it. This replaces separate `doctor`, `status`, and `config show`
   calls for that workflow:

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" setup verify file-payload-exact --workspace <workspace-root> --data-dir <PLUGIN_DATA> --json
   ```

   Stop before any send test unless the setup application and combined
   verification both succeed. The approval is required because these commands
   access Plugin data outside the task workspace, not because they use the
   network. Request each as a one-command approval and never request a reusable
   permission prefix.

   For a normal marketplace installation, do not depend on a Hook diagnostic
   and do not ask the user to paste `database_missing`, an absolute data path,
   or an initialization command. The installed launcher validates that its
   Plugin root is exactly inside the current Codex Plugin store, checks that the
   manifest name matches the installed Plugin identity, and then resolves the
   corresponding Codex Plugin data directory using Codex's Plugin-store
   contract. It fails closed if any identity or layout check differs.

   Apply the fixed profile with the explicit empty-settings precondition. This
   is safe for a new workspace, idempotent when the same profile is already
   applied, and refuses to overwrite a partial or different existing setup:

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" setup apply file-payload-exact --codex --expect-empty-settings --workspace <workspace-root> --json
   ```

   Then run the one read-only verification command:

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" setup verify file-payload-exact --workspace <workspace-root> --json
   ```

   These are the normal two approval screens. Never add `--data-dir` derived
   from a guessed path. If either command reports that the installed Plugin
   identity or data directory cannot be verified, lead with the setup-failure
   wording and stop. Do not fall back to asking the user for internal
   diagnostics.

5. For a manual context-bound Phase B workflow, run `doctor` and `status` with
   the exact context-supplied `--workspace` and `--data-dir` values when that
   workflow requires the individual commands. For a normal marketplace setup,
   the combined `setup verify` above is the health gate. Stop and explain every
   failing check before protected-source review or stronger policy tests. A
   legacy manifest may remain runtime-readable and active while reporting
   `registration_writable: false` and `migration_required: true`.
   In a manual Phase B run, if `init`, `doctor`, `status`, or `protect scan`
   returns an error or non-healthy status, stop that run immediately. Do not
   continue to any send test, do not attempt the protected call, and do not
   treat a later recovery as evidence for the failed run. Diagnose or prepare
   a fresh run separately.
   For steps 6 through 11 in a normal marketplace installation, continue to
   use the installed launcher without `--data-dir`; the same verified resolver
   selects the Plugin data directory. A manual context-bound workflow instead
   keeps using only its exact supplied `--data-dir` commands.
6. Treat the generated `protected_sources.json` as a user-owned manifest. Never edit it directly on the user's behalf. If `status` reports that schema is omitted or v1, create a value-free migration plan on POSIX:

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect migrate plan --workspace <workspace-root> --json
   ```

   Show the user the from/to schema, source count, whether a missing `sources` field will be added, formatting policy, private backup name, and preservation guarantees. Never show the manifest body, unknown-field values, source values, or previews. Explain that migration preserves existing entries, source order, existing key order, unknown fields, selectors, and protection semantics while changing the schema declaration and, only when `sources` is missing, adding the semantically equivalent empty list. It infers no selectors. It stores an exact-byte private backup under the data directory and normalizes the installed manifest to UTF-8, 2-space indentation, LF, and a trailing newline. Strict JSON does not support comments; do not strip comments or accept duplicate keys.

   Wait for explicit user approval of that exact migration plan. Setup approval, permission to edit another file, or a request to register a source does not approve migration. After approval, pass the unchanged revision and input manifest hash returned by the plan:

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect migrate apply --migration-revision <migration-revision> --expected-manifest-sha256 <manifest-sha256> --workspace <workspace-root> --json
   ```

   The apply command accepts no replacement JSON. If the manifest changed, run `protect migrate plan` again, present the new plan, and obtain new approval. For an interruption or durability-unknown result, retry the exact same apply command. The workspace lock serializes cooperating ToolUseProxy writers, but not a same-UID non-cooperating editor; filesystem updates are not guaranteed to be serialized across the final validation-to-replace or durability-revalidation-to-completion windows. Run migration only on POSIX (macOS/Linux); it is unsupported on Windows. Migration approval never approves a later protected-source proposal.
7. After schema v2 and `registration_writable: true` are confirmed, explicitly run the bounded offline scanner:

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect scan --workspace <workspace-root> --json
   ```

   The scanner is read-only for source files and the manifest, performs no network access, and uses fixed limits for traversal depth, entries, supported files, total bytes, and candidates. It excludes VCS, dependencies, virtual environments, build/cache directories, symlinks, and ToolUseProxy runtime data. It writes only a value-free candidate/review audit plus internal source hash/stat to the local runtime database and returns up to ten review candidates in stable relative-path order. Show the relative path, selected scope, reason codes, confidence, and scan completeness. Never show or repeat source values, source hashes, absolute paths, or file previews. If `scan_complete` is false, explain the reached limit reasons and that unscanned scope remains; never report that no protected source exists.

   Present every returned candidate in one numbered review list. Each item must
   include:

   - `ファイル`: show only the workspace-relative path.
   - `守る内容`: explain selectors as scope, not syntax. For `dotenv_keys`,
     say that only the values of the named settings are selected, not every
     value in the file. For `json_pointers`, identify the selected JSON fields
     without showing their values. If there is no selector, say that the file
     content is selected.
   - `できること`: say that ToolUseProxy can stop an attempt to send the
     selected content outside before the tool runs.
   - `「守る」を選ぶと`: say that the item is added to ToolUseProxy's protected
     list and the source file itself is not changed. Do not name the manifest.
   After the list, ask for all decisions in one reply. Explain that natural
   answers such as `全部守る` or `1と3は守る、2は見送る、4は今後表示しない`
   are accepted. Do not require an exact reply format. If only some items have
   an unambiguous decision, ask only about the undecided item numbers before
   changing anything.

   Map `守る` to approve, `今回は見送る` to reject, and
   `今後は候補に出さない` to ignore internally. Never require the user to
   reply with the English command words.

   Keep the exact value-free proposals and opaque revisions from the CLI result
   for the apply command, but do not make the user read raw JSON or internal
   candidate IDs. If the exact result is no longer available, stop and rerun
   the same bounded discovery command instead of reconstructing it. If the user
   says an item is unclear, explain its `守る内容` and what changes, then collect
   the remaining decisions in the same review batch.
8. If the user or agent already knows one `.env`, `.env.*`, or JSON path, use
   the selector-aware explicit-path fallback:

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect suggest --path <workspace-relative-path> --workspace <workspace-root> --json
   ```

   `suggest` has the same source/manifest read-only and value-free output/storage boundary as `scan`. Repeat `--path` to review up to ten known paths together.

   If the user explicitly asks to protect a complete UTF-8 text file such as a
   Markdown research plan, use the whole-file form instead. It remains bounded
   to one workspace-relative, non-symlink regular file of at most 1 MiB and
   does not add that format to automatic scanning:

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect suggest --path <workspace-relative-path> --whole-file --workspace <workspace-root> --json
   ```

   In the review card, say plainly that the entire file content is selected.
   Never preview or quote it. A directory-level request may be translated into
   a value-free list of relative file paths, but it is only a scope plan: it is
   not approval. Suggest the bounded path batch, show every relative path and
   scope together, and collect an explicit decision for every item.
9. Wait for explicit user decisions for the reviewed batch. Approval is not implied by setup, diagnosis, manifest migration, running a scan, a prior request to inspect a file, or permission to edit other project files. After every item has a clear decision, pass each unchanged candidate ID and opaque revision plus the shared manifest hash returned by `scan` or `suggest` in one command:

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect review --decision <candidate-id> <opaque-revision> <approve|reject|ignore> [--decision ...] --expected-manifest-sha256 <manifest-sha256> --workspace <workspace-root> --json
   ```

   Batch review holds the workspace lock while every candidate is checked and
   writes the manifest once for all approved items. A changed source, manifest,
   duplicate decision, unknown candidate, or stale detector stops the batch;
   never drop the failing item or weaken the comparison. For an interruption or
   durability-unknown result, retry the exact same review command. Run a fresh
   scan after a successful batch only when `remaining_candidate_count` was
   nonzero or the scan was incomplete. The single-candidate approve, reject,
   and ignore commands remain compatibility fallbacks, not the normal UX.

   After a Plugin update, never reuse a pending candidate ID, opaque revision, or approval command created by an older protected-source detector. If approve, reject, or ignore returns `candidate_detector_stale`, treat it as a version boundary rather than a transient error: do not retry the cached command, run `protect scan`, present the current detector's new proposal, and obtain new explicit approval. Old reject/ignore decisions do not suppress a new detector version. Already-approved manifest entries remain registered. Only an exact retry for a candidate already in `approving` or `approved` may cross the version boundary to recover an interrupted durable approval.

   Run the whole `protect scan / suggest / review / approve / reject / ignore` workflow only on POSIX (macOS/Linux); it is not supported on Windows yet. Neither `init` nor a Hook runs the scanner implicitly.

10. Use `status` to verify the database, canonical workspace registration, schema v2 manifest, and protected sources all resolve to the same workspace. `status: active` means runtime health, not that a complete scan ran or that every sensitive file is registered.

11. If the user asks to uninstall, remove or disable the Plugin first so new Hook writes stop. Data retention is the default; Plugin or package removal never approves data deletion. If the user also asks to delete local data, run a non-mutating plan from an installed package or the exact release artifact being removed:

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" uninstall plan --json
   ```

   Show the selected data directory, managed file count, managed byte count, unmanaged top-level entry count, and that all workspaces sharing the database will be affected. Never inspect or reveal stored payloads. Wait for explicit approval of that exact deletion plan. Then pass the unchanged opaque confirmation token:

   ```text
   sh "<PLUGIN_ROOT>/hooks/run_cli.sh" uninstall apply --confirmation-token <confirmation-token> --json
   ```

   Do not infer approval from a request to remove Plugin code, uninstall a Python package, clear a different cache, or approve a protected source. If managed data changes after review, `apply` rejects the stale token; create and present a new plan. The command deletes only the ToolUseProxy database / SQLite sidecars, migration backups, and manifest backups. It retains unknown entries, workspace manifests, protected source files, symlink targets, filesystem snapshots, and external backups. It does not provide secure erase.

The core defaults record tool activity and review final responses; PreToolUse
blocking is disabled until explicitly configured. The normal fixed
setup profile described above explicitly enables PreToolUse file-payload
blocking after the user approves the setup. Enabling PreToolUse also enables
MCP leak evaluation; do not describe ordinary MCP protection as requiring
another opt-in.
