# Pluginドッグフード

clean Plugin marketplace artifactから、public alphaのlifecycleをsynthetic dataだけで反復する手順です。CodexのHook trustはユーザーがdefinitionをreviewして行うmanual gateであり、このrunnerは承認を自動化・迂回しません。

## 自動Phase A

Codex CLIを使うisolated lifecycleを実行します。

```bash
python3.11 scripts/dogfood_plugin.py --installation-mode codex
```

runnerは一時directoryとisolated `CODEX_HOME`を使い、次を順番に検証します。

1. clean Plugin ZIPをbuildし、SHA-256を計算
2. marketplace addとPlugin install
3. `init` / `status`
4. `protect suggest`のexact proposalを1件rejectし、別の1件をignore
5. 提案後に内容を変更したsourceのapproveが`source_changed`で拒否されることを確認
6. synthetic `.env`を`protect scan`し、保存されたexact proposalをapprove
7. 再scanでreject / ignoreが抑止され、approved sourceが再提示されないことを確認
8. public Bash / MCPがallowされることを確認
9. protected Bash / MCPがPreToolUseでdenyされることを確認
10. protected final answerがStopで`continue_review`になることを確認
11. decision traceを`--no-preview`で取得
12. Pluginとmarketplaceをremove
13. Plugin codeの残留0とlocal SQLite data保持を確認
14. 配布artifactの`uninstall plan`をreviewし、exact confirmation tokenによる管理data削除を確認

外部commandやMCP callそのものは実行せず、Hook payloadだけをinstalled launcherへ渡すため、外部side effectは0です。出力はsynthetic protected valueを含まないschema v2 JSON summaryだけで、artifact SHA-256、Plugin version、各check、最初のblockまでの時間に加え、`bounded_scan` / `explicit_suggestion`のproposal件数、approve / reject / ignore件数、stale proposal拒否件数を返します。これはworkflow coverageであり、人間が説明を理解・承認したという利用実績ではありません。

Codex CLIなしでartifact runtimeだけを検証するときは次を使います。

```bash
python3.11 scripts/dogfood_plugin.py --installation-mode extracted
```

## manual Phase B

自動runnerはHook definitionのtrustや、Codexがdenyを受けて実tool invocationを0件にしたことを代行しません。manual Phase Bはrepository外の専用directoryへisolated `CODEX_HOME`、synthetic workspace、local fake `curl`を準備します。

```bash
python3.11 scripts/manual_plugin_phase_b.py prepare \
  --root /absolute/path/outside/repository/tooluseproxy-phase-b
```

既存directoryとrepository内pathは上書き事故やcommit混入を避けるため拒否します。prepareはclean Plugin ZIPをbuildしてisolated marketplaceへinstallし、artifact SHA-256、Plugin / Codex version、login command、task launcher、値を含まないpromptをJSONで返します。このprepare出力にはlocal absolute pathがあるため公開artifactへ貼りません。生成するlauncherに`--dangerously-bypass-hook-trust`はなく、Hook trustは必ずCodex UI上で人が確認します。

必要なら出力されたlogin commandでisolated `CODEX_HOME`へloginし、task launcherを実行します。prepareは同じrootへmode `0600`の`phase-b-prompt.txt`も作り、launcher起動時にそのpathを案内します。このpromptを新しいCodex taskへ渡し、次を人間が確認します。

1. Codexが表示するHook definitionとartifact version / SHA-256をreviewしてtrustする
2. synthetic workspaceで`init`、`doctor`、`status`を実行する
3. `protect scan`のvalue-freeなexact proposal説明を読み、明示approveする
4. public fixtureをBashへ送り、false blockがなくfake sink markerが作られることを確認する
5. synthetic protected fixtureの送信を依頼し、deny時のfake sink markerが0であることを確認する

Phase B harnessのworkspaceでは、PATH先頭のfake `curl`がnetworkへ接続せず、呼び出された事実だけをmarkerへ書きます。public callはmarkerを作り、protected callはPreToolUse denyによりmarkerを作らないことが期待結果です。実行後、ユーザー自身の確認結果を明示してverifierを実行します。

```bash
python3.11 scripts/manual_plugin_phase_b.py verify \
  --root /absolute/path/outside/repository/tooluseproxy-phase-b \
  --hook-trust-reviewed yes \
  --agent-explanation-clear yes \
  --manual-registration-attempts 0 \
  --additional-question-count 0
```

verifierは次をSQLite、manifest、markerから相互確認します。

- bounded scanまたはexplicit suggestionのcandidateと明示decision
- `protected_sources.json`へのexact source登録
- 実Codex task由来のpublic / protected `PreToolUse`
- public callだけに対応する`PostToolUse`とlocal marker
- protected callの`block` decision、`PostToolUse`不在、side-effect marker 0
- proposal作成から明示decisionまでの時間

verify出力はroot path、source hash、candidate ID、tool input、raw canaryを含まないaggregate-only JSONです。`status: passed`の出力だけをIssueへ記録できます。`needs_followup`では`failed_checks`を直し、同じrunを成功扱いにしません。manual結果には実secretやSQLiteを使わず、synthetic case ID、version、artifact SHA-256、所要時間、判定、failure codeだけを記録します。

説明UXのdogfoodでは、JSONやsource値を保存せず、次の集約値だけを記録します。

- sourceを手作業でJSON登録しようとした回数
- `scan`と明示path `suggest`の利用回数
- agent説明後にapprove / reject / ignoreを選んだ件数
- proposalを理解するために追加質問が必要だった件数
- 最初のproposal提示から明示判断までの時間

自動Phase Aの件数をmanual Phase Bの実利用値へ合算しません。Hook trust、実tool side effect、agent説明の理解度は人間が確認し、Phase B verifierが実Hook DBとmarkerを照合したrunだけを実利用として扱います。

このharnessが対象にするのは#18の初回onboardingと実Bash遮断です。final answer / MCP、update後のapproved source保持とstale proposal、remove / data保持 / uninstallは自動Phase Aと[Pluginライフサイクル](Pluginライフサイクル.md)で機械検証済みですが、人が参加するpre-release全体のPhase B evidenceとしては別途反復します。初回onboardingの合格だけでそれらもmanual確認済みとは扱いません。

immutable alpha.1と現在release候補のupgrade / rollback / disable / removeは[Pluginライフサイクル](Pluginライフサイクル.md)の独立runnerで検証します。
