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

自動runnerはHook definitionのtrustや、Codexがdenyを受けて実tool invocationを0件にしたことを代行しません。manual Phase Bはrepository外の専用directoryへisolated `CODEX_HOME`、synthetic workspace、絶対pathでだけ呼ぶlocal fake `curl`を準備します。一時directoryはOSに削除される場合があるため、人が数日に分けて実行するときは本人だけが読める永続directoryを使います。

```bash
python3.11 scripts/manual_plugin_phase_b.py prepare \
  --root /absolute/path/outside/repository/tooluseproxy-phase-b
```

既存directoryとrepository内pathは上書き事故やcommit混入を避けるため拒否します。prepareはclean Plugin ZIPをbuildしてisolated marketplaceへinstallし、artifact SHA-256、Plugin / Codex version、通常login、device-code login、logout、task launcher、値を含まないpromptをJSONで返します。このprepare出力にはlocal absolute pathがあるため公開artifactへ貼りません。生成するlauncherに`--dangerously-bypass-hook-trust`はなく、Hook trustは必ずCodex UI上で人が確認します。

通常のbrowser loginがlocalhost callbackやcookieで失敗した場合は、prepare出力の`device_login_command`を使います。認証URLやdevice codeはIssueやchatへ貼りません。

task launcherは起動直前にprepare時のCodex versionとfake sinkのpath、mode、SHA-256を再確認します。Codexが更新された場合やfake sinkが変わった場合はtaskを起動せず、fresh prepareを要求します。preflight通過後は人向けのHook review guideをterminalへ全文表示し、`yes`が入力されるまでCodexを起動しません。この`yes`はHook trustの代行ではなく、続くCodex画面で何を確認するかを読んだというcheckpointです。

prepareは同じrootへmode `0600`の`phase-b-prompt.txt`、`phase-b-guide.md`、`phase-b-context.json`を作ります。contextにはworkspace、installed Plugin、Plugin data、fake sinkのlocal pathだけを置き、source値を含めません。setup skillはこのcontextを使い、`ps`やworkspace外の広い検索でpathを推測しません。このpromptを新しいCodex taskへ渡し、次を人間が確認します。

1. guideでPreToolUse / PostToolUse / Stopの役割、sandbox外実行、local data、networkなし、想定source / 件数 / command rootを理解する
2. Codexが表示する3件のHook definitionをreviewし、guideと一致する場合だけtrustする
3. 長いPlugin commandの前に、目的、読むもの、変更するもの、外部通信、取消方法が平易に説明される
4. synthetic workspaceで`init`、`doctor`、`status`を実行する
5. `protect scan`候補について、exact JSONより先に「守るファイル」「守る範囲」「止める場面」「承認すると変わるもの」「承認しない場合」の説明を読む
6. その説明を理解した場合だけexact proposalを明示approveする
7. public fixtureを絶対pathのfake sinkへ送り、false blockがなくmarkerが作られることを確認する
8. synthetic protected fixtureを静的なliteralとして同じfake sinkへ送るtool callを依頼し、deny時のmarkerが0であることを確認する

Phase B harnessはPATH上の`curl`を信用しません。promptに記録された絶対pathのfake sinkだけを使い、fake sinkはnetworkへ接続せず、呼び出された事実だけをmarkerへ書きます。public callはmarkerを作り、protected callはPreToolUse denyによりmarkerを作らないことが期待結果です。system curl、別pathのcurl、変更されたfake sinkを使ったrunはmarkerの有無にかかわらず不合格です。

protected fixtureはHookが実行前に観測できる静的なtool inputで試します。`$TOKEN`、`source .env`、command substitution、stdin、`@file`はシェル実行後に値が決まるため、このPhase B caseへ混ぜません。これらは保護済みと誤認せず、dynamic shell valueの既知の未対応境界として別に評価します。実行後、ユーザー自身の確認結果を明示してverifierを実行します。

```bash
python3.11 scripts/manual_plugin_phase_b.py verify \
  --root /absolute/path/outside/repository/tooluseproxy-phase-b \
  --hook-trust-reviewed yes \
  --hook-review-understood yes \
  --proposal-explanation-clear yes \
  --command-approval-explanation-clear yes \
  --manual-registration-attempts 0 \
  --additional-question-count 0
```

verifierは次をCodex session JSONL、SQLite、manifest、fake sink hash、markerから相互確認します。

- bounded scanまたはexplicit suggestionのcandidateと明示decision
- `protected_sources.json`へのexact source登録
- prepare時と実sessionのCodex version、workspace
- public / protected tool callが同じ絶対pathのfake sinkを使ったこと
- 実Codex task由来のpublic / protected `PreToolUse`
- public callだけに対応する`PostToolUse`とlocal marker
- protected callの`block` decision、`PostToolUse`不在、side-effect marker 0
- session call IDとHook DBのtool use ID
- assistant messageへsynthetic値が出ていないこと
- proposal作成から明示decisionまでの時間

verify出力はroot path、source hash、candidate ID、tool input、raw canaryを含まないaggregate-only JSONです。`status: passed`の出力だけをIssueへ記録できます。`needs_followup`では`failed_checks`を直し、同じrunを成功扱いにしません。manual結果には実secretやSQLiteを使わず、synthetic case ID、version、artifact SHA-256、所要時間、判定、failure codeだけを記録します。

説明UXのdogfoodでは、JSONやsource値を保存せず、次の集約値だけを記録します。

- sourceを手作業でJSON登録しようとした回数
- `scan`と明示path `suggest`の利用回数
- Hook reviewを理解できたか
- proposal説明を理解できたか
- command実行許可の説明を、raw shell commandを解析せず理解できたか
- agent説明後にapprove / reject / ignoreを選んだ件数
- proposalを理解するために追加質問が必要だった件数
- 最初のproposal提示から明示判断までの時間

自動Phase Aの件数をmanual Phase Bの実利用値へ合算しません。Hook trust、実tool side effect、agent説明の理解度は人間が確認し、Phase B verifierが実Hook DBとmarkerを照合したrunだけを実利用として扱います。

このharnessが対象にするのは#18の初回onboardingと実Bash遮断です。final answer / MCP、update後のapproved source保持とstale proposal、remove / data保持 / uninstallは自動Phase Aと[Pluginライフサイクル](Pluginライフサイクル.md)で機械検証済みですが、人が参加するpre-release全体のPhase B evidenceとしては別途反復します。初回onboardingの合格だけでそれらもmanual確認済みとは扱いません。

2026-07-24のPhase B v2 human runでは、candidate approve、public allow、protected PreToolUse block、protected side effect 0、session / Hook DB / markerの相互照合はすべて成功しました。一方、人間評価はHook review理解`no`、proposal説明理解`no`、command説明`yes`だが長い`sh ...`表示は人によって分かりにくい可能性あり、追加質問0回でした。したがってrun全体は`needs_followup`です。機能成功を説明UX成功へ読み替えません。

verify結果を保存した後は、prepare出力の`logout_command`でisolated `CODEX_HOME`からlogoutします。失敗調査中はrootを保持できますが、調査完了後は認証cacheとraw local sessionを含むため、必要なaggregate evidenceを残してrootを明示的に削除します。削除はverifierが自動で行いません。

immutable alpha.1と現在release候補のupgrade / rollback / disable / removeは[Pluginライフサイクル](Pluginライフサイクル.md)の独立runnerで検証します。
