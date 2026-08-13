# Pluginドッグフード

公開Plugin marketplace artifactから、public alphaのlifecycleをsynthetic dataだけで反復する手順です。CodexのHook trustはユーザーがdefinitionをreviewして行うmanual gateであり、このrunnerは承認を自動化・迂回しません。

## 実projectでのself-dogfood

自分の別projectで試す場合も、最初から日常利用へ全面適用しません。公開済みartifactの利用と、まだreleaseへ昇格していない最新mainの評価を区別します。

| 目的 | install元 | 境界 |
| --- | --- | --- |
| 公開済みalphaを再現する | `public-alpha`またはimmutable tag | 公開済みreleaseだけ。release後にmainへ入った変更は含まない |
| 次release候補を自分で先行評価する | cleanなlocal checkoutまたはそこからbuildしたPlugin bundle | development build。version表示だけで公開artifactと同一視しない |

開始前に次を確認します。

1. 対象projectのbackupまたはcleanなGit状態を確認する
2. 顧客data、production credential、signing keyを含まない低risk workspaceを最初に選ぶ
3. `codex plugin list --json`と`codex plugin marketplace list --json`で既存installを確認する
4. ToolUseProxy Pluginが複数有効なら停止し、どの一つを使うか決める
5. 既存Plugin dataは削除せず保持する。削除は別の`uninstall plan`と明示承認に分ける
6. install元のcommit、Plugin version、Codex version、OS、対象workspaceの識別名だけをlocal記録へ残す

公開版を使うcommandは[Five-minute quickstart](../../QUICKSTART.md)を正本にします。最新mainを先行評価するときは、remote `main`を直接trustせず、まずcheckoutを`origin/main`の確認済みcommitへ固定してcleanであることを確認し、そのlocal absolute pathをmarketplaceとして登録します。

```bash
codex plugin marketplace add /absolute/path/to/ToolUseProxy
codex plugin add tooluseproxy@tooluseproxy
```

同名marketplaceがすでにある場合に上書きや混在を推測実行しません。既存installのremove、marketplace remove、新しいinstallをそれぞれ確認し、Plugin codeのremoveとmanaged dataの削除を分離します。install後はPreToolUse / PostToolUse / Stopの定義をreviewし、3件とも意図したsourceとhashである場合だけtrustして、新しいtaskを開始します。

最初のtaskではbundled setup skillだけを使います。最新buildでは、workspace外のPlugin dataへ初期化と3保護設定を一つのatomic profileとして適用し、その後に一つのread-only verificationを行います。承認理由は「外部通信」ではなく「workspace外のPlugin data操作」であり、通常の承認UIは2回程度です。広い再利用可能permission prefixは許可しません。

日常作業へ進む前に、低riskなsynthetic dataで次を順番に確認します。

- setup applyとread-only verificationが成功する
- harmlessなpublic operationが1回実行される
- synthetic protected valueを含む対応済みfile-backed operationが実行前にblockされる
- protected side effectが0である
- assistant出力へprotected valueが現れない
- 通常作業で予期しないblockがない

次のいずれかがあれば、そのprojectでの利用を停止します。

- setup / verification / doctor / statusの失敗
- Hookが`modified`、`untrusted`、想定外sourceになる
- ToolUseProxy Pluginの二重稼働
- public operationのfalse block
- protected operationのside effect発生
- raw protected valueの画面、report、Issueへの露出
- 未知schema、DB error、設定revision不一致

停止時は失敗した操作を繰り返さず、Pluginをdisableまたはremoveします。Plugin codeをremoveしてもlocal dataは保持されます。managed dataを削除する場合だけ、後からvalue-freeな`uninstall plan`を確認し、exact confirmationを別途承認します。

結果は`.github/ISSUE_TEMPLATE/dogfood-report.md`の項目で記録します。公開Issueへ貼れるのはversion、OS、判定、件数、value-freeなfailure code、分かりやすさの評価だけです。project名、absolute path、source値、raw Hook payload、`events.db`、task transcript、tokenは貼りません。security-sensitiveな結果は公開Issueではなく[SECURITY.md](../../SECURITY.md)の非公開窓口を使います。

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

現在のharnessが起動・検証するsurfaceは`codex_cli_tui`です。公式Codex資料ではDesktopとCLIが同じconfig layerを使い、local Plugin workflowを両方で利用できることまでは確認できますが、ToolUseProxyのHook review表示、command承認表示、PreToolUse blockのDesktop上の同等性はこのharnessでは証明していません。verify出力にもsurfaceを含め、TUIの合格をDesktop / GUIの合格へ読み替えません。

| surface | Plugin利用の公式案内 | ToolUseProxy Phase B |
| --- | --- | --- |
| Codex CLI TUI | あり | 機能動作を確認済み。説明UXは再検証待ち |
| Codex Desktop / GUI | あり | macOS実機でHook review、承認2回のatomic setup / read-only verify、public allow、protected block、raw exposure 0を確認済み |

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
3. 長いPlugin commandの承認ごとに、160文字以内の同じplain textが事前説明と承認理由の両方へ表示され、`行うこと：` `変更されるもの：` `外部通信：` `確認が必要な理由：`の順で説明した後に`この内容で実行してよいですか？`と尋ねている。absolute pathやMarkdownは承認理由へ含めない
4. synthetic workspaceで`init`、`doctor`、`status`を実行する
5. 候補について、exact JSONより先に「このファイルをToolUseProxyで守りますか？」と表示され、「ファイル」「守る内容」「できること」「守るを選ぶと」の説明と「守る」「今回は見送る」「今後は候補に出さない」の選択肢を読む
6. その説明を理解した場合だけexact proposalを明示approveする
7. public fixtureを絶対pathのfake sinkへ送り、false blockがなくmarkerが作られることを確認する
8. synthetic protected fixtureを静的なliteralとして同じfake sinkへ送るtool callを依頼し、deny時のmarkerが0であることを確認する

Phase B harnessはPATH上の`curl`を信用しません。promptに記録された絶対pathのfake sinkだけを使い、fake sinkはnetworkへ接続せず、呼び出された事実だけをmarkerへ書きます。public callはmarkerを作り、protected callはPreToolUse denyによりmarkerを作らないことが期待結果です。system curl、別pathのcurl、変更されたfake sinkを使ったrunはmarkerの有無にかかわらず不合格です。

protected fixtureはHookが実行前に観測できる静的なtool inputで試します。`$TOKEN`、`source .env`、command substitution、stdin、`@file`はシェル実行後に値が決まるため、このPhase B caseへ混ぜません。これらは保護済みと誤認せず、dynamic shell valueの既知の未対応境界として別に評価します。実行後、ユーザー自身の確認結果を明示してverifierを実行します。

`init`、`doctor`、`status`、`protect scan`のどれかが失敗または非正常statusを返したrunでは、public / protected callへ進みません。後からDBが自然復旧しても、そのrunを成功証拠へ変更しません。原因調査またはfresh prepareを別に行います。

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

2026-07-24のPhase B v2 human runでは、candidate approve、public allow、protected PreToolUse block、protected side effect 0、session / Hook DB / markerの相互照合はすべて成功しました。一方、最初のUX評価はHook review理解`no`、proposal説明理解`no`でした。起動前guideとcandidate review cardを追加した次のrunではcandidate説明は理解でき、同じ機能動作も成功しましたが、command承認は「起動前guideを覚えている」前提が残っていました。長い`sh ...`を理解せず、その承認直前の説明だけで判断することはできなかったため、command説明は`no`です。どちらのrunも`needs_followup`であり、機能成功を説明UX成功へ読み替えません。

現在のrunでは、各command承認の直前にexact command argumentsから作った自己完結型の説明を表示します。「説明済み」「上記の操作」「先ほどの説明」のような過去参照は禁止し、行うこと、変更されるもの、外部通信、確認が必要な理由を示したうえで「この内容で実行してよいですか？」と尋ねます。ToolUseProxy側から許可や拒否を指示しません。このTUI再検証とは別に、Desktop / GUI専用のPhase B caseを用意します。

その後のhuman runでは7項目は出ましたが、`- ラベル: 長い文章`が連続し、承認時に読みづらいという評価でした。また`doctor`の一時的な`OperationalError`後もagentがscanと送信テストへ進み、protected callは遮断されませんでした。DBはrun終了後にSQLite `quick_check`とdoctorが正常へ戻り、恒久破損ではありませんでしたが、このrunは明確に不合格です。次の改修では縦型Markdown cardを採用しましたが、TUIの承認導線ではMarkdown記号がそのまま見え、改行も判断に利用できないことがhuman runで判明しました。このためMarkdown cardを廃止し、改行がすべて消えても読める全角ラベル区切りの短いplain textへ変更します。異常時に送信テストへ進まず停止する契約は維持します。

## File-backed payload shadow Phase B

Issue #45のshadow modeは、onboarding用Phase Bと分離して評価します。onboarding harnessは静的literalのdenyを確認するため、意図的に`@file`を禁止しています。file-backed shadow caseでは逆に、synthetic protected/public fileを絶対pathのlocal fake `curl`へ渡し、現在policyは両方をallowしたまま、shadowだけが`would_block` / `would_allow`を1件ずつ記録することを確認します。

```bash
python3.11 scripts/manual_sink_payload_shadow.py prepare \
  --surface codex_cli_tui \
  --root /absolute/path/outside/repository/tooluseproxy-file-shadow
```

prepareは既存Phase Bのclean Plugin build、isolated marketplace / `CODEX_HOME`、Hook trust preflightを再利用します。workspaceはsynthetic `.env.phase-b`の選択keyを事前登録し、public fileとprotected file、networkへ接続しないfake sinkを作ります。policyは環境変数をlauncherへ渡さず、`PLUGIN_DATA/events.db`へ次のworkspace設定として保存します。

```text
pre-tool-policy=on
file-payload-shadow=on
```

macOSではlauncherがpreflight後にsynthetic promptを`pbcopy`へ渡します。起動後はHook 3件をreviewし、clipboardのpromptを新しいtaskへ貼り付けます。prompt本文やsource値をterminal commandとして組み立て直す必要はありません。

taskではpayload fileを読まず、fake sinkへ`--data-binary @shadow-public.txt`と`--data-binary @.env.phase-b`を1回ずつ送ります。shadowはobserve-onlyなので両方にPostToolUseとlocal side effectが必要です。protected callをblockしたrun、system curlを使ったrun、source値をassistant messageへ含めたrunは不合格です。

```bash
python3.11 scripts/manual_sink_payload_shadow.py verify \
  --root /absolute/path/outside/repository/tooluseproxy-file-shadow
```

verifierはTUI session、exact fake sink command、Pre / Post identity、二つのmarker、shadow observationを相互確認します。合格時は`allow->would_allow`と`allow->would_block`が各1件、resolution / comparisonは各2件evaluated、policy blockは0です。出力はidentityや値を含まず、status / match / decision diff / payload size bucket / latencyの集約だけです。

exact-only enforcementのhuman Phase Bは、同じharnessへmodeを指定し、shadowとは別の隔離rootに準備します。

```bash
python3.11 scripts/manual_sink_payload_shadow.py prepare \
  --mode exact-enforcement \
  --surface codex_cli_tui \
  --root /absolute/path/outside/repository/tooluseproxy-file-exact
```

このmodeでは`file-payload-exact-enforcement=on`もworkspace設定へ保存し、shadow観測を併用して同じ一回のfile snapshot比較を検証材料にします。public callだけがmarkerとPostToolUseを作り、protected callはexact evidenceによるpolicy block 1件を作って、markerもPostToolUseも作らないことが合格条件です。実行後は同じ`verify --root ...`を使います。これによりTUI表示だけを成功根拠にせず、session、Hook DB、shadow observation、local side effectを相互照合します。

2026-07-27のfresh TUI human runは`status: passed`でした。public / protectedのfile-backed callはshadow modeのため両方実行され、`allow->would_allow`と`allow->would_block`が各1件、resolution / comparisonは各2件evaluated、policy blockは0件でした。TUI session、exact command、Pre / Post identity、二つのside effect、tool output、shadow observationはすべて一致し、assistant出力とshadow tableへのraw protected value露出は0件でした。観測latencyはp50 `0.705 ms`、p95 / max `0.746 ms`です。この結果はTUIのopt-in shadow観測を合格とするものであり、実行前block、Desktop / GUI、TOCTOU解消を証明しません。

同日のfresh TUI exact-enforcement human runも`status: passed`でした。public callは実行されside effectとPostToolUseを各1件残し、protected callは`resolved_payload_exact_substring`によりPreToolUseでblockされ、side effectとPostToolUseは0件でした。resolution / comparisonは各2件evaluated、exact policy blockは1件、assistant出力とshadow tableへのraw protected value露出は0件です。観測latencyはp50 `0.765 ms`、p95 / max `0.874 ms`でした。この結果はTUIの明示opt-in exact-only enforcementを合格とするものであり、既定有効化、Desktop / GUI、semantic match、unsupported payload、TOCTOU解消を証明しません。

Codex Desktop / GUIは同じ成功へ読み替えません。Desktop自体はlocal Plugin workflowの対象ですが、現在のharnessが要求するisolated `CODEX_HOME`注入とは別問題です。次のpreflightは共有`CODEX_HOME`を変更せず、isolated Plugin / Hook dataとshadow opt-inをDesktop Hookへ渡すlauncherが存在するかだけを判定します。

```bash
python3.11 scripts/manual_sink_payload_shadow.py desktop-preflight
```

2026-07-27時点のlocal環境では、isolated `CODEX_HOME`とopt-in環境変数の両方がDesktop Hookへ届くことを証明できるlauncherが見つからないため、`unsupported: isolated_desktop_hook_environment_unavailable`です。これは「DesktopでPluginを使えない」という意味ではなく、「CLI用の隔離harnessをそのままDesktopへ流用できない」という意味です。

workspace単位のruntime設定とTUI harnessへの接続に加え、Desktop専用Phase B harnessも実装済みです。macOS Desktop実機でPlugin source / version、3 Hookのreview、doctor / status、public allow、protected exact block、marker / DB / session照合、disable / remove / 同一版reinstall、異versionmigration、backup rollback、Disableなしの直接Removeを確認しました。2026-08-09のfresh setup profile runは承認2回、public 1、protected 0、exact block 1、raw exposure 0で正式な`passed`です。実行手順、aggregate evidence、共有環境の復元条件は[Codex Desktop Phase B](DesktopPhaseB.md)を正本にします。

verify結果を保存した後は、prepare出力の`logout_command`でisolated `CODEX_HOME`からlogoutします。失敗調査中はrootを保持できますが、調査完了後は認証cacheとraw local sessionを含むため、必要なaggregate evidenceを残してrootを明示的に削除します。削除はverifierが自動で行いません。

immutable alpha.1と現在release候補のupgrade / rollback / disable / removeは[Pluginライフサイクル](Pluginライフサイクル.md)の独立runnerで検証します。
