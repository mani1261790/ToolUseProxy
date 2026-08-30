# Externality Judge

## Status

Externality Judgeは、adapterで外部性を確定できないHook-visibleなlocal function callについて、外部通信の可能性を値非保持で評価するための実験境界です。現在は初見unknownの保守的な実行前保護、Hook外classification queue、人間review、承認済みlocal rule cacheまで実装しています。remote modelもworkerも既定では動きません。

## 解決する問題

現行のBash / MCP adapterは、`curl`、`git push`、既知のpublish command、登録済みMCP profileなどをexternal sinkとして扱います。さらに、Hookへ届く未知のfunction toolはprotected flowが入力へ到達した場合に保守的なexternal sinkとして扱います。ただしこの方式でも、hosted tool、`write_stdin`による継続入力、Hookを省略する特殊経路は実行前に捕捉できません。

Externality Judgeは次の順で判定材料を作ります。

1. shell構造を実行せずに解析する
2. workspace内のbounded scriptをローカルで解析する
3. 公開済みの固定カテゴリだけをvalue-free envelopeへ入れる
4. static判定で不明な場合だけ、値非保持envelopeをlocal queueへ積む
5. 同じ初見callへprotected lineageが到達していれば、分類を待たず実行前denyする
6. Hook外workerが、明示設定されたjudge providerへ問い合わせる
7. 人間がrevision付きの分類を確認し、承認した完全一致ruleだけをlocal cacheへ入れる

Externality Judgeはprotected sourceとの一致やlineageを判定しません。外部通信可能性とprotected flowは別の判断として維持します。

## Value-free envelope

envelopeに含められる値はclosed enumとbounded countだけです。

- tool family
- 解析coverage
- executable category
- HTTP、socket、DNS、child processなどのcapability
- dynamic code、未知のexecutable、workspace外参照などのrisk signal
- segment、pipeline、redirection、file read、script fileの個数

次の値は含めません。

- raw command、argument、source code
- protected source、user prompt、transcript
- URL、host、DNS label
- credential、環境変数値
- workspace path、file name、独自identifier

unknown identifierをremote modelへ説明するために本文や名前を追加しません。情報不足なら`unknown`として扱います。

## Judge output

judge outputは自由記述を持たないstrict schemaです。

- verdict: `external` / `possibly_external` / `local` / `unknown`
- confidence: `high` / `medium` / `low`
- reason codes: 固定enumを1〜4件

response refusal、timeout、HTTP error、JSON不正、schema不一致はprovider failureです。将来Hookへ接続する場合は、これらをallowへ変換してはいけません。

## Provider boundary

LLM judgeは`CodexExecJudge`だけです。ToolUseProxyはOpenAI API endpointを直接呼ばず、API keyを受け取りません。workerは各jobについて独立した`codex exec --ephemeral`を起動します。`--ignore-user-config`、`--ignore-rules`、read-only sandbox、output schemaを使い、Hook、Plugin、shell、browser、computer use、MCPにつながる機能を明示的に無効化します。実CLI versionでlocal caseとrisk caseを通すcapability probeに合格するまで、judgeとして利用できません。

Codex probeの合格結果は、Codex実行ファイルのSHA-256、canonical pathのSHA-256、version、judge contract、modelへ結び付けたmode `0600`のreceiptとしてPlugin dataへ保存します。いずれかが変わった場合、または合格から24時間を超えた場合はstaleとしてproviderを呼びません。実行時はreceiptと一致したcanonical executable pathを使います。

routeは`off`または`codex`だけです。fallback、`auto`、別providerはありません。Codexが利用不能、timeout、receipt不一致、schema不一致の場合、jobは値非保持failureとなり、local ruleやallowへ変換されません。

## Hookとbackground workerの分離

workspace runtime setting `externality-protection`を明示的に有効化した場合だけ、PreToolUseでlocal判定を行います。このsettingは既存の`file-payload-exact` setup profileには含めません。

Hook内では外部通信もLLM実行も行いません。既存adapter、bounded static analysis、承認済み完全一致cacheだけを参照します。adapterとstatic analysisの両方がunknownで、承認済みruleもない場合は、closed enumとbounded countだけのenvelopeをSQLiteへ重複排除して保存し、そのcallを保守的なexternal sink候補として現在の情報流graphへ追加します。protected lineageが到達した場合だけ実行前denyし、public callやprotected flowのないunknown callは分類待ちでも実行を妨げません。

Hook外workerは次の環境設定で明示されたproviderだけを使います。

- `TOOLUSEPROXY_EXTERNALITY_JUDGE_PROVIDER`
- `TOOLUSEPROXY_EXTERNALITY_JUDGE_CODEX_MODEL`
- `TOOLUSEPROXY_EXTERNALITY_JUDGE_CODEX_RECEIPT`
- `TOOLUSEPROXY_EXTERNALITY_JUDGE_TIMEOUT_SECONDS`

provider chain全体のtimeoutは既定7秒、上限8秒です。正本とする2026-08-12のcapability probeは、Codex CLI 0.145.0、固定value-free envelope 2件、probe contract `codex-externality-probe-v2`を使い、local `5,208 ms` / `local`、risk `4,511 ms` / `possibly_external`、reason code 0でeligibleでした。この待ち時間はHookに入りません。時間切れやprovider failureはfailed jobになり、local判定やallow ruleへ変換しません。

queueとreviewに保存するのはenvelope、envelope hash、model hash、closed verdict、value-free failure codeだけです。raw command、source、URL、host、path、source identity、model名、API keyを保存しません。tableとimmutable triggerはHook外の明示的な`init` / setupで準備し、production HookはDDLやmigrationを行いません。

LLM分類は`review_pending`になるだけで、自動ではruleになりません。初見unknownに対する保守的sinkはreview前から有効です。人間が表示された構造要約、closed verdict、provider、model hashを確認し、exact revisionを指定して承認した`external` / `possibly_external` ruleは、同じworkspace、envelope hash、judge contractにだけ一致します。承認済み`local` ruleは、その完全一致構造に対する保守的unknown sinkだけを外します。既存adapter、static external判定、別構造のblockは解除しません。`unknown`は承認できません。

static解析、queue、cache準備が失敗した場合も、値非保持のfailure sinkを現在callへ追加し、protected lineageが到達すればdenyします。初期化後にruntime DBや情報流解析を利用できないPreToolUseも実行前denyします。未初期化DBだけはsetup用advisoryです。Hook非配送のhosted toolやTOCTOUなどPlugin外の境界が残るため、「偽陰性ゼロの数学的保証」とは表現しません。

```bash
# 明示したproviderで、待機中の値非保持jobを最大10件分類する
tooluseproxy externality process --data-dir "$PLUGIN_DATA" --limit 10 --json

# 人間が確認する。raw commandやprotected valueは表示されない
tooluseproxy externality review-list --data-dir "$PLUGIN_DATA" --json

# 表示されたjob IDとrevisionを完全一致で承認する
tooluseproxy externality approve JOB_ID \
  --expected-revision REVISION --data-dir "$PLUGIN_DATA" --json
```

## 現在の非目標

- LLM verdictの自動承認
- approved local ruleによる既存blockの解除
- remote judgeによる既存blockの解除
- localhost承認UI
- Codex network proxyとのdynamic permission連携
- protected sourceやraw sourceをremote modelへ送るoptional mode
- daemonやschedulerの自動install

## Gate

次の条件を満たすまでproduction policyへ接続しません。

- mandatory security corpusのfalse-localが0
- provider failureからallowが生成されない
- remote requestのprotected / raw canary exposureが0
- Codex probeでtool activityと予期しないfile writeが0
- 既存adapterのexternal判定をdowngradeしない
- ruff、pytest、`git diff --check`が通る

Codex probeは次で実行できます。入力はrepositoryやprotected sourceを読まず、固定のvalue-free envelopeだけです。

```bash
PYTHONPATH=. python3 scripts/probe_externality_judge.py
```

Plugin dataへreceiptを作る場合は次の形で実行します。これはproviderを自動有効化しません。

```bash
PYTHONPATH=. python3 scripts/probe_externality_judge.py \
  --write-receipt "$PLUGIN_DATA/externality-codex-probe.json"
```

旧shadow評価のaggregate reportは次で確認できます。production Hookのbackground queueとは別の評価用surfaceです。

```bash
PYTHONPATH=. python3 scripts/report_externality_shadow.py --db /path/to/events.db
```
