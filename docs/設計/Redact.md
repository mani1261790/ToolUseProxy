# Redact設計

Redactは、protected source由来の情報を含むtool inputから、送信してはいけない部分を除いてからtoolを実行する介入です。目的はblockを減らすことではなく、外部へ渡る値を安全に縮小できる場合だけ、元の操作を限定的に継続できるようにすることです。

## 現在の結論

現行Codex CLI `0.142.5`では、redactをblockの安全な代替としてruntimeへ接続しません。MCPのtool固有profile、実行しないpreview planner、hash-only監査保存、PostToolUse input hashのdormantな照合までを先に実装しています。

主な理由は次の通りです。

- `updatedInput`はtool全体のinputを書き換える契約であり、任意のsubstringだけを安全に差し替える共通APIではない
- 同じcallに複数のcritical findingがある場合、最強の1件だけでなく全件を1つのplanへまとめなければ、一部だけredactして残りを送信する危険がある
- 複数のPreToolUse Hookがrewriteを返すと、現行Codexは最後に完了したrewriteだけを採用する
- rewrite後にPreToolUseは再実行されないため、別Hookが後から保護情報を戻しても実行前に再検査できない
- PostToolUseで実際のinputを照合できるのは副作用の後であり、Stop境界にはならない

従って、最初の到達点は`redact-preview`です。previewは「このcallなら、どのfieldをどう置き換えられるか」を監査可能なplanとして出しますが、Hook stdoutへ`updatedInput`を返さず、現在のcritical findingは引き続きblockします。

2026-07-15時点で、versioned exact profile registry、MCP sink coverage、pure preview planner、hash-only監査保存、dormantなPost confirmationまで実装済みです。valid profileはdata / controlの全present scalar pointerを個別sink化し、shape不一致とunprofiled write-like toolはarguments内の全scalar valueとJSON object keyへ保守的fallbackします。plannerはcurrent event / workspace / session / tool use / sequence、profile / registry version、全present sink coverageを閉じ、全critical findingをsource chunkとtarget pointerの直接参照で集約します。1件でも非対応ならpartial targetと候補本文を破棄し、全件でraw case-sensitive matchを確認できた場合だけdeep copy上のwhole-field候補、canonical input hash、structure hash、finding単位targetを返します。初期exact profileは実Codexで観測したlocal E2E `publish_text(content)`だけで、実schema未確認の外部serviceはpreview適格にしません。real MCP inputは32 KiB / 32 fields / depth 8のbounded preflightをartifact生成より前に受け、超過したexternal writeはdeny、read-only / unsinked callは保存せず空stdoutでbypassします。PreToolUseはcurrent callの全critical findingを検出した後だけplannerを呼び、findingが参照するworkspace-owned source chunk IDを32件以下で取得します。eligible / rejected planと全targetはimmutableな1 transactionで保存し、source取得、planner、保存の失敗時も先に生成したdenyを返します。Post confirmationは記録済みPost eventの後に独立したfail-soft境界で動き、将来rendererが作る`mode = enforce AND status = rendered`の単一planだけを照合します。現在のpreview planは一致しても状態遷移しません。runtime outputは従来のdeny / 空stdoutのままで、`updatedInput`は返しません。

## Codexの実契約

PreToolUseでrewriteを返す形式は次です。

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "updatedInput": {
      "...": "rewritten tool input"
    }
  }
}
```

ここでの`permissionDecision: allow`は、PermissionRequestの`behavior: allow`とは意味が異なります。PreToolUseでは`updatedInput`を有効にするために必須ですが、rewrite後のinvocationは通常のsandbox / approval判定へ進みます。通常承認を自動通過させるものではありません。

現行実装の制約は次の通りです。

- `updatedInput`なしの`permissionDecision: allow`はinvalid
- `permissionDecision: allow`なしの`updatedInput`もinvalid
- `permissionDecision: ask`は未サポート
- non-emptyな`permissionDecisionReason`を伴う有効なdenyがmatching Hookに1件でもあればcall全体をblockする
- deny reason欠落、invalid JSON、timeoutなどのinvalid / failed Hookは、そのHook単体ではblockせずfail-openする
- denyがない場合、複数rewriteのうち最後に完了した1件だけを採用する
- rewriteしたinputに対してPreToolUseを再実行しない

toolごとの`updatedInput`は次の形です。

| tool | updatedInput | Codex内部での扱い |
|---|---|---|
| Bash | `{ "command": "..." }` | 元のexec引数を維持し、command文字列だけを置換 |
| apply_patch | `{ "command": "*** Begin Patch..." }` | custom toolのpatch全文を置換 |
| MCP | raw arguments object全体 | MCP argumentsを全置換 |

部分objectをmergeする共通契約ではありません。特にMCPで一部fieldだけを返すと、返さなかったfieldも消えます。必ず元inputのdeep copyへ限定変更を加え、全objectを返す必要があります。

## 安全性の不変条件

runtime redactを将来有効にする場合も、次をすべて満たす必要があります。

1. 対象は現在のworkspace、session、tool useだけに限定する
2. current callにある全critical findingを集約し、1件でも非対応なら元のblockを維持する
3. tool名、送信先、操作種別、segment構造、control fieldを変更しない
4. tool固有profileでdata fieldとcontrol fieldを明示し、未知fieldを推測で書き換えない
5. 変更前inputを破壊せず、deep copyに対する差分が予定pointerだけであることを検証する
6. rewritten inputを同じtool profileで再parseし、構造と送信先が不変であることを確認する
7. protected sourceとの直接対応を確認できないtransitive / normalized-only lineageはredactせずblockする
8. plan作成、保存、renderのどこかが失敗したらallowへ落とさず、元のblockを返す
9. Hook stdout、stderr、policy説明、audit rowへraw protected textを出さない
10. network、embedding、workspace走査、全DB再解析を使わない

`select_strongest_decision()`だけでredactを決めてはいけません。block / warnの優先順位選択は最終actionの表示には使えますが、rewrite planはcurrent callの全findingを入力にする必要があります。

## tool別の推奨範囲

### MCP

最初のpreview対象として最も適しています。argumentsはJSON objectで、field境界をJSON Pointerとして監査できるためです。ただし、tool名のverb推定だけでは不十分です。

tool profileはexactな`server / tool`ごとに、少なくとも次を定義します。

```text
outbound_data_pointers:
  外部へ送られるdata fieldの全一覧

redactable_pointers:
  whole-field replacementを許可するsubset

control_pointers:
  channel、recipient、repository、URL、actionなど変更禁止field

allowed_shape:
  許可するkey、型、optional field、nesting

post_input_stable:
  Codex内部でserver送信前にargumentsが変換されないことを確認済みか
```

profileはplannerだけの設定にしません。profiled toolでは同じversionのprofileをMCP adapterのauthoritative sourceとし、`outbound_data_pointers`の全pointerを個別のartifact fragment / sinkへ変換します。plannerは、その全sinkに対してcurrent callのfinding coverageが閉じていることを確認してからtargetを作ります。pointerを解決できない、sinkを作れない、adapterとplannerのprofile versionが一致しない場合はpreviewをrejectします。

旧MCP adapterはmessage-likeなtop-level scalarを優先し、他fieldを見落とす問題がありました。現在はexact profileから全classified scalarをsink化し、profile不適格callも全scalar valueとJSON object keyへfallbackするため、既知fieldだけを書き換えてcallを通す前提にはなりません。plannerは`profile_status = matched`かつ全coverageが閉じたcallだけを候補にします。

初期profileの適格条件は次です。

- real MCP tool名が`mcp__<server>__<tool>`として確定している
- tool profileがexact matchする
- inputがprofileどおりのobjectで、未知keyや未知nestingがない
- targetはarray要素ではないscalar string field
- findingのsource textがtarget fieldにraw exact / raw substringとして直接存在する
- tainted fieldがすべて`redactable_pointers`に含まれる
- taintがcontrol field、未知field、root fallbackへ到達していない
- `post_input_stable: true`であり、Codex管理のOpenAI file inputを含まない

初期replacementは部分文字列ではなくfield全体を固定placeholderへ置き換えます。

```json
{
  "channel_id": "C123",
  "message": "[REDACTED BY TOOLUSEPROXY]"
}
```

これにより公開可能な周辺文も失われますが、normalized textからraw spanを逆算して一部secretを残す危険を避けられます。部分redactは、raw span provenanceを保存できるようになってから別段階で扱います。

lineage scoreや5-gram類似だけをrewrite位置に使いません。shingle-only、whitespace / case normalizationだけの一致、encoded value、hash-only resource lineage、protected fileからstdinへ流れる値は位置不明としてblockします。将来部分redactへ進む場合も、current outgoing leaf上のraw case-sensitive span、全findingのspan、overlapのdeterministic merge、rewrite後の再検索を必須にします。

profileとfixture、全scalar value / JSON key fallbackに加え、plannerも実装済みです。plannerはsink metadataのprofile / registry version、pointer、field classを直接使い、adapterと異なるfield推定を再実装しません。source本文はplanへ含めず、候補JSONもeligible resultの非表示fieldにだけ保持し、rejected resultには残しません。実service profileは実Hook payloadとtool schemaを確認した後に別commitで追加します。

Codexは一部MCP toolで、PreToolUse後かつserver送信前にOpenAI file argumentsを内部変換し、その変換後objectをPostToolUseの`tool_input`へ載せます。この場合、正当な内部変換でもfull-input hashは不一致になります。初期profileはこのtool / fieldを対象外とし、`post_input_stable: true`を確認できるtoolだけでfull-input hashを使います。将来対応する場合は、Codexが変更しないcontrol / redactable pointerだけのprojected hashを別schemaで導入し、`post_transformed`とcompeting Hookによる`post_override`を区別してから対象へ加えます。

### Bash

Bashは初期runtime対象にしません。`updatedInput`はcommand文字列全体であり、data、送信先、option、redirection、shell controlが同じ文字列に混在するためです。

将来の対象は、現在の静的parserが理解でき、data operandのraw spanを一意に示せるallowlistに限定します。

候補条件:

- newline、variable expansion、command substitution、heredoc、glob、commentがない
- segment数、connector、program名がrewrite前後で一致する
- external destination、URL、recipient、path、redirection、optionが不変
- rewrite対象がtool profileでdata operandと明示されたtokenだけ
- token全体を安全なshell quote済みplaceholderへ置換する

次は対象外です。

- `cat protected.txt | curl ...`のようにfile / pipeからdataが来るcall
- `curl @file`、stdin、header、URL query、environment variableへtaintがあるcall
- shell変数、subshell、heredoc、複数解釈があり得るcommand
- どのtokenがexternal payloadか確定できないcommand

これらは元のPreToolUse denyを維持します。完全なshell parserを導入するのではなく、静的に証明できるdata operand profileだけを増やします。

### apply_patch

自動runtime redactの対象にしません。

理由は次の通りです。

- patch全文のhidden rewriteは、code、設定、文書の意味をユーザーに見えない形で変える
- added lineだけを置換しても、構文、indent、テスト、patch contextの意味を壊す可能性がある
- apply_patchは通常local writeであり、現在のexternal sinkではない
- 後続の`git push`などはresource lineageから別のexternal sinkとしてPreToolUseで止められる

公開前に内容を除く必要がある場合は、モデルへ明示的な修正turnを要求し、新しいapply_patchとして観測します。将来local-public sinkを導入しても、hidden rewriteよりblock / continue_reviewを優先します。

代替案として、`.md` / `.txt`などの明示plaintextだけを対象に、added lineのraw exact spanを書き換えるpreviewは設計できます。その場合も、再parse後にoperation数、順序、kind、source / target / move path、context、removed lineが全て同一であることが必要です。これはpublic artifact sinkを定義した後の研究候補であり、現在のexternal sink対策より先には置きません。

## data model

planはpolicy decisionとは別のcall単位auditとして保存します。1つのcallに複数source / sink findingがあるため、1 decisionへ押し込めません。以下のschemaはpreview監査として実装済みです。

```sql
CREATE TABLE redaction_plans (
    plan_id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL,
    pre_event_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    tool_use_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    adapter TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    profile_registry_version TEXT NOT NULL,
    mode TEXT NOT NULL,              -- preview / enforce
    status TEXT NOT NULL,            -- eligible / rejected / rendered / post_confirmed / post_mismatch
    planner_version TEXT NOT NULL,
    original_input_sha256 TEXT,
    rewritten_input_sha256 TEXT,
    structure_sha256_before TEXT,
    structure_sha256_after TEXT,
    critical_finding_count INTEGER NOT NULL,
    replacement_count INTEGER NOT NULL,
    rejection_code TEXT,
    post_event_id TEXT,
    created_at TEXT NOT NULL,
    rendered_at TEXT,
    confirmed_at TEXT
);

CREATE TABLE redaction_targets (
    plan_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    finding_id TEXT NOT NULL,
    decision_id TEXT NOT NULL,
    source_node_kind TEXT NOT NULL,
    source_node_id TEXT NOT NULL,
    sink_node_id TEXT NOT NULL,
    json_pointer TEXT NOT NULL,
    original_value_sha256 TEXT NOT NULL,
    replacement_profile TEXT NOT NULL,
    PRIMARY KEY (plan_id, ordinal),
    FOREIGN KEY (plan_id) REFERENCES redaction_plans(plan_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_redaction_plans_event_version
    ON redaction_plans(
        workspace_id, pre_event_id, analysis_run_id,
        planner_version, profile_version, mode
    );

CREATE INDEX idx_redaction_plans_tool_use
    ON redaction_plans(
        workspace_id, session_id, tool_use_id,
        created_at DESC, plan_id
    );
```

exact profileがないreject planでは、`profile_id`に`unprofiled:<server>/<tool>`、`profile_version`にregistry versionを入れ、nullable keyによる重複を避けます。これは適格profileが存在することを意味せず、`rejection_code = 'unknown_profile'`と対で扱います。

input size、field count、depthなどcanonicalization前にrejectするcaseでは、bounded workを優先して`original_input_sha256`と`structure_sha256_before`を`NULL`にします。scope自体が不整合なcaseはpersist可能なplanを作らず、`invalid_call_scope`のdiagnostic resultだけを返します。これによりevent側workspaceと別analysis runを1 rowへ混ぜません。

`plan_id`とunique indexには`analysis_run_id`を含めます。同じanalysis run内の再保存は冪等ですが、同じeventを新しいruntime analysis runで再評価した場合は別planとして残します。finding / decision IDもanalysis runに依存するため、runを跨いで同じplan IDへ異なるtargetを上書きしません。

hash対象はtool inputのcanonical JSONです。Bash / apply_patchも`{"command": ...}`として同じ規則を使います。`structure_sha256`はJSON Pointerとvalue typeだけを並べたcanonical shapeのhashとし、value本文を含めません。hashは同一性確認であり、暗号化ではありません。

保存方針:

- raw original inputは既存event / artifactに既に保存されるため、plan tableへ複製しない
- rewritten input本文も既定では保存せず、hash、pointer、replacement profileだけを保存する
- 保存transaction内で所有event、完了済みanalysis run、current-call sink、critical lineage、bounded source evidenceを再構成し、deadline判定を除いたpure planner出力と完全一致しないplanを拒否する
- targetは同じcallのexternal sink metadataにある`data`かつ`redactable`なpointer、exact profile version、固定replacement profileと一致する場合だけ保存する
- Hook stdoutを返す将来段階では、全derived `redact` decisionとplan / targetを同一transactionで保存してからrenderする
- `mode = enforce AND status = rendered`のplanだけをPost confirmation候補にし、previewのeligible / rejected planは遷移させない
- enforce planの全immutable列とbounded target集合が、storageで再証明済みのeligible previewとexact cloneであることを要求する
- exact workspace / session / turn / tool use / tool名、所有Pre event、完了analysis runが一致する単一planだけを扱う
- exact scopeでPreより後に保存された最小`sequence_no`のPost eventだけを採用し、confirmation呼出順には依存しない
- 1 MiB以下の保存済みPost payloadを正としてevent IDを再検証し、現在registryの同一versionかつ`post_input_stable: true`、file inputなしのprofileで、boundedなactual input hashが一致した場合だけ`post_confirmed`にする
- boundedなactual inputをhash化でき、そのhashが不一致なら`post_mismatch`とし、別Hookのoverrideなどを疑う
- input超過、profile drift、file input、曖昧な複数planは未確認のままにし、不一致と推測しない
- Postがない場合は、approval拒否、別Hook deny、tool failureを区別できないため、自動的に`applied`とは記録しない

previewではtargetの`decision_id`に元のblock decisionを保存します。現行のdormant confirmation testがseedするsynthetic enforce planは、rendererの実装ではなくstate machineだけを隔離検証するため、decision IDを含むpreview targetのexact cloneです。actual enforceへ進む場合は、全critical findingについて`redact` decisionを個別に導出し、同じcall-level planへ結ぶ必要があります。その際はderived decision linkage用のschema / writer APIとconfirmation側の再証明を先に追加し、previewのblock decisionをそのままruntime適用根拠として使いません。このgateが未実装のままenforce rendererを接続しません。最強の1 decisionだけをplanの代表にして残りを捨てない原則は維持します。

statusの`rendered`はHookがstdout用JSONを作ったことだけを表し、Codexが採用したことを意味しません。採用を示せるのは、観測したPost inputが一致した`post_confirmed`だけです。`post_mismatch`はexact scopeで最小sequenceのPost eventを保持し、後続Postで上書きしません。同じPost eventの再処理は冪等です。`confirmed_at`は一致時だけ設定し、不一致の観測時刻は`post_event_id`が参照するeventの`recorded_at`を使います。

Post confirmationはaudit用10 ms busy timeoutの短いread transactionで候補を確認し、一致または不一致を確定した1 rowだけを同じsnapshotからcompare-and-setします。現行のno-plan経路ではPost event rowへ触れず、writer lockへもupgradeしません。targetやinput本文を更新せず、network、embedding、filesystem、workspace走査、全DB解析を行いません。失敗はPost event本体の保存をrollbackせず、exception typeだけをstderrへ出してHookを継続します。現行runtimeは`rendered` planを作らないため、この経路はproductionではno-opです。synthetic testだけが将来rendererの境界をseedし、状態遷移を検証します。

retentionはeventと同じscopeへ連動させます。planだけを長く残すとsource / sink関係を不要に保持するため、`scripts/cleanup_redaction_audits.py`は所有するPreToolUse eventのworkspace、任意session、recorded-at cutoffでplan / targetを選びます。既定はdry-runで、`--execute`を明示した場合だけ削除します。SQLiteのforeign key enforcementはリポジトリ全体で現在offのため、`ON DELETE CASCADE`に依存せず、同じtransactionでtargetを先に明示削除してからplanを削除します。現行DBは暗号化されず、raw Hook payloadやartifactにplaintextが残り得ます。redactは外部送信を減らす機能であり、monitor DBのplaintext保存問題を解決する機能ではありません。

## plannerの処理順序

```text
current PreToolUse event
  -> workspace / session差分解析
  -> profileの全outbound pointerをfragment / sink化
  -> current callの全external finding
  -> tool profileで全targetを分類
  -> 1件でも非対応ならblock維持 + rejected preview
  -> 全件対応ならdeep copyへwhole-field replacement
  -> structural diff / destination不変 / profile再parse
  -> planとhashを保存
  -> preview段階ではblock維持
  -> 将来enforce段階だけupdatedInputをrender
```

plannerは既存の`session-incremental`結果を入力にし、全DBやworkspace全体を再解析しません。入力findingは`select_strongest_decision()`後の1件ではなく、`detect_leaks()`がcurrent callへ返した全critical findingのbounded tupleをそのまま渡します。source chunkはそのfindingが直接参照するIDだけを、workspace ownershipを確認して32件以下で取得します。size preflightと本文取得は同じread transaction snapshotで行い、plannerへ返すrowも`chunk_id / workspace_id / text / text_hash`だけに限定します。current eventとsink metadataはworkspace / session / sequence / tool useで絞ります。

新規audit insertでは、同じtransaction内で完了済みrunのcurrent-call critical assignmentを`idx_lineage_assignments_run_sink_score`から最大33 rowだけ確認します。33件目があればaudit保存を中止し、既存denyを維持します。32件以下ならsource evidenceを同じ32 KiB / finding、128 KiB / callで取得してpure plannerを決定論的に再実行し、plan metadataと全targetを完全比較します。このため、無関係sourceへの差し替え、case-insensitive lineageだけをraw matchと偽る変更、全critical findingの一部だけを保存する変更、有限集合外の`rejection_code`は受理しません。plannerの50 ms deadlineでrejectしたcaseと32件を超えるcaseは決定論的なhash-only auditとして再証明できないため保存せず、block outputだけを返します。

## failure fallback

redactはcritical external sinkに対するblockを置き換える候補です。そのため、redact固有の失敗をHook全体の一般的なfail-openへ伝播させてはいけません。

実装した境界は次です。

```text
runtime analysis自体が失敗
  -> 現行どおりHook boundaryのfail-open

analysis後、critical blockを得た後にsource取得またはredaction plannerが失敗
  -> 元のblock outputを返す

planは作れたが保存またはvalidationに失敗
  -> 元のblock outputを返す

Post確認がない、またはhash mismatch
  -> appliedとは記録しない
  -> 次callのallow条件には使わない
```

redact plannerを`try/except`の外へ投げて空stdoutにすると、blockすべきcallを通すため危険です。block outputを先に保持し、redactが完全に成功した場合だけ差し替える構造にします。

実装ではredaction audit schemaのdriftを初期化時に検出し、schemaを推測修復せずauditだけを無効化します。bounded source lookupとplan writeはaudit専用connectionの`busy_timeout` 10 msでfail-fastします。schema unavailable、SQLite lock、source read、plan validation / writeの例外はすべてpreview境界内で破棄し、すでにrender済みのdenyを返します。

## 複数Hook問題とenforcement gate

現行Codexの「last completed rewrite wins」では、ToolUseProxyがredactした後に別Hookが別inputを返せます。ToolUseProxy自身からはmatching rewriterの総数も、最終採用inputも実行前に確認できません。

このため、次のどちらかが満たされるまでruntime enforceへ進みません。

1. Codex側がrewriteのcomposition、priority、final-input再検査、またはstableなexclusive handler契約を提供する
2. ToolUseProxyを唯一のPreToolUse rewriterと保証できる配備境界を、設定検証を含めて別途確立する

環境変数で「唯一のrewriterだと仮定する」と宣言するだけでは、安全性の証明にはなりません。研究用のopt-in E2Eには使えても、本番のStop保証とは分けて扱います。

## Hook latency budget

redact plannerはlocal JSON、indexed DB row、hash、tool profileだけを使います。

初期defaultでは、次をplanner entryで強制します。このうちinput / fields / depthは現在のPreToolUse早期preflightと同じ定義で、compact canonical JSONのUTF-8 bytes、root以外のdict memberとarray elementの合計、root objectを0とした深さです。超過時はpreviewを`rejected`、将来enforceでは元のdenyとします。

| 対象 | 上限 |
|---|---:|
| canonical input | 32 KiB |
| MCP tool name / audit identifier | 4 KiB |
| fields | 32 |
| nesting depth | 8 |
| critical findings | 32 |
| distinct targets | 16 |
| source bytes / finding | 32 KiB |
| total source bytes / call | 128 KiB |
| sink metadata / row | 64 KiB |
| sink replay bytes / call | 512 KiB |
| stored Post payload for confirmation | 1 MiB |

現行source chunkingにはbyte上限がないため、inputだけでなくfindingから参照するsourceにもcapが必要です。plannerは`source_node -> target pointer`を直接参照し、全sourceと全fieldの直積比較を行いません。hard deadlineはcooperative checkであり、入力capの代用にはしません。上限値は初期benchmark envelopeに合わせた暫定値で、境界caseを実測して安全側に調整します。

推奨budget:

- pure planner p95 `<= 10 ms`、32 fields / 32 KiB input
- redaction追加overhead p95 `<= 25 ms`
- planner hard deadline `50 ms`
- PreToolUse全体p95 `< 300 ms`
- network call、embedding、workspace scan、全DB graph loadは0回

2026-07-15のpure planner実測では、fixture構築を除外し、200 warmup後に各2,000回をinterleaveした結果、単一targetはp95 0.0729 ms、32 fields / 32 KiB / 16 targetの最大eligible caseはp95 2.9471 ms、同じ最大caseの16件目でraw mismatchになるrejectはp95 2.6957 msでした。unit testでも3 caseをinterleaveして各p95 10 ms以下とする回帰gate、defaultの32 finding / 16 target境界、50 ms exact deadlineとlate crossing、oversize inputがcanonical hashより前にrejectされることを固定しています。

同日の最終local SQLite監査計測では、fixture構築とcleanupを除外した2,000 / 1,000 / 300 sampleのrunで、bounded source lookup p95 0.673 ms、同一planのexact replay p95 0.866 ms、完了runからcritical findingとsource evidenceを再構成する新規plan / target insert p95 3.767 msでした。write lockの10 ms fail-fastは単発計測で15.177 msであり、lock caseもpreview境界内でdenyへ戻るため、audit待ちでcore blockを解除しません。

同日の最終Post confirmation実測では、fixture構築とPost event保存を除外し、productionと同じrendered planなしのread-only経路2,000 sampleがp95 0.718 ms、同一terminal Post replay 1,000 sampleがp95 0.964 ms、synthetic rendered planの新規state transition 120 sampleがp95 2.964 msでした。10 MiBのPost responseを持つno-plan経路もplan-first lookupにより120 sampleでp95 0.649 msとなり、payload rowへ触れずsmall fixtureと同等でした。writer lock中もno-plan readは継続し、transitionだけが10 ms busy timeout内でfail-fastして`rendered`を維持します。

一方、synthetic rendered planが存在する10 MiB Post payloadのoversize未確認経路は20 sampleでp95 8.01 msでした。1 MiB capにより本文をPythonへmaterializeする前に止めますが、SQLiteの`length(payload_json)`がoverflow pageを読むコストはpayload量に比例します。現行productionはrendered planがないためこの経路へ入りません。actual enforce前に`payload_bytes`をevent record時の固定metadataとして保存するなどO(1) preflightへ変更し、enforcement latency gateを再計測します。

benchmarkはeligible、rejected、複数targetの3caseを同じroundで測り、no-redactのPreToolUseとの差をpaired sampleで計算します。Post confirmationは別HookなのでPre budgetへ混ぜません。

## 実装・commit単位

次の順序を推奨します。

1. `Define MCP outbound field profiles`（実装済み）
   - exact server/tool profile
   - outbound / redactable / control pointer
   - 同じprofileから全outbound pointerをadapterのfragment / sinkへ変換
   - unknown shapeのreject
   - server固有fixture
2. `Add redaction preview planner`（実装済み）
   - call内全finding集約
   - whole-field replacement plan
   - structural validation
   - runtime outputは引き続きblock
3. `Persist redaction preview audits`（実装済み）
   - plan / target schema
   - hash-only保存
   - workspace / session scope
   - current-call全critical findingの後にpreviewを接続し、eligible / rejectedを原子的に保存
   - event-scopeの既定dry-run cleanup
4. `Confirm rewritten inputs from PostToolUse`（実装済み）
   - future enforce用のdormantなhash照合とstate transition
   - preview中はsynthetic rendered fixtureだけでstate transitionを検証
   - mismatch / missingをapplied扱いしない
5. enforcement gateを再評価
   - 複数rewriter問題を解消する
   - derived redact decision linkageのschema / atomic writer / confirmation再証明を追加する
   - Post payload byte数をrecord時metadata化し、candidate confirmationのsize preflightをO(1)にする
   - すべてを満たした場合だけ、独立opt-inでMCP runtime rewriteを追加
6. `Prototype static Bash data-operand redaction`
   - MCPの安全性と監査を検証した後
   - apply_patch automatic redactは対象外のまま維持

各項目を別commitにし、preview plannerとruntime enforcementを同じcommitへ混ぜません。最初の4項目を実装しても、gateを満たすまではHook stdoutへ`updatedInput`を返しません。

## tests

### planner unit test

pure plannerは32 testsで、以下のhappy path、all-or-nothing、実MCP adapter metadata、profile coverage、scope、source evidence、cap、determinism、latencyを検証済みです。DB保存とHook runtimeの監査接続は別の作業単位で実装し、runtime rewriteと混ぜていません。

- exact profileの単一string fieldをwhole-field replacementできる
- 元inputをmutateせず、予定pointer以外のdiffがない
- 複数source / 複数fieldを1 planで全て置換する
- 1件でも非対応targetがあればplan全体をrejectする
- unknown tool、unknown key、root fallback、array、non-string、control fieldをrejectする
- synthetic multi-field profileの全outbound pointerをsink化し、public messageとprotected attachmentの同居を見落とさない
- adapter / plannerのprofile version不一致、未解決pointerをrejectする
- Codex管理file inputがあるtool、`post_input_stable`でないtoolをrejectする
- raw direct matchがなくtransitive lineageだけの場合はrejectする
- rewritten inputのtool名、destination、control fieldが同一である
- raw protected textがplan、reason、stderrへ入らない
- A/B workspace、同じsession / pathでもtargetを混ぜない
- preview結果がglobal / full DB APIを呼ばない
- input、field、depth、finding、target、source byteの各cap境界と超過を検証する
- sourceとfieldの直積比較を行わず、cap境界でもlatency budgetを満たす

### storage / integration test（実装済み）

- planと全targetをtransactionで保存する
- plaintext inputをplan tableへ複製しない
- canonical input hashが安定する
- 同じanalysis runの再保存でplan IDとtargetが冪等になり、新しいanalysis runでは別plan IDになる
- findingが参照するworkspace-owned source chunkだけを32 ID以下で取得する
- source取得、planner、保存の失敗で元のdenyを維持する
- cleanupはevent scopeの既定dry-runで、execute時はtargetから先に明示削除する

### Post confirmation test（実装済み）

- preview eligibleは候補hashと一致しても遷移しない
- syntheticなfuture rendered planだけを、一致時は`post_confirmed`、不一致時は`post_mismatch`にする
- Codex管理file input、profile / registry drift、input byte超過をfull-input override判定しない
- exact turnを含むowner scope不一致と複数候補を更新しない
- confirmation呼出順が逆でも最小sequenceのPostだけを採用する
- 同一Post replayは冪等、後続Postで終端状態を上書きしない
- caller側event objectを変更しても保存済みPost payloadだけを正とする
- 1 MiB超のPost payloadは未確認にし、actual enforce前のO(1) size metadata gateを残す
- enforce target欠落やverified previewとの不一致を拒否する
- confirmation失敗でも記録済みPost eventを残し、stdoutと機密本文を出さない
- Postなしをapplied扱いしない

### 将来runtime test

- `permissionDecision: allow`とfull `updatedInput`を対で返す
- public inputではrewriteせず、通常policyへ戻る
- unsupported critical inputはdenyし、MCP server副作用とPostToolUseが0件になる
- 複数critical fieldを全てredactし、1件だけ残して送信しない
- rewrite後も通常のCodex approvalが維持される
- competing rewriterがいるE2Eでlast-completed overrideを再現し、安全gate未達として検出する

## 実Codex E2E計画

ローカルstdio MCP serverに、受信argumentsをhashと固定markerだけで記録する`publish_text`を用意します。実secretではなくダミーprotected valueを使います。

1. eligible preview
   - exact profileの`content` fieldにダミーprotected value
   - planはeligible、pointerとhashを保存
   - runtimeはまだdenyし、server call 0、Post 0
2. aggregate reject
   - redactable fieldとunknown fieldの両方にprotected value
   - plan全体をrejectし、server call 0
   - synthetic multi-field fixtureでpublic messageとprotected attachmentを同居させ、attachment findingを作ってserver call 0
3. public call
   - planなし、既存のallow経路でserver call 1
4. 将来enforce E2E
   - gateを満たした隔離設定だけで実施
   - serverがplaceholderを受信し、original markerを受信しない
   - Post input hashとplan hashが一致する
5. competing rewriter
   - 2つのPreToolUse Hookが異なるrewriteを返す
   - completion orderで結果が変わることを確認し、production-ready判定には使わない

### 2026-07-15 実行結果

commit `81a519c`、Codex CLI `0.142.5`、`gpt-5.5`で、hash-onlyのローカルstdio MCP serverと別々のpublic / protected DBを使って1と3を再検証しました。runtime rewriteとsyntheticな`rendered` planは有効化していません。

- public callはPreToolUse 1件、PostToolUse 1件、server call 1件で、canonical arguments hashも期待値と一致した
- public DBのredaction planとpolicy decisionはともに0件で、Post confirmationはplan-first no-opだった
- protected callはPreToolUse 1件、PostToolUse 0件、server call 0件だった
- protected DBには`block / critical / external_api_call` 1件と`preview / eligible` plan 1件を保存し、`post_event_id`は`NULL`のままだった
- `rendered`、`post_confirmed`、`post_mismatch`は0件で、preview planを誤って終端状態へ進めなかった
- protected inputの期待hashはpublic側のhash-only監査に存在せず、protected側はserver call 0で監査file自体が作られなかった。Codex JSONLとfinal answerにもダミー本文は残らなかった

これにより、現行production経路ではpublic callを壊さず、protected callは従来どおり副作用前にblockし、dormant confirmationがpreview stateへ干渉しないことを確認しました。Post hash一致による`post_confirmed`遷移はfuture rendered planだけの境界なので、引き続きsynthetic integration testの検証対象です。

実験後も、original protected valueをterminal、Hook reason、server logの本文として出力しません。検証は固定marker、件数、hash、fileの有無で行います。

## 再評価条件

runtime redactへ進む前に、次を明示的に確認します。

- MCP tool profileが外部へ渡る全data fieldを列挙できる
- call内全findingをaggregateできる
- preview auditとPost hash照合が安定する
- pure planner / Hook latency budgetを満たす
- 複数PreToolUse rewriterによるoverrideを防ぐ配備契約がある
- block fallbackを維持したまま、実Codex E2Eでoriginal dataの副作用0を確認できる

このgateを満たさない限り、`redact`はpolicy modelとpreview planに留め、critical external sinkは既存のPreToolUse denyで止めます。
