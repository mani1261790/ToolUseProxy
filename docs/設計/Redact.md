# Redact設計

Redactは、protected source由来の情報を含むtool inputから、送信してはいけない部分を除いてからtoolを実行する介入です。目的はblockを減らすことではなく、外部へ渡る値を安全に縮小できる場合だけ、元の操作を限定的に継続できるようにすることです。

## 現在の結論

現行Codex CLI `0.142.5`では、redactをblockの安全な代替としてruntimeへ接続しません。まずMCPのtool固有profileと、実行しないpreview planner、監査schemaを作る順序を推奨します。

主な理由は次の通りです。

- `updatedInput`はtool全体のinputを書き換える契約であり、任意のsubstringだけを安全に差し替える共通APIではない
- 同じcallに複数のcritical findingがある場合、最強の1件だけでなく全件を1つのplanへまとめなければ、一部だけredactして残りを送信する危険がある
- 複数のPreToolUse Hookがrewriteを返すと、現行Codexは最後に完了したrewriteだけを採用する
- rewrite後にPreToolUseは再実行されないため、別Hookが後から保護情報を戻しても実行前に再検査できない
- PostToolUseで実際のinputを照合できるのは副作用の後であり、Stop境界にはならない

従って、最初の到達点は`redact-preview`です。previewは「このcallなら、どのfieldをどう置き換えられるか」を監査可能なplanとして出しますが、Hook stdoutへ`updatedInput`を返さず、現在のcritical findingは引き続きblockします。

2026-07-15時点で、最初の基盤であるversioned exact profile registryとMCP sink coverageは実装済みです。valid profileはdata / controlの全present scalar pointerを個別sink化し、shape不一致とunprofiled write-like toolはarguments内の全scalar valueとJSON object keyへ保守的fallbackします。key nameのlineageはraw exact一致だけに限定し、同値fieldはpointer別fragmentとして残します。初期exact profileは実Codexで観測したlocal E2E `publish_text(content)`だけで、実schema未確認の外部serviceはpreview適格にしません。real MCP inputは32 KiB / 32 fields / depth 8のbounded preflightをartifact生成より前に受け、超過したexternal writeはdeny、read-only / unsinked callは保存せず空stdoutでbypassします。runtime outputは従来のdeny / 空stdoutのままで、preview plannerと`updatedInput`はまだありません。

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

profileとfixture、全scalar value / JSON key fallbackは実装済みです。次のplannerはsink metadataのprofile / registry version、pointer、field classを直接使い、adapterと異なるfield推定を再実装しません。実service profileは実Hook payloadとtool schemaを確認した後に別commitで追加します。

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

## 推奨data model

planはpolicy decisionとは別のcall単位auditとして保存します。1つのcallに複数source / sink findingがあるため、1 decisionへ押し込めません。

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
    mode TEXT NOT NULL,              -- preview / enforce
    status TEXT NOT NULL,            -- eligible / rejected / rendered / post_confirmed / post_mismatch
    planner_version TEXT NOT NULL,
    original_input_sha256 TEXT NOT NULL,
    rewritten_input_sha256 TEXT,
    structure_sha256_before TEXT NOT NULL,
    structure_sha256_after TEXT,
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

CREATE UNIQUE INDEX redaction_plans_event_version
    ON redaction_plans(
        workspace_id, pre_event_id, planner_version, profile_version, mode
    );

CREATE INDEX redaction_plans_tool_use
    ON redaction_plans(workspace_id, session_id, tool_use_id);
```

exact profileがないreject planでは、`profile_id`に`unprofiled:<server>/<tool>`、`profile_version`にregistry versionを入れ、nullable keyによる重複を避けます。これは適格profileが存在することを意味せず、`rejection_code = 'unknown_profile'`と対で扱います。

hash対象はtool inputのcanonical JSONです。Bash / apply_patchも`{"command": ...}`として同じ規則を使います。`structure_sha256`はJSON Pointerとvalue typeだけを並べたcanonical shapeのhashとし、value本文を含めません。hashは同一性確認であり、暗号化ではありません。

保存方針:

- raw original inputは既存event / artifactに既に保存されるため、plan tableへ複製しない
- rewritten input本文も既定では保存せず、hash、pointer、replacement profileだけを保存する
- Hook stdoutを返す将来段階では、全derived `redact` decisionとplan / targetを同一transactionで保存してからrenderする
- `post_input_stable: true`のprofileで、PostToolUseのactual input hashが一致した場合だけ`post_confirmed`にする
- hash不一致は`post_mismatch`とし、別Hookのoverrideなどを疑う
- Postがない場合は、approval拒否、別Hook deny、tool failureを区別できないため、自動的に`applied`とは記録しない

previewではtargetの`decision_id`に元のblock decisionを保存します。将来enforceする場合は、全critical findingについて`redact` decisionを個別に導出し、同じcall-level planへ結びます。最強の1 decisionだけをplanの代表にして残りを捨てません。

statusの`rendered`はHookがstdout用JSONを作ったことだけを表し、Codexが採用したことを意味しません。採用を示せるのは、観測したPost inputが一致した`post_confirmed`だけです。

retentionはeventと同じscopeへ連動させます。planだけを長く残すとsource / sink関係を不要に保持するため、eventをpruneする際にplan / targetも削除します。現行event DBには自動pruneがないため、plan実装時には明示cleanup commandとdry-runを同じ作業単位で用意します。現行DBは暗号化されず、raw Hook payloadやartifactにplaintextが残り得ます。redactは外部送信を減らす機能であり、monitor DBのplaintext保存問題を解決する機能ではありません。

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

plannerは既存の`session-incremental`結果を入力にし、全DBやworkspace全体を再解析しません。source chunk、current event fragment、sink metadataはworkspace / session / sequenceで絞ったqueryだけを使います。

## failure fallback

redactはcritical external sinkに対するblockを置き換える候補です。そのため、redact固有の失敗をHook全体の一般的なfail-openへ伝播させてはいけません。

推奨する境界は次です。

```text
runtime analysis自体が失敗
  -> 現行どおりHook boundaryのfail-open

analysis後、critical blockを得た後にredaction plannerが失敗
  -> 元のblock outputを返す

planは作れたが保存、validation、renderに失敗
  -> 元のblock outputを返す

Post確認がない、またはhash mismatch
  -> appliedとは記録しない
  -> 次callのallow条件には使わない
```

redact plannerを`try/except`の外へ投げて空stdoutにすると、blockすべきcallを通すため危険です。block outputを先に保持し、redactが完全に成功した場合だけ差し替える構造にします。

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
| fields | 32 |
| nesting depth | 8 |
| critical findings | 32 |
| distinct targets | 16 |
| source bytes / finding | 32 KiB |
| total source bytes / call | 128 KiB |

現行source chunkingにはbyte上限がないため、inputだけでなくfindingから参照するsourceにもcapが必要です。plannerは`source_node -> target pointer`を直接参照し、全sourceと全fieldの直積比較を行いません。hard deadlineはcooperative checkであり、入力capの代用にはしません。上限値は初期benchmark envelopeに合わせた暫定値で、境界caseを実測して安全側に調整します。

推奨budget:

- pure planner p95 `<= 10 ms`、32 fields / 32 KiB input
- redaction追加overhead p95 `<= 25 ms`
- planner hard deadline `50 ms`
- PreToolUse全体p95 `< 300 ms`
- network call、embedding、workspace scan、全DB graph loadは0回

benchmarkはeligible、rejected、複数targetの3caseを同じroundで測り、no-redactのPreToolUseとの差をpaired sampleで計算します。Post confirmationは別HookなのでPre budgetへ混ぜません。

## 実装・commit単位

次の順序を推奨します。

1. `Define MCP outbound field profiles`（実装済み）
   - exact server/tool profile
   - outbound / redactable / control pointer
   - 同じprofileから全outbound pointerをadapterのfragment / sinkへ変換
   - unknown shapeのreject
   - server固有fixture
2. `Add redaction preview planner`
   - call内全finding集約
   - whole-field replacement plan
   - structural validation
   - runtime outputは引き続きblock
3. `Persist redaction preview audits`
   - plan / target schema
   - hash-only保存
   - workspace / session scope
4. `Confirm rewritten inputs from PostToolUse`
   - future enforce用のdormantなhash照合とstate transition
   - preview中はsynthetic fixtureだけで検証し、実Post確認はenforcement gate後
   - mismatch / missingをapplied扱いしない
5. enforcement gateを再評価
   - 複数rewriter問題が解消した場合だけ、独立opt-inでMCP runtime rewriteを追加
6. `Prototype static Bash data-operand redaction`
   - MCPの安全性と監査を検証した後
   - apply_patch automatic redactは対象外のまま維持

各項目を別commitにし、preview plannerとruntime enforcementを同じcommitへ混ぜません。最初の4項目を実装しても、gateを満たすまではHook stdoutへ`updatedInput`を返しません。

## tests

### planner unit test

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

### storage / integration test

- planと全targetをtransactionで保存する
- plaintext inputをplan tableへ複製しない
- canonical input hashが安定する
- duplicate event / retryでplan IDとtargetが冪等になる
- stable profileのPost input一致を`post_confirmed`、不一致を`post_mismatch`にする
- Codex管理file inputをfull-input hashでoverride判定しない
- Postなしをapplied扱いしない
- planner例外、保存例外、validation失敗では元のdenyを維持する

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
