# Sink payload evidenceの設計

## 目的

ToolUseProxyは、外部sinkが送るpayloadを実行前に解決し、protected sourceと比較します。ただし、file-backed payloadの本文をartifact fragmentやdurable graphとしてSQLiteへ複製すると、秘密の保存範囲が増え、mutableな実行前snapshotを再現可能なlineageと誤認しやすくなります。

`sink payload evidence`は、解決した値をPreToolUse処理中だけ保持し、比較後は値を捨てるための境界です。返却・保存できるのは次の値なし情報だけです。

- workspace ID
- sink node IDとsegment index
- resolver / evidence contract version
- resolutionの`evaluated` / `unsupported`
- comparisonの`evaluated` / `unsupported` / `not_run`
- `static_values` / `resolved_file` / `coarse_fallback`
- `tool_input_literal` / `pre_execution_file_snapshot` / `unresolved`
- value数、合計byte数、処理時間
- 一致したsource chunk ID、match method、score
- 値を含まないunsupported reason

payload本文、payload由来hash、raw commandの複製、file pathはevidenceへ含めません。source chunkはcurrent workspaceとIDが一致するものだけを比較対象にします。

## 現在のmatch

最初のcontractは、payload全体とsource chunkのexact match、およびsource chunkがpayload内へ確定的に現れるexact substringだけを作ります。`.env`全体をcurlへ渡す場合、resolverの値はfile全体、protected source chunkは選択されたkeyの値だけなので、全体一致だけでは漏えいを見逃すためです。

比較には既存のsource-binding lexical profileを使いますが、evidenceへ採用するmethodは`exact`と`substring`だけです。token equivalent、shingle、embeddingはこのcontractへ含めません。resolved valueのSHA-256はin-process比較にだけ使い、hash自体はevidenceへ返しません。

このcontractはproductionのopt-in shadow modeへ接続済みですが、policy enforcementへは未接続です。`PreToolUse`のdeny、allow、Hook outputは変更せず、shadow metricsと将来のexact-only enforcementが利用する接続点を固定します。

## Shadow observation

`TOOLUSEPROXY_PRE_TOOL_FILE_PAYLOAD_SHADOW=1`は、current Bash eventの`curl` HTTP sinkだけを観測します。現在のruntime解析が使ったactive source chunksを`RuntimeAnalysisResult`から直接受け取り、manifest更新後のstale chunkや別workspaceのchunkを別queryで混ぜません。

shadow用SQLite tableへ保存するのは、status、有限のreason、snapshot semantics、件数・byte数のbucket、strongest exact match種別、match件数、処理時間、baseline / shadow actionの集約値です。ephemeral evidenceが持つsource chunk IDもshadow tableには保存しません。payload本文、raw command、path、payload由来hashを複製しないため、shadow追加によってdurable plaintextの範囲を広げません。

現在policyの判断とHook outputを先に確定し、その後にresolverとshadow writeを独立したfail-soft境界で実行します。shadow schema drift、10 msでfail-fastするSQLite lock、resolver / validation / write例外は観測だけを欠落させ、すでに確定したallow / denyを変更しません。同一Pre event / sink / segment / evidence versionは最初の観測をimmutableに保持します。

`scripts/report_sink_payload_shadow.py`はidentityを出さず、status、match、decision diff、payload size bucket、p50 / p95 / p99 / max latencyだけをJSONで集計します。`would_block`は「現在のexact-only候補」であり、遮断が実行された意味ではありません。

## Bounded file resolver

resolver v2が扱うのは、staticな`curl --data-binary @relative-file`と`--data-binary=@relative-file`です。

- 1 path: 4 KiB
- file reference: 1 commandあたり8件
- 1 value: 32 KiB
- value: 1 commandあたり32件
- payload合計: 128 KiB
- resolution time budget: 200 ms
- 比較対象source chunk: 512件、1件32 KiB、合計512 KiB
- regular UTF-8 textだけを許可
- NUL、stdin、dynamic operand、workspace外、`..`を拒否
- shell、subprocess、curl、networkを実行しない

POSIXではworkspace directoryからcomponentごとにdirectory FDを開き、`O_DIRECTORY`と`O_NOFOLLOW`を使って親directoryを辿ります。leafも同じdirectory FDから`O_NOFOLLOW`で開き、読み取り前後のdevice、inode、size、mtimeを確認します。親pathの名前が途中で差し替えられても、既に開いたdirectory FDからworkspace外へ解決し直しません。

component-safe openを提供できないplatformではfile-backed resolutionを`component_safe_open_unavailable`としてunsupportedにします。現在のWindows supportはexperimentalであり、POSIXと同じ保護を提供したとは扱いません。

## TOCTOUの保証境界

component-wise openが防ぐのはresolver自身のpath解決raceです。Hookがsnapshotを読んだ後、target toolはpathを再度開きます。したがって、resolverが読んだbytesとcurlが送るbytesの同一性は保証しません。

- exact matchを観測した場合は、target toolの実行前block候補にできる
- no-matchは「検査時点で一致を観測しなかった」という意味に限る
- no-matchを実送信bytesの安全証明として表示しない
- 悪意あるlocal processとの実行raceは現在の保証範囲外

実送信bytesを保証するには、検査済みFDの受け渡し、最終inputの排他的rewrite、または送信proxyが必要です。現行Codex Hook contractでそれを提供できるとは仮定しません。

## 次の接続

1. [#44](https://github.com/mani1261790/ToolUseProxy/issues/44)でcontractとcomponent-safe readerを固定する
2. [#45](https://github.com/mani1261790/ToolUseProxy/issues/45)の値なしshadow modeでmetricsを実測する
3. validation precision、false block、latency、privacy gateを満たしたexact matchだけ、別のopt-inでblockへ接続する
4. [#46](https://github.com/mani1261790/ToolUseProxy/issues/46)のsemantic matchはobserve-onlyで別評価する
