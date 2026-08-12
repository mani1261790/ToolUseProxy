# Externality Protectionロードマップ

## 現在地

現在の実装は、既知adapter、bounded static analysis、初見unknownの保守的sink、値非保持queue、Hook外Codex judge、人間review、workspace単位の完全一致rule cacheまでを持ちます。

Hookはnetwork通信やLLM待機を行いません。LLM分類はjobごとに新しい隔離済み`codex exec --ephemeral`セッションで行い、ToolUseProxyはOpenAI APIやAPI keyを直接扱いません。LLM結果は自動昇格しません。

## Phase 1: Codex-only契約の固定

状態: 実装・自動test・2026-08-12実Codex capability probeまで完了。

完了条件:

- provider routeは`off` / `codex`だけ
- Responses API client、API key設定、fallback、`auto`が存在しない
- Codex executable、version、model、judge contractをprobe receiptへ固定
- jobごとにfresh ephemeral session
- read-only sandbox、Hook / Plugin / shell / browser / MCP無効
- timeout、tool activity、unexpected write、schema不一致はruleを作らない

正本とする2026-08-12のcapability probeは、Codex CLI 0.145.0、固定value-free envelope 2件、probe contract `codex-externality-probe-v2`を使い、local `5,208 ms` / `local`、risk `4,511 ms` / `possibly_external`、reason code 0でeligibleでした。これは実projectの精度評価ではありません。

## Phase 2: isolated dogfood

合成値だけを使うfresh Plugin dataで次を確認します。

- public local callは継続
- public unknown callはqueueへ入り、継続
- protected unknown callは初回から実行前deny
- static external＋protected flowもdeny
- Hook内network 0、Hook latency budget内
- Codexへ送るraw command、path、host、protected valueが0
- background分類後も自動昇格0
- revision不一致、stale receipt、workspace違いはrule不採用
- approved localは完全一致unknownだけを解除

## Phase 3: 実project pilot

複数projectでfalse blockと見逃し候補を値非保持で記録します。protected source本文、raw Hook payload、SQLite DBをreportへ載せません。

評価指標:

- protected unknownの実行前block率
- public unknownの誤block率
- static / adapter / reviewed rule別の寄与
- queue重複排除率とreview件数
- Hook p50 / p95 latency
- raw exposure、workspace混線、既存block downgradeが各0

## Phase 4: 運用UX

pilotで安全性を確認してから、workerを手動commandのまま維持するか、明示opt-inのschedulerへ進めるか判断します。自動化する場合も、広いpermission、常駐network service、LLM verdictの自動承認は導入しません。

review表示は、利用者が構造要約、判定、影響、revisionを一画面で判断できる形にします。技術用語を覚えることを前提にしません。

## Phase 5: 公開候補

公開前にfresh Desktop run、package install / update / rollback / remove、macOS実機を完走します。Linux / Windowsは未検証のまま保証しません。

公開判断の必須条件:

- full test、package、lifecycle、ruff、diff checkが合格
- Hook内network 0
- protected side effect 0
- raw exposure 0
- public local / public unknownの意図しないdeny 0
- stale / invalid reviewからrule採用0
- 文書と実挙動が一致

## 現時点で保証しないこと

- hosted Web SearchなどHookへ現れない経路の実行前遮断
- runtime DBが利用不能な場合の完全なfail-closed
- 実network ground truthの完全観測
- 数学的な偽陰性ゼロ
- LLM分類の自動承認
- cross-platform scheduler
