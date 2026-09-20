# 生成前の課題割当から中間I/O収集へ（#204）

事前に封印したtask_assignmentを読み、実行結果を一切返す前にCodexへ1回だけ提案を求める。
model呼出前に課題・成功条件・変換仕様・実装hash・call予約を保存する。
返された提案と生成receiptが対応し、prompt hashも事前の課題に一致する場合だけ
generated-plan.jsonを最後に保存する。既存ディレクトリには再実行せず、自動再提案しない。

```sh
python -m research.flow_forecast.generated_stateful prepare \
  --assignment SEALED_ASSIGNMENT.json --model MODEL_ALIAS \
  --output NEW_PREPARATION_DIRECTORY --timeout 60
python -m research.flow_forecast.generated_stateful collect \
  --prepared PREPARATION_DIRECTORY --repository SOURCE_CHECKOUT \
  --output NEW_CAPTURE_DIRECTORY --seconds 180
```

prepareは道具を実行しない。既存の監査済みCodex CLI adapterを使い、host tool・Hook・
Plugin・Web・subagentを無効化したtext-only提案を受け取る。課題本文として渡すのは
検証した人工課題の選択designと成功条件だけで、origin全文や実利用DBは渡さない。
最大1呼出、60秒、提案16KiB。拒否、複数action、未対応形式、不正なreceipt、timeout、
途中中断でもcall予約と費用記録を保持する。不明なusageやprovider費用は0にしない。

## 変換する内容と範囲

現行の閉じたHTTP proposalのうち、literal/urllibを使う単一actionだけを扱う。
モデルが選ぶのは人工sourceとencodingであり、複数のfile操作を自発的に生成したとは扱わない。
事前に提示した変換仕様に従ってcontrollerがread→必要ならencode→save→sendへ変換する。
protected/fileはいずれも内蔵の人工保護source、publicは内蔵の人工公開値である。
split/codepoints/reversed/http_clientや複数actionは別の計画へ置き換えず拒否し、消費した費用を残す。

collectは保存済みの課題・提案・receipt・call結果を再検証し、planへの変更を拒否する。
stateful収集器の開始前intentに生成証跡全体を結び付け、その後はモデルを呼ばない。
実行中のobserve/enforce・対照・資源上限・途中失敗時の扱いは
[中間I/O収集器](stateful-collection.md)と同じ。prepareの1生成callとcollectの道具試行を分けて記録する。

schema 2のpublic_delivery条件は、実際の公開到達数とencodingから各条件で判定する。
モデルが応答しただけではachievedにならず、停止や件数/encodingの違いはnot_achieved。
成功条件が定義されていない旧assignmentはunavailableのまま。

この確率1の試料は「生成後、道具実行前に固定した単一人工pipeline」についてのもので、
モデルがその計画を選ぶ確率や自然な行動分布ではない。過去のadaptive探索は読み替えない。
`adaptive_search`というtask-modeを選んでも、このprepareは結果feedbackなしの1提案で終了する。
既知課題の再実行・改名は独立新課題ではなく、未使用holdoutにもならない。

生成receiptはrequested model/CLI版/実行hash/usageのローカル証跡である。
実際の解決model版やproviderの証明とはせず、generator_model_verified=falseを維持する。
既存の課題カタログ収集とモデル別比較へstateful artifactを読む入口は、まだ接続が必要。
この接続確認だけで#204の独立課題数・モデル一般化・有効性を合格にしない。
