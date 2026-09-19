# MBPP実行記録の評価collectionへの取込（#204）

```sh
python -m research.flow_forecast.task_catalog \
  --mbpp-captures inputs.json --mbpp-source /path/to/mbpp.jsonl \
  --output /path/to/new/collection
```

inputs.jsonは完了済みmbpp_collectionディレクトリの配列。元データは固定SHAの原版を
指定する。取込はコード・モデル・trialを実行しない。試行前originのsource/record/code/ケースと
固定資料を照合し、保存された実装hash、intent/execution/report、個別予約・guard・step・
resourceを検証する。実際の宛先とcallからscriptを再構成し、返答・状態・receiverの
body hash/サイズも確認する。失敗、余分な試行記録、異なるケース、架空の生成証跡は拒否する。

これはローカル記録の整合性検査であり、署名された第三者実行証明や独立保管ではない。
固定資料と実装が変わった場合、旧記録を新しい意味で読み替えず拒否する。

F01には実際のcompute ack、public/get返答、送信を反映する。内部stateやobserverの
private値を予測入力に渡さない。保護sourceからの入力関係は、照会返答に実際にprivateが
現れた時点でだけ追加する。同じ環境の回帰で、public/privateの照会前prefixが等しいことを
確認した。異なる実行image IDを持つ実測prefix全体が同一とは主張しない。

計算と選択はselection/unknownのまま、送信だけを実受信の証拠に結び付ける。
期待結果との一致を、全入力に対する依存関係の真値に読み替えない。拒否された後の
未実行呼び出しを将来観測として作らない。現在の能力表現はtool_output/httpであり、
個別MCP名の未知ツール性能評価ではない。

出典は[固定版Google Research / MBPP](https://github.com/google-research/google-research/tree/4700efb9afa54286b0e04473ba80a13e8461e25f/mbpp)
（Austin et al., 2021、データCC BY 4.0）。origin資料には出典と各record/referenceのhash、
人工メタデータを付けた派生シナリオであることを記録する。public/privateと再実行を同じ
designへ結び付け、現在の保守的なflow構造判定では3design全体が1関連群になる。
異なるtask IDや参照コードhashだけで独立性を認定しない。

## 実際の取込と比較

source2d83025で既存6バッチを取り込み、3design/1関連群/6roots/18prefix/36枝の
collection-v1を封印した。全train、horizon4の真値は36枝ともunknown、生成モデル証跡0。
最初のplan-v1はcollectionを指定していなかったため、collection付きevaluateで
comparison_generator_plan_mismatchとして拒否され、比較reportは作られなかった。
旧planを保存し、collectionを指定したplan-v2を別に作成した。

plan-v2によるtrain診断はinconclusive_do_not_adopt。未使用holdoutの評価ではなく、
新しいモデル呼出・trial・採用独立群はいずれも0。
results/mbpp-import-20260919.jsonにseal・計画・比較のhashとこの経緯を記録した。
F02の凍結条件を変更せず、#204は継続する。

次は計算と公有/private投影の依存関係を、実装と入力domainを限定した証拠に接続する。
独立性と実生成モデルの不足が残っており、collectionを作れたことだけで採用とはしない。
