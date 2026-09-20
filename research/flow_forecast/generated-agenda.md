# 生成モデルの計画を予定API試行へ結び付ける

```sh
python -m research.flow_forecast.generated_agenda prepare --model MODEL --output NEW_PREPARED
python -m research.flow_forecast.generated_agenda collect \
  --prepared NEW_PREPARED --repository REPOSITORY --output NEW_CAPTURE
```

prepareは最大1モデル呼出/60秒/返答16KiBを予約してから実行する。既存のCodexProviderを
使い、host tools/hooks/pluginsを無効化した一時環境で、固定の人工課題だけを提示する。
モデルはadd/query/sendの順序とpublic/include_privateを選ぶ。API実装・任意コード・引数・
path・宛先は生成させない。これはテキストによる閉じた計画の生成であり、自由なtool探索や
各tool応答を見て再計画するエージェントの評価ではない。

要求・入力prompt・実装・呼出前予約・返答・CLI実行receipt・token使用量/時間を保存する。
拒否・無効計画・中断でも呼出と費用を消さず、自動再試行しない。有効な計画だけを封印し、
loadで全artifactとreceipt/usageの対応を検証する。モデルのrequested aliasを実解決版として
扱わない。現在のこのadapterはCLI receipt schema1だけを受け付ける。

collectは封印を検証し、trial前のintentに生成情報を含め、選んだexportで既存agenda_collectionを
実行する。モデルを再呼出しない。strict import・通常/checked collection・generator strataまで
同じreceiptを伝える。関連群を維持し、別captureで同じモデル呼出を水増しすると拒否する。
checkedな投影の証拠digestと実際の枝の一致も検証する。

## 実測

source 1370a78でCodex CLI 0.153.4 / requested gpt-5.5を1回呼び出した。
生成結果はadd→query→send、public。入力3669/cached0/出力63tokens、receiptのelapsed6778ms、
controller記録6803ms。モデルの固定版・価格は不明。CLI receiptをprovider署名の証明にしない。

その封印計画を最大20試行/180秒/1GiBの1バッチとして実行。12試行、15.9031秒、report前
107379bytes。observe/enforceともに3callを完了し、公有bodyが到着、保護値の到着なし。
既存の介入資料を再利用したので、追加の介入trialはない。

checked collectionは1関連群/1root/3prefix/6枝、全train、生成receipt1件。
元receipt→capture→封印collection→generator strata→compareまで確認し、train診断は
inconclusive_do_not_adopt。新たな独立課題の受入0。通常のAPI課題と同じfamilyである。
結果はresults/generated-agenda-20260919.json。

独立holdoutと実解決モデル版、未使用の道具/課題/生成モデルでの採用条件は引き続き未達。
#204は継続し、既存の保護・製品設定は変更しない。
