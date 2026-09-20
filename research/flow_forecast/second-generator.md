# 同じ人工課題を別の生成モデルで実行する

在庫課題を要求モデルgpt-5.6-terraで1回だけ生成し、observe/enforceの有限バッチを
実行した。実行sourceはd74bb41、監査済みCLI 0.153.4のhost tools無効化を維持。
最大1call/60秒、capture最大20試行/180秒/1GiB。自動再試行・自動延長なし。

提案はload/compute/save/send、公有結果のみ。入力5844/cached0/出力61トークン、
準備5990ms。計算コードはcontrollerが提供しており、モデルが算法を実装したとは
主張しない。実提供モデルの版とprovider単価は取得できていない。

captureは11試行/13.834秒/report前110176bytes。observeは正常完了し保護到達なし、
enforceは最初の操作で遮断。既存gpt-5.5の在庫captureと組み合わせても、同じ課題なので
1群のまま。既存の在庫介入証拠へ結合し、新たな介入は起動していない。

この2モデル混在群の集計で、実際に観測した要求モデル名が表示から消える問題を
確認した。単一モデル群の評価ラベルと、証跡で観測した要求モデル名の一覧を分ける。
`observed_requested_models_by_partition`は混在群や一部証跡欠損群の既知名も残す。
`requested_models_by_partition`は従来どおり単一モデルの完全な群のみ。
未使用test aliasを求める際は、学習側の混在群で観測済みの名前も除く。
混在群をモデルごとの独立標本に分割しない。

封印済みcollection: /private/tmp/tooluseproxy-204-two-model-collection-v1。
prepare/evaluate(train)済み、結果inconclusive_do_not_adopt。
実測hashと費用はresults/second-generator-20260919.json。
新しい独立課題0、未使用評価なし。2種類の要求aliasの実行証跡を得たことは、
固定版モデル間の一般化が実証されたことを意味しない。
