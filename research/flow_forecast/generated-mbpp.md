# 生成モデル証跡とMBPP試行の接続

`generated_mbpp prepare --source PINNED_JSONL --task-id 602 --model MODEL --output NEW_DIR`で、固定602/603/604のいずれかについて1回・60秒・16KiBの生成呼出を事前予約する。課題は元record hashで固定し、公開入力と目的、compute/query/sendの道具定義をモデルへ渡す。モデルがアルゴリズムを実装したことや自由探索したことは主張しない。

応答の操作順とexport、CLI receipt、token使用量、controller時間を保存し、失敗や拒否も費用へ計上する。`collect --source PINNED_JSONL --repository REPO --prepared PREPARED --output NEW_CAPTURE`は封印した計画を読み、実行前intentへ結び付ける。別課題やexportの不一致は試行前に拒否する。collectorはモデルを再呼出しない。

通常/checked importとgenerator_strataまで接続し、別rootへのreceipt使い回し、課題との不一致、checked projection proofの改変を拒否する。モデル名の指定はaliasとして記録する。固定モデル版の確認や単価のない費用を推測しない。

## 実測

source e3260c8でgpt-5.5に1回生成を依頼し、compute/query/send・publicを取得した。input3728/cached0/output73 tokens、controller5831ms。provider費用/単価は不明。詳細receiptは [results/generated-mbpp-20260919.json](results/generated-mbpp-20260919.json)。

1明示バッチ（上限20試行/180秒/1GiB）で12試行、15.676013292秒、report前105419bytes。observe/enforceとも公開結果が実receiverへ到着し、保護値の到着なし。既存602の有限介入を再検証してchecked collectionへ取り込み、新しい介入試行は0。

1関連群/1root/3prefix/6枝、生成receipt1件。今回の固定splitはcalibrationのみでtrainがないため、prepare/evaluateはno_fixed_distribution_training_rootsで停止した。計画・比較出力は作られず、採用判断も出ていない。割当てを変更したりrootを作り直したりしない。既に開発で使った課題の派生なので、split名だけを未使用調整群の証明にしない。採用独立群は0。

関連958テストとRuff成功。#204は継続する。次は課題の関連群と収集前割当てをバッチを跨いで固定し、開発済み課題が別collectionのsplit名だけで未使用扱いにならないことを確認する。
