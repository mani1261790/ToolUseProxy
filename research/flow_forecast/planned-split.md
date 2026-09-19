# 事前用途に沿ったF01分割

PlannedSplitManifestは、事前計画SHAとroot→安定した関連群→用途の対応を保持する。従来のSplitManifestと旧serializationは変更しない。新形式だけ追加情報を保存・再検証し、rootを作り直しても課題群・区分が変わらない。

同じ関連群は同じ用途へ集め、共通snapshotや明示関連が異なる宣言群/用途に跨がれば拒否する。分割別保存・development/test再結合でも計画を維持し、旧形式との混在や異なる計画の結合を拒否する。MBPP collectionは各captureの試行前bindingを検証した後、事前用途を使って分割する。既存captureの事後再割当ては行わない。

この型は計画と分割の整合性を示す。独立性・履歴完全性・未使用性・第三者による事前封印時刻を証明しない。既知課題の履歴照合とholdout開封記録は別途必要。

## 実測

source c25ca6eで、前段で全trainに封印したMBPP計画（dfdfbe3d…）を使い、新しい公有602の1明示バッチを実行した。上限20試行/180秒/1GiB、実際は12試行。以前のcaptureには何も追記していない。

新captureを既存介入へ結び付け、新しいchecked collectionへ封印。1関連群/1root/3prefix/6枝、全train。train診断はinconclusive_do_not_adopt。新model/採用独立群0。正確な時間・容量・計画/collection/比較hashは [results/planned-split-20260919.json](results/planned-split-20260919.json)。

関連973テスト/Ruff成功。旧mbpp/checked-mbpp/generated-mbppの3collectionを旧形式として再検証できた。計画を持つ分割の保存/再読込/区分別保存/結合を回帰で確認した。次はモデル生成より前の計画bindingと履歴照合を同じ収集経路へ接続する。#204継続。
