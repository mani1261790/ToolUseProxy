# 保存済み人工パイプラインの取込

`python -m research.flow_forecast.task_catalog --stateful-captures inputs.json --output NEW_DIR`

inputs.json は generated_stateful collect が完了したディレクトリの配列。生成前に固定した assignment の catalog / origins / design を使い、後から任意の課題名を付け直さない。

intent・execution・implementation の digest、生成 proposal / receipt / prompt、条件別レポート、対照試行の結果、操作別 I/O / Hook receipt / reservation、完了判定、保存済み F01 と再構成 F01 の一致を検証する。これはローカル整合性の検証であり、第三者の実行証明ではない。取込対象の証跡は最大 32 MiB、収集後も既存の容量・枝数上限を守る。

封印済み collection に stateful_captures 証跡を保持する。generator_strata は生成前の要求モデル名を復元し、元の実行枝と収集後の枝を照合する。同一生成 call_id の重複は拒否する。課題の再実行は catalog の関連群としてまとめる。要求モデル名から実際の提供モデル版や未使用課題の独立性を推定しない。

2026-09-19 の保存済み generated-stateful-capture-v1 を取込・再読込して確認した結果は results/stateful-import-20260919.json。追加のモデル実行・Docker trial はなし。train 1群のみで calibration/test はなく、F02 の有効性評価を満たしていない。
