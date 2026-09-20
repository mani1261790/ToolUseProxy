# 収集前の課題用途の封印

`cohort_plan --catalog CATALOG --origins ORIGINS --assignments ASSIGNMENTS --output NEW_PLAN`で全設計の用途を事前に指定し、origin本文・catalog・割当てをhashで結び付ける。assignmentsはdesign IDからtrain/calibration/testへの対応。欠落・未知用途・由来本文の不一致・同じ関連群を異なる用途へ割り当てる指定は拒否する。

`mbpp_collection --cohort-plan PLAN`はモデル/試行とは別に封印した計画を読み、固定参照由来のcatalogと照合し、最初の試行予約より前のintentに計画とdesign/group/partitionを記録する。strict importerはbindingを再検証する。取込対象に計画のないcaptureを混ぜたり、別の計画を混ぜたり、計画と異なるsplitになった場合はcollectionを拒否する。

この変更は事前用途の記録と不一致拒否まで。既存F01 splitはroot基準のため、事前用途に沿ったsplitの構築は未接続で、不一致を都合よく再割当てしない。生成モデル呼出前の計画bindingも残件。既存captureに事後追記しない。ローカル封印だけで第三者の時刻証明・履歴完全性・独立性・未使用性を主張しない。

## 確認

source230ad03で実固定MBPP 602/603/604の由来から、すべてtrainの計画を新規作成した。計画SHAはdfdfbe3d38e21681d3e1a09180fe585112bda42398e2998694c8eea386075d4d、関連群は1。保存先は/private/tmp/tooluseproxy-204-mbpp-cohort-plan-v1.json。開発済み課題なので未使用calibration/testへ指定しなかった。これは新試行の実行証拠ではない。

関連969テスト/Ruff成功。回帰では試行予約前のintent binding、関係群分離拒否、hashを再計算した区分の付け替え拒否、取込時のsplit不一致拒否を確認。新model/trial/採用独立群0、#204継続。
