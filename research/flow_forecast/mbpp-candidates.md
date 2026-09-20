# MBPPの開発用候補を取り出す（#204）

API名や同じ操作列の派生を増やす代わりに、問題・参照実装・期待結果が揃う課題の
取り込み経路を用意する。対象はGoogle ResearchのMostly Basic Python Problems
（Austin et al., 2021）。[固定した公開元](https://github.com/google-research/google-research/tree/4700efb9afa54286b0e04473ba80a13e8461e25f/mbpp)
の原版974件と、手作業で検証したとREADMEに記載される別ファイル427件を取得した。
今回使うのは原版の上流training（ID 601–974）だけ。上流のtestという名称を、
ToolUseProxyの未使用holdoutの証明には使わない。

root READMEによるデータのライセンスは[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)、
ソースコードはApache-2.0。5取得ファイルのGit blob SHAとSHA-256を照合し、
results/mbpp-candidates-20260919.jsonに記録した。問題文・参照コード・元データは
このrepoに複製していない。候補JSONはGoogle Researchのデータから引数/期待値を抽出した
派生資料であり、共有時もこの出典・ライセンス・変換内容を引き継ぐ。

```sh
python -m research.flow_forecast.mbpp_candidates --source /path/to/mbpp.jsonl
```

固定SHAの完全一致を確認してから、上流training 374件だけを静的に調べる。単一関数、
位置引数、literal同士の等値assertから、JSONで扱える引数・期待値を取り出す。
Pythonのimport、eval、参照コードやassertの実行はしない。関数本体の安全性を許可する
機能でもない。任意の副作用を持つ本体でも「candidate」になり得るため、この出力を
実行許可として使わない。各候補には元record・参照コード・ASTのhashを持たせる。
challenge_test_listは未検証であると明記する。

source c4eefb5で実際の固定資料を処理した結果は199候補・597正解例だった。
除外175件はJSON外の値71、単一関数でないもの103、setupコード必須1。
199の異なるASTがあっても、変数名変更・同じアルゴリズム・派生関係の確認は未完了であり、
199独立群とは扱わない。全374件のコードがimportなしとも主張しない。

元JSON全体は機械的に読み込み、件数/IDを検証した。コード/テストの解析は上流trainingに
限定しているが、それだけで残りの過去未使用性やモデルの訓練汚染がないことは証明できない。
候補はすべて開発資料。収集・封印されたF01資料やtestへの割当てではない。

次は、参照コードと期待結果が一致するかを隔離Dockerの明示的な有限バッチで観測する。
まず少数の候補と全3例を選び、元record hash、実行script、予約、終了状態、実際の出力を
記録する。参照コードの成功を保護情報の流れの真値に読み替えず、必要な介入とreceiverの
観測へ接続する。各20試行/1800秒/1GiBの上限を維持する。

今回のmodel/trialは0、採用独立群0。#204の520独立群・未使用評価・実モデル版は未達。
