# MBPP参照関数の入力能力検査（#204）

参照コードのhashだけでは、関数が外部の値を読まないことは分からない。
`mbpp_contract`は、選定済み3レコードのhashとASTを検査し、固定した小さな構文と
入力操作だけを認める。任意Pythonの実行許可やsandboxとしては使わない。

単一関数・引数・局所変数・定数・分岐/ループ・返却、必要な文字列/list操作に限定する。
非局所名の読出、import、ファイル/環境アクセス、反射、decorator/default/annotationの評価、
内部関数、呼出対象のalias、組み込み名の再定義、未確認の構文は拒否する。
組み込み関数/メソッドの引数個数も固定する。局所名の収集は安全性許可ではなく、
未初期化名による例外や無限ループがないことは証明しない。

前提はplain JSON引数、変更されていないPython基本処理、正常に完了した実行経路。
タイミング・例外の情報流、停止性、全入力に対する課題正解、細かなfield因果関係は対象外。
返却する証拠にもexecution_authorized=false、semantic_truth_promoted=falseを記録する。

```sh
python -m research.flow_forecast.mbpp_contract \
  --source /path/to/mbpp.jsonl --captures inputs.json
```

inputs.jsonは既存の完了済みcaptureの配列。strict readerで元記録を検証してから、
記録中の候補と参照recordを比較し、root/report/dataset hashへ検査結果を結び付ける。
同じrootの重複指定は拒否する。この処理でもモデル・trial・元参照コードは実行しない。

[固定版Google Research / MBPP](https://github.com/google-research/google-research/tree/4700efb9afa54286b0e04473ba80a13e8461e25f/mbpp)
（Austin et al., 2021、データCC BY 4.0）が出典。元コードの複製は追加していない。
source910eabeで実際の3参照と6captureを検査し、すべて対応が確認できた。
602はenumerate/count、603はlen/range/append/remove、604はreversed/join/splitを使用する。
結果とhashはresults/mbpp-contract-20260919.json。

既存collectionの因果関係はunknownを維持し、過去のsealやplanを変更していない。
次は、この能力検査と人工サービスのpublic/private投影を、入力・privateメタデータの
変更観測および固定wrapperの契約へ結び付ける。今回の新model/trial/採用独立群は0。
#204の独立holdout・実モデル版・有効性の条件は引き続き未達である。
