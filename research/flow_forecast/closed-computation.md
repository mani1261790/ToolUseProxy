# 固定された人工計算の入力契約と正解経路

一般的な意味変換を未知として扱う既存経路は維持する。新しい `--checked-task-worlds` は、閉じた3課題の実測と有限介入が同じ計算を表す場合に限り、粗いオブジェクト単位の依存関係を追加する。

```sh
python -m research.flow_forecast.task_catalog --checked-task-worlds pairs.json --output NEW_COLLECTION
```

pairs.json は `{ "capture": "...", "interventions": "..." }` の配列。既存資料を上書きせず、別のdataset/collection sealを作る。

## 根拠を揃える条件

1. 既存readerでintent・固定課題定義・実装・対照試行・Hook receipt・操作予約・I/O・受信・完了判定を検証する。
2. 介入の入力・別定義の正解・実行script hash・結果を検証し、同じDocker context、実computeコマンド、baseline出力へ結び付ける。再読込が異なるcaptureを返した場合も拒否する。
3. Python ASTを限定して検査する。外部値はplain JSONのsourceのみ。変数の使用前定義を確認し、分岐の片側や0回の可能性があるloopで作った変数を既定義にしない。呼出はdict/range/all/any/sumとJSONコンテナのget/append/valuesに限定し、import・ファイル/環境参照・動的実行・属性取出・任意関数・定義・例外・while等は拒否する。
4. load/compute/saveの実コマンドhashを、信頼した固定wrapperから再構成して一致させる。wrapperによる入力読込や任意の追加処理まで名前だけで信頼しない。
5. publicのsaveは既存のbytesコピー。privateのsaveは、正解オブジェクトの保持と人工保護元に一致するprivateフィールド、全出力hashを既存observerで確認する。sendは独立受信記録のhash/長さと一致する。

AST検査は任意Pythonを安全に実行するsandboxではない。plain JSON入力、変更されていないPython組込み、固定wrapperという前提を明記する。停止性・資源上限や細かなフィールド因果は証明しない。実行は従来の隔離環境と有限バッチで行う。

## F01での表現

- `closed_compute / checked_computation`: 単一のJSON入力だけを読む固定計算。有限介入で入力変更に出力が反応することも確認した、粗いオブジェクト依存。
- `json_projection / checked_json_projection`: 固定のJSONフィールド追加/保持。値と実コマンドが一致した場合に限定する。
- 新しい関係と証拠種別の組合せを強制し、checked_bytesで意味変換を証明したことにはしない。
- 一般のsemantic/selection、証跡不足、未知の計算、遮断後の未実行部分には適用しない。
- F02の閾値・群数・分割・未知結果の扱いは変更しない。課題変種・介入・新しいrootを独立群として加算しない。

## 実測再評価

source baa060b379b0ebe5ffa7580f3097ba5e6ab29417、/private/tmp/tooluseproxy-204-checked-world-collection-v1。

observe/4は在庫引当=no、会議調整=no、private明細=yes（protected-source → value-3 → receiver）。enforceは全件censored/unknown。3群すべてtrainであり、学習用開発診断。compare prepare/evaluateまで確認し、総合結果はinconclusive_do_not_adopt。結果hashと正解数は results/checked-task-worlds-20260919.json。

追加モデル呼出・trialは0。独立課題としての受入0、生成モデル証跡0、calibration/testの必要数は未達。次は実生成エージェントの課題計画と実行への接続、および独立した課題設計の拡張へ進む。
