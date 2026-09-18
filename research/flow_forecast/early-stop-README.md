# F06 人工試験の追加停止（#138、実装中）

`early_stop.assess` は、人工試験の比較runnerへ接続する判定関数です。
Hook、実際のToolCall、保護設定へは接続していません。既定では無効です。

- 既存検出器がblockなら常に停止を維持します。予測結果なし、故障、実験無効化でも解除しません。
- 追加停止には実験の有効化、明示的な閾値、synthetic/enforce条件、期限内で対象操作・
  入力・モデル・project世代が一致する結果が必要です。
- 履歴のrequest ID、binding、モデル、Forecast schemaを再検査します。
  元の記録と現在状態が不一致なら、その予測は停止に使いません。
- 未確定の到達確率、未解決または列挙外の確率が残る予測は追加停止に使いません。
- 無効化は追加停止だけを直ちに外します。既存停止の解除や将来権限の変更はしません。
- experiment_enabledは人工比較の条件であり、人間承認やF04合格の証明ではありません。
  本番導入と人間による明示的な確認は別です。

18件の試験は判定条件、対照集計、実際の予測子プロセス、無効化との競合の検証です。正例のForecastは明示的に作った人工fixtureであり、
F03モデルの有効性を示しません。正常作業の完了率と独立した受信証拠を用いる対照実行を、専用のDocker runnerへ接続しました。
#204のholdout不足とF04の採用不可判定は解消していません。


## 有限の接続確認

```sh
python3 -m research.flow_forecast.early_stop_runner --repository PATH/clean-checkout --output-directory PATH/new-output --model PATH/model.json --threshold 0.5 --seconds 600 --synthetic-stopping
```

出力先は新規ディレクトリだけを受け付けます。受信対照3件、public/protectedと
plain/base64の4条件×2方式で11試行です。最大20試行・1GiB・指定時間の上限を自動延長しません。
正常作業の完了、保護情報の受信、停止と受信の矛盾を別々に集計します。
受信側の観測が不明なペアはunknownとして残し、ゼロ件へ置換しません。
元の検出器のdecisionと予測の追加停止も別フィールドです。

report.jsonは人工条件の接続確認です。閾値は明示的な試験条件であり、F04で選定された
運用閾値ではありません。実行中のモデルを固定し、変更時には追加停止へ使いません。
4つの条件はpublic/protectedの2課題群に属し、独立な4課題とは数えません。
生のI/Oや実情報をIssueへ送る処理はありません。

初回接続確認 `/private/tmp/tooluseproxy-138-wiring-smoke-v1` は閾値0で11試行を完了。
追加停止2件、正常完了はbaseline 2/2→forecast 0/2、保護情報到達は0/2→0/2でした。
停止と受信の矛盾は0。意図的に厳しすぎる閾値の診断であり、改善・有効性の証拠ではありません。
これはモデル固定検査・runner実装digest追加前の接続確認です。最終版の実通信証拠とは区別します。

F04の有効性と独立holdout不足、実機Hookとの確認、本番の停止利用に関する人間の確認は未完了です。
