# 予定APIのフィールド別介入

```sh
python -m research.flow_forecast.agenda_batch --suite projection \
  --repository REPOSITORY --output NEW_DIRECTORY --seconds 180
```

固定AgendaAPIの追加→公有照会→全体照会を、baseline、所有者Aの保護値変更、別所有者Bの
保護値変更、公開タイトル変更、公開時刻変更の5caseで実行する。各3呼び出し、計15試行。
入力・期待状態・出力は別に宣言し、実際のAPIの戻り値と各呼び出し前後の全状態を照合する。
外部case/任意コードは受け付けず、API本体のSHA-256が固定値と異なる場合は実行を拒否する。
これは変更検知用の固定であり、hashそのものが意味論の正しさを証明するわけではない。

既存の隔離runnerを共用する。既定suite=apiの7case/10試行は維持する。projectionでは各caseを
新しいnetwork none・read-only・非特権containerで実行し、3呼び出しを実行前に予約する。
最大20試行/1800秒/1GiB（今回180秒）、失敗の予約・時間・容量は保存し、自動延長しない。

agenda_projection_evidence.read_interventionsはsource/intent/execution/report、全15予約、
5個のcontainer identity、全観測・結果を再照合する。余分な予約や失敗記録も拒否する。
bind_captureは既存strict capture readerを通した照会結果とbaselineの公有/保護出力hashを
照合し、同じsource-only build contextへ結び付ける。比較対象ごとのimage IDも保存する。

## 実測

source 9fbebc5で15試行を実行、4.6995秒、report前57466bytes、モデル0。すべて期待値一致。

- 所有者Aの保護値を変えても公有出力は同じ。全体照会のprivateだけが変わる。
- 別所有者Bの保護値を変えても、Aの公有/全体照会の出力は同じ。Bの状態は呼び出しで変わらない。
- 公開タイトル/時刻を変えると、公有/全体照会の対応フィールドへ反映される。
- 既存の公有/保護capture各2条件の実照会結果をbaselineへ結び付けた。

以前のcaptureと今回のimage IDは異なる。同じbuild contextとAPIソースは確認できるが、
以前のimageの一つは現Dockerで見つからず、layer同一性の事後比較はできなかった。
原因は断定せず、identical_image_verified=falseを記録する。過去の実行記録は書き換えない。

結果はresults/agenda-projection-20260919.json。有限の入力介入は一般的な非干渉性の証明ではない。
F01のselection/unknownは変更せず、独立課題・未使用holdout・新しい生成モデルの追加には
数えない。次はこの証拠を、閉じたAPIの入力domainと実装に限定した依存関係の契約へ接続する。
#204は継続。
