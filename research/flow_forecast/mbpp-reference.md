# MBPP参照実装の有限実行（#204）

候補抽出だけでは、元のコードと期待結果が一致するか分からない。最初の実行対象を
上流trainingの602（最初の重複文字）、603（ludic数列）、604（単語順反転）へ固定し、
各3例を別々の隔離Dockerで実行する経路を追加した。

[Google Research / MBPPの固定版](https://github.com/google-research/google-research/tree/4700efb9afa54286b0e04473ba80a13e8461e25f/mbpp)
を使用。データの出典はAustin et al., 2021、ライセンスはCC BY 4.0。
元データの複製はrepoへ含めず、実行時に固定SHAと選定した3レコードのhashを再確認する。
変換内容は、元の参照関数へ抽出済みの引数を与え、戻り値をJSONで観測するwrapperの追加。
隔離実行はこの3レコードだけであり、199候補すべての実行や安全性承認ではない。

```sh
python -m research.flow_forecast.mbpp_batch \
  --repository /path/to/isolated/checkout --source /path/to/mbpp.jsonl \
  --output /path/to/new/private/output
```

既存のnetwork none・非特権・read-only・host mountなしのprofileを検証する。
コード/引数はcontainerのPythonだけで実行し、各例で新しいcontainerを使う。
事前intent、9件の試行予約、script hash、container名/image、実出力と判定結果を保存する。
実出力は検証前に保存し、不一致も残す。timeout/実行失敗は予約を保持して停止する。
自動retry・次バッチへの自動延長はない。

上限は20試行/180秒/1GiB（secondsは最大1800まで指定可能）。各実行も既存runnerで
10秒に制限する。全体deadlineは各処理の前後で検査し、buildや実行を途中で強制中断する
単一のhard deadlineではない。超過したバッチを成功として報告しない。

## 実測

source 56277daで1バッチ9試行、5.6461秒、report出力前40,519bytes。
全9例が期待結果と一致し、保存した各出力を再読込して再判定した。9script hashと予約、
container名の一意性、intent/execution/implementationのhash対応も照合済み。
results/mbpp-reference-20260919.jsonに記録した。

関数の戻り値だけを確認しており、guard、receiver、native Hook、モデル生成は未接続。
上流の期待値も有限例であり、全入力における正しさや保護情報の流れの真値ではない。
実モデル呼出0、採用独立群0。名前を変えて独立試料とせず、開発用として保持する。
次はこの由来と実処理を保ったtool I/O収集・受信確認へ接続する。#204は継続する。
