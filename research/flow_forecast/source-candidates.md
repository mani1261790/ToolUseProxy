# 公開人工課題の設計元候補の確認（2026-09-19）

既存HTTP課題の改名を増やさず、外部の設計由来を持つ候補を調査した。
第三者コード・参考解法・外部APIは実行していない。以下は設計元調査であり、F02試料ではない。

## APIFlow-Bench

[公式README](https://github.com/postmanlabs/APIFlow-Bench/tree/501766a9ccbebe32a72bf29189ba034e34c5333a)は
467課題を13のworldから派生したsolo/chainとして説明している。各chainの短縮版や
prefixを独立課題として数えず、world内は関連群にする必要がある。
また公開済みの解答・履歴があるため、未使用holdoutの証明にもならない。
このbankだけを467独立群として採用しない。固定した版は上のcommit。

## Microsoft TaskBench

[公式README](https://github.com/microsoft/JARVIS/blob/7624cf388b47334ff8a0868e7d862dde18cfda86/taskbench/README.md)の
設計元は道具グラフのサンプリングと生成・検証工程。これは道具呼出グラフの資料であり、
ToolUseProxyによる実送信・保護停止の記録ではない。依存辺を情報流のtruthへ直接変換しない。

同commitのdata_dailylifeapis/data.json、tool_desc.json、root LICENSEの3ファイルだけを
ローカルへ取得し、Git blob SHAを公開固定版と照合した。データ原文はこのrepoへ複製しない。
MITライセンスのMicrosoft資料を設計元候補として参照する。

```sh
python -m research.flow_forecast.audit_taskbench --directory PINNED_SOURCE_DIRECTORY
```

このコマンドは固定hashのファイルだけを読み、生成文・引数・コードを実行せず集計する。
結果はresults/taskbench-source-audit-20260919.json。4,318件のうち、固定道具一覧40種と
構造が整合する4,050件を2,854の構造特徴に整理した。252件は道具一覧外、8件は未知の接続先、
4件は道具ノード重複、4件は構造の読取不成立として除外した。これは意味・正解の全件検証ではない。

実課題への次の接続では、候補ごとに人工source/receiver、実行可能な道具のI/Oと成功条件を
固定し、宣言した依存辺と実際に観測した情報流を分ける必要がある。現行HTTP DSLへ道具名だけを
置換して実行済みにしない。同じ原グラフやその派生は群を跨がせず、学習・調整・testを生成前に
割り当てる。公開データを読んだ今回の調査を未開封評価とは扱わない。

F02受入数は0、独立性/未使用性の確認はfalse。生成モデルの実解決版も依然未確認。
現在の環境ではOPENAI_API_KEY/ANTHROPIC_API_KEYの有無だけを調べ、どちらも未設定だった。
認証情報の値を出力・保存していない。既存Codex認証で得たrequested model/CLI版を、providerが証明した
モデル版へ昇格させない。#204は継続する。
