# Qwen3の公開manifestとローカルファイルの照合（#204）

PR #269の生成応答に記録したmanifest識別子を、Ollamaの公開registryとローカルの
実ファイルへ結び付けた。新しいモデル呼出やtrial、モデルのダウンロードは行っていない。

[公開registryの8b tag](https://registry.ollama.ai/v2/library/qwen3/manifests/8b)から
HTTPSで859bytesを取得し、生成時の観測hashと同一であることを確認した。
タグの将来の不変性は仮定せず、[取得した原本](results/qwen3-8b-manifest-500a1f067a9f.json)を
改行・整形せず保存した。digestをURLに指定した取得は404で、tagから取得した原本の
SHA-256を照合している。

- manifest SHA-256: `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`
- 生成観測SHA-256: `a37e9987e1ef2298880049753f868b818ea2c700fc2bad9a2d56ee1ac142a02c`
- model blob SHA-256: `a3de86cd1c132c822487ededd47a324c50491393e6565cd14bafa40d0b8e686f`

manifestに列挙されたconfig/model/template/license/paramsの5ファイルだけを、既存の
ローカルblobsから読んだ。各digestはsha256形式に限定し、O_NOFOLLOWで開き、通常ファイルと
宣言サイズを確認した。1MiBずつSHA-256を計算し、各ファイルの読み取り前後とpathの
device/inode/size/mtime/ctimeが一致することを確認した。結果は5ファイルとも一致。
全ファイルを同一時刻にロックした検査ではない。既存ファイルの変更・削除は行っていない。

読取量は5,225,388,164bytes、経過7.915秒。60秒の経過上限を各読取ループで確認した。
読み取ったモデルbytesは新たに保存しておらず、収集artifactはmanifestとhash等の小さな記録のみ。
[実測記録](results/qwen3-artifact-verification-20260920.json)に全blobのサイズとhashを保存した。

## この証拠が示す範囲

生成応答で観測したmanifestが公開されたどの構成を指すか、その構成と同じ内容の
ローカルファイルが後日の検査時点で存在することを確認した。単なるモデル名の自己申告より
照合可能な証拠を増やしたが、推論サーバーのメモリにその重みが実際に読み込まれたことを
遡って証明したものではない。`inference_loaded_weights_attested`と
`resolved_model_verified`はfalseのまま。生成receiptや旧collectionのsealは変更していない。

再確認では原本manifestのSHA-256と生成観測の識別子を照合し、その原本に列挙された
5つのsha256 blobの内容・サイズを照合する。mutable tagの現在の応答が異なる場合は
過去の観測を置き換えない。これだけで固定モデル版の受入、費用、独立群、未使用testの
有効性が達成されたとは扱わない。#204は未完了。
