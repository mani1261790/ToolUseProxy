# Pythonの固定HTTP送信の検証

Issue #140。送信内容を確認できないPythonを一律許可せず、完全に解釈できる
限定形式だけを既存の保護情報照合へ接続する。実利用Pluginの有効化は伴わない。

## 対象となる形式

- 単一の静的なshellコマンド `python -I -S -B -c '<script>'`。
  python3、/usr/bin/python3、/usr/local/bin/pythonも同じ引数で扱う。
- スクリプトは `python_http_payload.py` の2つの生成関数が表すASTと一致するもの。
  `urllib.request` のHTTP専用OpenerDirector、または `http.client.HTTPConnection`
  を使い、固定URL/host/port/path、固定bytesのbody、固定文字列のheadersをPOSTする。
- `-I -S`でユーザーsite、site初期化、Python環境変数由来のimportを避ける。
  urllibはHTTPHandlerだけを明示し、環境proxy・redirect・HTTPS handlerを追加しない。
  HTTPConnectionも環境proxyを使用しない。正常終了はHTTP 204を要求する。
- 標準Pythonと標準ライブラリが信頼できることが前提。実行ファイルの差し替えや
  shell aliasまで証明するサンドボックスではない。Docker人工試験では固定image、
  read-only root、固定entrypointと、検査・実行する引数の一致を別途確認する。

抽出するのはbodyだけではなく送信先と全header。workspaceの保護chunk全件と比較し、
通常の正規化・類似照合に加えてBase64、URL-safe Base64、hex、URL encoding、
JSONのunicode escape表現も照合する。件数・サイズ・時間の制限超過は未確認として拒否する。
先に得たlineage等の拒否判定を解除せず、未確認sinkの追加拒否だけを省略する。

## 未対応のまま拒否するもの

任意のPython、追加import/呼出し/代入、ファイル読み取り、環境変数、動的URL、
bytesの計算、split/codepoints/reversedによる構成、複数shell命令、リダイレクト、
起動フラグ不足、HTTPSなど。旧 `urlopen` 形式も環境proxyやredirectの影響を
閉じていないため未確認のまま。あらゆる符号化や未知の表現の漏洩防止は主張しない。

## 検証と証拠

- parser/照合/Hook回帰試験で公開文字列の許可と、保護文字列、既知の符号化、
  ファイル参照、追加処理の拒否を確認。
- 標準ライブラリによる人工loopback受信試験で、環境proxyが指定されていても
  固定受信先に届き、302 redirect先へ追加送信しないことを確認。
- #130の48形式（source × encoding × representation × client）を回帰試験化。
  public/literalの4形式のみ検証済みとし、その他は保守的拒否を維持する。
- #131の旧新版比較は同じ更新済みの送信コードを両方に渡す。
  送信器の起動フラグとHTTP処理も変更したため、旧urlopen形式自体を許可できた
  という意味ではない。実行されるsenderも検査対象と同じ `-I -S -B -c` を使う。
- 2026-09-18の人工Docker比較: 旧版 source-321e89c…、新版 source-2059fed…。
  5ケース・20試行、元の2操作を公開文字列1操作へ短縮。旧版は未確認payloadで拒否、
  新版は公開文字列を受信・完了し、独立した保護情報の停止対照も成立。結果improved。
  ローカル証拠 `/private/tmp/tooluseproxy-140-first-comparison` と
  `/private/tmp/tooluseproxy-140-first-report.json` に保存。

これは閉じた人工HTTP試験の結果。実利用Hookの再有効化、任意Pythonの安全性、
実利用全体の正解率や#188の管理者受入を証明するものではない。

同日のDocker全48形式試験も完了。public/literalの4形式は実行・到達・完了、
残る44形式は実行前拒否・未到達、保護情報の到達0件。5ケースすべてで公開受信・
保護受信・保護停止の独立対照が成立した。証拠は
`/private/tmp/tooluseproxy-140-matrix` と `/private/tmp/tooluseproxy-140-matrix-report.json`。
