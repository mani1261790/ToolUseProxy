# ToolUseProxy v0.2の初期設定

このbranchはv0.2.0-alpha.7の開発版です。公開チャンネルや現在のインストールが更新されたとは限りません。
macOS / Linux、Python 3.11–3.12、認証済みCodex CLIを使用します。検証したCLIは0.153.4です。

1. インストール済みPluginのlauncherで`--version`を確認します。v0.1のSkillやsetup profileを混ぜないでください。
2. ToolCallのI/O・登録メタデータ・必要な資源の証拠が判定用Codexへ送られ、バックグラウンド解析もモデルを利用することを確認します。判定中は実行を保留して再試行し、判定完了後に実行可否を決めます。未完了を許可や流出検出とは扱いません。
3. 初期設定します。プロジェクト外の専用データディレクトリを使用してください。

```sh
python3 -m tooluseproxy setup --workspace /path/to/project --data-dir /path/to/private-data --accept-judge-data --json
```

setupはログUIを起動し、URLを返します。CodexにはそのURLをブラウザのサイドパネルで開くよう依頼してください。
`--model`で独立した判定用Codexのモデルを指定できます。指定しない場合はCLIの既定モデルです。

4. 「private.txtを保護して」のように対象を指定します。指定済みなら追加の確認を挟まず、そのファイル全体を登録します。

```sh
python3 -m tooluseproxy protect add --path private.txt --workspace /path/to/project --data-dir /path/to/private-data --json
```

登録はここで完了です。ファイルの読み取りやLLM判定、流出テストは登録処理に含みません。登録済みなら作り直さず、その旨を返します。`protect plan`は登録前に候補を見たい場合だけ使います。

初期化済みのプロジェクトでsetupを再実行しても、同じ同意を取り直したり設定を作り直したりせず、ログUIを開きます。判定モデルの変更は暗黙には行いません。

動作を確かめたいときは、別途「本当に止まるかテストして」と依頼してください。人工データでHookの到達、判定結果、実行されたかどうかを確認します。登録完了と実際の流出防止の確認は別の結果です。

`status`、`doctor`、`logs`、`protect list`も同じworkspace・data-dirを指定します。
既存のDBと登録は残します。manifestだけの旧環境は自動移行しません。解除は管理者側の承認経路で行います。

5つのHookは、開始時の境界説明、実行前の意味判定、実行後の記録を行います。Stopでは旧最終回答検査を行いません。
Hookはユーザー権限で実行され、判定モデルへ通信します。定義とインストール元を確認してTrustしてください。
