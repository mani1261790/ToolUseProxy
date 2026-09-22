# ToolUseProxy v0.2の初期設定

このbranchはv0.2.0-alpha.1の開発版です。公開チャンネルや現在のインストールが更新されたとは限りません。
macOS / Linux、Python 3.11–3.12、認証済みCodex CLIを使用します。検証したCLIは0.153.4です。

1. インストール済みPluginのlauncherで`--version`を確認します。v0.1のSkillやsetup profileを混ぜないでください。
2. ToolCallのI/Oと登録メタデータが判定用Codexへ送られることを確認します。判定不能時は警告して通すので、その間の流出防止を保証しません。
3. 初期設定します。プロジェクト外の専用データディレクトリを使用してください。

```sh
python3 -m tooluseproxy setup --workspace /path/to/project --data-dir /path/to/private-data --accept-judge-data --json
```

setupはログUIを起動し、URLを返します。CodexにはそのURLをブラウザのサイドパネルで開くよう依頼してください。
`--model`で独立した判定用Codexのモデルを指定できます。指定しない場合はCLIの既定モデルです。

4. 登録するファイルを確認し、承認した対象だけを登録します。現在の新規登録はファイル全体です。

```sh
python3 -m tooluseproxy protect plan --path private.txt --workspace /path/to/project --data-dir /path/to/private-data --json
python3 -m tooluseproxy protect add --path private.txt --workspace /path/to/project --data-dir /path/to/private-data --json
```

5. まず人工データで、Hookの到達、判定結果、実行されたかどうかを確認します。`configured_unverified`やログUIの表示だけでは保護の成功を確認できません。

`status`、`doctor`、`logs`、`protect list`も同じworkspace・data-dirを指定します。
既存のDBと登録は残します。manifestだけの旧環境は自動移行しません。解除は管理者側の承認経路で行います。

5つのHookは、開始時の境界説明、実行前の意味判定、実行後の記録を行います。Stopでは旧最終回答検査を行いません。
Hookはユーザー権限で実行され、判定モデルへ通信します。定義とインストール元を確認してTrustしてください。
