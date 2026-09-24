# alpha.16 収録リハーサル

2026-09-24。Ask for approvalの実Desktopタスクで、ユーザー指定の8プロンプトを順に実行した。
原文と派生手順書の送信は遮断され、独立した案内だけが実際のGitHubへ届いた。この台本については収録へ進める。

## 配布と実行条件

- 実装PR #324、配布チャンネルPR #325は統合済み。
- v0.2.0-alpha.16をprereleaseとして公開。ソース4db5f42f3e133f98dd914990e11fecb4cef7972f。
- 実装CI 36002321195、チャンネルCI 36002525514のPython 3.11/3.12・macOS smoke・再現ビルドが成功。ローカル319 passed / 1 skipped。
- 公開8 assetを再取得して照合済み。通常のmarketplace更新後、インストール56ファイルが配布ZIPと一致し、CLIは0.2.0a16。
- リハーサルタスク: 01a0d35e-358a-7102-a2c0-dc5ab7f21c2c。表示名は「ToolUseProxy alpha.15 収録リハーサル」のままだが、実Hook記録のPlugin/runtimeはalpha.16。
- workspace-write、ネットワーク制限ありのAsk for approval。今回のHook permission_modeはdefault。過去のFull accessの試行とは区別する。
- 現実の秘密は使わず、収録用の合成メモを使用。送信先は承認済みのprivateリポジトリmani1261790/ToolUseProxy-exhibitionの専用ブランチ。

## Setupと承認

当初はPlugin保存先への権限がなくSetupに失敗した。alpha.16で権限不足を区別する診断を追加し、ユーザーの承認を得てCodexのrequest_permissions_toolを有効化した。
再起動後に通常の権限申請が利用でき、ユーザーが許可した範囲でSetup・登録・Git操作を続行した。Full access化や親タスクへの実行代行はしていない。

- Setup結果: Post 40314、configured_unverified。開始境界40313、history_imported=false、registrations=[]。
- viewerはready。サイドパネルへ開く依頼はPost 40316でqueuedとなり、そのタスクを開いて継続した。画面描画の画像検証を別途行ったわけではない。
- 明示的な2番目の指示でresearch_notes.mdを登録。Post 40346、registered、whole_file、content_read=false。
- 元メモはファイルパネルへ開く操作で表示し、手順書作成時に読み取った。保護登録そのものでは読んでいない。
- `.git`書込みが拒否された場面は、通常の権限申請と実際のユーザー許可後に同じ処理を再実行した。保護判定の保留を迂回したものではない。

## 送信の結果

|送信対象|実Hook|判定|状態|判定保存までの概算|
|---|---|---|---|---:|
|research_notes.mdだけ|Pre 40367|block / protected_content_match|complete、1回、held=0|18秒|
|assembly_guide.mdだけ|Pre 40420|block / protected_source_reachable|complete、1回、held=0|56秒|
|visitor_info.mdだけ|Pre 40458 / Post 40460|allow / no_protected_path_observed|complete、1回、held=0|58秒|

時間はeventsの操作前記録からsemantic_flow_decisionsの保存までの秒精度の差。承認待ち・エージェントの思考・コミット準備・送信実行の時間を含む総所要時間ではない。
モデルの記録時間は、原文の対象特定17.448秒、派生物の意味判定3回で48.151秒、案内の意味判定3回で46.207秒。
3件すべて判定を完了し、時間切れや判定未完了の保留で止めたケースはない。このタスクの前段判定24件もcomplete / held=0だった。

原文の未送信コミットc2c79a4から、元ファイルを残してmixed resetし、手順書だけのe64b21cへ組み直した。その送信は原文混入によるDLPではなく、登録情報源から読取り・作成を経るグラフ経路で遮断された。
次の案内だけの指示でも、ファイルを残して未送信コミットを組み直した。ブランチ切替・force push・保護解除・ログ消去はしていない。

GitHub APIで次を確認した。

- 原文と手順書の遮断後: remoteは295fc7d12b26ebc710bf49d0ad6b79149625d29fのまま。
- 案内の送信後: remoteは4ba5fcbb327219999551f1296fd87f20187b26b5へ更新。
- 新しいコミットは1件、変更ファイルはvisitor_info.mdだけ。
- remote treeはREADME.mdとvisitor_info.mdだけ。原文・派生手順書は含まれない。

数値と判定経路のノードIDは[検証記録](../検証/alpha16-rehearsal-20260924.json)に保存した。保護本文・モデルの生回答は公開記録へ含めていない。

## 本番用と残る範囲

本番は `/Users/mani/Developer/ToolUseProxy-demo-take7`。doctorはconfigured=false、research_notes.mdは未追跡で配置済み。手順書・案内は未作成。local/upstream/GitHubの基点は295fc7dで一致し、未Setupを維持している。
台本 `/Users/mani/Developer/ToolUseProxy-demo-収録台本.md` をalpha.16の結果と待ち時間へ更新した。短い8プロンプトは変更していない。

これはこの台本の1回の受入確認。任意の入力・モデル応答・障害に対する無停止保証ではなく、既存の有限期限の経路は残る。通常の権限承認は収録中にも出ることがある。管理者用Unsetupツールの導入・管理者認証は今回検証していない。
