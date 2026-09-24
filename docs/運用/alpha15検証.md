# alpha.15 配布・インストールと収録リハーサル

2026-09-24。配布とインストールまで完了。Ask for approvalへ変更後、最初のSetupで停止した。収録台本の一周は未完了。

## 配布・インストール

- 実装PR [#321](https://github.com/mani1261790/ToolUseProxy/pull/321)をmainへ統合。mergeは5831fb6f9565b5e927ef2018a81b368c9b642497。
- 配布元ソース24fe4a92069bca699f7c91d1ae35bfc97299dc3d。main統合後もツリーに差分なし。
- 実装CI 35998838994のPython 3.11/3.12、macOS package smoke、再現ビルドが成功。
- public-alphaへの反映PR [#322](https://github.com/mani1261790/ToolUseProxy/pull/322)も統合済み。チャンネルCI 35999223822の4項目が成功。
- [v0.2.0-alpha.15](https://github.com/mani1261790/ToolUseProxy/releases/tag/v0.2.0-alpha.15)をprereleaseとして公開。公開8 assetを再取得し、検証済み候補とSHA256がすべて一致。
- 通常の `codex plugin marketplace upgrade tooluseproxy --json` が errors=[] で完了。
- インストール先の56ファイルを公開Plugin ZIPと照合。すべて一致し、ランチャーは0.2.0a15。

CIで一度、Setupスキル内の文言を確認する契約テストが失敗した。未完了状態を保持するという実際の挙動を説明文へ明示して修正し、上記CIで通過した。
有限期限による未完了の経路は残る。タイムアウトを正常な保護成功へ読み替えず、実Hookの収録条件で確かめる。

## リハーサル環境

- タスク: `01a0d35e-358a-7102-a2c0-dc5ab7f21c2c`、表示名「ToolUseProxy alpha.15 収録リハーサル」。
- ディレクトリ: `/Users/mani/Documents/Codex/2026-09-24/tooluseproxy-alpha15-rehearsal`。
- GitHub: デモ専用privateリポジトリ `mani1261790/ToolUseProxy-exhibition` の `codex/exhibition-alpha15-rehearsal`。
- 開始HEADは295fc7d12b26ebc710bf49d0ad6b79149625d29f、README.mdだけ。research_notes.mdは356 bytesで未追跡。手順書と案内は未作成。
- alpha.15のdoctorでconfigured=false。保護対象の事前登録はしていない。
- 作成直後のタスクはapproval_policy=never / danger-full-access。収録条件に合わせるため、Ask for approvalへの変更をユーザーへ依頼した。
- タスク作成APIに承認モード指定はなく、Codexアプリの自動UI操作もツール側で禁止されていた。設定変更と承認の代行はしていない。

本番のtake7は別に保持。doctorのconfigured=falseを再確認し、Setupしていない。

## 受入条件

ユーザー指定の8プロンプトを順に送り、Setup・ログ画面・明示されたファイルの登録・原文の遮断・派生物の遮断・独立した案内の実GitHub到達を確認する。
判定待ちの時間と停止理由、実Hookのruntime版とpermission_mode、送信後のremote treeを照合する。
保留や判定未完了は、保護対象の遮断に成功した件数へ含めない。
現時点の配布確認を、リハーサル完了や収録可という結論へ読み替えない。

## Ask for approvalでの最初の試行

ユーザーの設定変更後、タスクのworkspace-writeとネットワーク制限を確認した。
最初のプロンプト「このプロジェクトでToolUseProxy使いたい」を送信したが、Setupはoperation_unavailableで失敗し、doctorでもconfigured=falseだった。
原文の登録、派生物の作成、送信検査にはまだ進んでいない。これをモデルの判定未完了や時間切れと扱わない。

承認ポリシーはgranularでsandbox_approval=false、request_permissions=true。
直接公開ツールとALL_TOOLSの両方にrequest_permissionsがなく、従来のshell昇格申請も明示的に禁止されている。
ローカルCLIのfeatures listではrequest_permissions_toolがfalse。申請機能を有効化する設定変更をユーザーへ確認中で、権限設定を勝手に変えてはいない。

製品側の修正として、OSのPermissionErrorとSQLiteのREADONLYを、内容を漏らさないfilesystem_access_requiredへ分類する。
Skillへ通常の承認経路と、申請機能がないときに迂回しない手順を追加した。これは承認機能の追加・権限の自動付与ではない。
