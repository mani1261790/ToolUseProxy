# Unsetupの実機受入（#188）

これは実施手順であり、合格記録ではない。Pluginを無効に保ち、製品の実データ・
保護リストを対象にしない。検証には専用の人工project A/Bと専用data directoryを使う。
エージェントが操作できる管理者Terminalや、エージェントへsudo権限を渡す構成では
承認分離の受入試験にならない。[導入条件](Unsetup管理者導入.md)を先に確認する。

## 候補の固定

最初の検証候補はcommit `6fa1ff95bcd2c3924f7ad7d463cb02c91ec39b94`。
release candidateの4 artifact、manifest、SHA256SUMS、SBOM、release notesを一緒に渡す。
受領した管理者は独立に確認したsource/配布物と照合し、candidate verifierを実行する。
署名があるとは扱わない。hashは改変検出であり、エージェントが作ったhashだけを
信頼の根拠にしない。候補のversion表示は開発中のalpha.24のままで、公開版ではない。

管理者用コードは `tooluseproxy-authority-admin.py`。導入時だけ固定名
`authority-admin.py` とする。配置先・mode・owner・親directory・ACL・Python実行系は
導入手順の条件に従う。既存の管理状態を上書き・消去して試験を通さない。

## 役割と証拠

| 実施者 | 操作 | 必須の観測 |
| --- | --- | --- |
| 人間の管理者 | 人工A/Bと専用dataのUID/pathを確認してenroll | A/Bともactive、対象・保持内容が日本語表示される |
| 非管理者の試験プロセス | 管理者入口を直接呼ぶ | administrator_context_required、状態不変 |
| 非管理者の試験プロセス | 管理コードと状態のwrite/delete/rename/差替えを試す | OSが拒否。試験対象は人工環境の導入物に限定 |
| 人間の管理者 | Aのdeactivateを取消す | Aはactiveのまま |
| 人間の管理者 | Aの確認表示後120秒以上待って適用 | administrator_review_expired、Aはactiveのまま |
| 人間の管理者 | Aのdeactivateを承認 | Aだけinactive、Bはactive |
| 非管理者の試験プロセス | Aの5 Hookを人工入力で実行 | 出力なし、記録増加なし、初期化要求なし |
| 非管理者の試験プロセス | Aのinit/setup/config変更/個別解除を試す | 拒否、設定・保護登録・元ファイル不変 |
| 非管理者の試験プロセス | Bの通常処理 | 従来どおり動作し、Aの停止で一括停止されない |
| 人間の管理者 | Aのreactivateを承認 | 新世代active、以前の設定と登録を保持 |

「非管理者の試験プロセス」は承認主体ではない。管理者セッションへの入力・GUI操作・
認証情報の取得を許さない。結果記録は操作名、終了code、状態と世代、件数、保持確認に
限定する。元ファイルの内容や実際の保護値を証拠へコピーしない。

## 同時実行・中断・故障

1. 人工AのHook/workerにleaseを保持させる。人間がAの停止を承認するとdeactivating。
   新しいAの処理を受け付けず、Bは動く。既存処理終了後、人間がfinishを行うとinactive。
2. 停止処理の前後で管理者用processを中断する。statusを読み、確定状態からfinishする。
   エラー表示だけで「未変更」と決めない。reactivate後に古い操作を再送しても新世代を
   停止しない。承認表示後の対象directory差替え・別projectへの付替えも拒否する。
3. 専用人工DBで排他lock、破損、DB不存在をそれぞれ作る。管理者のdeactivate/statusは
   検出DBに依存せず動作する。inactiveの5 HookもDBを開かない。
4. 故障DBを正常な人工DBへ戻して人間がreactivateする。設定・登録が保持され、通常の
   初期化/状態確認が回復する。破損DB自体をUnsetupが修復するとは扱わない。
5. 人工データの期限切れ整理とpilot比較/同期を実行し、A停止中の履歴・待機データを保持し、
   Bを含む稼働中projectの処理だけ進むことを確認する。ネットワーク送信は偽transportを使う。

## 合格記録に必要な項目

- 実施日、OS、対象候補commit/hash、使用したPythonの実体
- エージェント用と管理者用の権限分離、owner/mode/ACLの観測
- 上表と故障・中断試験それぞれの結果。未実施は明記する
- 人工A/Bの設定・登録・履歴・元ファイルの保持確認
- 現在のPluginが無効のままであること、実データへ触れていないこと

単体試験の合格だけでこの記録を埋めない。管理者境界を確保できない環境では、
通常CLIのapply拒否を維持し、#188を完了にしない。次の#189へ進むために実機の
未検証を「合格」へ読み替えない。
