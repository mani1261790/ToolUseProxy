# 過去の設計・運用・評価資料

[現在の文書一覧](../索引.md) · [最新の引き継ぎ](../運用/次セッション引き継ぎ.md)

ここには旧仕様と過去の検証記録を集約しています。「現在」「次」「未実装」は作成当時の意味です。現行の操作手順や検証済み範囲として使わないでください。週報は[GitHub Issues](https://github.com/mani1261790/ToolUseProxy/issues?q=label%3Aweekly-report)で管理します。

## v0.1の設計・運用

- [プライバシーとデータ保持](v0.1/PRIVACY.md)
- [Codex Plugin 導入](v0.1/Plugin導入.md)
- [ToolUseProxy 5分クイックスタート](v0.1/QUICKSTART.md)
- [ToolUseProxy（v0.1.0-alpha.24当時）](v0.1/README.en.md)
- [サポート範囲と既知の制限](v0.1/SUPPORT.md)
- [アーキテクチャ概要](v0.1/アーキテクチャ.md)
- [ToolUseProxy 現行研究方針](v0.1/研究方針.md)
- [Hookの設定](v0.1/設定/Hook設定.md)
- [Workspace runtime設定](v0.1/設定/Runtime設定.md)
- [外部通信の分類器](v0.1/設計/ExternalityJudge.md)
- [Policy判断](v0.1/設計/Policy判断.md)
- [Redact設計](v0.1/設計/Redact.md)
- [Sink payload evidenceの設計](v0.1/設計/SinkPayloadEvidence.md)
- [ツール入力の変換器](v0.1/設計/アダプター.md)
- [保存容量と自動整理](v0.1/設計/保存容量と自動整理.md)
- [保存内容の重複削減](v0.1/設計/保存重複削減.md)
- [情報流グラフの可視化](v0.1/設計/可視化.md)
- [外部流出の候補](v0.1/設計/外部流出候補.md)
- [実プロジェクト試行の記録・比較・改善提案](v0.1/設計/実プロジェクト試行.md)
- [情報流追跡の設計指針](v0.1/設計/情報流追跡.md)
- [漏えいの検出](v0.1/設計/漏えい検知.md)
- [Sink中心の情報流評価計画](v0.1/調査/Sink中心の情報流評価計画.md)
- [Codex Desktopの実機確認（第2段階）](v0.1/運用/DesktopPhaseB.md)
- [Codex Desktop update / rollback 検証計画](v0.1/運用/DesktopUpdateRollback.md)
- [Externality Protectionロードマップ](v0.1/運用/ExternalityProtectionRoadmap.md)
- [Pluginドッグフード](v0.1/運用/Pluginドッグフード.md)
- [プラグインの更新・復元のリハーサル](v0.1/運用/Pluginライフサイクル.md)
- [Sink-first比較評価](v0.1/運用/Sink-first比較評価.md)
- [repository外holdout評価](v0.1/運用/外部holdout評価.md)
- [類似度baseline評価](v0.1/運用/類似度評価.md)

## v0.2の変更経緯と版別検証

- [SQLiteによる動的プロパティグラフ](v0.2/SQLiteプロパティグラフ初期実装.md)
- [ToolCall記録から作る意味依存グラフ](v0.2/設計/ToolCall意味依存グラフ.md)
- [情報流検査の統合実装計画](v0.2/設計/情報流検査の統合実装計画.md)
- [情報継承グラフの再設計計画](v0.2/設計/情報継承グラフの再設計計画.md)
- [実装順とデータ整理（2026-09-18）](v0.2/運用/2026-09-18-実装順とデータ整理.md)
- [2026-09-24 alpha.16 実Desktopリハーサル完了](v0.2/運用/2026-09-24までの引き継ぎ.md)
- [v0.2.0-alpha.11 の検証状況](v0.2/運用/alpha11検証.md)
- [v0.2.0-alpha.12 の検証状況](v0.2/運用/alpha12検証.md)
- [alpha.13 の実Hook検証](v0.2/運用/alpha13検証.md)
- [alpha.14 検証](v0.2/運用/alpha14検証.md)
- [alpha.15 配布・インストールと収録リハーサル](v0.2/運用/alpha15検証.md)
- [alpha.16 収録リハーサル](v0.2/運用/alpha16検証.md)
- [判定完了までの実行保留への修正計画](v0.2/運用/判定完了までの実行保留.md)
- [現行実装タスク](v0.2/運用/実装タスク.md)
- [v0.2.0-alpha.2の実装と検証](v0.2/運用/情報流検査-alpha2検証.md)

## 初期の運用記録

- [実装タスク計画（2026-08-10時点・履歴）](運用/実装タスク-2026-08-10.md)

## 初期の調査記録

- [Network egress観測とAudit改善計画（履歴）](調査/NetworkEgress観測とAudit改善計画.md)
