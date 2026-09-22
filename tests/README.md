# v0.2の検証対象

`python -m pytest -q`はpyproject.tomlに列挙したv0.2製品契約を実行する。
新Hook・モデル結果の検証・到達性・workspace/session・管理者状態・登録・setup・ライブUI・配布物を対象とする。
旧類似度の正解率を、新方式の品質証拠にはしない。実LLMを使う人工試験は
`python -m scripts.probe_semantic_flow`で別に行い、CIからモデルを無断で呼ばない。

旧テストと旧スクリプトは `legacy/v0.1/tests-and-tools.tar.gz` に隔離した。
現行の `tests/` にはv0.2の試験だけを置く。再現方法は `legacy/README.md` を参照。
旧DB互換性のため、tests/conftest.pyだけが旧コードの探索パスを追加する。
製品の起動経路には追加しない。

今回、明示的に全履歴テストを実行した結果は2,785件＋補助1,609件成功、38件失敗、2件skipだった。
38件を成功として数え直すのではなく、旧仕様との非互換、公開元監査、既存の並行試験の失敗を
残したまま記録する。新しい製品試験の成功と、旧全体試験の成功を混同しない。

配布物はソースツリー外へ展開して検証する。Hookは旧hook_monitorをimportしてはならず、
wheel・Pluginに旧CLI・旧解析器を含めてはならない。登録や管理者停止の検証も省かない。
