# Release候補の作成と検証

public alphaのrelease候補は、wheel、sdist、Codex Plugin ZIPを個別に手作業で集めず、同じsource commitから一括生成します。

```bash
python3.11 scripts/build_release_candidate.py \
  --outdir dist/release-candidate \
  --require-clean
```

出力directoryには次の7ファイルだけが入ります。

- Python wheel
- Python sdist
- clean Codex Plugin marketplace ZIP
- `release-manifest.json`
- CycloneDX 1.7 `*.cdx.json`
- release notes候補
- `SHA256SUMS`

wheel、sdist、Plugin ZIPは同じsource treeから再buildすると同じSHA-256になります。manifestはfull Git commit ID、commit timestamp、dirty状態、Python / Plugin version、artifact role / media type / size / SHA-256、外部確認が必要なgateを記録します。absolute checkout pathやGitの変更file一覧は含めません。

既存候補はnetworkを使わず検証できます。

```bash
python3.11 scripts/build_release_candidate.py \
  --verify dist/release-candidate
```

verifierは次を確認します。

- file setがmanifestで宣言した7ファイルと完全一致する
- symlink、subdirectory、追加fileがない
- `SHA256SUMS`がchecksum file以外をexactに覆う
- manifestのsize / hashと実artifactが一致する
- wheel / sdist / Plugin manifestのversionが一致する
- CycloneDX SBOMのcomponentとartifact hashがmanifestに一致する

`artifact_set_eligible`はclean sourceとLICENSEの両方が揃った場合だけtrueになります。green CI run、manual Hook trust、実Codex task dogfood、公開承認はlocal builderから推測せず`external_required`のまま残します。candidate生成はGit tag、GitHub Release、repository公開を行いません。

GitHub Actionsの`Reproducible release candidate` jobでも、clean checkoutに対して同じbuildとoffline検証を行います。local候補を公開判断へ進める場合は、そのsource commitに対応するgreen jobを外部CI evidenceとして確認します。

候補directoryは[Pluginライフサイクル](Pluginライフサイクル.md)の`--candidate`へ渡し、immutable baselineからのupgrade / rollback / disable / removeにも同じ検証済みartifactを使えます。

SBOMはCycloneDX 1.7 JSONを使い、ToolUseProxy applicationと3つの配布artifactをSHA-256付きcomponentとして記録します。runtime third-party dependencyは現在ありません。build / test dependencyはrelease artifactへ同梱されないため、release SBOMのruntime componentには含めません。
