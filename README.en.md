# ToolUseProxy

ToolUseProxy records Codex ToolCalls, asks an isolated `codex exec` judge to infer information dependencies and external communication, and mechanically follows the resulting graph back to registered protected sources.

This branch develops **v0.2.0-alpha.1**. It does not mean the public release channel or installed Plugin has been upgraded.

- Each ToolCall is a node; actual output updates it after execution.
- Dependencies are inferred by the model, not I/O similarity scores.
- External calls with a protected-source path are blocked.
- Failed or incomplete judgments warn and continue. They are not evidence of safety or a detected leak.
- Setup starts the live log viewer, with project/session and blocked-only filters.

Recorded I/O and source metadata are sent to the judge. Setup requires agreement to this data handling; the v0.1 local-only agreement is not reused. Hosted tools outside Codex Hook coverage cannot be intercepted. A mechanically correct traversal does not prove the inferred graph is accurate.

See the [quickstart](QUICKSTART.md), [privacy contract](PRIVACY.md), and [design](docs/設計/ToolCall意味依存グラフ.md). Historical v0.1 documents and research code are not instructions for this version.
