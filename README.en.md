# ToolUseProxy

ToolUseProxy records Codex ToolCalls, asks an isolated `codex exec` judge to infer information dependencies and external communication, and mechanically follows the resulting graph back to registered protected sources.

This branch develops **v0.2.0-alpha.2**. It does not mean the public release channel or installed Plugin has been upgraded.

- Each ToolCall is a node; actual output updates it after execution.
- Dependencies are inferred by the model, not I/O similarity scores.
- External calls with a protected-source path or an independent exact-content match are blocked.
- Witnessed resource generations connect related calls across sessions; prior judgments retain pinned revisions.
- Failed or incomplete judgments warn and continue. They are not evidence of safety or a detected leak.
- Setup starts the live log viewer, with project/session and blocked-only filters, plus a separate 2D provenance view.

Recorded I/O, source metadata, and bounded resource evidence needed for inspection are sent to the judge. New setup enables background provenance analysis, which also uses the model. Setup requires agreement to this data handling; the v0.1 local-only agreement is not reused. Hosted tools outside Codex Hook coverage cannot be intercepted. A mechanically correct traversal does not prove the inferred graph is accurate.

See the [quickstart](QUICKSTART.md), [privacy contract](PRIVACY.md), and [design](docs/設計/ToolCall意味依存グラフ.md). Historical v0.1 documents and research code are not instructions for this version.
