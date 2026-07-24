# Security policy

## Supported versions

ToolUseProxy is currently a public alpha. Security fixes are applied
only to the latest `0.1.0-alpha.x` release. Older alpha builds are unsupported.

## Reporting a vulnerability

Do not open a public Issue when a report may contain a secret, protected source,
local path, Hook payload, database content, or instructions for bypassing a
security boundary.

Use GitHub's private vulnerability reporting form instead:

<https://github.com/mani1261790/ToolUseProxy/security/advisories/new>

Include the affected ToolUseProxy version, operating system, Codex version,
reproduction steps, and security impact. Replace real secrets and private
content with synthetic values before submitting whenever possible.

ToolUseProxy is a research implementation, not a complete DLP system. Until a
fix is available, disable enforcement or remove the Plugin and follow the
retention guidance in [PRIVACY.md](PRIVACY.md). If a real credential may have
been exposed, revoke or rotate it independently of this report.
