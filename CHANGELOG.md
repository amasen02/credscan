# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial release: `credscan scan [path]` and `credscan scan --staged`, detectors for AWS
  access/secret keys, GCP service-account JSON, PEM private keys, JWTs, Bearer/API tokens, and
  generic high-entropy strings, `.credscanignore` + inline `# credscan:ignore` allowlisting,
  exit code 1 on findings, JSON and text output, and a Dockerfile.
- AI coding-agent artifact scanning: full-repo scans now include `.claude/`, `.cursor/`,
  `.codex/`, any `mcp.json`, and local session/shell-history files by default (they were never
  excluded, but this is now explicitly tested), plus a structural JSON detector
  (`mcp-config-secret`) that parses `mcpServers` blocks and flags hardcoded secrets nested in
  `env`, `headers`, and `args` fields — the shape a line-oriented scanner alone can miss once the
  key is JSON-quoted.
- `credscan scan --agent-artifacts` to scan only those agent-specific paths.
- `github-token` detector for GitHub's documented token prefixes (`ghp_`/`gho_`/`ghu_`/`ghs_`/
  `ghr_`/`github_pat_`). Found via manual verification against a planted MCP-config secret: real
  GitHub tokens are near-hex and routinely fall under the generic 4.5-bits/char entropy
  threshold, so without a dedicated shape rule this extremely common credential type went
  undetected by every existing rule.

### Fixed

- Findings are now deduplicated by precedence (structural content rules, then shape-specific
  line rules, then the generic high-entropy fallback) so the same underlying secret is never
  reported twice under two different rule IDs — e.g. a GitHub token inside an MCP config was
  being flagged by both `github-token` and `mcp-config-secret` before this fix.
