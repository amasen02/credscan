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

### Changed

- Packaging metadata now uses the distinct distribution name `amasen-credscan`. The import
  package and `credscan` command remain unchanged; the README documents source and local-wheel
  installation while the distribution is unpublished.
- Removed stale competitor comparisons and unverified popularity figures from the README; the
  documentation now describes this project's scope directly.
- Dependency auditing of exact installed third-party versions is a required CI step. Audit
  installation, collection, or vulnerability failures now fail the workflow rather than being
  suppressed.
- `credscan scan --staged` now loads `.credscanignore` from the git index rather than the working
  tree. An untracked ignore file used to silence staged findings while appearing in no diff and no
  commit, contradicting the documented guarantee that every suppression is reviewable; it is now
  reported on stderr and has no effect until it is itself staged.
- A path scan names every directory it pruned from the default exclude list on stderr, so a clean
  run is never silently partial, and `--no-default-excludes` scans them (`dist/`, `build/`, and the
  rest) — build output is a common landing place for a bundler-inlined `.env`.

### Fixed

- `mcp-config-secret` no longer drops a secret whose JSON source form contains an escape. The
  rule searched the raw text for the *parsed* string, so any value written with a JSON escape
  (a PEM key's newlines, an embedded credential blob's quotes, a Windows path's backslashes)
  was recognised as a secret and then discarded with no diagnostic; it now falls back to the
  escaped source form. It also reports every location of a reused secret, not just the first.
- Findings are now deduplicated by precedence (structural content rules, then shape-specific
  line rules, then the generic high-entropy fallback) so the same underlying secret is never
  reported twice under two different rule IDs — e.g. a GitHub token inside an MCP config was
  being flagged by both `github-token` and `mcp-config-secret` before this fix.

### Removed

- The OpenSSF Best Practices badge from the README. It pointed at bestpractices.dev project 10332,
  which belongs to an unrelated third-party project, and linked to the site homepage rather than a
  project page — credscan holds no such badge, so the claim was false.
- `.github/SECURITY.md`, an unedited template that GitHub preferred over the real root
  `SECURITY.md`: it carried an unfilled `<Project Name>` placeholder, a second reporting address
  that conflicted with the documented one (so a private report could land in an unmonitored
  mailbox), and control assertions not verifiable from the repository. The hand-written root
  `SECURITY.md` is now the single policy.
