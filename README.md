# credscan — secrets scanner for your code *and* your AI agent's memory

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/amasen02/credscan/badge)](https://securityscorecards.dev/viewer/?uri=github.com/amasen02/credscan)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/10332/badge)](https://www.bestpractices.dev/en)
[![Security Policy](https://img.shields.io/badge/Security-Policy-blue.svg)](.github/SECURITY.md)


[![CI](https://github.com/amasen02/credscan/actions/workflows/ci.yml/badge.svg)](https://github.com/amasen02/credscan/actions/workflows/ci.yml)
[![CodeQL](https://github.com/amasen02/credscan/actions/workflows/codeql.yml/badge.svg)](https://github.com/amasen02/credscan/actions/workflows/codeql.yml)
[![Python](https://img.shields.io/badge/Python-%E2%89%A53.10-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](CONTRIBUTING.md)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-blue)](CODE_OF_CONDUCT.md)

**gitleaks scans your code. credscan also scans your AI agent's memory.**

AI coding agents (Claude Code, Cursor, Codex/VS Code) read and write plaintext config every
session: `.claude/settings.json`, `.cursor/mcp.json`, `.codex/`, and any `mcp.json` MCP server
config, all of which routinely embed real API keys and tokens in `env`/`headers`/`args` fields.
An agent can also paste a real secret straight into a session transcript. None of that is source
code, so a code-only scanner never looks there. credscan does — by default, not as an opt-in.

```
$ credscan scan .
[1] HIGH   Hardcoded secret in MCP server config (mcp-config-secret)
    .claude/settings.json:5  ghp_****************************1f0a
[2] HIGH   AWS access key ID (aws-access-key-id)
    src/config.env:12  AKIA****************MPLE

credscan: 2 finding(s) across 2 file(s).
```

## Quickstart

```bash
pip install credscan          # once published to PyPI
# or, from source:
git clone https://github.com/amasen02/credscan.git && cd credscan
pip install -e .

credscan scan .                # scan a directory (current dir by default)
credscan scan --staged         # scan only what's about to be committed
credscan scan --agent-artifacts  # scan only .claude/.cursor/.codex/MCP configs/session logs
```

### Docker

```bash
docker build -t credscan .
docker run --rm -v "$PWD":/scan credscan .
docker run --rm -v "$PWD":/scan credscan --agent-artifacts .
```

## Why this scope

gitleaks (27,982★), trufflehog (26,943★), git-secrets (13,334★), and detect-secrets (4,582★)
already do generic source-code secret scanning extremely well — there is no room for a fifth
entrant with the same feature set. What none of them specifically parse for is the JSON shape AI
coding agents converged on for MCP server configuration: a `mcpServers` block whose `env`,
`headers`, and `args` fields are exactly where a hardcoded token ends up. A `key: value` regex
built for `.env` files or shell scripts routinely misses it once the key is JSON-quoted —
`"API_KEY": "..."` doesn't match a pattern written for `API_KEY=...` or `API_KEY: ...`. credscan's
`mcp-config-secret` rule parses the JSON structurally instead of guessing at line shape, so it
generalizes across Claude Code, Cursor, and VS Code's MCP config convention rather than needing a
bespoke regex per tool.

## Usage

```
credscan scan [path] [options]
```

| Flag | Meaning |
|---|---|
| `path` | Directory to scan (default: current directory). |
| `--staged` | Scan the git *index* (what `git commit` would actually commit), not the working tree. |
| `--agent-artifacts` | Scan only AI-agent artifact paths: `.claude/`, `.cursor/`, `.codex/`, any `mcp.json`, and local session/shell-history logs (`.jsonl`, `.bash_history`, `.zsh_history`, PowerShell history). Combine with `--staged` to check only staged agent-config changes. |
| `--json` | Emit machine-readable JSON instead of text — pipe into `jq` or a CI gate. |
| `-h, --help` | Show help. |

Exit codes: `0` clean, `1` findings present (CI-friendly — fail the build on it), `2` usage or
filesystem error (not a directory, not a git repo for `--staged`, etc).

### Detectors

| Rule | Catches |
|---|---|
| `aws-access-key-id` | AWS access key IDs (`AKIA…`/`ASIA…`) |
| `aws-secret-access-key` | AWS secret keys, in `aws_secret_access_key = …` context |
| `gcp-service-account-key` | GCP service-account JSON key files |
| `private-key-pem` | PEM-encoded private keys (RSA/EC/OpenSSH/DSA/encrypted) |
| `jwt` | JSON Web Tokens |
| `github-token` | GitHub tokens (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/`github_pat_`) — their near-hex alphabet often lands under the generic entropy threshold, so this needs its own shape rule |
| `bearer-token` | `Bearer <token>` headers |
| `generic-api-key-assignment` | `api_key = "…"` / `client_secret: …` style assignments |
| `generic-high-entropy-string` | Long random-looking tokens no more specific rule already claimed |
| `mcp-config-secret` | Literal secrets nested in an MCP server config's `env`/`headers`/`args` fields |

### Suppressing false positives

- A `.credscanignore` file of path globs (one per line, `#` comments allowed), checked against
  every scanned/staged path.
- An inline `# credscan:ignore` marker on a line suppresses just that line.

Both are plain, visible, reviewable text — there is no way to silently suppress a finding that
doesn't show up in a diff.

## Tests

```bash
pip install -e ".[test]"
ruff check .
pytest
```

The suite exercises real files in `pytest`'s `tmp_path` and real throwaway git repositories for
`--staged` — not mocks — because this tool's entire value proposition is correct filesystem and
git behavior. It covers every detector (true positives, plausible false positives, and
overlap/double-report regressions), the allowlist, redaction, JSON/text rendering, the
`--agent-artifacts` path filter, and the `mcp-config-secret` structural parser (valid secrets,
`${ENV_VAR}` placeholders correctly ignored, malformed JSON handled without crashing).

## Architecture

```
src/credscan/
  cli.py              argv -> exit code; wires flags to scanner calls
  scanner.py          walks a directory or the git index, runs every rule, redacts, sorts
  detectors.py        line-based regex rules + the generic high-entropy rule (the base engine)
  agent_artifacts.py  is_agent_artifact_path() + the structural mcp-config-secret rule
  entropy.py          Shannon entropy + the shared "is this random enough to be a secret" check
  allowlist.py        .credscanignore + inline `credscan:ignore` marker
  redact.py           masks a matched secret before it's ever printed
  render.py           text/JSON output
  git_integration.py  thin `git` wrapper for --staged (reads the index blob, not the working tree)
  models.py           Finding / Severity shared types
tests/                one test module per src module, plus CLI end-to-end tests
```

## Contributing

Contributions are welcome — new detectors, fewer false positives, better docs. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the workflow and coding bar, and please be mindful of the
[Code of Conduct](CODE_OF_CONDUCT.md). Use the issue templates; green CI (lint + test) is required
on every pull request. Report security issues privately per [`SECURITY.md`](SECURITY.md) — never
as a public issue.

## Open source commitments

This project is, and will remain, free and open source. As maintainer I commit to:

- **A permissive licence, kept stable.** [MIT](LICENSE) — use it commercially, fork it, build on
  it. No relicensing of accepted contributions.
- **No CLA.** Contributions are accepted under the MIT licence; you keep the copyright to your work.
- **An honest history.** Real, walkable commits — no fabricated activity, no rewritten releases.
- **Best-effort, transparent triage.** Issues and pull requests are read and answered; security
  reports are acknowledged within 72 hours (see [`SECURITY.md`](SECURITY.md)).
- **A welcoming community** governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
- **Reproducible builds.** Green CI — lint, tests, and CodeQL security analysis — on every change.

## License

MIT — see [`LICENSE`](LICENSE). You are free to use, modify, and distribute this software,
including for commercial purposes, provided the copyright notice is retained.

## Author

**Ama Senevirathne** — [GitHub](https://github.com/amasen02)

---

## 🌟 Fork, Build Upon & Extend This Project

We deliberately built this repository to be **100% open, modular, and easy to fork and extend**:

- 🔓 **Permissive MIT License**: Zero CLA, commercial use permitted, you keep full ownership of your contributions.
- 🛡️ **Hardened Supply Chain**: Built with automated CI testing, OpenSSF Scorecard supply-chain security, and strict quality checks.
- ⚡ **High-Performance Foundation**: Zero unnecessary bloat &mdash; clean architectural boundaries that make hacking on this code a joy.

### 💡 High-Impact Ideas Ready for You to Build:
- **Add detection patterns for OpenAI API keys, Anthropic tokens, and HuggingFace credentials**
- **Add scanning for AI coding agent workspaces (.claude, .cursor, MCP server configs)**
- **Build a pre-commit git hook generator (`credscan install-hook`)**
- **Package a zero-dependency standalone binary for Linux / macOS / Windows CI runners**

### 🚀 60-Second Quickstart
```bash
git clone https://github.com/amasen02/credscan.git
cd credscan
dotnet test
```

### 🤝 Frictionless Contributions
1. **Fork** the repo & clone it locally.
2. Create your feature branch (`git checkout -b feat/my-awesome-idea`).
3. Verify tests pass cleanly.
4. Open a PR &mdash; we review and merge PRs within 24–48 hours!
