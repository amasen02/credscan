# Security policy

credscan is a local static-analysis CLI: it reads files you point it at (or your git index for
`--staged`) and prints findings. It makes no network calls and writes nothing back to disk.

## Security-relevant behaviour

| Area | Behaviour |
|---|---|
| Redaction | Every finding is redacted (`credscan.redact.redact`) before it is printed, whether as text or JSON — a full secret never reaches stdout, a CI log, or a saved report. |
| False negatives | This is a best-effort pattern/entropy scanner, not a guarantee. A clean `credscan` run is evidence, not proof, that no secret is present — it is one layer in a defense-in-depth strategy (pre-commit hook, CI gate, provider-side secret scanning), not a replacement for any of them. |
| `--staged` scope | Reads the git *index* blob (`git show :path`), i.e. exactly what would be committed — not the working-tree copy, so a secret you fixed but forgot to re-stage is still correctly flagged. |
| Allowlist | `.credscanignore` and inline `# credscan:ignore` markers suppress findings. Both are visible, reviewable, plain-text mechanisms — there is no way to silently suppress a finding that doesn't show up in a diff. |
| Telemetry | None. credscan makes no network calls. |

## Reporting a vulnerability

Email `amasen02@gmail.com` with the subject prefix `[SECURITY]`, or open a private
[GitHub security advisory](https://github.com/amasen02/credscan/security/advisories/new).
**Do not open a public issue.** Expect acknowledgement within 72 hours.

## Coordinated disclosure window

90 days from acknowledgement, unless mutually extended.
