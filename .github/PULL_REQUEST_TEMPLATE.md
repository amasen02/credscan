## What

<!-- One short paragraph: what does this PR change? -->

## Why

<!-- Link an issue, or describe the driver. -->

## How

<!-- Notable design decisions, trade-offs, alternatives considered. -->

## Affected area

- [ ] Line/regex detectors
- [ ] Agent-artifact / MCP config detection
- [ ] Scanner / directory walk / `--staged`
- [ ] Allowlist (`.credscanignore` / inline markers)
- [ ] Redaction / rendering (text, JSON)
- [ ] CLI parsing / options
- [ ] Docs

## Tests

- [ ] Unit tests added or updated (true positive, plausible false positive, and — for detectors
      that can overlap the generic high-entropy rule — a no-double-report case)
- [ ] `pytest` passes locally
- [ ] `ruff check .` passes locally

## Checklist

- [ ] No secrets or credentials committed
- [ ] Every finding path still goes through `credscan.redact.redact()` before printing
- [ ] `--help` / README updated if flags or behaviour changed
- [ ] Conventional-commit title
