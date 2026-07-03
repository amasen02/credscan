# Contributing to credscan

Pull requests are welcome — new detectors, fewer false positives, better docs — provided they
keep the tone and quality of the codebase.

## Ground rules

1. **One concern per pull request.** No drive-by refactors mixed with feature work.
2. **Branch from `main`**, keep the branch short, and squash-merge back.
3. **Conventional commits** (`feat:`, `fix:`, `perf:`, `refactor:`, `test:`, `docs:`, `chore:`).
4. **Green CI is non-negotiable.** Lint (`ruff check`) and tests (`pytest`) must pass before review.
5. **The PR template must be filled.** Empty checkboxes block review.

## Coding standards

- **Python 3.10+, stdlib-only at runtime.** `pytest`/`ruff` are dev-only; don't add a runtime
  dependency without discussing it first — "minimal deps" is a design constraint, not a slogan.
- **Intention-revealing names.** Full descriptive identifiers; `c`, `tmp`, `mgr` are rejected.
- **Comments explain *why*, never *what*.** No filler comments or docstring padding.
- **Never print a raw secret.** Every finding goes through `credscan.redact.redact()` before it
  reaches stdout, JSON, or a log. A PR that prints an unredacted match is rejected outright.
- **New detector = new test.** Every regex needs a true-positive case, a plausible
  false-positive case it correctly ignores, and — if it can overlap with the generic
  high-entropy rule — a case proving it doesn't double-report.

## Build, test, run

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[test]"
ruff check .
pytest
credscan scan .        # exercise the CLI on this repo itself
```

## Reporting bugs and proposing features

Use the issue templates. For security vulnerabilities, **do not open a public issue** — follow
[`SECURITY.md`](SECURITY.md).
