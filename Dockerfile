# syntax=docker/dockerfile:1

# ---- Test gate: fails the build if lint or the test suite fails ----------------
# git is required at test time (the git-integration/staged-scan tests shell out to it) and at
# runtime (credscan itself shells out to it for `scan --staged`) — not a test-only dependency.
FROM python:3.13-slim AS test
WORKDIR /src

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY src/ src/
COPY tests/ tests/
RUN pip install --no-cache-dir --root-user-action=ignore ".[test]" \
    && ruff check . \
    && pytest -q

# ---- Runtime: a fresh, minimal install with none of the test/lint tooling ------
FROM python:3.13-slim AS runtime
WORKDIR /scan

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=test /src /src
RUN pip install --no-cache-dir --root-user-action=ignore /src \
    && rm -rf /src

RUN useradd --uid 1000 --shell /bin/false credscan
USER credscan

# The "scan" subcommand is baked into the entrypoint so `docker run <image> <path-or-flags>`
# maps directly onto `credscan scan <path-or-flags>`, matching the README's usage examples.
ENTRYPOINT ["credscan", "scan"]
CMD ["--help"]
