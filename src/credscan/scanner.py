"""Turns a directory tree or a set of staged git files into a sorted list of findings."""

import os
from collections.abc import Callable, Collection, Iterator
from pathlib import Path

from credscan import git_integration
from credscan.agent_artifacts import AGENT_ARTIFACT_CONTENT_RULES, is_agent_artifact_path
from credscan.allowlist import Allowlist
from credscan.detectors import CONTENT_RULES, HIGH_ENTROPY_RULE, LINE_RULES
from credscan.models import Finding
from credscan.redact import redact

DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        ".git", "node_modules", "__pycache__", ".venv", "venv",
        ".mypy_cache", ".pytest_cache", ".tox", "dist", "build",
    }
)
_BINARY_SNIFF_BYTES = 8192
_ALL_CONTENT_RULES = [*CONTENT_RULES, *AGENT_ARTIFACT_CONTENT_RULES]


def _finding(rule, file_path: str, line_number: int, match: str) -> Finding:
    return Finding(
        rule.rule_id, rule.rule_name, rule.severity, file_path, line_number, redact(match)
    )


def _overlaps_any(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    return any(start < claimed_end and end > claimed_start for claimed_start, claimed_end in spans)


def scan_text(file_path: str, content: str) -> list[Finding]:
    """Runs every rule against a single file's content, keyed by the path used for reporting.

    Rules run in order of specificity — content rules, then line rules, then the generic
    high-entropy fallback — and each tier skips any character span an earlier, more specific
    tier already claimed. Without this, the same underlying secret can independently satisfy
    more than one rule (e.g. a structural JSON parser and a plain regex both matching the same
    token) and get double-reported under two different rule IDs.
    """
    findings: list[Finding] = []

    content_hits: list[tuple[int, int, str, object]] = []
    for rule in _ALL_CONTENT_RULES:
        for offset, match in rule.find(content):
            content_hits.append((offset, offset + len(match), match, rule))
            line_number = content.count("\n", 0, offset) + 1
            findings.append(_finding(rule, file_path, line_number, match))

    line_starts = _line_start_offsets(content)

    for line_number, line in enumerate(content.splitlines(), start=1):
        line_start = line_starts[line_number - 1]
        line_end = line_start + len(line)
        claimed_spans: list[tuple[int, int]] = [
            (max(0, start - line_start), min(len(line), end - line_start))
            for start, end, _match, _rule in content_hits
            if start < line_end and end > line_start
        ]

        if Allowlist.is_line_ignored(line):
            continue

        for rule in LINE_RULES:
            for start, end, match in rule.finditer(line):
                if _overlaps_any(start, end, claimed_spans):
                    continue
                claimed_spans.append((start, end))
                findings.append(_finding(rule, file_path, line_number, match))

        for match in HIGH_ENTROPY_RULE.find(line, claimed_spans):
            findings.append(_finding(HIGH_ENTROPY_RULE, file_path, line_number, match))

    return findings


def _line_start_offsets(content: str) -> list[int]:
    """starts[i] is the character offset where line i+1 begins (1-based line numbering)."""
    starts = [0]
    for index, character in enumerate(content):
        if character == "\n":
            starts.append(index + 1)
    return starts


def scan_directory(
    root: Path,
    allowlist: Allowlist,
    *,
    only_agent_artifacts: bool = False,
    excluded_dirs: Collection[str] = DEFAULT_EXCLUDED_DIRS,
    on_skipped_directory: Callable[[str], None] | None = None,
) -> list[Finding]:
    """Scans every readable text file under `root`.

    Directory names in `excluded_dirs` are pruned from the walk; pass an empty collection to
    scan the whole tree (build output included). Every pruned directory is reported to
    `on_skipped_directory` so a caller can tell the user that a clean run was partial.
    """
    findings: list[Finding] = []
    for file_path in _iter_files(root, excluded_dirs, on_skipped_directory):
        relative = str(file_path.relative_to(root)).replace("\\", "/")
        if allowlist.is_path_ignored(relative):
            continue
        if only_agent_artifacts and not is_agent_artifact_path(relative):
            continue

        content = _read_text_if_not_binary(file_path)
        if content is not None:
            findings.extend(scan_text(relative, content))

    return sorted(findings, key=lambda f: (f.file_path, f.line_number, f.rule_id))


def scan_staged(
    repo_root: str, allowlist: Allowlist, *, only_agent_artifacts: bool = False
) -> list[Finding]:
    findings: list[Finding] = []
    for staged in git_integration.staged_files(repo_root):
        if allowlist.is_path_ignored(staged.path):
            continue
        if only_agent_artifacts and not is_agent_artifact_path(staged.path):
            continue
        findings.extend(scan_text(staged.path, staged.content))

    return sorted(findings, key=lambda f: (f.file_path, f.line_number, f.rule_id))


def _iter_files(
    root: Path,
    excluded_dirs: Collection[str] = DEFAULT_EXCLUDED_DIRS,
    on_skipped_directory: Callable[[str], None] | None = None,
) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        kept = []
        for name in dirnames:
            if name in excluded_dirs:
                if on_skipped_directory is not None:
                    skipped = Path(dirpath, name).relative_to(root)
                    on_skipped_directory(str(skipped).replace("\\", "/"))
            else:
                kept.append(name)
        dirnames[:] = kept
        for filename in sorted(filenames):
            yield Path(dirpath) / filename


def _read_text_if_not_binary(file_path: Path) -> str | None:
    try:
        data = file_path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:_BINARY_SNIFF_BYTES]:
        return None
    return data.decode("utf-8", errors="replace")
