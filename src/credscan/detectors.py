"""Regex/entropy rules that turn a line (or whole file) of text into candidate secrets.

Each rule finds the *sensitive substring* it cares about, not the whole line — that substring is
what gets redacted and reported, so a rule matching too much of the line would leak more of the
secret into the finding than necessary.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass

from credscan.entropy import HIGH_ENTROPY_MIN_LENGTH, is_high_entropy_secret
from credscan.models import Severity

_CANDIDATE_TOKEN_PATTERN = re.compile(rf"[A-Za-z0-9+/_=-]{{{HIGH_ENTROPY_MIN_LENGTH},}}")


@dataclass(frozen=True)
class LineRule:
    """A rule evaluated independently against each physical line of a file."""

    rule_id: str
    rule_name: str
    severity: Severity
    pattern: re.Pattern[str]
    group: int = 0

    def finditer(self, line: str) -> Iterable[tuple[int, int, str]]:
        """Yields (start, end, matched text) for the sensitive group of every match on the line."""
        for match in self.pattern.finditer(line):
            yield match.start(self.group), match.end(self.group), match.group(self.group)


@dataclass(frozen=True)
class ContentRule:
    """A rule that needs the whole file's content to decide (e.g. two JSON fields co-occurring)."""

    rule_id: str
    rule_name: str
    severity: Severity

    def find(self, content: str) -> Iterable[tuple[int, str]]:
        """Yields (character offset into content, matched text) pairs."""
        raise NotImplementedError


class GcpServiceAccountKeyRule(ContentRule):
    _TYPE_MARKER = re.compile(r'"type"\s*:\s*"service_account"')
    _PRIVATE_KEY_FIELD = re.compile(r'"private_key"\s*:\s*"')

    def __init__(self) -> None:
        super().__init__(
            rule_id="gcp-service-account-key",
            rule_name="GCP service-account key (JSON)",
            severity=Severity.HIGH,
        )

    def find(self, content: str) -> Iterable[tuple[int, str]]:
        if not self._TYPE_MARKER.search(content):
            return
        match = self._PRIVATE_KEY_FIELD.search(content)
        if match:
            yield match.start(), "private_key"


class HighEntropyStringRule:
    """Flags long random-looking tokens whose character span no more specific rule already claimed.

    Span overlap (not substring comparison) is what makes this correct: a more specific rule's
    match can span characters — e.g. the dots in a JWT — that this rule's own candidate-token
    regex splits on, so comparing matched *text* would miss the overlap and double-report a
    fragment of an already-classified secret.
    """

    rule_id = "generic-high-entropy-string"
    rule_name = "Generic high-entropy string"
    severity = Severity.MEDIUM

    def find(self, line: str, claimed_spans: list[tuple[int, int]]) -> Iterable[str]:
        for match in _CANDIDATE_TOKEN_PATTERN.finditer(line):
            start, end = match.span()
            if any(
                start < claimed_end and end > claimed_start
                for claimed_start, claimed_end in claimed_spans
            ):
                continue
            token = match.group(0)
            if is_high_entropy_secret(token):
                yield token


LINE_RULES: list[LineRule] = [
    LineRule(
        rule_id="aws-access-key-id",
        rule_name="AWS access key ID",
        severity=Severity.HIGH,
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    LineRule(
        rule_id="aws-secret-access-key",
        rule_name="AWS secret access key",
        severity=Severity.HIGH,
        pattern=re.compile(r'(?i)aws_secret_access_key\s*[:=]\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?'),
        group=1,
    ),
    LineRule(
        rule_id="private-key-pem",
        rule_name="Private key (PEM)",
        severity=Severity.HIGH,
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    ),
    LineRule(
        # GitHub's documented token prefixes. These alphabets skew hex/base62-heavy enough that
        # real tokens routinely land under the 4.5 bits/char generic-entropy threshold, so without
        # a dedicated shape rule this extremely common credential type would go undetected.
        rule_id="github-token",
        rule_name="GitHub token",
        severity=Severity.HIGH,
        pattern=re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
    ),
    LineRule(
        rule_id="jwt",
        rule_name="JSON Web Token",
        severity=Severity.MEDIUM,
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    LineRule(
        rule_id="bearer-token",
        rule_name="Bearer token",
        severity=Severity.MEDIUM,
        pattern=re.compile(r"(?i)\bbearer\s+([A-Za-z0-9\-_.=]{16,})"),
        group=1,
    ),
    LineRule(
        rule_id="generic-api-key-assignment",
        rule_name="Generic API key/secret assignment",
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"(?i)\b(?:api[_-]?key|api[_-]?token|secret[_-]?key|access[_-]?token|client[_-]?secret)"
            r"\b\s*[:=]\s*['\"]?([A-Za-z0-9\-_./+]{16,})['\"]?"
        ),
        group=1,
    ),
]

CONTENT_RULES: list[ContentRule] = [GcpServiceAccountKeyRule()]

HIGH_ENTROPY_RULE = HighEntropyStringRule()

_VALUE_SHAPE_RULE_IDS = frozenset({"aws-access-key-id", "private-key-pem", "jwt", "github-token"})
_VALUE_SHAPE_RULES = [rule for rule in LINE_RULES if rule.rule_id in _VALUE_SHAPE_RULE_IDS]


def matches_known_secret_shape(value: str) -> bool:
    """Whether `value` alone (no surrounding `key = ` context) matches a known secret shape --
    for callers that pull a bare value out of a structured field (e.g. an MCP config's JSON
    `env`/`headers` map) rather than matching a `key: value` line."""
    return any(rule.pattern.search(value) for rule in _VALUE_SHAPE_RULES)
