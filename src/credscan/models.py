"""Data types shared across the scanner, detectors, and renderers."""

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    rule_name: str
    severity: Severity
    file_path: str
    line_number: int
    redacted_match: str
