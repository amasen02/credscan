"""False-positive suppression: a `.credscanignore` file of path globs, plus inline markers."""

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

INLINE_IGNORE_MARKER = "credscan:ignore"
IGNORE_FILE_NAME = ".credscanignore"


@dataclass(frozen=True)
class Allowlist:
    path_patterns: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def load(cls, directory: Path) -> "Allowlist":
        ignore_file = directory / IGNORE_FILE_NAME
        if not ignore_file.is_file():
            return cls()

        patterns = tuple(
            stripped
            for line in ignore_file.read_text(encoding="utf-8", errors="replace").splitlines()
            if (stripped := line.strip()) and not stripped.startswith("#")
        )
        return cls(patterns)

    def is_path_ignored(self, relative_path: str) -> bool:
        normalized = relative_path.replace("\\", "/")
        return any(
            fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch(Path(normalized).name, pattern)
            for pattern in self.path_patterns
        )

    @staticmethod
    def is_line_ignored(line: str) -> bool:
        return INLINE_IGNORE_MARKER in line
