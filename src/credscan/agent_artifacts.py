"""AI coding-agent artifacts: config directories, MCP server configs, and session logs.

gitleaks and trufflehog scan source code. Neither specifically parses the JSON shape AI coding
agents use for MCP server configuration (Claude Code's `.mcp.json`/`.claude/settings.json`,
Cursor's `.cursor/mcp.json`, VS Code's `mcp.json`), where a hardcoded token in an `env`, `headers`,
or `args` field is a real, plaintext, committable secret that a line-oriented `key: value` regex
alone can miss once the key is JSON-quoted. This module adds:

- `is_agent_artifact_path`, used by `credscan scan --agent-artifacts` to scope a scan to just
  these paths.
- `McpConfigSecretRule`, a structural (JSON-parsing) content rule that walks `mcpServers` blocks
  looking for literal secrets, independent of the generic line-based detectors in `detectors.py`.
"""

import json
import re
from collections.abc import Iterable
from pathlib import PurePosixPath

from credscan.detectors import matches_known_secret_shape
from credscan.entropy import is_high_entropy_secret
from credscan.models import Severity

_AGENT_CONFIG_DIR_NAMES = frozenset({".claude", ".cursor", ".codex"})
_MCP_CONFIG_FILENAMES = frozenset({"mcp.json", ".mcp.json"})
_SHELL_HISTORY_FILENAMES = frozenset(
    {".bash_history", ".zsh_history", ".python_history", "ConsoleHost_history.txt"}
)
_SESSION_LOG_SUFFIXES = frozenset({".jsonl"})

_MCP_SECRET_FIELD_NAMES = frozenset({"env", "headers"})
_PLACEHOLDER_VALUE_PATTERN = re.compile(r"^\$\{[^}]+\}$|^\$[A-Za-z_][A-Za-z0-9_]*$")


def is_agent_artifact_path(relative_path: str) -> bool:
    """True for anything `credscan scan --agent-artifacts` should include: AI coding-agent config
    directories, MCP server config files anywhere in the tree, and local session
    transcript/shell-history files that an agent may have pasted a real secret into."""
    posix_path = PurePosixPath(relative_path.replace("\\", "/"))
    directory_parts = posix_path.parts[:-1]

    if any(part in _AGENT_CONFIG_DIR_NAMES for part in directory_parts):
        return True
    if posix_path.name in _MCP_CONFIG_FILENAMES:
        return True
    if posix_path.name in _SHELL_HISTORY_FILENAMES:
        return True
    return posix_path.suffix in _SESSION_LOG_SUFFIXES


class McpConfigSecretRule:
    """Parses `mcpServers`-shaped JSON (the convention shared by Claude Code, Cursor, and VS
    Code) and flags literal secrets nested in `env`/`headers`/`args` fields at any depth -- the
    exact shape a line-oriented `key: value` regex misses once the key is JSON-quoted."""

    rule_id = "mcp-config-secret"
    rule_name = "Hardcoded secret in MCP server config"
    severity = Severity.HIGH

    def find(self, content: str) -> Iterable[tuple[int, str]]:
        try:
            document = json.loads(content)
        except ValueError:
            return
        if not isinstance(document, dict) or not isinstance(document.get("mcpServers"), dict):
            return

        reported_offsets: set[int] = set()
        for value in _iter_candidate_values(document["mcpServers"]):
            if not _looks_like_secret_value(value):
                continue
            offset = content.find(value)
            if offset == -1 or offset in reported_offsets:
                continue
            reported_offsets.add(offset)
            yield offset, value


AGENT_ARTIFACT_CONTENT_RULES = [McpConfigSecretRule()]


def _iter_candidate_values(node: object) -> Iterable[str]:
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _MCP_SECRET_FIELD_NAMES and isinstance(value, dict):
                yield from (v for v in value.values() if isinstance(v, str))
            elif key == "args" and isinstance(value, list):
                yield from (item for item in value if isinstance(item, str))
            elif isinstance(value, (dict, list)):
                yield from _iter_candidate_values(value)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_candidate_values(item)


def _looks_like_secret_value(value: str) -> bool:
    if not value or _PLACEHOLDER_VALUE_PATTERN.match(value):
        return False
    return matches_known_secret_shape(value) or is_high_entropy_secret(value)
