import json
from pathlib import Path

from credscan.agent_artifacts import McpConfigSecretRule, is_agent_artifact_path
from credscan.allowlist import Allowlist
from credscan.scanner import scan_directory, scan_text

_RULE = McpConfigSecretRule()

# A proven high-entropy token (>= 4.5 bits/char) — the same shape already used to exercise the
# generic high-entropy detector elsewhere, so these tests aren't relying on the arbitrary "looks
# secret-ish" appearance of a hand-picked string.
_HIGH_ENTROPY_TOKEN = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
_AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"


def test_is_agent_artifact_path_matches_known_agent_config_directories():
    assert is_agent_artifact_path(".claude/settings.json")
    assert is_agent_artifact_path(".claude/settings.local.json")
    assert is_agent_artifact_path(".cursor/mcp.json")
    assert is_agent_artifact_path(".codex/config.toml")
    assert is_agent_artifact_path("nested/project/.claude/skills/foo.md")


def test_is_agent_artifact_path_matches_mcp_config_filenames_anywhere():
    assert is_agent_artifact_path("mcp.json")
    assert is_agent_artifact_path(".mcp.json")
    assert is_agent_artifact_path("some/deep/path/mcp.json")


def test_is_agent_artifact_path_matches_shell_history_and_session_logs():
    assert is_agent_artifact_path(".bash_history")
    assert is_agent_artifact_path(".zsh_history")
    assert is_agent_artifact_path("ConsoleHost_history.txt")
    assert is_agent_artifact_path("projects/session-transcript.jsonl")


def test_is_agent_artifact_path_ignores_ordinary_source_files():
    assert not is_agent_artifact_path("src/app.py")
    assert not is_agent_artifact_path("README.md")
    assert not is_agent_artifact_path(".github/workflows/ci.yml")


def test_mcp_config_rule_flags_a_hardcoded_secret_in_env():
    content = json.dumps(
        {
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {"GITHUB_TOKEN": _HIGH_ENTROPY_TOKEN},
                }
            }
        }
    )

    results = list(_RULE.find(content))

    assert results == [(content.find(_HIGH_ENTROPY_TOKEN), _HIGH_ENTROPY_TOKEN)]


def test_mcp_config_rule_flags_a_hardcoded_secret_in_headers():
    content = json.dumps(
        {
            "mcpServers": {
                "remote-api": {
                    "url": "https://api.example.com/mcp",
                    "headers": {"Authorization": _HIGH_ENTROPY_TOKEN},
                }
            }
        }
    )

    results = list(_RULE.find(content))

    assert results == [(content.find(_HIGH_ENTROPY_TOKEN), _HIGH_ENTROPY_TOKEN)]


def test_mcp_config_rule_flags_a_secret_passed_as_a_cli_arg():
    content = json.dumps(
        {
            "mcpServers": {
                "custom": {
                    "command": "my-mcp-server",
                    "args": ["--api-key", _AWS_ACCESS_KEY],
                }
            }
        }
    )

    results = list(_RULE.find(content))

    assert results == [(content.find(_AWS_ACCESS_KEY), _AWS_ACCESS_KEY)]


def test_mcp_config_rule_ignores_environment_variable_placeholders():
    content = json.dumps(
        {
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}", "OTHER": "$OTHER_VAR"},
                }
            }
        }
    )

    assert list(_RULE.find(content)) == []


def test_mcp_config_rule_ignores_short_low_entropy_args():
    content = json.dumps(
        {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@some/mcp-server"]}}}
    )

    assert list(_RULE.find(content)) == []


def test_mcp_config_rule_ignores_json_without_an_mcp_servers_key():
    content = json.dumps({"someOtherConfig": {"env": {"TOKEN": _AWS_ACCESS_KEY}}})

    assert list(_RULE.find(content)) == []


def test_mcp_config_rule_ignores_content_that_is_not_valid_json():
    assert list(_RULE.find("not json at all { env: broken")) == []


def test_mcp_config_rule_reports_the_correct_line_number_via_scan_text():
    content = (
        "{\n"
        '  "mcpServers": {\n'
        '    "github": {\n'
        '      "env": {\n'
        f'        "GITHUB_TOKEN": "{_HIGH_ENTROPY_TOKEN}"\n'
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n"
    )

    findings = scan_text(".claude/settings.json", content)

    # The raw token also independently trips the generic line-based high-entropy rule (same
    # co-occurrence the existing GCP content-rule test accounts for) -- assert the MCP-specific
    # finding is present and correctly placed, rather than that it's the only finding.
    mcp_findings = [f for f in findings if f.rule_id == "mcp-config-secret"]
    assert len(mcp_findings) == 1
    assert mcp_findings[0].line_number == 5


def test_scan_directory_finds_a_planted_secret_under_dot_claude_by_default(tmp_path: Path):
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text(
        json.dumps({"mcpServers": {"github": {"env": {"GITHUB_TOKEN": _HIGH_ENTROPY_TOKEN}}}}),
        encoding="utf-8",
    )

    findings = scan_directory(tmp_path, Allowlist())

    assert any(f.rule_id == "mcp-config-secret" for f in findings)
    assert any(f.file_path == ".claude/settings.json" for f in findings)


def test_scan_directory_with_agent_artifacts_only_skips_ordinary_source_files(tmp_path: Path):
    (tmp_path / "app.py").write_text(f"AWS_ACCESS_KEY_ID={_AWS_ACCESS_KEY}\n", encoding="utf-8")
    cursor_dir = tmp_path / ".cursor"
    cursor_dir.mkdir()
    (cursor_dir / "mcp.json").write_text(
        json.dumps({"mcpServers": {"svc": {"env": {"TOKEN": _HIGH_ENTROPY_TOKEN}}}}),
        encoding="utf-8",
    )

    findings = scan_directory(tmp_path, Allowlist(), only_agent_artifacts=True)

    assert {f.file_path for f in findings} == {".cursor/mcp.json"}


def test_scan_directory_without_agent_artifacts_only_still_scans_everything(tmp_path: Path):
    (tmp_path / "app.py").write_text(f"AWS_ACCESS_KEY_ID={_AWS_ACCESS_KEY}\n", encoding="utf-8")

    findings = scan_directory(tmp_path, Allowlist(), only_agent_artifacts=True)

    assert findings == []
