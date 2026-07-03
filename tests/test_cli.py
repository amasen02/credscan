import json
import subprocess
from pathlib import Path

import pytest

from credscan.cli import main


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


def test_scan_clean_directory_exits_zero(tmp_path: Path, capsys):
    (tmp_path / "notes.txt").write_text("nothing sensitive here", encoding="utf-8")

    exit_code = main(["scan", str(tmp_path)])

    assert exit_code == 0
    assert "no secrets found" in capsys.readouterr().out


def test_scan_directory_with_secret_exits_one(tmp_path: Path, capsys):
    (tmp_path / "config.env").write_text(
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8"
    )

    exit_code = main(["scan", str(tmp_path)])

    assert exit_code == 1
    assert "AWS access key ID" in capsys.readouterr().out


def test_scan_json_flag_emits_valid_json(tmp_path: Path, capsys):
    (tmp_path / "config.env").write_text(
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8"
    )

    exit_code = main(["scan", str(tmp_path), "--json"])

    assert exit_code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["findingCount"] == 1


def test_scan_missing_directory_exits_two(capsys):
    exit_code = main(["scan", "/definitely/not/a/real/path/credscan-test"])

    assert exit_code == 2
    assert "credscan:" in capsys.readouterr().err


def test_no_subcommand_prints_help_and_exits_two(capsys):
    exit_code = main([])

    assert exit_code == 2
    assert "usage" in capsys.readouterr().out.lower()


def test_scan_defaults_to_current_directory(tmp_path: Path, monkeypatch, capsys):
    (tmp_path / "config.env").write_text(
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)

    exit_code = main(["scan"])

    assert exit_code == 1
    assert "config.env" in capsys.readouterr().out


def test_scan_staged_flag_scans_the_git_index(tmp_path: Path, capsys):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test")
    (tmp_path / "secret.env").write_text(
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8"
    )
    _git(tmp_path, "add", "secret.env")

    exit_code = main(["scan", "--staged", str(tmp_path)])

    assert exit_code == 1
    assert "secret.env" in capsys.readouterr().out


def test_scan_staged_outside_git_repo_exits_two(tmp_path: Path, capsys):
    exit_code = main(["scan", "--staged", str(tmp_path)])

    assert exit_code == 2
    assert "credscan:" in capsys.readouterr().err


def test_agent_artifacts_flag_scans_only_agent_paths(tmp_path: Path, capsys):
    (tmp_path / "app.py").write_text(
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8"
    )
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text(
        json.dumps(
            {"mcpServers": {"svc": {"env": {"TOKEN": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}}}}
        ),
        encoding="utf-8",
    )

    exit_code = main(["scan", str(tmp_path), "--agent-artifacts"])
    output = capsys.readouterr().out

    assert exit_code == 1
    assert ".claude/settings.json" in output
    assert "app.py" not in output


def test_agent_artifacts_flag_on_a_clean_agent_config_exits_zero(tmp_path: Path, capsys):
    (tmp_path / "app.py").write_text(
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8"
    )

    exit_code = main(["scan", str(tmp_path), "--agent-artifacts"])

    assert exit_code == 0
    assert "no secrets found" in capsys.readouterr().out


@pytest.mark.parametrize("flag", ["-h", "--help"])
def test_help_flag_exits_cleanly(flag: str):
    with pytest.raises(SystemExit) as excinfo:
        main([flag])
    assert excinfo.value.code == 0
