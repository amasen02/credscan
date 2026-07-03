import subprocess
from pathlib import Path

from credscan.allowlist import Allowlist
from credscan.scanner import scan_directory, scan_staged, scan_text


def test_scan_text_finds_a_secret_and_reports_correct_line_number():
    content = "line one\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nline three\n"

    findings = scan_text("config.env", content)

    assert len(findings) == 1
    assert findings[0].rule_id == "aws-access-key-id"
    assert findings[0].line_number == 2
    assert findings[0].file_path == "config.env"


def test_scan_text_respects_inline_ignore_marker():
    content = 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE  # credscan:ignore\n'

    assert scan_text("config.env", content) == []


def test_scan_text_finds_gcp_service_account_key_across_lines():
    content = '{\n  "type": "service_account",\n  "private_key": "abc"\n}\n'

    findings = scan_text("key.json", content)

    assert any(f.rule_id == "gcp-service-account-key" for f in findings)


def test_scan_text_returns_nothing_for_clean_content():
    assert scan_text("notes.txt", "just a normal file\nwith nothing sensitive in it\n") == []


def test_scan_directory_finds_secrets_in_nested_files(tmp_path: Path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "config.env").write_text(
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8"
    )

    findings = scan_directory(tmp_path, Allowlist())

    assert len(findings) == 1
    assert findings[0].file_path == "sub/config.env"


def test_scan_directory_skips_default_excluded_directories(tmp_path: Path):
    excluded = tmp_path / "node_modules"
    excluded.mkdir()
    (excluded / "vendored.env").write_text(
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8"
    )

    assert scan_directory(tmp_path, Allowlist()) == []


def test_scan_directory_respects_credscanignore_patterns(tmp_path: Path):
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "planted.env").write_text(
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8"
    )
    allowlist = Allowlist(path_patterns=("fixtures/*",))

    assert scan_directory(tmp_path, allowlist) == []


def test_scan_directory_skips_binary_files(tmp_path: Path):
    binary_file = tmp_path / "image.bin"
    binary_file.write_bytes(b"\x00\x01\x02AKIAIOSFODNN7EXAMPLE\x00")

    assert scan_directory(tmp_path, Allowlist()) == []


def test_scan_directory_results_are_deterministically_sorted(tmp_path: Path):
    (tmp_path / "b.env").write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    (tmp_path / "a.env").write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")

    findings = scan_directory(tmp_path, Allowlist())

    assert [f.file_path for f in findings] == ["a.env", "b.env"]


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


def test_scan_staged_finds_secrets_in_staged_content_only(tmp_path: Path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test")
    secret_file = tmp_path / "secret.env"
    secret_file.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    _git(tmp_path, "add", "secret.env")

    findings = scan_staged(str(tmp_path), Allowlist())

    assert len(findings) == 1
    assert findings[0].file_path == "secret.env"
