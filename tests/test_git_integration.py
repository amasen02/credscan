import subprocess
from pathlib import Path

import pytest

from credscan import git_integration
from credscan.git_integration import NotAGitRepositoryError


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test")
    return tmp_path


def test_repository_root_returns_the_repo_root(git_repo: Path):
    nested = git_repo / "nested" / "dir"
    nested.mkdir(parents=True)

    root = git_integration.repository_root(str(nested))

    assert Path(root).resolve() == git_repo.resolve()


def test_repository_root_raises_outside_a_git_repository(tmp_path: Path):
    non_repo = tmp_path / "not-a-repo"
    non_repo.mkdir()

    with pytest.raises(NotAGitRepositoryError):
        git_integration.repository_root(str(non_repo))


def test_staged_files_returns_the_staged_blob_not_the_working_tree_copy(git_repo: Path):
    target = git_repo / "secret.env"
    target.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    _git(git_repo, "add", "secret.env")

    # Modify the working tree *after* staging — the staged content must still be what's reported.
    target.write_text("no secret here anymore\n", encoding="utf-8")

    files = git_integration.staged_files(str(git_repo))

    assert len(files) == 1
    assert files[0].path == "secret.env"
    assert "AKIAIOSFODNN7EXAMPLE" in files[0].content


def test_staged_files_excludes_unstaged_files(git_repo: Path):
    (git_repo / "staged.txt").write_text("staged", encoding="utf-8")
    (git_repo / "unstaged.txt").write_text("unstaged", encoding="utf-8")
    _git(git_repo, "add", "staged.txt")

    files = git_integration.staged_files(str(git_repo))

    assert [f.path for f in files] == ["staged.txt"]


def test_staged_files_returns_empty_list_when_nothing_is_staged(git_repo: Path):
    assert git_integration.staged_files(str(git_repo)) == []


def test_index_file_content_returns_the_staged_copy(git_repo: Path):
    (git_repo / ".credscanignore").write_text("*.env\n", encoding="utf-8")
    _git(git_repo, "add", ".credscanignore")
    (git_repo / ".credscanignore").write_text("everything/*\n", encoding="utf-8")

    assert git_integration.index_file_content(str(git_repo), ".credscanignore") == "*.env\n"


def test_index_file_content_returns_none_for_an_untracked_file(git_repo: Path):
    (git_repo / ".credscanignore").write_text("*.env\n", encoding="utf-8")

    assert git_integration.index_file_content(str(git_repo), ".credscanignore") is None
