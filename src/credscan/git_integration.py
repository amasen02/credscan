"""Thin wrappers around `git` for scanning what's about to be committed, not the working tree."""

import subprocess
from dataclasses import dataclass


class NotAGitRepositoryError(RuntimeError):
    pass


@dataclass(frozen=True)
class StagedFile:
    path: str
    content: str


def _run_git(args: list[str], cwd: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise NotAGitRepositoryError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout


def repository_root(start_dir: str) -> str:
    return _run_git(["rev-parse", "--show-toplevel"], cwd=start_dir).strip()


def staged_files(repo_root: str) -> list[StagedFile]:
    """Returns each staged file's path and its *staged* content (the git index blob), not the
    working-tree copy — that's what will actually land in the commit."""
    names = [
        name
        for name in _run_git(
            ["diff", "--cached", "--name-only", "--diff-filter=ACM"], cwd=repo_root
        ).splitlines()
        if name
    ]

    files = []
    for name in names:
        try:
            content = _run_git(["show", f":{name}"], cwd=repo_root)
        except NotAGitRepositoryError:
            continue  # e.g. a staged submodule pointer or a path git show can't blob
        files.append(StagedFile(path=name, content=content))
    return files
