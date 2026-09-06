"""argv -> exit code. Exit codes: 0 clean, 1 findings present (CI-friendly), 2 usage/tool error."""

import argparse
import sys
from pathlib import Path

from credscan import git_integration, scanner
from credscan.allowlist import IGNORE_FILE_NAME, Allowlist
from credscan.git_integration import NotAGitRepositoryError
from credscan.models import Finding
from credscan.render import render_json, render_text

_MAX_NAMED_SKIPPED_DIRS = 5


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 2

    try:
        findings = _run_scan(args)
    except (NotAGitRepositoryError, OSError) as error:
        print(f"credscan: {error}", file=sys.stderr)
        return 2

    print(render_json(findings) if args.json else render_text(findings))
    return 1 if findings else 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="credscan", description="Scan for likely-leaked secrets.")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser(
        "scan", help="Scan a path or staged git changes for secrets."
    )
    scan_parser.add_argument(
        "path", nargs="?", default=".", help="Directory to scan (default: current directory)."
    )
    scan_parser.add_argument(
        "--staged", action="store_true", help="Scan staged git changes instead of a path."
    )
    scan_parser.add_argument(
        "--json", action="store_true", help="Emit machine-readable JSON instead of text."
    )
    scan_parser.add_argument(
        "--agent-artifacts",
        action="store_true",
        help=(
            "Scan only AI coding-agent artifact paths (.claude/, .cursor/, .codex/, MCP server "
            "configs, session/shell-history logs) instead of the full path."
        ),
    )
    scan_parser.add_argument(
        "--no-default-excludes",
        action="store_true",
        help=(
            "Do not prune the default excluded directories ("
            + ", ".join(sorted(scanner.DEFAULT_EXCLUDED_DIRS))
            + "). Use this to scan build output, where a bundler can inline a real secret."
        ),
    )

    return parser


def _run_scan(args: argparse.Namespace) -> list[Finding]:
    if args.staged:
        repo_root = git_integration.repository_root(args.path)
        allowlist = _staged_allowlist(repo_root)
        return scanner.scan_staged(
            repo_root, allowlist, only_agent_artifacts=args.agent_artifacts
        )

    root = Path(args.path).resolve()
    if not root.is_dir():
        raise OSError(f"not a directory: {args.path}")

    allowlist = Allowlist.load(root)
    skipped: list[str] = []
    findings = scanner.scan_directory(
        root,
        allowlist,
        only_agent_artifacts=args.agent_artifacts,
        excluded_dirs=() if args.no_default_excludes else scanner.DEFAULT_EXCLUDED_DIRS,
        on_skipped_directory=skipped.append,
    )
    _warn_about_skipped_directories(skipped)
    return findings


def _staged_allowlist(repo_root: str) -> Allowlist:
    """Loads `.credscanignore` from the git index, not the working tree.

    `--staged` exists to answer "is the commit I am about to make clean?", and the answer must
    not depend on a file that is in no commit and no diff. An untracked or unstaged
    `.credscanignore` used to silence staged findings while being invisible to every reviewer;
    now it is reported and ignored, and only a staged suppression takes effect.
    """
    staged_text = git_integration.index_file_content(repo_root, IGNORE_FILE_NAME)
    working_copy = Path(repo_root) / IGNORE_FILE_NAME

    if working_copy.is_file():
        working_text = working_copy.read_text(encoding="utf-8", errors="replace")
        if staged_text is None:
            print(
                f"credscan: ignoring the working-tree {IGNORE_FILE_NAME}: it is not staged, so "
                "it would suppress findings without appearing in the diff. Stage it to apply it.",
                file=sys.stderr,
            )
        elif working_text != staged_text:
            print(
                f"credscan: the working-tree {IGNORE_FILE_NAME} differs from the staged copy; "
                "--staged is using the staged copy.",
                file=sys.stderr,
            )

    return Allowlist.from_text(staged_text) if staged_text is not None else Allowlist()


def _warn_about_skipped_directories(skipped: list[str]) -> None:
    """A clean run over a partially walked tree is not a clean tree — say so on stderr."""
    if not skipped:
        return

    shown = ", ".join(skipped[:_MAX_NAMED_SKIPPED_DIRS])
    if len(skipped) > _MAX_NAMED_SKIPPED_DIRS:
        shown += f", and {len(skipped) - _MAX_NAMED_SKIPPED_DIRS} more"
    print(
        f"credscan: skipped {len(skipped)} directory/directories from the default exclude list "
        f"({shown}); re-run with --no-default-excludes to scan them.",
        file=sys.stderr,
    )
