"""argv -> exit code. Exit codes: 0 clean, 1 findings present (CI-friendly), 2 usage/tool error."""

import argparse
import sys
from pathlib import Path

from credscan import git_integration, scanner
from credscan.allowlist import Allowlist
from credscan.git_integration import NotAGitRepositoryError
from credscan.models import Finding
from credscan.render import render_json, render_text


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

    return parser


def _run_scan(args: argparse.Namespace) -> list[Finding]:
    if args.staged:
        repo_root = git_integration.repository_root(args.path)
        allowlist = Allowlist.load(Path(repo_root))
        return scanner.scan_staged(
            repo_root, allowlist, only_agent_artifacts=args.agent_artifacts
        )

    root = Path(args.path).resolve()
    if not root.is_dir():
        raise OSError(f"not a directory: {args.path}")

    allowlist = Allowlist.load(root)
    return scanner.scan_directory(root, allowlist, only_agent_artifacts=args.agent_artifacts)
