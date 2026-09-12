"""Generate exact installed distributions for the CI dependency audit."""

from __future__ import annotations

import argparse
import json
import re
from importlib import metadata
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import url2pathname

OWN_DISTRIBUTION = "amasen-credscan"


class AuditRequirementsError(RuntimeError):
    """Raised when installed metadata cannot be audited safely."""


def canonicalize_name(name: str) -> str:
    """Apply the PEP 503 normalization used for distribution names."""

    return re.sub(r"[-_.]+", "-", name).lower()


def _editable_source(distribution: metadata.Distribution) -> Path | None:
    """Return an editable local source, or ``None`` when it is not one."""

    direct_url = distribution.read_text("direct_url.json")
    if direct_url is None:
        return None

    try:
        payload = json.loads(direct_url)
    except json.JSONDecodeError as exc:
        raise AuditRequirementsError(
            f"invalid direct_url.json for {distribution.name!r}"
        ) from exc

    if not isinstance(payload, dict):
        raise AuditRequirementsError(f"invalid direct_url.json for {distribution.name!r}")

    dir_info = payload.get("dir_info")
    if not isinstance(dir_info, dict) or dir_info.get("editable") is not True:
        return None

    url = payload.get("url")
    parsed = urlparse(url) if isinstance(url, str) else None
    if parsed is None or parsed.scheme != "file" or parsed.netloc not in ("", "localhost"):
        raise AuditRequirementsError(f"unsupported editable source for {distribution.name!r}")

    source = Path(url2pathname(parsed.path))
    if not source.is_absolute():
        raise AuditRequirementsError(
            f"editable source is not an absolute local path for {distribution.name!r}"
        )
    return source.resolve()


def _record(distribution: metadata.Distribution) -> str:
    """Format one installed distribution as an exact requirement."""

    name = distribution.name
    version = distribution.version
    if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
        raise AuditRequirementsError("installed distribution has incomplete name/version metadata")
    return f"{name}=={version}"


def _is_source_egg_info(distribution: metadata.Distribution, root: Path) -> bool:
    """Identify setuptools' duplicate source-tree metadata record."""

    if distribution.read_text("PKG-INFO") is None:
        return False
    try:
        metadata_path = Path(distribution.locate_file("")).resolve()
    except (AttributeError, OSError, TypeError):
        return False
    return metadata_path.is_relative_to(root)


def generate_requirements(
    distributions: list[metadata.Distribution] | tuple[metadata.Distribution, ...],
    root: Path,
) -> list[str]:
    """Return exact requirements, omitting only this checkout's editable project."""

    root = root.resolve()
    proven_own: set[tuple[str, str]] = set()
    for distribution in distributions:
        if canonicalize_name(distribution.name) != canonicalize_name(OWN_DISTRIBUTION):
            continue
        source = _editable_source(distribution)
        if source == root:
            proven_own.add((canonicalize_name(distribution.name), distribution.version))

    records: set[str] = set()
    for distribution in distributions:
        omit_own = False
        if canonicalize_name(distribution.name) == canonicalize_name(OWN_DISTRIBUTION):
            source = _editable_source(distribution)
            identity = (canonicalize_name(distribution.name), distribution.version)
            omit_own = source == root or (
                identity in proven_own and _is_source_egg_info(distribution, root)
            )
        if not omit_own:
            records.add(_record(distribution))

    if not records:
        raise AuditRequirementsError("no installed distributions remain to audit")
    return sorted(records, key=str.casefold)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--output", type=Path, default=Path(".pip-audit-requirements.txt")
    )
    args = parser.parse_args()

    records = generate_requirements(tuple(metadata.distributions()), args.root)
    args.output.write_text("\n".join(records) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
