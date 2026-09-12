import json
from pathlib import Path

import pytest

from scripts.generate_audit_requirements import (
    AuditRequirementsError,
    generate_requirements,
)


class FakeDistribution:
    def __init__(
        self,
        name: str,
        version: str,
        direct_url: dict | None = None,
        location: Path | None = None,
        metadata_path: Path | None = None,
    ):
        self.name = name
        self.version = version
        self._direct_url = json.dumps(direct_url) if direct_url is not None else None
        self._location = location or Path("/site-packages")
        self._metadata_path = metadata_path

    def read_text(self, filename: str) -> str | None:
        if filename == "PKG-INFO" and self._metadata_path is not None:
            return "Metadata-Version: 2.1\n"
        assert filename == "direct_url.json"
        return self._direct_url

    def locate_file(self, _path: str = "") -> Path:
        if _path == "PKG-INFO" and self._metadata_path is not None:
            return self._metadata_path
        return self._location


def _editable_url(root: Path) -> dict:
    return {"dir_info": {"editable": True}, "url": root.as_uri()}


def test_third_party_direct_url_is_retained(tmp_path: Path):
    third_party = FakeDistribution(
        "third-party",
        "1.2.3",
        direct_url=_editable_url(tmp_path),
        location=tmp_path / ".venv" / "Lib" / "site-packages",
    )

    assert generate_requirements([third_party], tmp_path) == ["third-party==1.2.3"]


def test_in_repo_venv_distribution_is_retained(tmp_path: Path):
    in_repo = FakeDistribution(
        "third-party",
        "1.2.3",
        location=tmp_path / ".venv" / "Lib" / "site-packages",
    )

    assert generate_requirements([in_repo], tmp_path) == ["third-party==1.2.3"]


def test_only_matching_own_editable_distribution_is_omitted(tmp_path: Path):
    tmp_path = tmp_path / "repo%20with-literal-percent"
    tmp_path.mkdir()
    own = FakeDistribution(
        "AmaSen_CredScan",
        "0.1.0",
        direct_url=_editable_url(tmp_path),
        location=tmp_path / "src",
    )
    third_party = FakeDistribution("requests", "2.32.4")

    assert generate_requirements([own, third_party], tmp_path) == ["requests==2.32.4"]


def test_own_distribution_from_another_source_is_retained(tmp_path: Path):
    own = FakeDistribution(
        "amasen-credscan",
        "0.1.0",
        direct_url=_editable_url(tmp_path / "other-checkout"),
    )

    assert generate_requirements([own], tmp_path) == ["amasen-credscan==0.1.0"]


def test_source_egg_info_duplicate_is_omitted_after_editable_root_proof(tmp_path: Path):
    installed = FakeDistribution(
        "amasen-credscan",
        "0.1.0",
        direct_url=_editable_url(tmp_path),
    )
    source_metadata = FakeDistribution(
        "amasen-credscan",
        "0.1.0",
        location=tmp_path / "src",
        metadata_path=tmp_path / "src" / "amasen_credscan.egg-info" / "PKG-INFO",
    )

    with pytest.raises(AuditRequirementsError, match="no installed distributions"):
        generate_requirements([installed, source_metadata], tmp_path)


def test_external_same_name_egg_info_is_retained(tmp_path: Path):
    installed = FakeDistribution(
        "amasen-credscan",
        "0.1.0",
        direct_url=_editable_url(tmp_path),
    )
    external_metadata = FakeDistribution(
        "amasen-credscan",
        "0.1.0",
        location=tmp_path.parent / "other-checkout" / "src",
        metadata_path=tmp_path.parent / "other-checkout" / "src" / "PKG-INFO",
    )

    assert generate_requirements([installed, external_metadata], tmp_path) == [
        "amasen-credscan==0.1.0"
    ]


def test_unsupported_own_editable_source_fails_loudly(tmp_path: Path):
    own = FakeDistribution(
        "amasen-credscan",
        "0.1.0",
        direct_url={"dir_info": {"editable": True}, "url": "https://example.test/credscan"},
    )

    with pytest.raises(AuditRequirementsError, match="unsupported editable source"):
        generate_requirements([own], tmp_path)


def test_empty_audit_records_fail(tmp_path: Path):
    own = FakeDistribution("amasen.credscan", "0.1.0", direct_url=_editable_url(tmp_path))

    with pytest.raises(AuditRequirementsError, match="no installed distributions"):
        generate_requirements([own], tmp_path)
