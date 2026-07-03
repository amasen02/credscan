import json

from credscan.models import Finding, Severity
from credscan.render import render_json, render_text


def _sample_finding() -> Finding:
    return Finding(
        rule_id="aws-access-key-id",
        rule_name="AWS access key ID",
        severity=Severity.HIGH,
        file_path="config.env",
        line_number=2,
        redacted_match="AKIA**************LE",
    )


def test_render_text_reports_no_findings():
    assert render_text([]) == "credscan: no secrets found."


def test_render_text_includes_rule_location_and_redacted_value():
    output = render_text([_sample_finding()])

    assert "AWS access key ID" in output
    assert "config.env:2" in output
    assert "AKIA**************LE" in output
    assert "1 finding(s)" in output


def test_render_text_never_leaks_the_raw_secret():
    finding = Finding("x", "x", Severity.HIGH, "f.env", 1, redacted_match="AKIA**************LE")
    assert "AKIAIOSFODNN7EXAMPLE" not in render_text([finding])


def test_render_json_produces_a_valid_summary():
    payload = json.loads(render_json([_sample_finding()]))

    assert payload["summary"]["findingCount"] == 1
    assert payload["summary"]["fileCount"] == 1
    assert payload["findings"][0]["ruleId"] == "aws-access-key-id"
    assert payload["findings"][0]["lineNumber"] == 2


def test_render_json_with_no_findings_has_empty_list():
    payload = json.loads(render_json([]))

    assert payload["findings"] == []
    assert payload["summary"]["findingCount"] == 0
