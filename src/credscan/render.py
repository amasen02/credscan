"""Text and JSON rendering of scan results."""

import json

from credscan.models import Finding


def render_text(findings: list[Finding]) -> str:
    if not findings:
        return "credscan: no secrets found."

    lines = []
    for index, finding in enumerate(findings, start=1):
        lines.append(
            f"[{index}] {finding.severity.value.upper():<6} {finding.rule_name} "
            f"({finding.rule_id})\n"
            f"    {finding.file_path}:{finding.line_number}  {finding.redacted_match}"
        )

    file_count = _distinct_file_count(findings)
    lines.append("")
    lines.append(f"credscan: {len(findings)} finding(s) across {file_count} file(s).")
    return "\n".join(lines)


def render_json(findings: list[Finding]) -> str:
    payload = {
        "findings": [
            {
                "ruleId": finding.rule_id,
                "ruleName": finding.rule_name,
                "severity": finding.severity.value,
                "filePath": finding.file_path,
                "lineNumber": finding.line_number,
                "redactedMatch": finding.redacted_match,
            }
            for finding in findings
        ],
        "summary": {
            "findingCount": len(findings),
            "fileCount": _distinct_file_count(findings),
        },
    }
    return json.dumps(payload, indent=2)


def _distinct_file_count(findings: list[Finding]) -> int:
    return len({finding.file_path for finding in findings})
