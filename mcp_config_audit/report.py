# Text and JSON rendering for audit results.

import json

from .findings import counts_by_severity


def render_text(findings, source):
    lines = []
    if not findings:
        lines.append("No findings in %s" % source)
        return "\n".join(lines)
    for finding in findings:
        lines.append("[%s] %s: %s" % (finding.severity.upper(), finding.rule, finding.server))
        lines.append("    %s" % finding.message)
        if finding.evidence:
            lines.append("    evidence: %s" % finding.evidence)
    tally = counts_by_severity(findings)
    lines.append("")
    lines.append(
        "%d finding(s): %d high, %d medium, %d low"
        % (len(findings), tally.get("high", 0), tally.get("medium", 0), tally.get("low", 0))
    )
    return "\n".join(lines)


def to_dict(findings, source):
    return {
        "source": source,
        "counts": counts_by_severity(findings),
        "findings": [
            {
                "rule": f.rule,
                "severity": f.severity,
                "server": f.server,
                "message": f.message,
                "evidence": f.evidence,
            }
            for f in findings
        ],
    }


def render_json(findings, source):
    return json.dumps(to_dict(findings, source), indent=2)
