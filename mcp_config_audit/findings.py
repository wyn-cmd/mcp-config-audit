# Shared result type and severity ordering for the audit rules.

from dataclasses import dataclass, field

# Higher number means the finding deserves more attention.
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


@dataclass
class Finding:
    rule: str
    severity: str
    server: str
    message: str
    evidence: str = ""

    # A stable key so the same finding keeps its place when results are merged.
    @property
    def sort_key(self):
        return (-SEVERITY_ORDER.get(self.severity, 0), self.server, self.rule)


def sort_findings(findings):
    return sorted(findings, key=lambda f: f.sort_key)


def at_least(findings, minimum):
    # Keep only the findings whose severity is at or above the given level.
    floor = SEVERITY_ORDER.get(minimum, 1)
    return [f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= floor]


def counts_by_severity(findings):
    tally = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        tally[finding.severity] = tally.get(finding.severity, 0) + 1
    return tally
