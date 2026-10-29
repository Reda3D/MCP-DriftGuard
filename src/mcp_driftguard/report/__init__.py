"""Report assembly and rendering dispatch."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Any, Dict, List, Sequence

from ..changes import DiffResult
from ..policy import Finding, Policy
from ..severity import Severity
from ..snapshot import Snapshot


@dataclass
class Report:
    version: str
    evaluated_on: _dt.date
    baseline: Snapshot
    candidate: Snapshot
    policy: Policy
    diff: DiffResult
    findings: Sequence[Finding]

    # -- derived state -----------------------------------------------------

    @property
    def active_findings(self) -> List[Finding]:
        return [finding for finding in self.findings if not finding.waived]

    @property
    def waived_findings(self) -> List[Finding]:
        return [finding for finding in self.findings if finding.waived]

    @property
    def failed(self) -> bool:
        return self.policy.must_fail(self.findings)

    def severity_counts(self) -> Dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.active_findings:
            counts[finding.severity.value] += 1
        return counts

    def change_counts(self) -> Dict[str, int]:
        return self.diff.count_by_type()

    def summary(self) -> Dict[str, Any]:
        return {
            "result": "fail" if self.failed else "pass",
            "total_changes": len(self.diff.changes),
            "total_findings": len(self.active_findings),
            "waived": len(self.waived_findings),
            "blocking": any(finding.blocking for finding in self.active_findings),
            "fail_on": self.policy.fail_on.value,
            "by_severity": self.severity_counts(),
            "by_change": self.change_counts(),
        }

    def highest_severity(self) -> Severity:
        highest = Severity.INFO
        for finding in self.active_findings:
            if finding.severity > highest:
                highest = finding.severity
        return highest
