"""SSTI detection — template expression evaluation."""

import re
from webbreach.engines import BaseEngine
from webbreach.findings import Finding, Severity


MARKERS = [
    ("{{7*7}}", "49"),
    ("{{7+7}}", "14"),
    ("${7*7}", "49"),
]


class SSTIEngine(BaseEngine):
    name = "ssti"
    description = "Server-Side Template Injection detector"

    def _scan(self) -> list[Finding]:
        findings: list[Finding] = []
        base = self.target_url

        for expr, expected in MARKERS:
            url = f"{base}/ssti?name={expr}"
            status, body, _ = self._get(url)
            if expected in body:
                findings.append(self._finding(
                    severity=Severity.CRITICAL,
                    title=f"SSTI — expression {expr} evaluated to {expected}",
                    param="name",
                    method="GET",
                    evidence=body[:300],
                    payload=expr,
                ))
                break

        return findings
