"""Command injection detection — marker echo, no exec side effects."""

import re
from webbreach.engines import BaseEngine
from webbreach.findings import Finding, Severity


class CommandInjectionEngine(BaseEngine):
    name = "cmd"
    description = "Command injection detector (marker echo)"

    MARKER = "WBCMD_9f3a"

    def _scan(self) -> list[Finding]:
        findings: list[Finding] = []
        base = self.target_url

        # Test various injection markers
        payloads = [
            f"; echo {self.MARKER}",
            f"| echo {self.MARKER}",
            f"$(echo {self.MARKER})",
            f"`echo {self.MARKER}`",
        ]

        for payload in payloads:
            encoded = urllib.parse.quote(payload)
            url = f"{base}/cmd?host={encoded}"
            status, body, _ = self._get(url)
            if self.MARKER in body:
                findings.append(self._finding(
                    severity=Severity.CRITICAL,
                    title="Command Injection — marker echoed",
                    param="host",
                    method="GET",
                    evidence=body[:300],
                    payload=payload,
                ))
                break

        return findings


import urllib.parse
