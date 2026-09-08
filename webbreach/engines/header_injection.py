"""Header injection detection — CRLF in headers."""

from webbreach.engines import BaseEngine
from webbreach.findings import Finding, Severity


class HeaderInjectionEngine(BaseEngine):
    name = "header_injection"
    description = "Header Injection / CRLF detector"

    def _scan(self) -> list[Finding]:
        findings: list[Finding] = []
        base = self.target_url

        marker = "WBHDR_test123"
        payload = f"safe\r\nX-Injected: {marker}"
        url = f"{base}/header_inject?val={payload}"
        status, body, headers = self._get(url)
        if marker in headers.get("X-Injected", "") or marker in body:
            findings.append(self._finding(
                severity=Severity.MEDIUM,
                title="Header Injection — CRLF accepted",
                param="val",
                method="GET",
                evidence=f"Headers: {headers}",
                payload=payload,
            ))

        return findings
