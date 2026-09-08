"""XSS scanner — reflected + stored detection."""

import html
import re
import urllib.parse
from webbreach.engines import BaseEngine
from webbreach.findings import Finding, Severity


PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "';alert(1)//",
]


class XSSEngine(BaseEngine):
    name = "xss"
    description = "Reflected + stored XSS scanner"

    def _scan(self) -> list[Finding]:
        findings: list[Finding] = []
        base = self.target_url

        # --- Reflected XSS ---
        for payload in PAYLOADS:
            encoded = urllib.parse.quote(payload)
            url = f"{base}/xss?q={encoded}"
            status, body, _ = self._get(url)
            # Check: payload echoed unescaped in DOM
            if payload in body:
                findings.append(self._finding(
                    severity=Severity.HIGH,
                    title="Reflected XSS",
                    param="q",
                    method="GET",
                    evidence=body[:300],
                    payload=payload,
                ))
                break  # one proof is enough

        # --- Stored XSS ---
        marker = "<marquee>WB_XSS_TEST_7e2a</marquee>"
        # Add marker to stored XSS
        self._get(f"{base}/xss/stored/add?msg={urllib.parse.quote(marker)}")
        status, body, _ = self._get(f"{base}/xss/stored")
        if marker in body:
            findings.append(self._finding(
                severity=Severity.CRITICAL,
                title="Stored XSS",
                param="msg",
                method="GET",
                evidence=body[:400],
                payload=marker,
            ))

        return findings
