"""Header injection detection — CRLF in headers."""

import urllib.error
import urllib.request
from webbreach.engines import BaseEngine
from webbreach.findings import Finding, Severity


class HeaderInjectionEngine(BaseEngine):
    name = "header_injection"
    description = "Header Injection / CRLF detector"

    def _scan(self) -> list[Finding]:
        findings: list[Finding] = []
        base = self.target_url

        # The lab adds user-controlled value to X-Custom header.
        # We check if the server reflects unsanitized header values.
        marker = "WBHDR_test123"
        # URL-encode the value with CRLF to test
        payload_encoded = f"safe%0d%0aX-Injected%3A+{marker}"
        url = f"{base}/header_inject?val={payload_encoded}"

        try:
            status, body, headers = self._get(url)
        except Exception:
            return findings

        # Check if custom header was injected
        if marker in headers.get("X-Injected", ""):
            findings.append(self._finding(
                severity=Severity.MEDIUM,
                title="Header Injection — CRLF accepted",
                param="val",
                method="GET",
                evidence=f"Injected header found in response",
                payload=payload_encoded,
            ))
            return findings

        # Fallback: check if server reflects value without sanitization
        # by sending a value that would appear in headers
        url2 = f"{base}/header_inject?val={marker}"
        try:
            status2, body2, headers2 = self._get(url2)
            custom = headers2.get("X-Custom", "")
            if marker in custom:
                # Value reflected in header without sanitization - potential for injection
                # Check if it also accepts raw newlines in the URL query
                url3 = f"{base}/header_inject?val=%0d%0aInjected%3A+yes"
                try:
                    status3, body3, headers3 = self._get(url3)
                    if "Injected" in headers3.get("Injected", "") or "Injected" in str(headers3):
                        findings.append(self._finding(
                            severity=Severity.MEDIUM,
                            title="Header Injection — CRLF accepted",
                            param="val",
                            method="GET",
                            evidence=f"Server accepts CRLF in header values",
                            payload="%0d%0aInjected: yes",
                        ))
                except Exception:
                    pass
        except Exception:
            pass

        return findings
