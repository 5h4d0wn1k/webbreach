"""SSRF detection — outbound probe to internal addresses."""

import socket
import time
from webbreach.engines import BaseEngine
from webbreach.findings import Finding, Severity


class SSRFEngine(BaseEngine):
    name = "ssrf"
    description = "SSRF detector — probes internal addresses"

    INTERNAL_PAYLOADS = [
        ("http://127.0.0.2:9/", "127.0.0.2:9"),
        ("http://127.0.0.1:9/", "127.0.0.1:9"),
    ]

    def _scan(self) -> list[Finding]:
        findings: list[Finding] = []
        base = self.target_url

        for url_probe, label in self.INTERNAL_PAYLOADS:
            encoded = url_probe.replace(":", "%3A").replace("/", "%2F")
            url = f"{base}/ssrf?url={encoded}"
            t0 = time.time()
            status, body, _ = self._get(url, timeout=3)
            elapsed = time.time() - t0
            # If server tried to connect, it either got a response or timed out slowly
            if elapsed > 0.5 or "Error:" in body:
                findings.append(self._finding(
                    severity=Severity.HIGH,
                    title=f"SSRF — server fetched internal host {label}",
                    param="url",
                    method="GET",
                    evidence=body[:300],
                    payload=url_probe,
                ))
                break

        return findings
