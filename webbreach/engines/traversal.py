"""Path traversal detection — read planted marker file."""

import json
import os
import tempfile
from webbreach.engines import BaseEngine
from webbreach.findings import Finding, Severity


class TraversalEngine(BaseEngine):
    name = "traversal"
    description = "Path traversal detector — reads secret marker file"

    SECRET = "TOP_SECRET_F4G_a1b2c3d4"

    def _scan(self) -> list[Finding]:
        findings: list[Finding] = []
        url = f"{self.target_url}/traversal"

        secret_name = os.path.basename(tempfile.gettempdir()) + "/" + os.path.basename(
            os.path.join(tempfile.gettempdir(), "lab_secret.txt")
        )

        payloads = [
            f"../../tmp/lab_secret.txt",
            f"../../../tmp/lab_secret.txt",
            f"....//....//tmp/lab_secret.txt",
        ]

        for payload in payloads:
            data = json.dumps({"file": payload})
            status, body, _ = self._post(url, data, content_type="application/json")
            if self.SECRET in body:
                findings.append(self._finding(
                    severity=Severity.HIGH,
                    title="Path Traversal — secret file readable",
                    param="file",
                    method="POST",
                    evidence=body[:300],
                    payload=payload,
                ))
                break

        return findings
