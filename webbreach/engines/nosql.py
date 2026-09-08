"""NoSQL injection detection — $where style."""

import json
from webbreach.engines import BaseEngine
from webbreach.findings import Finding, Severity


class NoSQLEngine(BaseEngine):
    name = "nosql"
    description = "NoSQL injection detector ($where style)"

    def _scan(self) -> list[Finding]:
        findings: list[Finding] = []
        url = f"{self.target_url}/nosql"

        payload = {"query": {"$where": "this.name == 'admin'"}}
        status, body, _ = self._post(url, json.dumps(payload), content_type="application/json")
        if "admin" in body and "F4G" in body:
            findings.append(self._finding(
                severity=Severity.CRITICAL,
                title="NoSQL Injection — $where bypass dumps all records",
                param="query",
                method="POST",
                evidence=body[:300],
                payload=json.dumps(payload),
            ))

        return findings
