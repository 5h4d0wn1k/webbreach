"""CSRF checker — token presence + SameSite flags."""

import re
from webbreach.engines import BaseEngine
from webbreach.findings import Finding, Severity


class CSFREngine(BaseEngine):
    name = "csrf"
    description = "CSRF token + SameSite cookie checker"

    def _scan(self) -> list[Finding]:
        findings: list[Finding] = []
        url = f"{self.target_url}/csrf"

        status, body, headers = self._get(url)

        # Check: form lacks CSRF token
        has_token = bool(re.search(r'(csrf|_token|authenticity)', body, re.I))
        if not has_token:
            findings.append(self._finding(
                severity=Severity.MEDIUM,
                title="CSRF: No anti-CSRF token in form",
                url=url,
                method="GET",
                evidence=body[:300],
            ))

        # Check: SameSite cookie attribute missing
        cookie_header = headers.get("Set-Cookie", "")
        if cookie_header and "samesite" not in cookie_header.lower():
            findings.append(self._finding(
                severity=Severity.LOW,
                title="CSRF: Session cookie missing SameSite attribute",
                url=url,
                method="GET",
                evidence=cookie_header[:200],
            ))

        return findings
