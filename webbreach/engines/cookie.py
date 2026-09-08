"""Insecure cookie detection."""

from webbreach.engines import BaseEngine
from webbreach.findings import Finding, Severity


class CookieEngine(BaseEngine):
    name = "cookie"
    description = "Insecure cookie flag checker"

    def _scan(self) -> list[Finding]:
        findings: list[Finding] = []
        url = f"{self.target_url}/cookie"

        status, body, headers = self._get(url)
        cookie = headers.get("Set-Cookie", "")
        if not cookie:
            return findings

        issues = []
        lower = cookie.lower()
        if "secure" not in lower:
            issues.append("missing Secure flag")
        if "httponly" not in lower:
            issues.append("missing HttpOnly flag")
        if "samesite" not in lower:
            issues.append("missing SameSite attribute")

        if issues:
            findings.append(self._finding(
                severity=Severity.MEDIUM,
                title=f"Insecure cookie — {', '.join(issues)}",
                method="GET",
                evidence=cookie[:200],
            ))

        return findings
