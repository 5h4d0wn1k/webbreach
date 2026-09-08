"""Open Redirect detection."""

from webbreach.engines import BaseEngine
from webbreach.findings import Finding, Severity


class RedirectEngine(BaseEngine):
    name = "redirect"
    description = "Open Redirect detector"

    REDIRECT_MARKERS = [
        "http://evil.com",
        "//evil.com",
        "/\\evil.com",
        "http://127.0.0.1",
    ]

    def _scan(self) -> list[Finding]:
        findings: list[Finding] = []
        base = self.target_url

        for marker in self.REDIRECT_MARKERS:
            url = f"{base}/redirect?next={marker}"
            status, body, headers = self._get(url)
            location = headers.get("Location", "")
            if status in (301, 302) and marker.lstrip("/").lstrip("\\") in location:
                findings.append(self._finding(
                    severity=Severity.MEDIUM,
                    title=f"Open Redirect — to {marker}",
                    param="next",
                    method="GET",
                    evidence=f"Location: {location}",
                    payload=marker,
                ))
                break

        return findings
