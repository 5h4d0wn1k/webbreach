"""HTTP Request Smuggling detection — CL/TE desync probe."""

from webbreach.engines import BaseEngine
from webbreach.findings import Finding, Severity


class SmugglingEngine(BaseEngine):
    name = "smuggling"
    description = "HTTP Request Smuggling (CL/TE) detector"

    def _scan(self) -> list[Finding]:
        findings: list[Finding] = []
        url = f"{self.target_url}/smuggle"

        # CL/TE mismatch payload:
        # Content-Length says 6, Transfer-Encoding says chunked.
        # Body: "0\r\n\r\nSMUGGLE"
        body = b"0\r\n\r\nSMUGGLE_MARKER_x4a GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        cl = str(len(body)).encode()

        raw = (
            b"POST /smuggle HTTP/1.1\r\n"
            b"Host: " + self.target_url.encode() + b"\r\n"
            b"Content-Length: " + cl + b"\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n" + body
        )

        status, resp_body, _ = self._post_raw(url, raw)
        # If server didn't reject the malformed request, it may be vulnerable
        if status in (200, 400):
            findings.append(self._finding(
                severity=Severity.HIGH,
                title="HTTP Request Smuggling — CL/TE mismatch accepted",
                method="POST",
                evidence=f"Status {status}, body: {resp_body[:200]}",
                payload="CL/TE mismatch",
            ))

        return findings
