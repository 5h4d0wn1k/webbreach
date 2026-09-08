"""Open Redirect detection."""

import urllib.error
from webbreach.engines import BaseEngine
from webbreach.findings import Finding, Severity


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(newurl, code, msg, headers, fp)


import urllib.request


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

        # Build opener that doesn't follow redirects
        import ssl as _ssl
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        opener = urllib.request.build_opener(
            _NoRedirect,
            urllib.request.HTTPSHandler(context=ctx),
        )

        for marker in self.REDIRECT_MARKERS:
            url = f"{base}/redirect?next={marker}"
            try:
                req = urllib.request.Request(url)
                resp = opener.open(req, timeout=self.timeout)
                status = resp.status
                headers = dict(resp.headers)
                location = headers.get("Location", "")
            except urllib.error.HTTPError as e:
                status = e.code
                headers = dict(e.headers) if e.headers else {}
                location = headers.get("Location", "")
            except Exception:
                continue

            clean = marker.lstrip("/").lstrip("\\")
            if status in (301, 302) and clean in location:
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
