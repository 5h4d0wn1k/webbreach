"""Base class for all attack engines."""

from __future__ import annotations

import abc
import time
import urllib.request
import urllib.error
import urllib.parse
import ssl

from webbreach.findings import Finding, ScanResult, Severity


class BaseEngine(abc.ABC):
    """Every engine inherits from this.  Implement ``_scan()``."""

    name: str = "base"
    description: str = ""

    def __init__(self, target_url: str, timeout: float = 3.0):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> ScanResult:
        t0 = time.time()
        result = ScanResult(target=self.target_url, engine=self.name)
        try:
            result.findings = self._scan()
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - t0
        return result

    @abc.abstractmethod
    def _scan(self) -> list[Finding]:
        ...

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _get(self, url: str, timeout: float | None = None) -> tuple[int, str, dict]:
        timeout = timeout or self.timeout
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self._ssl_ctx) as r:
                headers = dict(r.headers)
                body = r.read().decode(errors="replace")
                return r.status, body, headers
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace") if e.fp else ""
            return e.code, body, dict(e.headers) if e.headers else {}
        except Exception as e:
            raise RuntimeError(f"GET {url} failed: {e}")

    def _post(self, url: str, data: bytes | str, content_type: str = "application/json",
              timeout: float | None = None) -> tuple[int, str, dict]:
        timeout = timeout or self.timeout
        if isinstance(data, str):
            data = data.encode()
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", content_type)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self._ssl_ctx) as r:
                headers = dict(r.headers)
                body = r.read().decode(errors="replace")
                return r.status, body, headers
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace") if e.fp else ""
            return e.code, body, dict(e.headers) if e.headers else {}
        except Exception as e:
            raise RuntimeError(f"POST {url} failed: {e}")

    def _post_raw(self, url: str, raw: bytes, headers: dict | None = None,
                  timeout: float | None = None) -> tuple[int, str, dict]:
        """Send raw bytes (for smuggling)."""
        timeout = timeout or self.timeout
        req = urllib.request.Request(url, data=raw, method="POST")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self._ssl_ctx) as r:
                return r.status, r.read().decode(errors="replace"), dict(r.headers)
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace") if e.fp else ""
            return e.code, body, dict(e.headers) if e.headers else {}
        except Exception as e:
            raise RuntimeError(f"RAW POST {url} failed: {e}")

    def _finding(self, **kw) -> Finding:
        kw.setdefault("engine", self.name)
        kw.setdefault("url", self.target_url)
        return Finding(**kw)
