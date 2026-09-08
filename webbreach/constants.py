"""Shared constants for webbreach."""

ENGINE_NAMES = [
    "sqli", "xss", "csrf", "ssrf", "ssti", "xxe",
    "cmd", "traversal", "smuggling", "redirect", "header_injection",
    "cookie", "nosql",
]

LAB_ENDPOINTS = {
    "/": "landing",
    "/api/health": "health",
    "/sqli": "SQL injection (GET)",
    "/sqli_post": "SQL injection (POST)",
    "/xss": "Reflected XSS",
    "/xss/stored": "Stored XSS",
    "/xss/stored/add": "Stored XSS add",
    "/csrf": "CSRF form",
    "/ssrf": "SSRF",
    "/ssti": "SSTI",
    "/xxe": "XXE",
    "/redirect": "Open Redirect",
    "/header_inject": "Header Injection",
    "/traversal": "Path Traversal",
    "/cmd": "Command Injection",
    "/nosql": "NoSQL Injection",
    "/cookie": "Insecure Cookie",
    "/smuggle": "HTTP Smuggling target",
}

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
