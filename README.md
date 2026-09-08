# webbreach

Web application exploitation framework — OWASP Top-10 engines, built-in localhost vuln targets, AI-guided scan queue

> **IMPORTANT: Read before use.**
>
> This is an **authorized security testing and education** tool. It is designed to be
> used exclusively against systems, networks, and hardware that **you own** or for which
> you have **explicit written authorization** to test.
>
> ## Authorization Requirements
>
> - Only test targets you own, your own accounts, or systems you have written permission
>   to assess (scope, duration, and limits in writing).
> - This tool defaults to **offline / simulation mode**. Any action that could affect a
>   real system, emit radio signals, or contact a real network requires an explicit
>   confirmation flag **and** membership of the configured LAB allowlist.
> - The demo/harness functionality runs entirely on localhost, fixtures, or your own lab.
>
> ## Legal Framework
>
> Unauthorized security testing is a crime in most jurisdictions, including:
>
> - **Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030** (US) — unauthorized
>   access to computers is a federal crime, punishable by up to 20 years imprisonment.
> - **Wiretap Act (18 U.S.C. § 2511)** (US) — intercepting electronic communications
>   without consent is illegal.
> - **EU Directive 2013/40/EU on attacks against information systems** — criminalises
>   illegal access and interference.
> - **State / local computer-crime statutes** — nearly all jurisdictions criminalise
>   unauthorised access, data theft, or network disruption.
> - **RF regulatory law** — transmitting on ISM bands without the appropriate
>   authorisation may violate terms of your licence/regulatory regime in your country.
>
> ## Acceptable Use
>
> - Learning and coursework in a controlled lab environment.
> - Authorised penetration testing and red/blue-team exercises with written scope.
> - Security research on systems you own.
> - Building defensive detections and hardening your own infrastructure.
>
> ## Prohibited Use
>
> - **Any** unauthorised access, interception, or disruption.
> - Use against third-party networks, devices, or accounts at any time.
> - Removing or weakening the safety gates, allowlists, or legal notices.
> - Any activity that violates applicable law.
>
> ## No Warranty
>
> This software is provided "AS IS", without warranty of any kind, express or
> implied, including but not limited to the warranties of merchantability, fitness
> for a particular purpose, and non-infringement. **In no event shall the authors or
> copyright holders be liable** for any claim, damages or other liability arising
> from, out of, or in connection with the software or the use or other dealings in
> the software. **You are solely responsible for how you use this tool.**
>
> ## Responsible Disclosure
>
> If you discover real vulnerabilities while learning with this tool, follow
> responsible disclosure:
>
> 1. Report privately to the affected vendor/owner.
> 2. Give a reasonable remediation window.
> 3. Do not exploit beyond proof of concept.
> 4. Only publish with the vendor's consent.

## Quickstart

```bash
python3 -m pip install -e .
python3 -m webbreach --help
python3 -m webbreach --demo    # offline, exit 0
python3 -m unittest discover -s tests
```

## Attack Engines

| Engine | OWASP | Description |
|--------|-------|-------------|
| `sqli` | A03 | SQL Injection (error-based + time-based blind + UNION) |
| `xss` | A03 | Cross-Site Scripting (reflected + stored) |
| `csrf` | A01 | Cross-Site Request Forgery (token + SameSite) |
| `ssrf` | A10 | Server-Side Request Forgery |
| `ssti` | A03 | Server-Side Template Injection |
| `xxe` | A05 | XML External Entity |
| `cmd` | A03 | Command Injection (marker echo) |
| `traversal` | A01 | Path Traversal / LFI |
| `smuggling` | A05 | HTTP Request Smuggling (CL/TE) |
| `redirect` | A01 | Open Redirect |
| `header_injection` | A05 | Header Injection / CRLF |
| `cookie` | A05 | Insecure Cookie Flags |
| `nosql` | A03 | NoSQL Injection ($where) |
| `fuzzer` | — | Param mutation fuzzer with dictionary |

## Usage

```bash
# Scan all engines against built-in lab
python3 -m webbreach scan --target lab

# Run single engine against lab
python3 -m webbreach attack --engine sqli --target lab

# Run single engine against custom URL
python3 -m webbreach attack --engine xss --target http://localhost:8080

# AI-guided scan queue (heuristic priority ordering)
python3 -m webbreach queue --target lab

# Start interactive lab server
python3 -m webbreach lab

# Offline demo (exits 0, prints evidence)
python3 -m webbreach --demo

# List reports
python3 -m webbreach report
```

## Live Lab Test Plan

**Target:** `127.0.0.1` (built-in lab, ephemeral port)

| Engine | Proof | Expected Output |
|--------|-------|-----------------|
| sqli | `attack --engine sqli --target lab` | `[CRITICAL] SQL Injection (error-based GET)` |
| xss | `attack --engine xss --target lab` | `[CRITICAL] Stored XSS` |
| csrf | `attack --engine csrf --target lab` | `[MEDIUM] CSRF: No anti-CSRF token in form` |
| ssrf | `attack --engine ssrf --target lab` | `[HIGH] SSRF — server fetched internal host` |
| ssti | `attack --engine ssti --target lab` | `[CRITICAL] SSTI — expression {{7*7}} evaluated to 49` |
| xxe | `attack --engine xxe --target lab` | `[CRITICAL] XXE — external entity processed` |
| cmd | `attack --engine cmd --target lab` | `[CRITICAL] Command Injection — marker echoed` |
| traversal | `attack --engine traversal --target lab` | `[HIGH] Path Traversal — secret file readable` |
| smuggling | `attack --engine smuggling --target lab` | `[HIGH] HTTP Request Smuggling — CL/TE mismatch accepted` |
| redirect | `attack --engine redirect --target lab` | `[MEDIUM] Open Redirect — to http://evil.com` |
| header_injection | `attack --engine header_injection --target lab` | `[MEDIUM] Header Injection — CRLF accepted` |
| cookie | `attack --engine cookie --target lab` | `[MEDIUM] Insecure cookie — missing Secure flag` |
| nosql | `attack --engine nosql --target lab` | `[CRITICAL] NoSQL Injection — $where bypass` |

## Metrics

See [METRICS.md](METRICS.md) for measured numbers.

**v1.0.0** — stdlib-only, 13 engines, 24 tests, 100% pass rate, 62 demo findings.
