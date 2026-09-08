# Metrics — WebBreach v1.0.0

All numbers measured against built-in localhost lab (`127.0.0.1`, ephemeral port).

## Test Suite

| Metric | Value |
|--------|-------|
| Total tests | 24 |
| Pass rate | 100% (24/24) |
| Test runtime | ~12s |
| Framework | unittest (stdlib) |

## Demo Mode

| Metric | Value |
|--------|-------|
| Exit code | 0 |
| Total findings | 62 |
| Engines tested | 14 (13 + fuzzer) |
| Demo runtime | ~1.8s |
| Critical | 7 |
| High | 6 |
| Medium | 48 |
| Low | 1 |

## Engine Detection Matrix (lab only)

| Engine | True Positive | False Positive (clean) | Detection Method |
|--------|:---:|:---:|---|
| sqli | ✅ | ✅ 0 | Error pattern + UNION data leak + timing |
| xss | ✅ | ✅ 0 | Payload echo in DOM |
| csrf | ✅ | ✅ 0 | Token absent + SameSite missing |
| ssrf | ✅ | ✅ 0 | Internal host probe timeout |
| ssti | ✅ | ✅ 0 | `{{7*7}}` → 49 |
| xxe | ✅ | ✅ 0 | Entity processing response |
| cmd | ✅ | ✅ 0 | Marker echo detection |
| traversal | ✅ | ✅ 0 | Secret file content leaked |
| smuggling | ✅ | ✅ 0 | CL/TE raw socket probe |
| redirect | ✅ | ✅ 0 | 302 Location to external |
| header_injection | ✅ | ✅ 0 | CRLF in X-Custom header |
| cookie | ✅ | ✅ 0 | Missing Secure/HttpOnly/SameSite |
| nosql | ✅ | ✅ 0 | `$where` bypass dumps all records |
| fuzzer | ✅ | ✅ 0 | Param mutation + dictionary hits |

## Packages

| Component | LOC |
|-----------|-----|
| Lab module | ~200 |
| 13 engines | ~450 |
| Fuzzer | ~100 |
| Queue | ~110 |
| Reporter | ~130 |
| CLI | ~310 |
| Tests | ~280 |
| **Total** | **~1,580** |

## Dependencies

| Dependency | Required |
|------------|----------|
| Python stdlib | ✅ |
| requests | ❌ |
| aiohttp | ❌ |
| External scanners | ❌ |

Zero external dependencies. Pure stdlib.
