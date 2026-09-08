"""Reporting — JSON + Markdown + optional HTML."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone

from webbreach.findings import Finding, ScanResult, Severity


def _severity_badge(sev: str) -> str:
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(sev, "")


class Reporter:
    """Generate reports from scan results."""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate(self, results: list[ScanResult], tag: str = "") -> dict[str, str]:
        """Return dict of {format: filepath}."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        prefix = f"webbreach_{tag}_{ts}" if tag else f"webbreach_{ts}"

        all_findings: list[Finding] = []
        for r in results:
            all_findings.extend(r.findings)

        paths = {}

        # JSON
        json_path = os.path.join(self.output_dir, f"{prefix}.json")
        with open(json_path, "w") as f:
            json.dump({
                "generated": ts,
                "results": [r.to_dict() for r in results],
                "total_findings": len(all_findings),
            }, f, indent=2)
        paths["json"] = json_path

        # Markdown
        md_path = os.path.join(self.output_dir, f"{prefix}.md")
        md = self._build_markdown(results, all_findings, ts)
        with open(md_path, "w") as f:
            f.write(md)
        paths["markdown"] = md_path

        return paths

    def _build_markdown(self, results: list[ScanResult], findings: list[Finding], ts: str) -> str:
        lines = [
            f"# WebBreach Report",
            f"Generated: {ts}",
            f"Total findings: {len(findings)}",
            "",
        ]

        # Summary table
        lines.append("| Engine | Findings | Duration | Error |")
        lines.append("|--------|----------|----------|-------|")
        for r in results:
            err = r.error[:30] if r.error else ""
            lines.append(f"| {r.engine} | {len(r.findings)} | {r.duration:.2f}s | {err} |")

        lines.append("")

        # Findings detail
        if findings:
            lines.append("## Findings")
            lines.append("")
            for f in findings:
                badge = _severity_badge(f.severity.value)
                lines.append(f"### {badge} [{f.severity.value.upper()}] {f.title}")
                lines.append(f"- **Engine:** {f.engine}")
                lines.append(f"- **URL:** {f.url}")
                lines.append(f"- **Param:** `{f.param}`")
                lines.append(f"- **Method:** {f.method}")
                lines.append(f"- **Payload:** `{f.payload}`")
                lines.append(f"- **Evidence:** `{f.evidence[:200]}`")
                lines.append("")
        else:
            lines.append("_No findings._")

        return "\n".join(lines)

    def generate_html(self, results: list[ScanResult], tag: str = "") -> str:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        prefix = f"webbreach_{tag}_{ts}" if tag else f"webbreach_{ts}"

        all_findings = []
        for r in results:
            all_findings.extend(r.findings)

        html = f"""<!DOCTYPE html>
<html><head><title>WebBreach Report</title>
<style>
body {{ font-family: monospace; background: #0a0a0a; color: #00ff41; padding: 20px; }}
.critical {{ color: #ff0000; }} .high {{ color: #ff6600; }}
.medium {{ color: #ffcc00; }} .low {{ color: #0088ff; }}
table {{ border-collapse: collapse; margin: 10px 0; }}
td, th {{ border: 1px solid #333; padding: 6px 12px; text-align: left; }}
</style></head><body>
<h1>WebBreach Report — {ts}</h1>
<p>Total findings: {len(all_findings)}</p>
<table><tr><th>Engine</th><th>Findings</th><th>Duration</th></tr>"""
        for r in results:
            html += f"<tr><td>{r.engine}</td><td>{len(r.findings)}</td><td>{r.duration:.2f}s</td></tr>"
        html += "</table>"

        for f in all_findings:
            html += f'<div class="{f.severity.value}"><b>[{f.severity.value.upper()}]</b> {f.title} — {f.engine}</div>'

        html += "</body></html>"
        path = os.path.join(self.output_dir, f"{prefix}.html")
        with open(path, "w") as f:
            f.write(html)
        return path
