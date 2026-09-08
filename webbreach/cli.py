"""WebBreach CLI — the single entry point for all operations."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from webbreach import __version__
from webbreach.constants import ENGINE_NAMES


def _get_lab_url():
    """Start lab in-process and return base_url + server."""
    from webbreach.lab import LabServer
    server = LabServer()
    server.start()
    return server


def _get_engine(name: str, target_url: str, timeout: float = 3.0):
    if name == "sqli":
        from webbreach.engines.sqli import SQLiEngine
        return SQLiEngine(target_url, timeout)
    elif name == "xss":
        from webbreach.engines.xss import XSSEngine
        return XSSEngine(target_url, timeout)
    elif name == "csrf":
        from webbreach.engines.csrf import CSFREngine
        return CSFREngine(target_url, timeout)
    elif name == "ssrf":
        from webbreach.engines.ssrf import SSRFEngine
        return SSRFEngine(target_url, timeout)
    elif name == "ssti":
        from webbreach.engines.ssti import SSTIEngine
        return SSTIEngine(target_url, timeout)
    elif name == "xxe":
        from webbreach.engines.xxe import XXEEngine
        return XXEEngine(target_url, timeout)
    elif name == "cmd":
        from webbreach.engines.cmd import CommandInjectionEngine
        return CommandInjectionEngine(target_url, timeout)
    elif name == "traversal":
        from webbreach.engines.traversal import TraversalEngine
        return TraversalEngine(target_url, timeout)
    elif name == "smuggling":
        from webbreach.engines.smuggling import SmugglingEngine
        return SmugglingEngine(target_url, timeout)
    elif name == "redirect":
        from webbreach.engines.redirect import RedirectEngine
        return RedirectEngine(target_url, timeout)
    elif name == "header_injection":
        from webbreach.engines.header_injection import HeaderInjectionEngine
        return HeaderInjectionEngine(target_url, timeout)
    elif name == "cookie":
        from webbreach.engines.cookie import CookieEngine
        return CookieEngine(target_url, timeout)
    elif name == "nosql":
        from webbreach.engines.nosql import NoSQLEngine
        return NoSQLEngine(target_url, timeout)
    elif name == "fuzzer":
        from webbreach.fuzzer import FuzzerEngine
        return FuzzerEngine(target_url, timeout)
    else:
        raise ValueError(f"Unknown engine: {name}")


def cmd_scan(args):
    """Run all engines against a target."""
    lab = None
    if args.target == "lab":
        lab = _get_lab_url()
        target_url = lab.base_url
        print(f"[+] Lab started at {target_url}")
    elif args.target == "demo":
        lab = _get_lab_url()
        target_url = lab.base_url
        print(f"[+] Demo mode — lab at {target_url}")
    else:
        target_url = args.target

    try:
        results = []
        for name in ENGINE_NAMES:
            try:
                engine = _get_engine(name, target_url, args.timeout)
                result = engine.run()
                results.append(result)
                hits = len(result.findings)
                status = f"{hits} findings" if hits else "clean"
                print(f"  [{name:20s}] {status} ({result.duration:.2f}s)")
            except Exception as e:
                print(f"  [{name:20s}] ERROR: {e}")

        from webbreach.report import Reporter
        reporter = Reporter("reports")
        paths = reporter.generate(results, tag=args.target)
        total = sum(len(r.findings) for r in results)
        print(f"\n[+] Total: {total} findings across {len(results)} engines")
        print(f"[+] Reports: {paths.get('json', '')} | {paths.get('markdown', '')}")
        return 0
    finally:
        if lab:
            lab.stop()


def cmd_attack(args):
    """Run a single engine against a target."""
    lab = None
    if args.target == "lab":
        lab = _get_lab_url()
        target_url = lab.base_url
        print(f"[+] Lab started at {target_url}")
    else:
        target_url = args.target

    try:
        engine = _get_engine(args.engine, target_url, args.timeout)
        result = engine.run()

        if result.error:
            print(f"[!] Engine error: {result.error}")
            return 1

        if not result.findings:
            print(f"[+] {args.engine}: no findings ({result.duration:.2f}s)")
            return 0

        for f in result.findings:
            print(f"[{f.severity.value.upper():8s}] {f.title}")
            print(f"  Param:  {f.param}")
            print(f"  Method: {f.method}")
            print(f"  Payload: {f.payload}")
            print(f"  Evidence: {f.evidence[:120]}")
            print()
        print(f"[+] {args.engine}: {len(result.findings)} findings ({result.duration:.2f}s)")
        return 0
    finally:
        if lab:
            lab.stop()


def cmd_lab(args):
    """Start the vulnerable lab interactively."""
    lab = _get_lab_url()
    print(f"[+] WebBreach Lab running at {lab.base_url}")
    print("[+] Endpoints:")
    from webbreach.constants import LAB_ENDPOINTS
    for ep, desc in LAB_ENDPOINTS.items():
        print(f"    {ep:30s} {desc}")
    print("\n[+] Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        lab.stop()
    return 0


def cmd_queue(args):
    """AI-guided scan queue."""
    lab = None
    if args.target == "lab":
        lab = _get_lab_url()
        target_url = lab.base_url
    elif args.target == "demo":
        lab = _get_lab_url()
        target_url = lab.base_url
    else:
        target_url = args.target

    try:
        from webbreach.queue import ScanQueue
        queue = ScanQueue(ENGINE_NAMES + ["fuzzer"], target_url)
        print(queue.summary())
        print()

        def run_engine(name):
            engine = _get_engine(name, target_url, args.timeout)
            return engine.run()

        results = queue.run_all(run_engine)
        print(queue.summary())

        from webbreach.report import Reporter
        reporter = Reporter("reports")
        paths = reporter.generate(results, tag="queue")
        total = sum(len(r.findings) for r in results)
        print(f"\n[+] Queue complete: {total} findings")
        return 0
    finally:
        if lab:
            lab.stop()


def cmd_report(args):
    """Generate report from existing scan results."""
    print("[+] Scanning for reports...")
    if not os.path.isdir("reports"):
        print("[-] No reports/ directory found. Run a scan first.")
        return 1
    files = [f for f in os.listdir("reports") if f.endswith(".json")]
    if not files:
        print("[-] No JSON reports found.")
        return 1
    print(f"[+] Found {len(files)} report(s)")
    return 0


def cmd_demo(args):
    """Offline demo — spin lab, run all engines, print evidence, exit 0."""
    lab = _get_lab_url()
    target = lab.base_url
    print(f"[+] WebBreach {__version__} — Demo Mode")
    print(f"[+] Lab: {target}\n")

    all_findings = []
    for name in ENGINE_NAMES:
        try:
            engine = _get_engine(name, target, timeout=3)
            result = engine.run()
            hits = len(result.findings)
            if hits:
                for f in result.findings:
                    print(f"  [{f.severity.value.upper():8s}] {f.title}")
                    print(f"    Payload: {f.payload}")
                    print(f"    Evidence: {f.evidence[:120]}")
                    all_findings.append(f)
            else:
                print(f"  [INFO   ] {name}: no findings")
        except Exception as e:
            print(f"  [ERROR  ] {name}: {e}")
        print()

    # Run fuzzer
    from webbreach.fuzzer import FuzzerEngine
    fuzzer = FuzzerEngine(target, timeout=2)
    fresult = fuzzer.run()
    if fresult.findings:
        print(f"  [FUZZER ] {len(fresult.findings)} fuzzer hits")
        all_findings.extend(fresult.findings)

    total = len(all_findings)
    print(f"\n[+] Demo complete: {total} findings across {len(ENGINE_NAMES)+1} engines")

    # Print summary
    sev_counts = {}
    for f in all_findings:
        sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
    print("[+] Severity breakdown:")
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in sev_counts:
            print(f"    {sev:10s}: {sev_counts[sev]}")

    lab.stop()
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="webbreach",
        description="WebBreach — Web Application Exploitation Framework (OWASP Top-10)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser("scan", help="Scan all engines against a target")
    p_scan.add_argument("--target", default="lab", help="lab, demo, or URL")
    p_scan.add_argument("--timeout", type=float, default=3)
    p_scan.set_defaults(func=cmd_scan)

    # attack
    p_attack = sub.add_parser("attack", help="Run a single engine")
    p_attack.add_argument("--engine", required=True, choices=ENGINE_NAMES + ["fuzzer"])
    p_attack.add_argument("--target", default="lab")
    p_attack.add_argument("--timeout", type=float, default=3)
    p_attack.set_defaults(func=cmd_attack)

    # lab
    p_lab = sub.add_parser("lab", help="Start vulnerable lab")
    p_lab.set_defaults(func=cmd_lab)

    # queue
    p_queue = sub.add_parser("queue", help="AI-guided scan queue")
    p_queue.add_argument("--target", default="lab")
    p_queue.add_argument("--timeout", type=float, default=3)
    p_queue.set_defaults(func=cmd_queue)

    # report
    p_report = sub.add_parser("report", help="List existing reports")
    p_report.set_defaults(func=cmd_report)

    # demo
    p_demo = sub.add_parser("demo", help="Offline demo mode")
    p_demo.set_defaults(func=cmd_demo)

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
