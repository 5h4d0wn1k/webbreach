"""Comprehensive engine tests — each engine TRUE-POSITIVE on vuln page + FALSE-POSITIVE-free on clean page."""

import json
import unittest

from webbreach.lab import LabServer


class _LabTestCase(unittest.TestCase):
    """Base class that starts/stops lab for the class."""

    _server: LabServer
    _url: str

    @classmethod
    def setUpClass(cls):
        cls._server = LabServer()
        cls._server.start()
        cls._url = cls._server.base_url

    @classmethod
    def tearDownClass(cls):
        cls._server.stop()


# -----------------------------------------------------------------------
# SQLi
# -----------------------------------------------------------------------
class TestSQLi(_LabTestCase):
    def test_true_positive_error_based(self):
        from webbreach.engines.sqli import SQLiEngine
        r = SQLiEngine(self._url).run()
        self.assertTrue(any("error" in f.title.lower() or "union" in f.title.lower() for f in r.findings),
                        "Should detect error-based or UNION-based SQLi")

    def test_true_positive_time_based(self):
        from webbreach.engines.sqli import SQLiEngine
        r = SQLiEngine(self._url).run()
        self.assertTrue(any("time" in f.title.lower() for f in r.findings),
                        "Should detect time-based blind SQLi")

    def test_true_positive_post(self):
        from webbreach.engines.sqli import SQLiEngine
        r = SQLiEngine(self._url).run()
        self.assertTrue(any("post" in f.title.lower() for f in r.findings),
                        "Should detect POST SQLi")


# -----------------------------------------------------------------------
# XSS
# -----------------------------------------------------------------------
class TestXSS(_LabTestCase):
    def test_true_positive_reflected(self):
        from webbreach.engines.xss import XSSEngine
        r = XSSEngine(self._url).run()
        self.assertTrue(any("reflected" in f.title.lower() for f in r.findings),
                        "Should detect reflected XSS")

    def test_true_positive_stored(self):
        from webbreach.engines.xss import XSSEngine
        r = XSSEngine(self._url).run()
        self.assertTrue(any("stored" in f.title.lower() for f in r.findings),
                        "Should detect stored XSS")


# -----------------------------------------------------------------------
# CSRF
# -----------------------------------------------------------------------
class TestCSRF(_LabTestCase):
    def test_true_positive(self):
        from webbreach.engines.csrf import CSFREngine
        r = CSFREngine(self._url).run()
        self.assertGreater(len(r.findings), 0, "Should detect CSRF issues")

    def test_detects_missing_token(self):
        from webbreach.engines.csrf import CSFREngine
        r = CSFREngine(self._url).run()
        self.assertTrue(any("token" in f.title.lower() for f in r.findings))


# -----------------------------------------------------------------------
# SSRF
# -----------------------------------------------------------------------
class TestSSRF(_LabTestCase):
    def test_true_positive(self):
        from webbreach.engines.ssrf import SSRFEngine
        r = SSRFEngine(self._url).run()
        self.assertGreater(len(r.findings), 0, "Should detect SSRF")


# -----------------------------------------------------------------------
# SSTI
# -----------------------------------------------------------------------
class TestSSTI(_LabTestCase):
    def test_true_positive(self):
        from webbreach.engines.ssti import SSTIEngine
        r = SSTIEngine(self._url).run()
        self.assertTrue(len(r.findings) > 0, "Should detect SSTI with 7*7=49")
        self.assertIn("49", r.findings[0].evidence)


# -----------------------------------------------------------------------
# XXE
# -----------------------------------------------------------------------
class TestXXE(_LabTestCase):
    def test_true_positive(self):
        from webbreach.engines.xxe import XXEEngine
        r = XXEEngine(self._url).run()
        self.assertGreater(len(r.findings), 0, "Should detect XXE")


# -----------------------------------------------------------------------
# Command Injection
# -----------------------------------------------------------------------
class TestCmdInjection(_LabTestCase):
    def test_true_positive(self):
        from webbreach.engines.cmd import CommandInjectionEngine
        r = CommandInjectionEngine(self._url).run()
        self.assertGreater(len(r.findings), 0, "Should detect command injection")
        self.assertIn("WBCMD_9f3a", r.findings[0].evidence)


# -----------------------------------------------------------------------
# Path Traversal
# -----------------------------------------------------------------------
class TestTraversal(_LabTestCase):
    def test_true_positive(self):
        from webbreach.engines.traversal import TraversalEngine
        r = TraversalEngine(self._url).run()
        self.assertGreater(len(r.findings), 0, "Should detect path traversal")
        self.assertIn("TOP_SECRET_F4G", r.findings[0].evidence)


# -----------------------------------------------------------------------
# HTTP Smuggling
# -----------------------------------------------------------------------
class TestSmuggling(_LabTestCase):
    def test_true_positive(self):
        from webbreach.engines.smuggling import SmugglingEngine
        r = SmugglingEngine(self._url).run()
        self.assertGreater(len(r.findings), 0, "Should detect smuggling CL/TE")


# -----------------------------------------------------------------------
# Open Redirect
# -----------------------------------------------------------------------
class TestRedirect(_LabTestCase):
    def test_true_positive(self):
        from webbreach.engines.redirect import RedirectEngine
        r = RedirectEngine(self._url).run()
        self.assertGreater(len(r.findings), 0, "Should detect open redirect")


# -----------------------------------------------------------------------
# Header Injection
# -----------------------------------------------------------------------
class TestHeaderInjection(_LabTestCase):
    def test_true_positive(self):
        from webbreach.engines.header_injection import HeaderInjectionEngine
        r = HeaderInjectionEngine(self._url).run()
        self.assertGreater(len(r.findings), 0, "Should detect header injection")


# -----------------------------------------------------------------------
# Insecure Cookie
# -----------------------------------------------------------------------
class TestCookie(_LabTestCase):
    def test_true_positive(self):
        from webbreach.engines.cookie import CookieEngine
        r = CookieEngine(self._url).run()
        self.assertGreater(len(r.findings), 0, "Should detect insecure cookie")


# -----------------------------------------------------------------------
# NoSQL
# -----------------------------------------------------------------------
class TestNoSQL(_LabTestCase):
    def test_true_positive(self):
        from webbreach.engines.nosql import NoSQLEngine
        r = NoSQLEngine(self._url).run()
        self.assertGreater(len(r.findings), 0, "Should detect NoSQL injection")


# -----------------------------------------------------------------------
# False-positive checks on clean page
# -----------------------------------------------------------------------
class TestCleanPageNoFalsePositives(_LabTestCase):
    def test_health_endpoint_clean(self):
        """Clean /api/health should produce zero findings from any engine."""
        from webbreach.engines.sqli import SQLiEngine
        from webbreach.engines.xss import XSSEngine
        from webbreach.engines.ssti import SSTIEngine
        from webbreach.engines.cmd import CommandInjectionEngine
        from webbreach.engines.traversal import TraversalEngine

        clean = f"{self._url}/api/health"
        for Engine in [SQLiEngine, XSSEngine, SSTIEngine, CommandInjectionEngine, TraversalEngine]:
            r = Engine(clean).run()
            self.assertEqual(len(r.findings), 0,
                             f"{Engine.name} should have 0 findings on clean page")


# -----------------------------------------------------------------------
# Fuzzer
# -----------------------------------------------------------------------
class TestFuzzer(_LabTestCase):
    def test_fuzzer_runs(self):
        from webbreach.fuzzer import FuzzerEngine
        r = FuzzerEngine(self._url, timeout=2).run()
        self.assertIsNotNone(r)
        self.assertGreaterEqual(r.duration, 0)


# -----------------------------------------------------------------------
# Queue
# -----------------------------------------------------------------------
class TestQueue(_LabTestCase):
    def test_queue_builds(self):
        from webbreach.queue import ScanQueue
        from webbreach.constants import ENGINE_NAMES
        q = ScanQueue(ENGINE_NAMES[:3], self._url)
        self.assertEqual(len(q.items), 3)
        self.assertIn("sqli", [i.engine for i in q.items])

    def test_queue_summary(self):
        from webbreach.queue import ScanQueue
        q = ScanQueue(["sqli", "xss"], self._url)
        s = q.summary()
        self.assertIn("Scan Queue", s)


# -----------------------------------------------------------------------
# Reporter
# -----------------------------------------------------------------------
class TestReporter(unittest.TestCase):
    def test_json_and_md(self):
        from webbreach.report import Reporter
        from webbreach.findings import ScanResult, Finding, Severity
        r = Reporter("/tmp/webbreach_test_reports")
        result = ScanResult(target="http://test", engine="sqli", findings=[
            Finding(engine="sqli", severity=Severity.HIGH, title="test", evidence="ev")
        ])
        paths = r.generate([result], tag="test")
        self.assertIn("json", paths)
        self.assertIn("markdown", paths)
        # cleanup
        import os
        for p in paths.values():
            try:
                os.unlink(p)
            except OSError:
                pass


# -----------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------
class TestCLI(unittest.TestCase):
    def test_demo_exits_0(self):
        from webbreach.cli import cmd_demo

        class Args:
            pass
        ret = cmd_demo(Args())
        self.assertEqual(ret, 0)

    def test_help(self):
        from webbreach.cli import main
        with self.assertRaises(SystemExit) as cm:
            main(["--help"])
        self.assertEqual(cm.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
