"""Exposed composer.lock audit — scan integration tests.

When a site serves its composer.lock publicly, the external scan
fetches it through the guarded fetcher, runs the dependency audit
engine against the locked versions, and merges the findings into
the scan report with the lockfile URL as provenance. Hermetic:
every fetch is stubbed, no test touches the network (OSV is
stubbed or disabled via offline=True).
Run: python3 -m unittest discover -s tests
"""

import json
import os
import unittest
from unittest import mock

from phpscan import audit, scan

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
with open(os.path.join(FIXTURES, "composer-vuln.lock"),
          encoding="utf-8") as fh:
    VULN_LOCK = fh.read()
with open(os.path.join(FIXTURES, "composer-clean.lock"),
          encoding="utf-8") as fh:
    CLEAN_LOCK = fh.read()

HOME = "<html><head><title>site</title></head><body>hello</body></html>"
PATCHED = {"X-Powered-By": "PHP/8.3.36"}


def ok(body="", headers=None, status=200, url="https://example.com/"):
    return {"ok": status < 400, "status": status, "final_url": url,
            "headers": headers or {}, "body": body,
            "error": None if status < 400 else f"HTTP {status}"}


def notfound(url=""):
    return {"ok": False, "status": 404,
            "final_url": url or "https://example.com/",
            "headers": {}, "body": "", "error": "HTTP 404"}


def make_fetch(lock_body=None, lock_status=200):
    def fetch(url, ctx=None, deadline=None, max_body=None):
        if url.rstrip("/") == "https://example.com":
            return ok(HOME, PATCHED)
        if url.endswith("/composer.lock"):
            if lock_body is None:
                return notfound(url)
            return ok(lock_body, status=lock_status, url=url)
        return notfound(url)
    return fetch


def _no_osv(pkgs, timeout=20):
    return [{} for _ in pkgs]


class ExposedLockScan(unittest.TestCase):
    def run_scan(self, fetch, offline=True):
        with mock.patch.object(scan, "_fetch", fetch), \
                mock.patch.object(audit, "osv_querybatch", _no_osv):
            return scan.scan("https://example.com/", offline=offline)

    def test_vulnerable_lock_merged_with_provenance(self):
        r = self.run_scan(make_fetch(VULN_LOCK))
        deps = r["dependencies"]
        self.assertIsNotNone(deps)
        self.assertEqual(deps["source"], "exposed_composer_lock")
        self.assertEqual(deps["source_url"],
                         "https://example.com/composer.lock")
        self.assertEqual(deps["packages_scanned"], 2)
        self.assertEqual(deps["dev_packages_scanned"], 1)
        ids = {f["id"] for f in deps["findings"]}
        self.assertIn("CVE-2017-9841", ids)   # phpunit, CISA KEV
        self.assertIn("CVE-2022-31042", ids)  # guzzle
        for f in deps["findings"]:
            self.assertEqual(f["provenance"]["type"],
                             "exposed_composer_lock")
            self.assertEqual(f["provenance"]["url"],
                             "https://example.com/composer.lock")
            self.assertTrue(f["remediation"])

    def test_vulnerable_lock_escalates_verdict(self):
        # Homepage discloses PHP 8.3.36 (patched): only the
        # dependency findings can escalate this verdict.
        r = self.run_scan(make_fetch(VULN_LOCK))
        self.assertEqual(r["php_version"], "8.3.36")
        kinds = {f["kind"] for f in r["findings"]}
        self.assertIn("composer_lock_exposed", kinds)
        dep = [f for f in r["findings"]
               if f["kind"] == "vulnerable_dependency"]
        self.assertTrue(dep)
        kev = [f for f in dep if f.get("cve") == "CVE-2017-9841"]
        self.assertEqual(len(kev), 1)
        self.assertEqual(kev[0]["severity"], "high")
        self.assertEqual(r["verdict"]["status"], "vulnerable")
        self.assertEqual(r["verdict"]["findings"], r["findings"])

    def test_clean_lock_no_dep_findings_no_escalation(self):
        r = self.run_scan(make_fetch(CLEAN_LOCK))
        self.assertIsNotNone(r["dependencies"])
        self.assertEqual(r["dependencies"]["findings"], [])
        self.assertEqual(
            [f for f in r["findings"]
             if f["kind"] == "vulnerable_dependency"], [])
        kinds = {f["kind"] for f in r["findings"]}
        self.assertIn("composer_lock_exposed", kinds)
        self.assertEqual(r["verdict"]["status"], "patched")

    def test_no_lock_404(self):
        r = self.run_scan(make_fetch(None))
        self.assertIsNone(r["dependencies"])
        self.assertNotIn("composer_lock_exposed",
                         {f["kind"] for f in r["findings"]})
        self.assertEqual(r["verdict"]["status"], "patched")

    def test_malformed_lock_ignored(self):
        r = self.run_scan(make_fetch("{this is not json"))
        self.assertIsNone(r["dependencies"])
        self.assertEqual(r["verdict"]["status"], "patched")

    def test_truncated_lock_ignored(self):
        # What an over-cap response looks like after the bounded
        # read: valid JSON cut mid-stream. Defensive parse fails,
        # the scan proceeds exactly as if no lock were there.
        r = self.run_scan(make_fetch(VULN_LOCK[:len(VULN_LOCK) // 2]))
        self.assertIsNone(r["dependencies"])
        self.assertEqual(r["verdict"]["status"], "patched")

    def test_html_at_lock_path_ignored(self):
        # SPA-style fallback: 200 with the homepage HTML is not a
        # lockfile and must not be reported as one.
        r = self.run_scan(make_fetch(HOME))
        self.assertIsNone(r["dependencies"])
        self.assertNotIn("composer_lock_exposed",
                         {f["kind"] for f in r["findings"]})

    def test_offline_never_calls_osv(self):
        boom = mock.Mock(side_effect=AssertionError("OSV called"))
        with mock.patch.object(scan, "_fetch", make_fetch(VULN_LOCK)), \
                mock.patch.object(audit, "osv_querybatch", boom):
            r = scan.scan("https://example.com/", offline=True)
        self.assertEqual(r["dependencies"]["sources"]["osv"]["status"],
                         "offline")
        self.assertIn("CVE-2017-9841",
                      {f["id"] for f in r["dependencies"]["findings"]})

    def test_live_osv_failure_degrades_to_vendored(self):
        def boom(pkgs, timeout=20):
            raise RuntimeError("no network")
        with mock.patch.object(scan, "_fetch", make_fetch(VULN_LOCK)), \
                mock.patch.object(audit, "osv_querybatch", boom):
            r = scan.scan("https://example.com/", offline=False)
        self.assertEqual(r["dependencies"]["sources"]["osv"]["status"],
                         "error")
        self.assertIn("CVE-2017-9841",
                      {f["id"] for f in r["dependencies"]["findings"]})
        self.assertEqual(r["verdict"]["status"], "vulnerable")


class SeverityLevel(unittest.TestCase):
    def test_words(self):
        self.assertEqual(audit.severity_level({"severity": "HIGH"}),
                         "high")
        self.assertEqual(audit.severity_level({"severity": "Critical"}),
                         "critical")
        self.assertEqual(
            audit.severity_level({"severity": "MODERATE"}), "medium")
        self.assertEqual(audit.severity_level({"severity": "low"}),
                         "low")

    def test_kev_is_high(self):
        self.assertEqual(
            audit.severity_level({"severity": None, "kev": True}),
            "high")

    def test_no_evidence_no_level(self):
        self.assertIsNone(audit.severity_level({"severity": None}))
        self.assertIsNone(audit.severity_level({}))
        self.assertIsNone(
            audit.severity_level({"severity": "not-a-severity"}))

    def test_cvss_vectors(self):
        crit = {"severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/"
                            "C:H/I:H/A:H"}
        self.assertEqual(audit.severity_level(crit), "critical")
        high = {"severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/"
                            "C:H/I:H/A:H"}
        self.assertEqual(audit.severity_level(high), "critical")
        med = {"severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/"
                           "C:L/I:L/A:N"}
        self.assertEqual(audit.severity_level(med), "medium")
        self.assertIsNone(
            audit.severity_level({"severity": "CVSS:3.1/AV:X"}))


class BoundedRead(unittest.TestCase):
    class Resp:
        def __init__(self, data):
            self._data = data

        def read(self, n=-1):
            if n is None or n < 0:
                n = len(self._data)
            out, self._data = self._data[:n], self._data[n:]
            return out

    def test_max_body_caps_the_read(self):
        out = scan._read_capped(self.Resp(b"x" * 5000), max_body=100)
        self.assertEqual(len(out), 100)

    def test_default_cap_unchanged(self):
        out = scan._read_capped(self.Resp(b"x" * 5000))
        self.assertEqual(len(out), 5000)


if __name__ == "__main__":
    unittest.main()
