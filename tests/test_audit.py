"""Tests for phpscan audit — the composer.lock dependency audit.

Hermetic: live-mode tests inject fake OSV callables through
run_audit's seams; everything else runs against the real vendored
FriendsOfPHP/KEV snapshots and the fixture locks in
tests/fixtures/. No test touches the network.
Run: python3 -m unittest discover -s tests
"""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from phpscan import __main__ as cli
from phpscan import audit

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
VULN_LOCK = os.path.join(FIXTURES, "composer-vuln.lock")
CLEAN_LOCK = os.path.join(FIXTURES, "composer-clean.lock")

EMPTY_KEV = ({"snapshot_date": "test", "catalog_version": "test"},
             set())


def _lock(packages, dev=()):
    return {"packages": [{"name": n, "version": v} for n, v in packages],
            "packages-dev": [{"name": n, "version": v} for n, v in dev]}


def _tmp_lock(data):
    fd, path = tempfile.mkstemp(suffix=".lock")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return path


def _ids(report):
    return {f["id"] for f in report["findings"]}


class VendoredMatching(unittest.TestCase):
    def test_vulnerable_match_with_fixed_and_remediation(self):
        report, code = audit.run_audit(VULN_LOCK, offline=True)
        self.assertEqual(code, 1)
        self.assertEqual(report["verdict"]["status"], "vulnerable")
        by_id = {f["id"]: f for f in report["findings"]}
        f = by_id["CVE-2022-31042"]
        self.assertEqual(f["package"], "guzzlehttp/guzzle")
        self.assertEqual(f["version"], "6.5.5")
        self.assertFalse(f["dev"])
        self.assertEqual(f["fixed"], "6.5.7")
        self.assertIn("composer update guzzlehttp/guzzle",
                      f["remediation"])
        self.assertIn("friendsofphp", f["sources"])

    def test_clean_packages_produce_no_findings(self):
        report, code = audit.run_audit(CLEAN_LOCK, offline=True)
        self.assertEqual(code, 0)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["verdict"]["status"], "no_findings")

    def test_psr_log_is_clean_in_vuln_lock(self):
        report, _ = audit.run_audit(VULN_LOCK, offline=True)
        self.assertNotIn("psr/log",
                         {f["package"] for f in report["findings"]})
        self.assertEqual(report["packages_scanned"], 2)
        self.assertEqual(report["dev_packages_scanned"], 1)

    def test_every_finding_carries_remediation(self):
        report, _ = audit.run_audit(VULN_LOCK, offline=True)
        self.assertTrue(report["findings"])
        for f in report["findings"]:
            self.assertIn("composer update", f["remediation"], f)


class BranchScoping(unittest.TestCase):
    """A numeric FriendsOfPHP branch key scopes its constraints to
    that release line: CVE-2026-55568 is listed only under branch
    "7.12" with "<7.12.1", so 6.5.5 must NOT match it (an earlier
    union-of-constraints build did — a false verdict)."""

    def test_other_line_not_matched(self):
        report, _ = audit.run_audit(VULN_LOCK, offline=True)
        self.assertNotIn("CVE-2026-55568", _ids(report))
        self.assertNotIn("CVE-2026-24765", _ids(report))

    def test_own_line_matched(self):
        path = _tmp_lock(_lock([("guzzlehttp/guzzle", "7.12.0")]))
        report, code = audit.run_audit(path, offline=True)
        self.assertEqual(code, 1)
        by_id = {f["id"]: f for f in report["findings"]}
        self.assertEqual(by_id["CVE-2026-55568"]["fixed"], "7.12.1")

    def test_branch_in_scope_units(self):
        v655 = audit.parse_version("6.5.5")
        v7120 = audit.parse_version("7.12.0")
        self.assertFalse(audit.branch_in_scope("7.12", v655))
        self.assertTrue(audit.branch_in_scope("7.12", v7120))
        self.assertTrue(audit.branch_in_scope("6.x", v655))
        self.assertTrue(audit.branch_in_scope("master", v655))
        self.assertFalse(audit.branch_in_scope("8.5.x",
                                                audit.parse_version(
                                                    "5.6.2")))


class DevAndKev(unittest.TestCase):
    def test_dev_only_finding_flagged_and_kev(self):
        report, _ = audit.run_audit(VULN_LOCK, offline=True)
        by_id = {f["id"]: f for f in report["findings"]}
        f = by_id["CVE-2017-9841"]  # phpunit RCE, in CISA KEV
        self.assertEqual(f["package"], "phpunit/phpunit")
        self.assertTrue(f["dev"])
        self.assertTrue(f["kev"])
        self.assertEqual(f["fixed"], "5.6.3")


class Honesty(unittest.TestCase):
    FOP_BAD = {"snapshot_date": "test", "commit": None, "packages": {
        "acme/widget": [{"id": "CVE-0000-0001", "cve": "CVE-0000-0001",
                         "title": "Widget flaw", "link": None,
                         "ranges": [{"branch": "1.x",
                                     "versions": [">=banana"]}]}]}}

    def test_unparseable_range_is_unassessed_not_a_verdict(self):
        path = _tmp_lock(_lock([("acme/widget", "1.2.3")]))
        report, code = audit.run_audit(path, offline=True,
                                       fop=self.FOP_BAD, kev=EMPTY_KEV)
        self.assertEqual(report["findings"], [])
        self.assertEqual(code, 0)
        self.assertEqual(len(report["unassessed"]), 1)
        u = report["unassessed"][0]
        self.assertEqual(u["advisory"], "CVE-0000-0001")
        self.assertIn("could not be parsed", u["reason"])
        self.assertIn("unassessed", report["verdict"]["detail"])

    def test_dev_version_string_is_unassessed(self):
        path = _tmp_lock(_lock([("guzzlehttp/guzzle", "dev-master")]))
        report, code = audit.run_audit(path, offline=True)
        self.assertEqual(report["findings"], [])
        self.assertEqual(code, 0)
        self.assertEqual(len(report["unassessed"]), 1)
        self.assertIn("not a release version",
                      report["unassessed"][0]["reason"])


class OsvWiring(unittest.TestCase):
    VULN = {"id": "GHSA-f2wf-25xc-69c9",
            "summary": "Failure to strip the Cookie header",
            "aliases": ["CVE-2022-31042"],
            "database_specific": {"severity": "HIGH"},
            "affected": [{"package": {"name": "guzzlehttp/guzzle",
                                      "ecosystem": "Packagist"},
                          "ranges": [{"type": "ECOSYSTEM", "events":
                                      [{"introduced": "0"},
                                       {"fixed": "6.5.7"}]}]}],
            "references": [{"type": "ADVISORY",
                            "url": "https://example.com/adv"}]}

    def _batch(self, seen):
        def batch(pkgs):
            seen.append(pkgs)
            return [{"vulns": [{"id": "GHSA-f2wf-25xc-69c9"}]}
                    if n == "guzzlehttp/guzzle" else {}
                    for n, _ in pkgs]
        return batch

    def test_osv_merges_with_friendsofphp(self):
        seen = []
        report, code = audit.run_audit(
            VULN_LOCK, osv_batch=self._batch(seen),
            osv_vuln=lambda vid: self.VULN)
        self.assertEqual(code, 1)
        merged = [f for f in report["findings"]
                  if f["id"] == "CVE-2022-31042"]
        self.assertEqual(len(merged), 1)
        f = merged[0]
        self.assertEqual(set(f["sources"]), {"osv", "friendsofphp"})
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["fixed"], "6.5.7")
        # Only names + versions were queried, one batch for the lock.
        self.assertEqual(len(seen), 1)
        self.assertIn(("guzzlehttp/guzzle", "6.5.5"), seen[0])

    def test_offline_never_calls_osv(self):
        def boom(pkgs):
            raise AssertionError("OSV called in offline mode")
        report, code = audit.run_audit(VULN_LOCK, offline=True,
                                       osv_batch=boom)
        self.assertEqual(code, 1)
        self.assertEqual(report["sources"]["osv"]["status"],
                         "offline")

    def test_osv_failure_degrades_disclosed_not_silent(self):
        def boom(pkgs):
            raise RuntimeError("connection reset")
        report, code = audit.run_audit(VULN_LOCK, osv_batch=boom)
        self.assertEqual(report["sources"]["osv"]["status"], "error")
        self.assertIn("connection reset",
                      report["sources"]["osv"]["detail"])
        self.assertEqual(code, 1)  # vendored findings still stand
        self.assertIn("CVE-2022-31042", _ids(report))


class CliExitCodes(unittest.TestCase):
    def _run(self, argv):
        with redirect_stdout(io.StringIO()):
            return cli.main(argv)

    def test_missing_file_is_2(self):
        self.assertEqual(self._run(["audit", "/nonexistent.lock"]), 2)

    def test_unparseable_lock_is_2(self):
        fd, path = tempfile.mkstemp(suffix=".lock")
        with os.fdopen(fd, "w") as f:
            f.write("{not json")
        self.assertEqual(self._run(["audit", path]), 2)

    def test_not_a_lock_is_2(self):
        path = _tmp_lock({"hello": "world"})
        self.assertEqual(self._run(["audit", path]), 2)

    def test_no_path_is_2(self):
        self.assertEqual(self._run(["audit"]), 2)

    def test_clean_0_vuln_1(self):
        self.assertEqual(
            self._run(["audit", CLEAN_LOCK, "--offline"]), 0)
        self.assertEqual(
            self._run(["audit", VULN_LOCK, "--offline"]), 1)

    def test_directory_argument(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "composer.lock"), "w",
                      encoding="utf-8") as f:
                with open(VULN_LOCK, encoding="utf-8") as src:
                    f.write(src.read())
            self.assertEqual(self._run(["audit", d, "--offline"]), 1)


class ConstraintSemantics(unittest.TestCase):
    def m(self, constraint, version):
        return audit.constraint_matches(
            constraint, audit.parse_version(version).key)

    def test_comparators_and_conjunction(self):
        self.assertTrue(self.m(">=4,<6.5.7", "6.5.5"))
        self.assertFalse(self.m(">=4,<6.5.7", "6.5.7"))
        self.assertTrue(self.m(">=7,<7.4.4", "7.4.0"))
        self.assertFalse(self.m(">=7,<7.4.4", "6.5.5"))

    def test_or_groups(self):
        self.assertTrue(self.m("<1.2.3 || >=2,<2.0.1", "2.0.0"))
        self.assertFalse(self.m("<1.2.3 || >=2,<2.0.1", "1.5.0"))

    def test_caret(self):
        self.assertTrue(self.m("^1.2.3", "1.9.0"))
        self.assertFalse(self.m("^1.2.3", "2.0.0"))
        self.assertTrue(self.m("^0.3", "0.3.9"))
        self.assertFalse(self.m("^0.3", "0.4.0"))
        self.assertFalse(self.m("^0.0.3", "0.0.4"))

    def test_tilde(self):
        self.assertTrue(self.m("~1.2.3", "1.2.9"))
        self.assertFalse(self.m("~1.2.3", "1.3.0"))
        self.assertTrue(self.m("~1", "1.9.9"))
        self.assertFalse(self.m("~1", "2.0.0"))

    def test_wildcards_and_partials(self):
        self.assertTrue(self.m("1.2.*", "1.2.9"))
        self.assertFalse(self.m("1.2.*", "1.3.0"))
        self.assertTrue(self.m("1.2", "1.2.0"))
        self.assertTrue(self.m("*", "9.9.9"))
        self.assertFalse(self.m("!=1.2.3", "1.2.3"))
        self.assertTrue(self.m("!=1.2.3", "1.2.4"))

    def test_hyphen_range(self):
        self.assertTrue(self.m("1.0 - 2.0", "2.0.9"))
        self.assertFalse(self.m("1.0 - 2.0", "2.1.0"))
        self.assertTrue(self.m("1.0.0 - 2.0.3", "2.0.3"))
        self.assertFalse(self.m("1.0.0 - 2.0.3", "2.0.4"))

    def test_prerelease_ordering(self):
        self.assertTrue(self.m("<1.0.0", "1.0.0-RC1"))
        self.assertFalse(self.m(">=1.0.0", "1.0.0-beta2"))
        self.assertTrue(self.m(">=4.0.0-rc2", "4.0.0"))
        self.assertTrue(self.m("<2.0", "2.0.0-dev"))

    def test_unparseable_raises(self):
        with self.assertRaises(audit.UnparseableConstraint):
            self.m(">=banana", "1.2.3")
        with self.assertRaises(audit.UnparseableConstraint):
            self.m("", "1.2.3")


if __name__ == "__main__":
    unittest.main()
