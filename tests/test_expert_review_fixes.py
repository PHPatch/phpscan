"""Regression tests for the 2026-10-30 expert review fixes
(phpscan sections §3.1–§3.3, §4 C2/C6).

Each class pins one finding: P1 degraded audit verdict, P2
catch-all control + shell signatures, P3 asset-URL version
confidence, P4/P4b/P4c hunt gaps, P5 coverage block, P6
severity normalization + --fail-on, P7 OSV leading-v handling,
P8 UA / --format text, P9 CMS signal discipline, versioning
pre-release handling, and the C6 exposed-lockfile constraints.
Hermetic throughout: fetches and OSV are stubbed.
Run: python3 -m unittest discover -s tests
"""

import hashlib
import io
import json
import os
import re
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from phpscan import __main__ as cli
from phpscan import __version__, audit, detect, hunt, scan, \
    versioning

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
VULN_LOCK = os.path.join(FIXTURES, "composer-vuln.lock")
CLEAN_LOCK = os.path.join(FIXTURES, "composer-clean.lock")
with open(VULN_LOCK, encoding="utf-8") as fh:
    VULN_LOCK_BODY = fh.read()

PATCHED = {"X-Powered-By": "PHP/8.3.36"}
HOME = "<html><head><title>site</title></head><body>hi</body></html>"


def ok(body="", headers=None, status=200, url="https://example.com/"):
    return {"ok": status < 400, "status": status, "final_url": url,
            "headers": headers or {}, "body": body,
            "error": None if status < 400 else f"HTTP {status}"}


def notfound(url=""):
    return {"ok": False, "status": 404,
            "final_url": url or "https://example.com/",
            "headers": {}, "body": "", "error": "HTTP 404"}


def _write(root, rel, data):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(path, mode) as f:
        f.write(data)
    return path


# ----------------------------------------------------------------
# P1 — a failed OSV lookup must never read as a clean audit
# ----------------------------------------------------------------

class P1DegradedAudit(unittest.TestCase):
    @staticmethod
    def _boom(pkgs, timeout=20):
        raise RuntimeError("osv unreachable")

    def test_clean_lock_osv_down_is_degraded_exit_3(self):
        report, code = audit.run_audit(CLEAN_LOCK,
                                       osv_batch=self._boom)
        self.assertEqual(code, 3)
        v = report["verdict"]
        self.assertEqual(v["status"], "no_findings_degraded")
        self.assertTrue(v["incomplete"])
        # The detail names only the source actually consulted.
        self.assertIn("vendored FriendsOfPHP", v["detail"])
        self.assertNotIn("No advisory in OSV or", v["detail"])
        self.assertIn("OSV could not be consulted", v["detail"])

    def test_vuln_lock_osv_down_findings_stand_exit_1(self):
        report, code = audit.run_audit(VULN_LOCK,
                                       osv_batch=self._boom)
        self.assertEqual(code, 1)
        self.assertEqual(report["verdict"]["status"], "vulnerable")
        self.assertIn("OSV could not be consulted",
                      report["verdict"]["detail"])

    def test_offline_clean_is_not_degraded(self):
        report, code = audit.run_audit(CLEAN_LOCK, offline=True)
        self.assertEqual(code, 0)
        self.assertEqual(report["verdict"]["status"], "no_findings")
        self.assertNotIn("incomplete", report["verdict"])


# ----------------------------------------------------------------
# P6 — normalized severity + --fail-on
# ----------------------------------------------------------------

class P6SeverityAndFailOn(unittest.TestCase):
    def test_severities_normalized(self):
        report, _ = audit.run_audit(VULN_LOCK, offline=True)
        by_id = {f["id"]: f for f in report["findings"]}
        # KEV-listed -> high; FriendsOfPHP publishes no severity
        # and this CVE is not in KEV -> unknown (never invented).
        self.assertEqual(by_id["CVE-2017-9841"]["severity"],
                         "high")
        self.assertEqual(by_id["CVE-2022-31042"]["severity"],
                         "unknown")
        for f in report["findings"]:
            self.assertIn(f["severity"],
                          ("critical", "high", "medium", "low",
                           "unknown"))

    def test_cvss_vector_banded(self):
        vuln = {"id": "GHSA-test-0001", "summary": "vector sev",
                "aliases": ["CVE-2022-31042"],
                "severity": [{"type": "CVSS_V3", "score":
                              "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/"
                              "C:H/I:H/A:H"}],
                "affected": [{"package": {
                    "name": "guzzlehttp/guzzle",
                    "ecosystem": "Packagist"},
                    "ranges": [{"type": "ECOSYSTEM", "events":
                                 [{"introduced": "0"},
                                  {"fixed": "6.5.7"}]}]}],
                "references": []}

        def batch(pkgs, timeout=20):
            return [{"vulns": [{"id": "GHSA-test-0001"}]}
                    if n == "guzzlehttp/guzzle" else {}
                    for n, _ in pkgs]

        report, _ = audit.run_audit(VULN_LOCK, osv_batch=batch,
                                    osv_vuln=lambda vid: vuln)
        f = {x["id"]: x for x in report["findings"]}[
            "CVE-2022-31042"]
        self.assertEqual(f["severity"], "critical")  # 9.8 band

    def test_fail_on_thresholds(self):
        # Vuln lock's highest normalized severity is high (KEV).
        _, code = audit.run_audit(VULN_LOCK, offline=True,
                                  fail_on="critical")
        self.assertEqual(code, 0)
        _, code = audit.run_audit(VULN_LOCK, offline=True,
                                  fail_on="high")
        self.assertEqual(code, 1)

    def test_fail_on_cli(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(
                cli.main(["audit", VULN_LOCK, "--offline",
                          "--fail-on", "critical"]), 0)
            self.assertEqual(
                cli.main(["audit", VULN_LOCK, "--offline",
                          "--fail-on=high"]), 1)
            self.assertEqual(
                cli.main(["audit", VULN_LOCK, "--offline",
                          "--fail-on", "bogus"]), 2)

    def test_include_packages_is_opt_in(self):
        report, _ = audit.run_audit(VULN_LOCK, offline=True)
        self.assertNotIn("packages", report)
        report, _ = audit.run_audit(VULN_LOCK, offline=True,
                                    include_packages=True)
        self.assertEqual(len(report["packages"]), 3)
        self.assertEqual(
            {p["name"] for p in report["packages"]},
            {"guzzlehttp/guzzle", "psr/log", "phpunit/phpunit"})


# ----------------------------------------------------------------
# P7 — OSV normalizes a leading "v" itself (verified live
# 2026-10-30: querybatch returned identical vuln sets for
# 6.5.5 / v6.5.5 and 5.6.2 / v5.6.2), so the raw lock version
# is sent unchanged. This pins the pass-through.
# ----------------------------------------------------------------

class P7LeadingV(unittest.TestCase):
    def test_raw_version_sent_to_osv(self):
        seen = []

        def batch(pkgs, timeout=20):
            seen.extend(pkgs)
            return [{} for _ in pkgs]

        fd, path = tempfile.mkstemp(suffix=".lock")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"packages": [{"name": "acme/widget",
                                     "version": "v1.2.3"}],
                       "packages-dev": []}, f)
        report, code = audit.run_audit(path, osv_batch=batch)
        self.assertEqual(code, 0)
        self.assertIn(("acme/widget", "v1.2.3"), seen)


# ----------------------------------------------------------------
# P2 — catch-all control + shell-signature requirement
# ----------------------------------------------------------------

class P2RemoteIndicators(unittest.TestCase):
    def test_catch_all_site_yields_no_indicators(self):
        def fetch(url, deadline=None):
            return {"ok": True, "status": 200,
                    "body": "<html>spa fallback</html>"}
        self.assertEqual(
            hunt.remote_indicators(fetch, "https://example.com"),
            [])

    def test_control_path_is_random_phpatch_hex(self):
        calls = []

        def fetch(url, deadline=None):
            calls.append(url)
            return {"ok": False, "status": 404}

        hunt.remote_indicators(fetch, "https://example.com")
        controls = [u for u in calls if "phpatch-" in u]
        self.assertEqual(len(controls), 1)
        self.assertRegex(
            controls[0],
            r"/phpatch-[0-9a-f]{16}\.php$")

    def test_bare_200_without_signature_dropped(self):
        def fetch(url, deadline=None):
            if url.endswith("/c99.php"):
                return {"ok": True, "status": 200,
                        "body": "<html>empty placeholder</html>"}
            return {"ok": False, "status": 404}
        self.assertEqual(
            hunt.remote_indicators(fetch, "https://example.com"),
            [])

    def test_signature_confirms_even_on_catch_all(self):
        def fetch(url, deadline=None):
            if url.endswith("/shell.php"):
                return {"ok": True, "status": 200,
                        "body": "FilesMan"}
            return {"ok": True, "status": 200,
                    "body": "<html>spa</html>"}
        out = hunt.remote_indicators(fetch, "https://example.com")
        paths = [i["path"] for i in out]
        # Every known shell path the fake serves is confirmed by
        # the signature despite the catch-all host.
        self.assertIn("/shell.php", paths)
        self.assertGreater(len(paths), 1)
        for i in out:
            self.assertIn("signature", i["detail"])


# ----------------------------------------------------------------
# P3 — asset-URL versions: low confidence, no escalation
# ----------------------------------------------------------------

FM_HOME = """<html><head>
<meta name="generator" content="WordPress 6.5">
<script src="https://example.com/wp-content/plugins/wp-file-manager/js/fm.js?ver=6.8"></script>
</head><body>hello</body></html>"""


class P3AssetVersionConfidence(unittest.TestCase):
    def test_ver_equal_to_core_is_no_evidence(self):
        body = FM_HOME.replace("WordPress 6.5",
                               "WordPress 6.8")
        _, plugins = detect.detect_from_homepage({}, body)
        self.assertIsNone(plugins["wp-file-manager"]["version"])

    def test_asset_version_tagged_low(self):
        _, plugins = detect.detect_from_homepage({}, FM_HOME)
        hit = plugins["wp-file-manager"]
        self.assertEqual(hit["version"], "6.8")
        self.assertEqual(hit["confidence"], "low")

    def test_uncorroborated_never_escalates(self):
        def fetch(url, ctx=None, deadline=None):
            if "wp-json" in url:
                return ok('{"namespaces": []}')
            return notfound(url)

        _, _, findings = detect.analyze(
            {}, FM_HOME, fetch, "https://example.com")
        kinds = {f["kind"] for f in findings}
        self.assertNotIn("plugin_vulnerable", kinds)
        unc = [f for f in findings
               if f["kind"] == "plugin_version_unconfirmed"]
        self.assertEqual(len(unc), 1)
        self.assertEqual(unc[0]["severity"], "info")
        v = detect.apply_findings(
            {"status": "patched", "detail": "fine"}, findings)
        self.assertEqual(v["status"], "patched")

    def test_second_asset_corroborates(self):
        body = FM_HOME.replace(
            "</head>",
            '<script src="https://example.com/wp-content/plugins/'
            'wp-file-manager/js/other.js?ver=6.8"></script></head>')
        _, plugins = detect.detect_from_homepage({}, body)
        hit = plugins["wp-file-manager"]
        self.assertEqual(hit.get("corroborated_by"),
                         "second asset")
        findings = detect.plugin_findings(plugins)
        crit = [f for f in findings
                if f["kind"] == "plugin_vulnerable"]
        self.assertEqual(len(crit), 1)
        self.assertEqual(crit[0]["severity"], "critical")


# ----------------------------------------------------------------
# P9 — one bare substring is not a CMS fingerprint
# ----------------------------------------------------------------

class P9CmsSignals(unittest.TestCase):
    def test_prose_mention_is_not_wordpress(self):
        cms, _ = detect.detect_from_homepage(
            {}, "<html><body><p>We migrated our wp-content "
                "uploads last year.</p></body></html>")
        self.assertNotIn("WordPress", cms)

    def test_two_bare_signals_do_detect(self):
        cms, _ = detect.detect_from_homepage(
            {}, "<html><body>wp-content and wp-includes are "
                "mentioned together in this writeup.</body>"
                "</html>")
        self.assertIn("WordPress", cms)


# ----------------------------------------------------------------
# P4 / P4b / P4c — hunt detection and evasion gaps
# ----------------------------------------------------------------

class P4HuntGaps(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="hunt-p4-")
        for i in range(5):
            _write(self.root, f"clean{i}.php", "<?php echo 'ok';\n")

    def _indicators(self, report, rel):
        return {f["indicator"] for f in report["findings"]
                if f["file"] == rel}

    def test_case_insensitive_eval(self):
        _write(self.root, "a.php", "<?php EVAL($_POST['x']); ?>\n")
        r = hunt.hunt_local(self.root)
        self.assertIn("pattern:eval-request-input",
                      self._indicators(r, "a.php"))

    def test_exec_family(self):
        _write(self.root, "b.php",
               "<?php system($_GET['c']); ?>\n")
        _write(self.root, "c.php",
               "<?php passthru($_REQUEST['c']); ?>\n")
        r = hunt.hunt_local(self.root)
        self.assertIn("pattern:exec-request-input",
                      self._indicators(r, "b.php"))
        self.assertIn("pattern:exec-request-input",
                      self._indicators(r, "c.php"))

    def test_preg_replace_e_modifier_tolerant(self):
        _write(self.root, "d.php",
               "<?php preg_replace('/x/ei', $_POST['y'], $s); ?>\n")
        r = hunt.hunt_local(self.root)
        self.assertIn("pattern:preg-replace-e-modifier",
                      self._indicators(r, "d.php"))

    def test_auto_prepend_persistence(self):
        _write(self.root, ".user.ini",
               "auto_prepend_file = /var/www/evil.php\n")
        _write(self.root, ".htaccess",
               'php_value auto_prepend_file "/var/www/e2.php"\n')
        _write(self.root, "sub/php.ini",
               "auto_append_file = /var/www/e3.php\n")
        _write(self.root, "clean.ini",
               "auto_prepend_file = none\n")
        # rename: the clean one must use a config name too
        os.rename(os.path.join(self.root, "clean.ini"),
                  os.path.join(self.root, "sub2.ini"))
        r = hunt.hunt_local(self.root)
        inds = {(f["file"], f["indicator"])
                for f in r["findings"]}
        self.assertIn((".user.ini", "auto-prepend-append"), inds)
        self.assertIn((".htaccess", "auto-prepend-append"), inds)
        self.assertIn(("sub/php.ini", "auto-prepend-append"),
                      inds)
        sev = {f["severity"] for f in r["findings"]
               if f["indicator"] == "auto-prepend-append"}
        self.assertEqual(sev, {"high"})

    def test_oversize_scanned_head_and_tail(self):
        payload = (b"<?php /*" + b"A" * (1100 * 1000)
                   + b"*/ eval($_POST['x']); ?>")
        _write(self.root, "big.php", payload)
        r = hunt.hunt_local(self.root)
        self.assertEqual(r["oversize_files"], 1)
        self.assertIn("pattern:eval-request-input",
                      self._indicators(r, "big.php"))
        self.assertIn("oversize_files", r["verdict"]["detail"])

    def test_rogue_vendor_dir_scanned(self):
        _write(self.root, "vendor/composer/installed.json",
               '{"packages": [{"name": "acme/pkg",'
               ' "version": "1.0.0"}]}')
        _write(self.root, "vendor/rogue/drop.php",
               "<?php eval($_POST['x']); ?>\n")
        _write(self.root, "vendor/acme/pkg/lib.php",
               "<?php eval($_POST['y']); ?>\n")
        r = hunt.hunt_local(self.root)
        self.assertIn("pattern:eval-request-input",
                      self._indicators(r, "vendor/rogue/drop.php"))
        self.assertNotIn("vendor/acme/pkg/lib.php",
                         {f["file"] for f in r["findings"]})

    def test_hash_over_raw_bytes(self):
        raw = b"<?php $x = '\xff\xfe'; ?>\n"
        real = hunt.load_iocs()
        custom = dict(real)
        custom["hashes_sha256"] = [
            hashlib.sha256(raw).hexdigest()]
        _write(self.root, "h.php", raw)
        with mock.patch.object(hunt, "load_iocs",
                               return_value=custom):
            r = hunt.hunt_local(self.root)
        self.assertIn("known-bad-hash",
                      self._indicators(r, "h.php"))


# ----------------------------------------------------------------
# P5 — coverage block; C6 — exposed-file constraints
# ----------------------------------------------------------------

def _scan_fetch(lock_body=None, installed_body=None):
    def fetch(url, ctx=None, deadline=None, max_body=None):
        if url.rstrip("/") == "https://example.com":
            return ok(HOME, PATCHED)
        if url.endswith("/composer.lock"):
            if lock_body is None:
                return notfound(url)
            return ok(lock_body, url=url)
        if url.endswith("/vendor/composer/installed.json"):
            if installed_body is None:
                return notfound(url)
            return ok(installed_body, url=url)
        return notfound(url)
    return fetch


def _no_osv(pkgs, timeout=20):
    return [{} for _ in pkgs]


class P5Coverage(unittest.TestCase):
    def run_scan(self, fetch, **kw):
        with mock.patch.object(scan, "_fetch", fetch), \
                mock.patch.object(audit, "osv_querybatch",
                                  _no_osv):
            return scan.scan("https://example.com/", **kw)

    def test_coverage_counts(self):
        r = self.run_scan(_scan_fetch())
        cov = r["coverage"]
        self.assertGreater(cov["probes_attempted"], 20)
        self.assertEqual(cov["probes_completed"],
                         cov["probes_attempted"])
        self.assertEqual(cov["probes_skipped_deadline"], 0)
        self.assertFalse(cov["catch_all"])

    def test_catch_all_flagged_and_no_indicators(self):
        def fetch(url, ctx=None, deadline=None, max_body=None):
            return ok("<html>spa fallback</html>", PATCHED, url=url)
        r = self.run_scan(fetch)
        self.assertTrue(r["coverage"]["catch_all"])
        self.assertEqual(r["compromise_indicators"], [])

    def test_deadline_starvation_is_counted(self):
        dead = {"ok": False, "status": None,
                "final_url": "https://example.com/",
                "headers": {}, "body": "",
                "error": "scan timed out: total deadline (40s) "
                         "exceeded"}

        def fetch(url, ctx=None, deadline=None, max_body=None):
            if url.rstrip("/") == "https://example.com":
                return ok(HOME, PATCHED)
            return dead

        r = self.run_scan(fetch)
        cov = r["coverage"]
        self.assertGreater(cov["probes_skipped_deadline"], 0)
        self.assertEqual(cov["probes_completed"], 0)


class C6ExposedFiles(unittest.TestCase):
    def run_scan(self, fetch, **kw):
        with mock.patch.object(scan, "_fetch", fetch), \
                mock.patch.object(audit, "osv_querybatch",
                                  _no_osv):
            return scan.scan("https://example.com/", **kw)

    def test_installed_json_audited_with_scope(self):
        installed = json.dumps({"packages": [
            {"name": "guzzlehttp/guzzle", "version": "6.5.5"}]})
        r = self.run_scan(_scan_fetch(installed_body=installed),
                          offline=True)
        deps = r["dependencies"]
        self.assertIsNotNone(deps)
        self.assertEqual(deps["source"], "exposed_installed_json")
        self.assertIn("CVE-2022-31042",
                      {f["id"] for f in deps["findings"]})
        self.assertIn("may differ from what is actually "
                      "deployed", deps["scope"])
        kinds = {f["kind"] for f in r["findings"]}
        self.assertIn("installed_json_exposed", kinds)
        for f in deps["findings"]:
            self.assertEqual(f["provenance"]["type"],
                             "exposed_installed_json")

    def test_package_list_not_echoed_by_scan(self):
        r = self.run_scan(_scan_fetch(lock_body=VULN_LOCK_BODY),
                          offline=True)
        self.assertNotIn("packages", r["dependencies"])
        # Counts and findings only.
        self.assertEqual(r["dependencies"]["packages_scanned"], 2)

    def test_too_large_lock_reported_not_skipped(self):
        cap = 100
        full = VULN_LOCK_BODY

        def fetch(url, ctx=None, deadline=None, max_body=None):
            if url.rstrip("/") == "https://example.com":
                return ok(HOME, PATCHED)
            if url.endswith("/composer.lock"):
                return {"ok": True, "status": 200,
                        "final_url": url,
                        "headers": {"Content-Length":
                                    str(len(full))},
                        "body": full[:cap], "error": None}
            return notfound(url)

        with mock.patch.object(scan, "_LOCK_MAX_BODY", cap):
            r = self.run_scan(fetch, offline=True)
        deps = r["dependencies"]
        self.assertIsNotNone(deps)
        self.assertEqual(deps["audit_status"],
                         "too_large_to_audit")
        exp = [f for f in r["findings"]
               if f["kind"] == "composer_lock_exposed"]
        self.assertEqual(len(exp), 1)
        self.assertIn("too large to audit fully",
                      exp[0]["detail"])


# ----------------------------------------------------------------
# P8 — UA from __version__; --format text wired
# ----------------------------------------------------------------

class P8CliSurface(unittest.TestCase):
    def test_user_agent_derived_from_version(self):
        self.assertTrue(
            scan._UA.startswith(f"phpscan/{__version__} "))

    def _result(self):
        return {"target": "https://example.com/",
                "reachable": True, "http_status": 200,
                "final_url": "https://example.com/",
                "cms": [], "php_version": "8.3.35",
                "version_source": "X-Powered-By",
                "phpinfo_exposed": False,
                "compromise_indicators": [], "findings": [],
                "dependencies": None,
                "verdict": {"status": "vulnerable",
                            "detail": "below floor"}}

    def test_format_text_prints_rendering(self):
        out = io.StringIO()
        with mock.patch.object(cli, "scan",
                               return_value=self._result()), \
                redirect_stdout(out):
            rc = cli.main(["--format", "text", "example.com"])
        self.assertEqual(rc, 1)
        self.assertIn("VERDICT:", out.getvalue())
        self.assertNotIn('"verdict"', out.getvalue())

    def test_format_json_default_and_bad_format(self):
        out = io.StringIO()
        with mock.patch.object(cli, "scan",
                               return_value=self._result()), \
                redirect_stdout(out):
            rc = cli.main(["example.com"])
        self.assertEqual(rc, 1)
        self.assertIn('"verdict"', out.getvalue())
        with redirect_stdout(io.StringIO()):
            self.assertEqual(
                cli.main(["--format", "yaml", "example.com"]), 2)


# ----------------------------------------------------------------
# §3.3 — pre-release builds are not the stable release
# ----------------------------------------------------------------

class VersioningPrerelease(unittest.TestCase):
    CUSTOM = [{"id": "TEST-1", "cves": ["CVE-0000-0001"],
               "title": "t", "fixed_releases": {"8.3": "8.3.10"},
               "no_fix_branches": []}]

    def test_is_prerelease(self):
        self.assertTrue(versioning.is_prerelease("8.3.0RC1"))
        self.assertTrue(versioning.is_prerelease("8.4.0-beta2"))
        self.assertFalse(versioning.is_prerelease("8.3.36"))
        self.assertFalse(
            versioning.is_prerelease("8.3.6-1ubuntu2.24.04"))
        self.assertFalse(versioning.is_prerelease(None))

    def test_prerelease_of_floor_is_below_floor(self):
        v = versioning.verdict_for((8, 3, 10),
                                   advisories=self.CUSTOM)
        self.assertEqual(v["status"], "patched")
        v = versioning.verdict_for((8, 3, 10), prerelease=True,
                                   advisories=self.CUSTOM)
        self.assertEqual(v["status"], "vulnerable")
        self.assertIn("pre-release", v["detail"])


if __name__ == "__main__":
    unittest.main()
