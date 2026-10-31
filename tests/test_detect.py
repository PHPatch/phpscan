"""CMS / plugin detection + config-hygiene tests.

Hermetic: every fetch is stubbed, no test touches the network.
Fixture pages model what real sites disclose publicly (generator
tags, enqueued asset URLs, readme files) — detection must work
from exactly that evidence and never guess a version.
Run: python3 -m unittest discover -s tests
"""

import json
import unittest
from unittest import mock

from phpscan import detect, hygiene, scan


def ok(body="", headers=None, status=200):
    return {"ok": status < 400, "status": status,
            "final_url": "https://example.com/",
            "headers": headers or {}, "body": body,
            "error": None if status < 400 else f"HTTP {status}"}


def notfound(url=""):
    return {"ok": False, "status": 404,
            "final_url": url or "https://example.com/",
            "headers": {}, "body": "", "error": "HTTP 404"}


WP_HOME = """<html><head>
<meta name="generator" content="WordPress 6.4.2">
<link rel="stylesheet" href="https://example.com/wp-content/plugins/elementor/assets/css/frontend.min.css?ver=3.18.0">
<script src="https://example.com/wp-content/plugins/essential-addons-for-elementor-lite/assets/js/eael.js"></script>
<script src="https://example.com/wp-content/plugins/wp-file-manager/js/fm.js?ver=6.8"></script>
<script src="https://example.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
</head><body>hello</body></html>"""

WP_JSON = json.dumps({"namespaces": ["wp/v2", "wc/v3",
                                     "oembed/1.0"]})
EAEL_README = "=== Essential Addons for Elementor ===\n" \
              "Stable tag: 5.7.0\n"


FM_README = "=== File Manager ===\nStable tag: 6.8\n"


def wp_fetch(url, ctx=None, deadline=None):
    if url.rstrip("/") == "https://example.com":
        return ok(WP_HOME)
    if "wp-json" in url:
        return ok(WP_JSON)
    if "essential-addons" in url and "readme.txt" in url:
        return ok(EAEL_README)
    if "wp-file-manager" in url and "readme.txt" in url:
        # Corroborates the asset-URL version (6.8) — without
        # this, the ?ver= evidence alone must NOT produce a
        # confirmed finding (P3).
        return ok(FM_README)
    return notfound(url)


class DottedVersions(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(detect.parse_dotted("6.3.0.1"),
                         (6, 3, 0, 1))
        self.assertEqual(detect.parse_dotted("5.7"), (5, 7))
        self.assertIsNone(detect.parse_dotted("trunk"))
        self.assertIsNone(detect.parse_dotted(None))

    def test_clause_matching(self):
        clauses = [{"range": "<5.7.2", "fixed": "5.7.2"}]
        self.assertIsNotNone(
            detect.match_clause((5, 7, 1), clauses))
        self.assertIsNone(detect.match_clause((5, 7, 2), clauses))

    def test_ranged_clause(self):
        clauses = [{"range": ">=6.0,<6.9", "fixed": "6.9"}]
        self.assertIsNotNone(
            detect.match_clause((6, 5, 0), clauses))
        self.assertIsNone(detect.match_clause((6, 9, 0), clauses))
        self.assertIsNone(detect.match_clause((5, 9, 9), clauses))

    def test_four_part_versions(self):
        clauses = [{"range": "<=6.3.0.1", "fixed": "6.3.0.2"}]
        self.assertIsNotNone(
            detect.match_clause((6, 3, 0, 1), clauses))
        self.assertIsNone(
            detect.match_clause((6, 3, 0, 2), clauses))


class HomepageFingerprints(unittest.TestCase):
    def test_wordpress_and_plugins(self):
        cms, plugins = detect.detect_from_homepage({}, WP_HOME)
        self.assertEqual(cms["WordPress"]["version"], "6.4.2")
        self.assertEqual(plugins["elementor"]["version"],
                         "3.18.0")
        self.assertIsNone(
            plugins["essential-addons-for-elementor-lite"]
            ["version"])

    def test_drupal_x_generator(self):
        cms, _ = detect.detect_from_homepage(
            {"X-Generator": "Drupal 7 (http://drupal.org)"},
            "<html></html>")
        self.assertEqual(cms["Drupal"]["version"], "7")

    def test_joomla_meta(self):
        cms, _ = detect.detect_from_homepage(
            {}, '<meta name="generator" content="Joomla! - Open '
                'Source Content Management">'
                '<script src="/media/jui/js/jquery.min.js">'
                '</script>')
        self.assertIn("Joomla", cms)
        self.assertIsNone(cms["Joomla"]["version"])

    def test_magento_static_path(self):
        cms, _ = detect.detect_from_homepage(
            {}, '<link href="https://example.com/static/'
                'version1700000000/frontend/Magento/luma/en_US/'
                'css/styles.css">')
        self.assertIn("Magento", cms)
        self.assertIsNone(cms["Magento"]["version"])

    def test_laravel_cookie(self):
        cms, _ = detect.detect_from_homepage(
            {"Set-Cookie": "laravel_session=abc; path=/; "
                           "XSRF-TOKEN=def; path=/"},
            "<html></html>")
        self.assertIn("Laravel", cms)

    def test_no_cms_no_hits(self):
        cms, plugins = detect.detect_from_homepage(
            {}, "<html><body>plain</body></html>")
        self.assertEqual(cms, {})
        self.assertEqual(plugins, {})


class Probes(unittest.TestCase):
    def test_readme_and_wpjson_fill_versions(self):
        cms_info, plugins, findings = detect.analyze(
            {}, WP_HOME, wp_fetch, "https://example.com")
        by_slug = {p["slug"]: p for p in plugins}
        eael = by_slug["essential-addons-for-elementor-lite"]
        self.assertEqual(eael["version"], "5.7.0")
        self.assertEqual(eael["version_source"],
                         "plugin readme.txt")
        self.assertIn("woocommerce", by_slug)
        wp = {c["name"]: c for c in cms_info}["WordPress"]
        self.assertEqual(wp["version"], "6.4.2")

    def test_joomla_manifest_probe(self):
        def fetch(url, ctx=None, deadline=None):
            if "joomla.xml" in url:
                return ok("<extension><version>3.10.12</version>"
                          "</extension>")
            return notfound(url)

        cms_info, _, findings = detect.analyze(
            {}, '<meta name="generator" content="Joomla! - Open '
                'Source Content Management">',
            fetch, "https://example.com")
        j = {c["name"]: c for c in cms_info}["Joomla"]
        self.assertEqual(j["version"], "3.10.12")
        self.assertTrue(any(f["kind"] == "cms_eol"
                            for f in findings))


class PluginMatching(unittest.TestCase):
    def test_vulnerable_eael_via_homepage(self):
        _, plugins = detect.detect_from_homepage({}, WP_HOME)
        plugins["essential-addons-for-elementor-lite"][
            "version"] = "5.7.0"
        findings = detect.plugin_findings(plugins)
        ea = [f for f in findings
              if f.get("slug") ==
              "essential-addons-for-elementor-lite"]
        self.assertTrue(ea)
        self.assertEqual(ea[0]["cve"], "CVE-2023-32243")
        self.assertIn("Essential Addons", ea[0]["remediation"])

    def test_kev_finding_names_fixed_version(self):
        plugins = {"wp-file-manager": {"kind": "plugin",
                                       "version": "6.8",
                                       "version_source":
                                       "asset URL"}}
        findings = detect.plugin_findings(plugins)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "critical")
        self.assertTrue(findings[0]["kev"])
        self.assertIn("6.9", findings[0]["remediation"])

    def test_patched_plugin_clean(self):
        plugins = {"wp-file-manager": {"kind": "plugin",
                                       "version": "6.9",
                                       "version_source":
                                       "asset URL"}}
        self.assertEqual(detect.plugin_findings(plugins), [])

    def test_kev_plugin_version_hidden_is_info(self):
        plugins = {"wp-file-manager":
                   {"kind": "plugin", "version": None,
                    "version_source": None}}
        findings = detect.plugin_findings(plugins)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "info")
        self.assertEqual(findings[0]["kind"],
                         "plugin_version_hidden")

    def test_kev_finding_is_critical(self):
        _, _, findings = detect.analyze(
            {}, WP_HOME, wp_fetch, "https://example.com")
        self.assertEqual(findings[0]["severity"], "critical")
        self.assertTrue(any(f.get("kev") and
                            f["severity"] == "critical"
                            for f in findings))


class CmsFindings(unittest.TestCase):
    def test_drupal7_eol(self):
        findings = detect.cms_findings(
            {"Drupal": {"version": "7.98",
                        "version_source": "CHANGELOG.txt"}})
        kinds = {f["kind"] for f in findings}
        self.assertIn("cms_eol", kinds)
        eol = [f for f in findings if f["kind"] == "cms_eol"][0]
        self.assertEqual(eol["severity"], "high")

    def test_wordpress_old_is_not_eol(self):
        findings = detect.cms_findings(
            {"WordPress": {"version": "5.0",
                           "version_source": "generator tag"}})
        self.assertFalse(any(f["kind"] == "cms_eol"
                             for f in findings))
        self.assertTrue(any(f["kind"] == "version_disclosure"
                            for f in findings))


class HeaderFindings(unittest.TestCase):
    def test_missing_headers_http(self):
        findings = hygiene.header_findings({}, "http")
        self.assertEqual(len(findings), 1)
        self.assertIn("X-Content-Type-Options",
                      findings[0]["detail"])
        self.assertNotIn("Strict-Transport-Security",
                         findings[0]["detail"])

    def test_missing_hsts_on_https(self):
        findings = hygiene.header_findings({}, "https")
        self.assertIn("Strict-Transport-Security",
                      findings[0]["detail"])

    def test_full_headers_clean(self):
        headers = {"X-Content-Type-Options": "nosniff",
                   "X-Frame-Options": "SAMEORIGIN",
                   "Referrer-Policy": "no-referrer",
                   "Strict-Transport-Security": "max-age=31536000"}
        self.assertEqual(
            hygiene.header_findings(headers, "https"), [])

    def test_x_powered_by_disclosure(self):
        findings = hygiene.header_findings(
            {"X-Powered-By": "PHP/8.3.36"}, "https")
        self.assertTrue(any(f["kind"] == "version_disclosure"
                            for f in findings))


class ExposureProbes(unittest.TestCase):
    def test_git_exposed(self):
        def fetch(url, ctx=None, deadline=None):
            if url.endswith("/.git/HEAD"):
                return ok("ref: refs/heads/main\n")
            return notfound(url)

        findings = hygiene.exposure_probes(
            fetch, "https://example.com", ())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["kind"], "git_exposed")
        self.assertEqual(findings[0]["path"], "/.git/HEAD")
        self.assertNotIn("heads/main", str(findings))

    def test_env_exposed_contents_never_leak(self):
        secret = "DB_PASSWORD=sup3r-s3cret-value"

        def fetch(url, ctx=None, deadline=None):
            if url.endswith("/.env"):
                return ok(f"APP_KEY=base64:xyz\n{secret}\n")
            return notfound(url)

        findings = hygiene.exposure_probes(
            fetch, "https://example.com", ())
        env = [f for f in findings if f["kind"] == "env_exposed"]
        self.assertEqual(len(env), 1)
        self.assertEqual(env[0]["severity"], "critical")
        self.assertNotIn("sup3r-s3cret-value", str(findings))

    def test_env_spa_fallback_not_flagged(self):
        def fetch(url, ctx=None, deadline=None):
            return ok("<html><body>APP_NAME=spa</body></html>")

        findings = hygiene.exposure_probes(
            fetch, "https://example.com", ())
        self.assertFalse(any(f["kind"] == "env_exposed"
                             for f in findings))

    def test_directory_listing(self):
        def fetch(url, ctx=None, deadline=None):
            if url.endswith("/wp-content/uploads/"):
                return ok("<title>Index of /wp-content/uploads"
                          "</title><h1>Index of /wp-content/"
                          "uploads</h1>")
            return notfound(url)

        findings = hygiene.exposure_probes(
            fetch, "https://example.com", ("WordPress",))
        dl = [f for f in findings
              if f["kind"] == "directory_listing"]
        self.assertEqual(len(dl), 1)
        self.assertEqual(dl[0]["path"], "/wp-content/uploads/")


class ApplyFindings(unittest.TestCase):
    CRIT = {"kind": "plugin_vulnerable", "severity": "critical",
            "title": "Vulnerable plugin: X 1.0",
            "detail": "X 1.0 is affected by CVE-0000-0001.",
            "remediation": "Update X to 2.0 or later."}
    LOW = {"kind": "security_headers", "severity": "low",
           "title": "Missing security response headers",
           "detail": "d", "remediation": "r"}

    def test_critical_escalates_patched(self):
        v = {"status": "patched", "detail": "PHP is fine."}
        out = detect.apply_findings(v, [self.CRIT])
        self.assertEqual(out["status"], "vulnerable")
        self.assertEqual(out["remediation"],
                         "Update X to 2.0 or later.")
        self.assertIn("findings", out)

    def test_low_does_not_escalate(self):
        v = {"status": "patched", "detail": "PHP is fine."}
        out = detect.apply_findings(v, [self.LOW])
        self.assertEqual(out["status"], "patched")

    def test_unreachable_untouched(self):
        v = {"status": "unreachable", "detail": "no answer"}
        self.assertIs(detect.apply_findings(v, [self.CRIT]), v)


class ScanIntegration(unittest.TestCase):
    def test_wp_site_end_to_end(self):
        with mock.patch.object(scan, "_fetch", wp_fetch):
            r = scan.scan("https://example.com/")
        self.assertIn("WordPress", r["cms"])
        wp = {c["name"]: c for c in r["cms_info"]}["WordPress"]
        self.assertEqual(wp["version"], "6.4.2")
        self.assertEqual(r["verdict"]["status"], "vulnerable")
        crit = [f for f in r["findings"]
                if f["severity"] == "critical"]
        self.assertTrue(crit)
        self.assertTrue(all("remediation" in f
                            for f in r["findings"]))
        self.assertEqual(r["verdict"]["findings"], r["findings"])


if __name__ == "__main__":
    unittest.main()
