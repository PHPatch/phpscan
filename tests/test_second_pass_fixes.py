"""Second-pass expert-review regression tests (N1-N3, N5-N7).

Each class pins one second-pass finding to its fixed behavior:

- N1: asset ?ver= versions never escalate on asset-only
  evidence — repetition is not corroboration; only a
  readme.txt Stable tag / style.css Version header confirms.
- N2: inside composer package dirs the high-severity hunt
  rules still run; only the noisy rules are reduced, the
  verdict text says so, and a clean corpus stays clean.
- N3: audit --fail-on fails closed on unrated (unknown)
  findings; --ignore-unrated is the explicit opt-out.
- N5: oversize files are streamed whole up to a 16 MB hard
  cap; bytes past it are reported as unscanned.
- N6: schema_version on every report; scan exit 3 on
  deadline-starved coverage; hunt's degraded exit 3;
  --version; multi-target exit precedence; lockfile early
  abort.
- N7: a signature-less 200 on a shell path on a non-catch-all
  site earns a low review note, and a low note alone never
  moves the scan exit code.
"""

import io
import json
import os
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from unittest import mock

from phpscan import __main__ as cli
from phpscan import __version__
from phpscan import audit, detect, hunt, scan

OLD = time.time() - 30 * 86400      # one release-day cluster


def _write(root, rel, data, mtime=OLD):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(path, mode) as f:
        f.write(data)
    os.utime(path, (mtime, mtime))
    return path


def _ok(body):
    return {"ok": True, "status": 200, "body": body}


def _notfound(url=""):
    return {"ok": False, "status": 404, "body": ""}


def _by_file(report):
    out = {}
    for f in report["findings"]:
        out.setdefault(f["file"], []).append(f)
    return out


# ----------------------------------------------------------------
# N1 — asset versions never escalate on asset-only evidence
# ----------------------------------------------------------------

FM_SCRIPT = ('<script src="https://example.com/wp-content/plugins/'
             'wp-file-manager/js/fm.js?ver=6.8"></script>')

FM_DUP_URL = """<html><head>
<meta name="generator" content="WordPress 6.5">
<link rel="preload" as="style" href="https://example.com/wp-content/plugins/wp-file-manager/css/fm.css?ver=6.8">
<link rel="stylesheet" href="https://example.com/wp-content/plugins/wp-file-manager/css/fm.css?ver=6.8">
</head><body>hello</body></html>"""

FM_TWO_ASSETS = """<html><head>
<meta name="generator" content="WordPress 6.5">
<link rel="stylesheet" href="https://example.com/wp-content/plugins/wp-file-manager/css/a.css?ver=6.8">
<script src="https://example.com/wp-content/plugins/wp-file-manager/js/b.js?ver=6.8"></script>
</head><body>hello</body></html>"""


class N1AssetNeverEscalates(unittest.TestCase):
    def _assert_info_only(self, body):
        _, plugins = detect.detect_from_homepage({}, body)
        hit = plugins["wp-file-manager"]
        self.assertTrue(hit.get("asset_repeat"))
        self.assertFalse(hit.get("version_confirmed"))
        findings = detect.plugin_findings(plugins)
        self.assertEqual(
            [f for f in findings if f["kind"] == "plugin_vulnerable"],
            [])
        unc = [f for f in findings
               if f["kind"] == "plugin_version_unconfirmed"]
        self.assertEqual(len(unc), 1)
        self.assertEqual(unc[0]["severity"], "info")

    def test_duplicate_asset_url_stays_info(self):
        # The reviewer's preload+stylesheet case: the SAME URL
        # counted twice by naive corroboration.
        self._assert_info_only(FM_DUP_URL)

    def test_two_distinct_assets_same_ver_stay_info(self):
        # Two different files, one shared enqueue constant.
        self._assert_info_only(FM_TWO_ASSETS)

    def test_readme_stable_tag_still_confirms(self):
        # Positive control: confirmation still exists — via
        # the component's own declaration, not asset repeats.
        body = ("<html><head>\n<meta name=\"generator\" "
                "content=\"WordPress 6.5\">\n" + FM_SCRIPT +
                "\n</head><body>hello</body></html>")

        def fetch(url, ctx=None, deadline=None):
            if "wp-json" in url:
                return _ok('{"namespaces": []}')
            if "readme.txt" in url:
                return _ok("=== File Manager ===\n"
                           "Stable tag: 6.8\n")
            return _notfound(url)

        _, _, findings = detect.analyze(
            {}, body, fetch, "https://example.com")
        crit = [f for f in findings
                if f["kind"] == "plugin_vulnerable"]
        self.assertEqual(len(crit), 1)
        self.assertEqual(crit[0]["severity"], "critical")


# ----------------------------------------------------------------
# N2 — vendor: high-severity rules run inside packages
# ----------------------------------------------------------------

class N2VendorRules(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="hunt-n2-")
        for i in range(6):
            _write(self.root, f"clean{i}.php", "<?php echo 'ok';\n")
        _write(self.root, "vendor/composer/installed.json",
               '{"packages": [{"name": "guzzlehttp/guzzle",'
               ' "install-path": "../guzzlehttp/guzzle",'
               ' "version": "7.8.0"}]}')
        _write(self.root, "vendor/guzzlehttp/guzzle/src/Client.php",
               "<?php namespace GuzzleHttp; class Client {}\n")

    def test_shell_inside_listed_package_found(self):
        _write(self.root,
               "vendor/guzzlehttp/guzzle/src/planted.php",
               "<?php eval($_POST['c']); ?>\n")
        r = hunt.hunt_local(self.root)
        inds = {f["indicator"] for f in r["findings"]
                if f["file"].endswith("planted.php")}
        self.assertIn("pattern:eval-request-input", inds)
        # The reduction is disclosed in the verdict TEXT, with
        # counts — not only in a report field.
        self.assertTrue(r["vendor_skipped"])
        self.assertGreaterEqual(r["vendor_partial_files"], 2)
        self.assertIn("vendor/guzzlehttp/guzzle",
                      r["vendor_partial_dirs"])
        detail = r["verdict"]["detail"]
        self.assertIn("high-severity rules only", detail)
        self.assertIn("incomplete", detail)
        self.assertEqual(r["schema_version"], 1)

    def test_forged_installed_json_does_not_hide(self):
        # The manifest is attacker-controlled input: listing a
        # directory in it must not exempt that directory from
        # the high-severity rules.
        _write(self.root, "vendor/composer/installed.json",
               '{"packages": [{"name": "evil/corp",'
               ' "install-path": "../evil/corp",'
               ' "version": "1.0.0"}]}')
        _write(self.root, "vendor/evil/corp/shell.php",
               "<?php eval($_POST['c']); ?>\n")
        r = hunt.hunt_local(self.root)
        inds = {f["indicator"] for f in r["findings"]
                if f["file"].endswith("shell.php")}
        self.assertIn("pattern:eval-request-input", inds)

    def test_noisy_rules_skipped_inside_package(self):
        _write(self.root, "vendor/guzzlehttp/guzzle/src/Util.php",
               "<?php $f = eval('return 1;'); "
               "preg_replace('/x/e', 'y', $s);\n")
        r = hunt.hunt_local(self.root)
        self.assertNotIn("vendor/guzzlehttp/guzzle/src/Util.php",
                         _by_file(r))
        full = hunt.hunt_local(self.root, include_vendor=True)
        inds = {f["indicator"] for f in
                _by_file(full)["vendor/guzzlehttp/guzzle/src/Util.php"]}
        self.assertIn("pattern:eval-plain", inds)

    def test_mtime_heuristic_skips_packages(self):
        _write(self.root, "vendor/guzzlehttp/guzzle/src/Fresh.php",
               "<?php echo 'new release';\n", time.time())
        r = hunt.hunt_local(self.root)
        self.assertNotIn("vendor/guzzlehttp/guzzle/src/Fresh.php",
                         _by_file(r))

    def test_clean_corpus_no_high_severity_findings(self):
        # FP GATE: opening vendor to the high-severity rules
        # must not flood clean trees. Unmodified WP-core-like
        # files + a synthetic clean vendor tree -> zero
        # findings at all, let alone high-severity ones.
        root = tempfile.mkdtemp(prefix="hunt-fp-gate-")
        _write(root, "index.php", "<?php // Silence is golden.\n")
        _write(root, "wp-load.php",
               "<?php require 'wp-config.php';\n")
        _write(root, "wp-config.php",
               "<?php define('DB_NAME', 'wordpress');\n"
               "$table_prefix = 'wp_';\n")
        _write(root, "wp-includes/functions.php",
               "<?php function esc_html($s) {"
               " return htmlspecialchars($s); }\n")
        _write(root, "wp-includes/plugin.php",
               "<?php function add_filter($t, $f) {}\n")
        _write(root, "wp-includes/formatting.php",
               "<?php function wpautop($t) { return $t; }\n")
        _write(root, "wp-admin/admin.php",
               "<?php require '../wp-load.php';\n")
        _write(root, "vendor/composer/installed.json",
               '{"packages": [{"name": "guzzlehttp/guzzle",'
               ' "install-path": "../guzzlehttp/guzzle"},'
               ' {"name": "psr/log",'
               ' "install-path": "../psr/log"}]}')
        _write(root, "vendor/guzzlehttp/guzzle/src/Client.php",
               "<?php namespace GuzzleHttp;\n"
               "class Client { public function get($u) {"
               " return null; } }\n")
        _write(root, "vendor/guzzlehttp/guzzle/src/functions.php",
               "<?php namespace GuzzleHttp;\n"
               "function choose_handler() { return null; }\n")
        _write(root, "vendor/psr/log/src/Logger.php",
               "<?php namespace Psr\\Log;\n"
               "abstract class Logger { abstract public function"
               " log($l, $m); }\n")
        _write(root, "vendor/autoload.php",
               "<?php require 'composer/autoload_real.php';\n")
        r = hunt.hunt_local(root)
        high = [f for f in r["findings"]
                if f["severity"] in ("critical", "high")]
        self.assertEqual(high, [])
        self.assertEqual(r["findings"], [])


# ----------------------------------------------------------------
# N3 — --fail-on fails closed on unrated findings
# ----------------------------------------------------------------

FOP_LOCK = {
    "packages": [
        {"name": "guzzlehttp/guzzle", "version": "6.5.5",
         "require": {"php": ">=5.5", "guzzlehttp/promises": "^1.0",
                     "guzzlehttp/psr7": "^1.9",
                     "psr/http-message": "~1.0",
                     "symfony/polyfill-intl-idn": "^1.17"}},
        {"name": "psr/log", "version": "1.1.0", "require": {}},
    ],
    "packages-dev": [],
}


class N3FailClosed(unittest.TestCase):
    def setUp(self):
        fd, self.lock = tempfile.mkstemp(suffix=".lock")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(FOP_LOCK, f)

    def test_fop_only_findings_are_unrated(self):
        report, _ = audit.run_audit(self.lock, offline=True)
        self.assertTrue(report["findings"])
        self.assertTrue(all(f["severity"] == "unknown"
                            for f in report["findings"]))
        self.assertEqual(report["schema_version"], 1)

    def test_unrated_meets_every_threshold(self):
        _, code = audit.run_audit(self.lock, offline=True,
                                  fail_on="low")
        self.assertEqual(code, 1)
        _, code = audit.run_audit(self.lock, offline=True,
                                  fail_on="critical")
        self.assertEqual(code, 1)

    def test_ignore_unrated_opts_out(self):
        _, code = audit.run_audit(self.lock, offline=True,
                                  fail_on="low", ignore_unrated=True)
        self.assertEqual(code, 0)

    def test_cli_fail_on_and_ignore_unrated(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(
                cli.main(["audit", self.lock, "--offline",
                          "--fail-on", "low"]), 1)
            self.assertEqual(
                cli.main(["audit", self.lock, "--offline",
                          "--fail-on", "low",
                          "--ignore-unrated"]), 0)


# ----------------------------------------------------------------
# N5 — oversize files: streamed whole, cap accounted
# ----------------------------------------------------------------

class N5OversizeStreaming(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="hunt-n5-")
        for i in range(5):
            _write(self.root, f"clean{i}.php", "<?php echo 'ok';\n")

    def test_payload_in_middle_of_3mb_found(self):
        pad = b"A" * (1500 * 1000)
        payload = (b"<?php /*" + pad + b"*/ eval($_POST['x']); ?>"
                   + b"/*" + pad + b"*/")
        _write(self.root, "mid.php", payload)
        r = hunt.hunt_local(self.root)
        inds = {f["indicator"] for f in r["findings"]
                if f["file"] == "mid.php"}
        self.assertIn("pattern:eval-request-input", inds)
        entry = [e for e in r["oversize_files"]
                 if e["path"] == "mid.php"]
        self.assertEqual(len(entry), 1)
        self.assertEqual(entry[0]["size"], len(payload))
        self.assertEqual(entry[0]["scanned_bytes"], len(payload))
        self.assertEqual(r["unscanned_bytes"], 0)

    def test_beyond_hard_cap_accounted_not_silent(self):
        pad = b"A" * (1500 * 1000)
        payload = (b"<?php /*" + pad + b"*/ eval($_POST['x']); ?>"
                   + b"/*" + pad + b"*/")
        _write(self.root, "big.php", payload)
        r = hunt.hunt_local(self.root, hard_cap=1024 * 1024)
        inds = {f["indicator"] for f in r["findings"]
                if f["file"] == "big.php"}
        self.assertNotIn("pattern:eval-request-input", inds)
        self.assertEqual(r["unscanned_bytes"],
                         len(payload) - 1024 * 1024)
        entry = [e for e in r["oversize_files"]
                 if e["path"] == "big.php"][0]
        self.assertEqual(entry["scanned_bytes"], 1024 * 1024)
        self.assertTrue(r["incomplete"])
        self.assertIn("incomplete", r["verdict"]["detail"])


# ----------------------------------------------------------------
# N6 — report/exit contracts, --version, precedence, abort
# ----------------------------------------------------------------

def _run_cli(results):
    it = iter(results)
    with mock.patch.object(cli, "scan", lambda url: next(it)), \
            redirect_stdout(io.StringIO()):
        return cli.main(["http://x"] * len(results))


def _result(status, skipped=0, indicators=None):
    return {"verdict": {"status": status},
            "coverage": {"probes_skipped_deadline": skipped},
            "compromise_indicators": indicators or []}


class N6Contracts(unittest.TestCase):
    def test_scan_report_has_schema_version(self):
        def fake_fetch(url, **kw):
            if url.rstrip("/").endswith("example.com"):
                return {"ok": True, "status": 200,
                        "final_url": url,
                        "headers": {"content-type": "text/html"},
                        "body": "<html><body>plain</body></html>",
                        "error": None}
            return {"ok": False, "status": 404, "final_url": url,
                    "headers": {}, "body": "", "error": None}

        with mock.patch.object(scan, "_fetch", fake_fetch):
            r = scan.scan("http://example.com/", offline=True)
        self.assertEqual(r["schema_version"], 1)

    def test_starved_scan_exits_3(self):
        self.assertEqual(_run_cli([_result("patched", skipped=5)]), 3)

    def test_findings_beat_degraded(self):
        self.assertEqual(
            _run_cli([_result("vulnerable", skipped=5)]), 1)
        self.assertEqual(
            _run_cli([_result("patched", skipped=5),
                      _result("vulnerable")]), 1)

    def test_precedence_pairs(self):
        # findings(1) > degraded(3) > cannot-judge(2) > clean(0)
        self.assertEqual(
            _run_cli([_result("unreachable"),
                      _result("vulnerable")]), 1)
        self.assertEqual(
            _run_cli([_result("unreachable"),
                      _result("patched", skipped=3)]), 3)
        self.assertEqual(
            _run_cli([_result("unreachable"),
                      _result("patched")]), 2)
        self.assertEqual(_run_cli([_result("patched")]), 0)

    def test_version_flag_never_scans(self):
        def boom(url):
            raise AssertionError("scan called for --version")

        out = io.StringIO()
        with mock.patch.object(cli, "scan", boom), \
                redirect_stdout(out):
            self.assertEqual(cli.main(["--version"]), 0)
            self.assertEqual(
                cli.main(["--version", "http://x"]), 0)
        self.assertIn(f"phpscan {__version__}", out.getvalue())

    def test_hunt_clean_but_incomplete_exits_3(self):
        root = tempfile.mkdtemp(prefix="hunt-n6-")
        for i in range(5):
            _write(root, f"clean{i}.php", "<?php echo 'ok';\n")
        _write(root, "vendor/composer/installed.json",
               '{"packages": [{"name": "acme/pkg",'
               ' "install-path": "../acme/pkg"}]}')
        _write(root, "vendor/acme/pkg/lib.php",
               "<?php echo 'library';\n")
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli.main(["hunt", root])
        self.assertEqual(rc, 3)
        report = json.loads(out.getvalue())
        self.assertEqual(report["findings"], [])
        self.assertTrue(report["incomplete"])
        self.assertIn("incomplete", report["verdict"]["detail"])
        self.assertEqual(report["schema_version"], 1)

    def test_hunt_findings_plus_incomplete_exits_1(self):
        root = tempfile.mkdtemp(prefix="hunt-n6b-")
        _write(root, "vendor/composer/installed.json",
               '{"packages": [{"name": "acme/pkg",'
               ' "install-path": "../acme/pkg"}]}')
        _write(root, "vendor/acme/pkg/lib.php",
               "<?php echo 'library';\n")
        _write(root, "shell.php", "<?php eval($_POST['x']); ?>\n")
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli.main(["hunt", root])
        self.assertEqual(rc, 1)
        report = json.loads(out.getvalue())
        self.assertIn("incomplete", report["verdict"]["detail"])

    def test_read_capped_stops_on_abort(self):
        body = b"<html>" + b"A" * 300000
        state = {"pos": 0, "calls": 0}

        class Resp:
            def read(self, n=-1):
                state["calls"] += 1
                chunk = body[state["pos"]:state["pos"] + n]
                state["pos"] += len(chunk)
                return chunk

        out = scan._read_capped(
            Resp(),
            abort_check=lambda p: scan._lock_early_abort({}, p))
        self.assertEqual(state["calls"], 1)
        self.assertLess(len(out), len(body))

    def test_lock_early_abort_predicate(self):
        abort = scan._lock_early_abort
        self.assertTrue(abort(
            {"content-type": "text/html; charset=utf-8"}, b"{"))
        self.assertTrue(abort({}, b"<html>nope"))
        self.assertFalse(abort({}, b'\n {"packages": []}'))
        self.assertFalse(abort(
            {"content-type": "application/json"}, b"{"))
        self.assertIsNone(abort({}, b"   \n\t"))


# ----------------------------------------------------------------
# N7 — low note exists; alone it never moves the exit code
# ----------------------------------------------------------------

class N7LowNote(unittest.TestCase):
    def test_low_indicator_alone_exits_0(self):
        note = {"indicator": "known-shell-path-unconfirmed",
                "severity": "low", "path": "/c99.php"}
        self.assertEqual(
            _run_cli([_result("patched", indicators=[note])]), 0)

    def test_high_indicator_exits_1(self):
        hit = {"indicator": "known-shell-path",
               "severity": "high", "path": "/c99.php"}
        self.assertEqual(
            _run_cli([_result("patched", indicators=[hit])]), 1)


if __name__ == "__main__":
    unittest.main()
