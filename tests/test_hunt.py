"""Tests for phpscan hunt — the local compromise check.

Fixtures are synthetic trees built in a temp dir: clean WP-ish
files, planted FAKE shells (classic patterns, inert text), a PHP
file in an uploads dir, a benign eval() in a minified library,
and mtime outliers. No real malware, no network.
Run: python3 -m unittest discover -s tests
"""

import io
import json
import os
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout

from phpscan import __main__ as cli
from phpscan import hunt

OLD = time.time() - 30 * 86400      # the "release" cluster
NEW = time.time()                   # the dropped file


def _write(root, rel, text, mtime=OLD):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    os.utime(path, (mtime, mtime))
    return path


def _by_file(report):
    out = {}
    for f in report["findings"]:
        out.setdefault(f["file"], []).append(f)
    return out


class FixtureTree(unittest.TestCase):
    """One tree exercising every indicator class at once."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="hunt-fixture-")
        w = lambda rel, text, mt=OLD: _write(self.root, rel, text, mt)
        # Clean WP-ish release cluster (>= 5 files, same day).
        w("index.php", "<?php // Silence is golden.\n")
        w("wp-load.php", "<?php require 'wp-config.php';\n")
        w("wp-config.php", "<?php $db = 'wordpress';\n")
        w("wp-includes/functions.php", "<?php function esc_html($s){"
                                       " return htmlspecialchars($s); }\n")
        w("wp-includes/plugin.php", "<?php // plugin API\n")
        w("wp-content/themes/site/header.php",
          "<?php get_header(); ?>\n")
        # Benign eval() in a legit-looking minified library -> LOW.
        w("wp-includes/js/minlib.php",
          "<?php /* minified */ $f=eval('return 1;');\n")
        # Planted fake shell: request-input eval (critical) ...
        w("wp-content/uploads/evil.php",
          "<?php eval($_POST['x']); ?>\n")
        # ... a fake c99 by filename + fingerprint + decode chain ...
        w("c99.php", "<?php /* c99shell */ "
                     "eval(gzinflate(base64_decode('AAAA'))); ?>\n")
        # ... and a harmless PHP file that should not be in uploads.
        w("wp-content/uploads/pic.php", "<?php echo 'hello';\n")
        # Double extension.
        w("images/avatar.php.jpg", "<?php echo 1;\n")
        # Hidden PHP dotfile.
        w(".hidden.php", "<?php echo 2;\n")
        # Mtime outlier: innocent content, lone fresh mtime.
        w("wp-includes/dropped.php", "<?php echo 3;\n", NEW)
        # Vendor tree with a loud pattern — skipped by default
        # because acme/pkg is a package in vendor/composer/
        # installed.json (the only vendor content skipped).
        w("vendor/composer/installed.json",
          '{"packages": [{"name": "acme/pkg",'
          ' "version": "1.0.0"}]}')
        w("vendor/acme/pkg/bad.php", "<?php eval($_POST['y']); ?>\n")
        self.report = hunt.hunt_local(self.root)
        self.files = _by_file(self.report)

    def test_request_input_eval_is_critical(self):
        fs = self.files["wp-content/uploads/evil.php"]
        crit = [f for f in fs if f["severity"] == "critical"]
        self.assertTrue(crit)
        self.assertTrue(any(
            f["indicator"] == "pattern:eval-request-input"
            for f in crit))

    def test_php_in_uploads_is_high(self):
        fs = self.files["wp-content/uploads/pic.php"]
        self.assertTrue(any(
            f["indicator"] == "php-in-special-dir"
            and f["severity"] == "high" for f in fs))

    def test_c99_filename_and_fingerprint_are_critical(self):
        fs = self.files["c99.php"]
        self.assertTrue(any(
            f["indicator"] == "filename:c99.php"
            and f["severity"] == "critical" for f in fs))
        self.assertTrue(any(
            f["indicator"] == "pattern:shell-fingerprint-c99"
            for f in fs))
        self.assertTrue(any(
            f["indicator"] == "pattern:eval-obfuscated-chain"
            and f["severity"] == "high" for f in fs))

    def test_benign_eval_lands_low_only(self):
        fs = self.files["wp-includes/js/minlib.php"]
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0]["severity"], "low")
        self.assertEqual(fs[0]["indicator"], "pattern:eval-plain")

    def test_double_extension_and_dotfile_are_medium(self):
        self.assertTrue(any(
            f["indicator"] == "double-extension"
            and f["severity"] == "medium"
            for f in self.files["images/avatar.php.jpg"]))
        self.assertTrue(any(
            f["indicator"] == "hidden-php-dotfile"
            and f["severity"] == "medium"
            for f in self.files[".hidden.php"]))

    def test_mtime_outlier_flagged_but_cluster_is_not(self):
        self.assertTrue(any(
            f["indicator"] == "mtime-outlier"
            for f in self.files["wp-includes/dropped.php"]))
        for clean in ("index.php", "wp-load.php", "wp-config.php"):
            self.assertNotIn(clean, self.files)

    def test_vendor_skipped_by_default_included_on_flag(self):
        self.assertNotIn("vendor/acme/pkg/bad.php", self.files)
        full = _by_file(hunt.hunt_local(self.root,
                                         include_vendor=True))
        self.assertIn("vendor/acme/pkg/bad.php", full)

    def test_every_finding_has_remediation(self):
        for f in self.report["findings"]:
            self.assertIn("remediation", f)
            self.assertTrue(f["remediation"])

    def test_verdict_is_findings_with_worst_critical(self):
        self.assertEqual(self.report["verdict"]["status"], "findings")
        self.assertEqual(self.report["verdict"]["worst_severity"],
                         "critical")


class CleanAndCli(unittest.TestCase):

    def _clean_tree(self):
        root = tempfile.mkdtemp(prefix="hunt-clean-")
        for i in range(5):
            _write(root, f"file{i}.php", "<?php echo 'ok';\n")
        return root

    def test_clean_tree_report(self):
        report = hunt.hunt_local(self._clean_tree())
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["verdict"]["status"], "clean")
        self.assertIn("not a guarantee", report["verdict"]["detail"])

    def test_cli_clean_exit_0(self):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli.main(["hunt", self._clean_tree()])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out.getvalue())["verdict"]
                         ["status"], "clean")

    def test_cli_findings_exit_1(self):
        root = self._clean_tree()
        _write(root, "cmd.php", "<?php echo 1;\n")
        with redirect_stdout(io.StringIO()):
            rc = cli.main(["hunt", root])
        self.assertEqual(rc, 1)

    def test_cli_usage_errors_exit_2(self):
        with redirect_stdout(io.StringIO()), \
                redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["hunt"]), 2)
            self.assertEqual(cli.main(["hunt", "/nonexistent-xx"]), 2)
            self.assertEqual(cli.main(["hunt", "/tmp", "--bogus"]), 2)

    def test_cli_help_exit_0(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["hunt", "--help"]), 0)

    def test_hunt_local_rejects_file(self):
        with self.assertRaises(ValueError):
            hunt.hunt_local(os.path.abspath(__file__))


class RemoteIndicators(unittest.TestCase):

    def _fake_fetch(self, hits):
        def fetch(url, deadline=None):
            for h in hits:
                if url.endswith(h):
                    # A hit now requires the shell's signature
                    # in the body (P2) — a bare 200 proves
                    # nothing.
                    return {"ok": True, "status": 200,
                            "body": "<html>FilesMan</html>"}
            return {"ok": False, "status": 404}
        return fetch

    def test_only_200_paths_reported(self):
        out = hunt.remote_indicators(
            self._fake_fetch({"/c99.php", "/files/shell.php"}),
            "https://example.com")
        paths = sorted(i["path"] for i in out)
        self.assertEqual(paths, ["/c99.php", "/files/shell.php"])
        for i in out:
            self.assertEqual(i["indicator"], "known-shell-path")
            self.assertIn("not conclusive", i["detail"])
            self.assertTrue(i["remediation"])

    def test_no_hits_no_indicators(self):
        self.assertEqual(
            hunt.remote_indicators(self._fake_fetch(set()),
                                   "https://example.com"), [])


if __name__ == "__main__":
    unittest.main()
