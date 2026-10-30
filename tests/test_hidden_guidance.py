"""VERSION HIDDEN (status "indeterminate") owner self-check guidance.

The hidden verdict used to be a dead end: honest, but with nothing
for the site's owner to do next. It now carries a `remediation`
one-liner and a `next_steps` list in the JSON verdict, and an
"If this is your site" block in the text output. These tests pin
the exact guidance strings (including the phpinfo delete warning)
and prove every other verdict is untouched.
"""

import json
import unittest
from unittest import mock

from phpscan import scan, versioning

EXPECTED_REMEDIATION = "Version not disclosed — if this is your site, check the version server-side (php -v, your hosting panel, or a temporary phpinfo page you delete immediately after), then verify it against the PHPatch advisory feed. Full guide: https://phpatch.com/guides/version-hidden"

EXPECTED_NEXT_STEPS = [
    "SSH or terminal: run `php -v` (note: CLI and web PHP can differ on some hosts — the panel method below shows the web version).",
    "Hosting panel: cPanel → MultiPHP Manager or 'Select PHP Version'; Plesk → Websites & Domains → PHP Settings — both show the PHP version serving your site.",
    "Temporary phpinfo: create check.php containing <?php phpinfo(); in your web root, open it in a browser, note the version, then DELETE the file immediately — a leftover phpinfo page is itself a serious exposure (phpscan flags it).",
    "Follow the full walkthrough: https://phpatch.com/guides/version-hidden — it covers checking your version against current advisories (feed: https://phpatch.com/feeds/php-advisories.json) and what to do if it's end-of-life.",
    "If the version is end-of-life or has known vulnerabilities, upgrade it or have it patched — see https://phpatch.com/patch.",
]

EXPECTED_CLOSING = "Not your site? A hidden version can't be assessed externally — that's by design, and it is not evidence the site is vulnerable."


def _home(**kw):
    d = {"ok": True, "status": 200,
         "final_url": "https://example.com/",
         "headers": {}, "body": "<html></html>", "error": None}
    d.update(kw)
    return d


def _not_found():
    return _home(status=404, ok=False, error="HTTP 404")


def _run(home):
    """scan() with _fetch stubbed: first call serves `home`, every
    probe after that 404s (same pattern as ScanFixtures)."""
    calls = []

    def fake_fetch(url, ctx=None, deadline=None):
        calls.append(url)
        return home if len(calls) == 1 else _not_found()

    with mock.patch.object(scan, "_fetch", fake_fetch):
        return scan.scan("https://example.com/")


def _hidden_result():
    # PHP present (PHPSESSID cookie) but no version disclosed.
    return _run(_home(headers={"Set-Cookie": "PHPSESSID=abc; path=/"}))


class HiddenVerdictGuidance(unittest.TestCase):

    def test_status_and_label_unchanged(self):
        r = _hidden_result()
        self.assertEqual(r["verdict"]["status"], "indeterminate")

    def test_remediation_is_the_specified_one_liner(self):
        r = _hidden_result()
        self.assertEqual(r["verdict"]["remediation"],
                         EXPECTED_REMEDIATION)

    def test_next_steps_exact_and_ordered(self):
        r = _hidden_result()
        self.assertEqual(r["verdict"]["next_steps"],
                         EXPECTED_NEXT_STEPS)

    def test_phpinfo_step_carries_delete_warning(self):
        r = _hidden_result()
        step = r["verdict"]["next_steps"][2]
        self.assertIn("phpinfo", step)
        self.assertIn("DELETE the file immediately", step)

    def test_guidance_survives_json_round_trip(self):
        r = _hidden_result()
        parsed = json.loads(json.dumps(r))
        self.assertEqual(parsed["verdict"]["next_steps"],
                         EXPECTED_NEXT_STEPS)
        self.assertEqual(parsed["verdict"]["remediation"],
                         EXPECTED_REMEDIATION)

    def test_next_steps_list_is_a_fresh_copy_per_scan(self):
        r1 = _hidden_result()
        r1["verdict"]["next_steps"].clear()
        r2 = _hidden_result()
        self.assertEqual(r2["verdict"]["next_steps"],
                         EXPECTED_NEXT_STEPS)

    def test_text_output_has_owner_block_and_closing_line(self):
        text = scan.render_text(_hidden_result())
        self.assertIn("If this is your site:", text)
        for i, step in enumerate(EXPECTED_NEXT_STEPS, 1):
            self.assertIn(f"{i}. {step}", text)
        self.assertIn(EXPECTED_CLOSING, text)


class OtherVerdictsUnchanged(unittest.TestCase):

    def test_vulnerable_verdict_is_versionings_verdict_verbatim(self):
        r = _run(_home(headers={"X-Powered-By": "PHP/8.3.35"}))
        self.assertEqual(r["verdict"],
                         versioning.verdict_for((8, 3, 35)))
        self.assertNotIn("next_steps", r["verdict"])
        text = scan.render_text(r)
        self.assertNotIn("If this is your site:", text)
        self.assertNotIn(EXPECTED_CLOSING, text)

    def test_patched_verdict_has_no_guidance(self):
        r = _run(_home(headers={"X-Powered-By": "PHP/8.3.36"}))
        self.assertEqual(r["verdict"]["status"], "patched")
        self.assertNotIn("next_steps", r["verdict"])

    def test_no_php_verdict_has_no_guidance(self):
        r = _run(_home())
        self.assertEqual(r["verdict"]["status"], "no_php_detected")
        self.assertNotIn("next_steps", r["verdict"])
        self.assertNotIn("remediation", r["verdict"])

    def test_unreachable_verdict_has_no_guidance(self):
        dead = {"ok": False, "status": None,
                "final_url": "https://example.com/",
                "headers": {}, "body": "", "error": "boom"}
        with mock.patch.object(scan, "_fetch",
                               lambda url, ctx=None, deadline=None: dead):
            r = scan.scan("https://example.com/")
        self.assertEqual(r["verdict"]["status"], "unreachable")
        self.assertNotIn("next_steps", r["verdict"])


if __name__ == "__main__":
    unittest.main()
