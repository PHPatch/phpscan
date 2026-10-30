"""Multi-advisory matching + the generated core advisory database.

Two layers:
  * FixtureInjection — verdict_for() against hand-built advisory
    sets (the full-DB matching semantics: aggregation, effective
    floor, no-fix branches), independent of the shipped data.
  * LiveDatabase — sanity of the generated phpscan/data/cves.json
    itself (size, branch coverage, known CVE floors, no duplicate
    php2shell CVEs) and of the public feed generation.
"""

import importlib.util
import json
import os
import unittest
import xml.etree.ElementTree as ET

from phpscan import versioning

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _adv(**kw):
    base = {"id": "CVE-2000-0001", "cves": ["CVE-2000-0001"],
            "title": "Fixture advisory", "summary": "fixture",
            "published": "2022-01-01", "references": [],
            "fixed_releases": {}, "no_fix_branches": [],
            "eol_below": "7.3", "cvss_v3": 7.5}
    base.update(kw)
    return base


ADV_A = _adv(fixed_releases={"7.4": "7.4.33", "8.1": "8.1.10"},
             no_fix_branches=["7.3"])
ADV_B = _adv(id="CVE-2000-0002", cves=["CVE-2000-0002"],
             title="Fixture advisory B", cvss_v3=9.8,
             published="2021-06-01",
             fixed_releases={"7.4": "7.4.30"})


class FixtureInjection(unittest.TestCase):
    def test_vulnerable_74x(self):
        v = versioning.verdict_for((7, 4, 30), advisories=[ADV_A])
        self.assertEqual(v["status"], "vulnerable")
        self.assertEqual(v["floor"], "7.4.33")
        self.assertIn("7.4.33", v["remediation"])

    def test_patched_81x(self):
        v = versioning.verdict_for((8, 1, 12), advisories=[ADV_A])
        self.assertEqual(v["status"], "patched")

    def test_eol_branch_case(self):
        v = versioning.verdict_for((7, 3, 5), advisories=[ADV_A])
        self.assertEqual(v["status"], "eol")
        self.assertEqual(v["advisory"], "CVE-2000-0001")

    def test_multi_advisory_aggregation(self):
        v = versioning.verdict_for((7, 4, 29),
                                   advisories=[ADV_A, ADV_B])
        self.assertEqual(v["status"], "vulnerable")
        # headline = most severe; floor = the branch's cumulative
        # patched release (the max), which fixes both
        self.assertEqual(v["advisory"], "CVE-2000-0002")
        self.assertEqual(v["floor"], "7.4.33")
        self.assertEqual(len(v["findings"]), 2)
        self.assertIn("2 advisories", v["detail"])

    def test_at_floor_is_patched(self):
        v = versioning.verdict_for((7, 4, 33),
                                   advisories=[ADV_A, ADV_B])
        self.assertEqual(v["status"], "patched")

    def test_unfixed_everywhere_is_vulnerable_without_floor(self):
        adv = _adv(id="CVE-2000-0003", cves=["CVE-2000-0003"],
                   no_fix_branches=["8.3"])
        v = versioning.verdict_for((8, 3, 1), advisories=[adv])
        self.assertEqual(v["status"], "vulnerable")
        self.assertIsNone(v["floor"])

    def test_newer_branch_not_assessed(self):
        v = versioning.verdict_for((8, 9, 1), advisories=[ADV_A])
        self.assertEqual(v["status"], "not_assessed")

    def test_fixed_tag_uses_effective_floor(self):
        tag = versioning.fixed_tag_for((7, 4, 30), "apache",
                                       advisories=[ADV_A, ADV_B])
        self.assertEqual(tag, "php:7.4.33-apache")


class LiveDatabase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(REPO, "phpscan", "data", "cves.json"),
                  encoding="utf-8") as f:
            cls.db = json.load(f)
        cls.advs = cls.db["advisories"]
        cls.by_id = {a["id"]: a for a in cls.advs}

    def test_database_is_full(self):
        self.assertGreater(len(self.advs), 700)

    def test_php2shell_curated_once(self):
        self.assertIn("php2shell-2026-10", self.by_id)
        for cid in ("CVE-2026-109618", "CVE-2026-109619"):
            self.assertNotIn(cid, self.by_id)

    def test_branch_coverage(self):
        branches = set()
        for a in self.advs:
            branches.update(a.get("fixed_releases", {}))
        for want in ("5.6", "7.4", "8.0", "8.1", "8.2", "8.3",
                     "8.4", "8.5"):
            self.assertIn(want, branches)

    def test_known_floors(self):
        a = self.by_id["CVE-2022-31629"]
        self.assertEqual(a["fixed_releases"]["8.1"], "8.1.11")
        self.assertEqual(a["fixed_releases"]["7.4"], "7.4.31")
        b = self.by_id["CVE-2024-11236"]
        self.assertEqual(b["fixed_releases"]["8.3"], "8.3.14")

    def test_every_advisory_wellformed(self):
        for a in self.advs:
            self.assertTrue(a["id"])
            self.assertTrue(a["cves"])
            self.assertTrue(a["title"])
            for br, fv in a.get("fixed_releases", {}).items():
                self.assertIsNotNone(versioning.parse_version(fv),
                                     (a["id"], br, fv))

    def test_current_branch_verdicts(self):
        self.assertEqual(
            versioning.verdict_for((8, 4, 20))["status"],
            "vulnerable")
        v = versioning.verdict_for((8, 4, 20))
        self.assertEqual(v["floor"], "8.4.27")  # php2shell floor
        self.assertGreaterEqual(len(v["findings"]), 2)
        # an end-of-life branch resolves via the curated EOL path
        self.assertEqual(
            versioning.verdict_for((7, 4, 33))["status"], "eol")


class FeedGeneration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "build_feed", os.path.join(REPO, "tools", "build_feed.py"))
        cls.feed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.feed)
        with open(os.path.join(REPO, "phpscan", "data", "cves.json"),
                  encoding="utf-8") as f:
            cls.db = json.load(f)

    def test_json_feed_roundtrip(self):
        doc = self.feed.build_json(self.db)
        parsed = json.loads(json.dumps(doc))
        self.assertEqual(parsed["feed"]["advisory_count"],
                         len(self.db["advisories"]))
        self.assertEqual(len(parsed["advisories"]),
                         len(self.db["advisories"]))

    def test_atom_feed_valid(self):
        xml_text = self.feed.build_atom(self.db)
        root = ET.fromstring(xml_text)
        ns = "{http://www.w3.org/2005/Atom}"
        entries = root.findall(f"{ns}entry")
        self.assertEqual(len(entries),
                         min(50, len(self.db["advisories"])))
        first = entries[0]
        self.assertTrue(first.findtext(f"{ns}title"))
        self.assertTrue(first.findtext(f"{ns}id"))
        # most recent first: php2shell (2026-10-21) leads the feed
        self.assertIn("php2shell", first.findtext(f"{ns}id"))


if __name__ == "__main__":
    unittest.main()
