#!/usr/bin/env python3
"""Publish the phpscan advisory database as public feeds.

Reads phpscan/data/cves.json (built by tools/build_core_db.py) and
writes, into feeds/ by default:

  php-advisories.json — the full database, republished verbatim
      under feed metadata. Stable-URL candidate for phpatch.com:
      https://phpatch.com/feeds/php-advisories.json
  php-advisories.atom — Atom 1.0 with the 50 most recent
      advisories (by published date, then severity), one entry
      per advisory, linking to its first reference (NVD detail
      for per-CVE entries). Candidate:
      https://phpatch.com/feeds/php-advisories.xml (serve the
      .atom content with Content-Type: application/atom+xml).

Both files are validated after writing (JSON parses; Atom parses
and has the expected entry count) and the script exits non-zero
if validation fails, so it is safe to run unattended from cron
(see tools/refresh_advisory_db.sh).

Deploy note for phpatch.com (main chat ships this, not this
script): copy both files to the site's feeds/ directory on every
database refresh; serve the JSON with
`Cache-Control: public, max-age=3600` and the Atom with
`Cache-Control: public, max-age=1800`; keep the URLs stable —
other tools are expected to poll them.
"""

import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DATA = os.path.join(REPO, "phpscan", "data", "cves.json")
ATOM = "http://www.w3.org/2005/Atom"
FEED_ID = "https://phpatch.com/feeds/php-advisories"
RECENT = 50


def _score(a):
    return a.get("cvss_v4") or a.get("cvss_v3") or a.get("cvss_v2") or 0


def recent(advisories, n=RECENT):
    return sorted(advisories,
                  key=lambda a: (a.get("published", ""), _score(a)),
                  reverse=True)[:n]


def build_json(db):
    return {"feed": {"title": "PHPatch — PHP core security advisories",
                     "publisher": "PHPatch (https://phpatch.com)",
                     "source": "phpscan advisory database "
                               "(NIST NVD + php.net ChangeLogs)",
                     "updated": db["updated"],
                     "advisory_count": len(db["advisories"]),
                     "canonical": FEED_ID + ".json",
                     "atom": FEED_ID + ".xml"},
            "advisories": db["advisories"]}


def build_atom(db):
    updated = db["updated"] + "T00:00:00Z"
    out = ['<?xml version="1.0" encoding="utf-8"?>',
           f'<feed xmlns="{ATOM}">',
           "<title>PHPatch — PHP core security advisories</title>",
           f"<id>{FEED_ID}</id>",
           f"<updated>{updated}</updated>",
           '<link rel="self" href="' + FEED_ID + '.xml"/>',
           '<link rel="alternate" href="https://phpatch.com/"/>',
           "<author><name>PHPatch</name></author>"]
    for a in recent(db["advisories"]):
        link = (a.get("references") or ["https://phpatch.com/"])[0]
        pub = (a.get("published") or db["updated"]) + "T00:00:00Z"
        title = f"{a['id']} — {a.get('title', '')}"
        fixed = a.get("fixed_releases", {})
        cats = "".join(
            f'<category term="PHP {escape(b)}"/>'
            for b in sorted(fixed))
        nofix = "".join(
            f'<category term="PHP {escape(b)} (no fix)"/>'
            for b in a.get("no_fix_branches", []))
        score = _score(a)
        summary = a.get("summary", "")
        if fixed:
            summary += (" Fixed in: " + ", ".join(
                f"{b} {v}" for b, v in sorted(fixed.items())) + ".")
        if score:
            summary += f" CVSS: {score}."
        out.append("<entry>")
        out.append(f"<title>{escape(title)}</title>")
        out.append(f"<id>urn:phpatch:advisory:{escape(a['id'])}</id>")
        out.append(f'<link href="{escape(link)}"/>')
        out.append(f"<published>{pub}</published>")
        out.append(f"<updated>{pub}</updated>")
        out.append(cats + nofix)
        out.append(f"<summary>{escape(summary)}</summary>")
        out.append("</entry>")
    out.append("</feed>")
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=DATA)
    ap.add_argument("--out-dir",
                    default=os.path.join(REPO, "feeds"))
    args = ap.parse_args()
    with open(args.data, encoding="utf-8") as f:
        db = json.load(f)
    os.makedirs(args.out_dir, exist_ok=True)
    jpath = os.path.join(args.out_dir, "php-advisories.json")
    apath = os.path.join(args.out_dir, "php-advisories.atom")
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump(build_json(db), f, indent=1, sort_keys=True,
                  ensure_ascii=False)
        f.write("\n")
    with open(apath, "w", encoding="utf-8") as f:
        f.write(build_atom(db))
    # Validate what we wrote — the feed must never ship broken.
    with open(jpath, encoding="utf-8") as f:
        parsed = json.load(f)
    assert parsed["feed"]["advisory_count"] == len(db["advisories"])
    root = ET.parse(apath).getroot()
    entries = root.findall(f"{{{ATOM}}}entry")
    assert len(entries) == min(RECENT, len(db["advisories"])), \
        len(entries)
    print(json.dumps({
        "json": jpath, "json_bytes": os.path.getsize(jpath),
        "atom": apath, "atom_bytes": os.path.getsize(apath),
        "atom_entries": len(entries),
        "advisories": len(db["advisories"])}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
