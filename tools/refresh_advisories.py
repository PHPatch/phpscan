#!/usr/bin/env python3
"""Refresh the vendored advisory snapshots used by `phpscan audit`.

Two snapshots live in phpscan/data/ and are the ONLY advisory data
the audit reads at runtime in --offline mode (and the fallback when
OSV is unreachable):

  friendsofphp.json — FriendsOfPHP/security-advisories, the canonical
      PHP advisory database. Upstream is one YAML file per advisory
      under <vendor>/<package>/<file>.yaml on GitHub:
      https://github.com/FriendsOfPHP/security-advisories
      This tool clones (or reuses, via --fop-dir) that repo and
      flattens every advisory to {id, cve, title, link, ranges},
      where `ranges` keeps the upstream branch structure as
      {branch, versions} pairs. Branch keys matter: a numeric key
      ("7.12", "6.x", "8.5.x") scopes its constraint list to that
      release line — an unbounded "<7.12.1" under branch "7.12"
      must not match 6.5.5. Non-numeric keys ("master") carry no
      line scoping; their constraint lists bound themselves.

  kev.json — CISA's Known Exploited Vulnerabilities catalog
      (https://www.cisa.gov/sites/default/files/feeds/
      known_exploited_vulnerabilities.json), reduced to the CVE id
      set. Pass --kev-file to vendor from a local copy instead of
      downloading (the phpatch threat swarm keeps dated snapshots).

Requires PyYAML (developer tooling only — the phpscan runtime is
standard-library only and never fetches either source directly,
except OSV queries in live audit mode).

Usage:
    python3 tools/refresh_advisories.py [--fop-dir PATH]
                                        [--kev-file PATH]
                                        [--out-dir phpscan/data]
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import urllib.request
from datetime import date

FOP_REPO = "https://github.com/FriendsOfPHP/security-advisories"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")


def load_fop(fop_dir):
    try:
        import yaml
    except ImportError:
        sys.exit("PyYAML is required: pip install pyyaml "
                 "(developer tooling only)")
    packages = {}
    skipped = 0
    for vendor in sorted(os.listdir(fop_dir)):
        vdir = os.path.join(fop_dir, vendor)
        if not os.path.isdir(vdir) or vendor.startswith("."):
            continue
        for pkg in sorted(os.listdir(vdir)):
            pdir = os.path.join(vdir, pkg)
            if not os.path.isdir(pdir):
                continue
            name = f"{vendor}/{pkg}"
            for fn in sorted(os.listdir(pdir)):
                if not fn.endswith(".yaml"):
                    continue
                try:
                    with open(os.path.join(pdir, fn),
                              encoding="utf-8") as f:
                        d = yaml.safe_load(f)
                except Exception:
                    skipped += 1
                    continue
                if not isinstance(d, dict):
                    skipped += 1
                    continue
                ranges = []
                for bname, branch in (d.get("branches") or {}).items():
                    if isinstance(branch, dict):
                        vs = branch.get("versions") or []
                        ranges.append({
                            "branch": str(bname),
                            "versions": [str(v) for v in vs]})
                cve = d.get("cve") or None
                stem = fn[:-len(".yaml")]
                packages.setdefault(name, []).append({
                    "id": cve or f"friendsofphp/{name}/{stem}",
                    "cve": cve,
                    "title": d.get("title") or stem,
                    "link": d.get("link"),
                    "ranges": ranges,
                })
    return packages, skipped


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--fop-dir",
                    help="existing FriendsOfPHP/security-advisories "
                         "checkout (default: shallow-clone upstream)")
    ap.add_argument("--kev-file",
                    help="local CISA KEV JSON (default: download "
                         "the official feed)")
    ap.add_argument("--out-dir", default="phpscan/data")
    args = ap.parse_args()

    tmp = None
    fop_dir = args.fop_dir
    if not fop_dir:
        tmp = tempfile.mkdtemp(prefix="fop-")
        subprocess.run(["git", "clone", "-q", "--depth", "1",
                        FOP_REPO, tmp], check=True)
        fop_dir = tmp
    commit = subprocess.run(
        ["git", "-C", fop_dir, "rev-parse", "HEAD"],
        capture_output=True, text=True).stdout.strip() or None

    packages, skipped = load_fop(fop_dir)
    fop_out = {
        "source": "FriendsOfPHP/security-advisories",
        "source_url": FOP_REPO,
        "snapshot_date": date.today().isoformat(),
        "commit": commit,
        "packages": packages,
    }
    os.makedirs(args.out_dir, exist_ok=True)
    fop_path = os.path.join(args.out_dir, "friendsofphp.json")
    with open(fop_path, "w", encoding="utf-8") as f:
        json.dump(fop_out, f, ensure_ascii=False, sort_keys=True)
    n_adv = sum(len(v) for v in packages.values())
    print(f"{fop_path}: {len(packages)} packages, {n_adv} advisories"
          f" ({skipped} files skipped)")

    if args.kev_file:
        with open(args.kev_file, encoding="utf-8") as f:
            kev = json.load(f)
    else:
        req = urllib.request.Request(KEV_URL,
                                     headers={"User-Agent":
                                              "phpscan-refresh"})
        with urllib.request.urlopen(req, timeout=60) as r:
            kev = json.load(r)
    kev_out = {
        "source": "CISA Known Exploited Vulnerabilities Catalog",
        "source_url": KEV_URL,
        "snapshot_date": (kev.get("dateReleased") or "")[:10]
                         or date.today().isoformat(),
        "catalog_version": kev.get("catalogVersion"),
        "cves": sorted({v["cveID"] for v in kev["vulnerabilities"]}),
    }
    kev_path = os.path.join(args.out_dir, "kev.json")
    with open(kev_path, "w", encoding="utf-8") as f:
        json.dump(kev_out, f, ensure_ascii=False, sort_keys=True)
    print(f"{kev_path}: {len(kev_out['cves'])} CVEs, catalog "
          f"{kev_out['catalog_version']}")


if __name__ == "__main__":
    main()
