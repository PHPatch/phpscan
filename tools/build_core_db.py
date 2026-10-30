#!/usr/bin/env python3
"""Regenerate phpscan/data/cves.json — the full PHP core advisory DB.

Sources (both public, no key required):
  * NIST NVD API 2.0 — every CVE whose configurations match the
    cpe:2.3:a:php:php CPE. The CPE version ranges give, per PHP
    branch, the release that fixed the CVE (versionEndExcluding).
  * php.net ChangeLogs (ChangeLog-4/5/7/8.php) — the PHP project's
    own per-release fix lists. Used to (a) supply the per-branch
    fixed release where NVD models only one coarse range, and
    (b) date each advisory by its earliest fixed release.

Curated advisories already in cves.json (any whose id does not start
with "CVE-") are preserved verbatim at the head of the list; CVEs
they cover are not duplicated as per-CVE entries.

The output keeps the exact shape versioning.load_advisories() has
always consumed: {"advisories": [...], "source_notes", "updated"}.
Per-CVE entries carry two fields the curated entries predate:
  no_fix_branches — branches NVD/ChangeLog show as affected for
                    which no fixed release exists;
  cvss_v3 / cvss_v2 / severity — when no CVSS v4 score exists.

Update path: the phpatch threat swarm already polls the NVD API
(services.nvd.nist.gov is on its source allowlist) every 2 hours.
Running tools/refresh_advisory_db.sh from any cron next to the
swarm regenerates this file and the public feeds from the same
upstream data; a maintainer then reviews and commits the diff
(CODEOWNERS requires review — verdicts change with this file).

Usage:
  python3 tools/build_core_db.py [--nvd-file F] [--changelog-dir D]
                                 [--out F] [--today YYYY-MM-DD]
Without --nvd-file/--changelog-dir the sources are fetched live
(NVD_API_KEY env var is honoured when set).
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DATA = os.path.join(REPO, "phpscan", "data", "cves.json")
UA = "PHPatch-phpscan-db-builder/1.0 (+https://phpatch.com/security)"
NVD_URL = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
           "?virtualMatchString=cpe:2.3:a:php:php&resultsPerPage=2000"
           "&startIndex={}")
CHANGELOG_URL = "https://www.php.net/ChangeLog-{}.php"
VER_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def _d(iso):
    """ISO date str -> ordinal, or None."""
    if not iso:
        return None
    try:
        y, m, dd = (int(x) for x in iso[:10].split("-"))
        import datetime
        return datetime.date(y, m, dd).toordinal()
    except Exception:
        return None


FIX_WINDOW = (-30, 400)      # days around NVD publication a fix may land
OPEN_RANGE_YEARS = 8         # no-start ranges reach back this many years


def parse_version(text):
    if not text:
        return None
    m = VER_RE.search(str(text))
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def branch_of(vtuple):
    return f"{vtuple[0]}.{vtuple[1]}"


def fetch(url, timeout=120):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    key = os.environ.get("NVD_API_KEY")
    if key and "services.nvd.nist.gov" in url:
        req.add_header("apiKey", key)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def fetch_nvd(cache_file=None):
    if cache_file:
        with open(cache_file, encoding="utf-8") as f:
            return json.load(f)["vulnerabilities"]
    vulns, start = [], 0
    while True:
        payload = json.loads(fetch(NVD_URL.format(start)))
        vulns.extend(payload["vulnerabilities"])
        total = payload["totalResults"]
        start += payload["resultsPerPage"]
        if start >= total:
            return vulns
        time.sleep(1 if os.environ.get("NVD_API_KEY") else 7)


def parse_changelog(text):
    """-> ({cve: set(release str)}, {release str: ISO date str})"""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&nbsp;", " ", text)
    fixes, dates = {}, {}
    parts = re.split(r"Version\s+(\d+\.\d+\.\d+)\s*", text)
    # parts: [pre, ver, body, ver, body, ...]
    months = {m: i + 1 for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}
    for i in range(1, len(parts) - 1, 2):
        ver, body = parts[i], parts[i + 1]
        dm = re.search(r"(\d{1,2})\s+([A-Z][a-z]{2})\s+(\d{4})", body[:200])
        if dm:
            dates[ver] = (f"{dm.group(3)}-{months[dm.group(2)]:02d}-"
                          f"{int(dm.group(1)):02d}")
        for cve in set(CVE_RE.findall(body)):
            fixes.setdefault(cve, set()).add(ver)
    return fixes, dates


def fetch_changelogs(cache_dir=None):
    fixes, dates = {}, {}
    for major in (4, 5, 7, 8):
        raw = None
        if cache_dir:
            p = os.path.join(cache_dir, f"cl{major}.html")
            if os.path.exists(p):
                raw = open(p, encoding="utf-8", errors="ignore").read()
        if raw is None:
            try:
                raw = fetch(CHANGELOG_URL.format(major)).decode(
                    "utf-8", "ignore")
            except Exception:
                continue  # best effort — NVD alone still builds a DB
        f, d = parse_changelog(raw)
        for cve, vers in f.items():
            fixes.setdefault(cve, set()).update(vers)
        dates.update(d)
    return fixes, dates


def iter_matches(nodes):
    for node in nodes or []:
        for m in node.get("cpeMatch", []):
            yield m
        yield from iter_matches(node.get("children"))


def cpe_version(criteria):
    parts = criteria.split(":")
    return parts[5] if len(parts) > 5 else "*"


def pick_cvss(metrics):
    """-> (field_name, score, severity) preferring v4, v3.1, v3.0, v2."""
    for key, field in (("cvssMetricV40", "cvss_v4"),
                       ("cvssMetricV31", "cvss_v3"),
                       ("cvssMetricV30", "cvss_v3")):
        for entry in metrics.get(key, []):
            if entry.get("type") == "Primary" or \
                    metrics[key].index(entry) == 0:
                d = entry["cvssData"]
                return field, d["baseScore"], d.get("baseSeverity")
    for entry in metrics.get("cvssMetricV2", []):
        d = entry["cvssData"]
        return "cvss_v2", d["baseScore"], entry.get("baseSeverity")
    return None, None, None


def short_title(desc):
    desc = re.sub(r"\s+", " ", desc).strip()
    first = re.split(r"(?<=[.!?])\s+", desc)[0]
    if len(first) <= 110:
        return first
    return desc[:107].rsplit(" ", 1)[0] + "…"


def build(vulns, cl_fixes, cl_dates, curated, curated_cves, today):
    # branch universe + first/last known release per branch
    branches = set()
    first_rel, last_rel = {}, {}
    for vers in cl_fixes.values():
        for v in vers:
            t = parse_version(v)
            if t:
                branches.add(branch_of(t))
    for ver in cl_dates:
        t = parse_version(ver)
        if t:
            b = branch_of(t)
            branches.add(b)
            first_rel[b] = min(first_rel.get(b, t), t)
            last_rel[b] = max(last_rel.get(b, t), t)
    branch_list = sorted(branches, key=lambda b: parse_version(b + ".0"))
    last_rel_ord, first_rel_ord = {}, {}
    for ver, iso in cl_dates.items():
        t = parse_version(ver)
        o = _d(iso)
        if t and o:
            b = branch_of(t)
            last_rel_ord[b] = max(last_rel_ord.get(b, 0), o)
            first_rel_ord[b] = min(first_rel_ord.get(b, 1 << 62), o)

    def covers(rng, branch, pub_ord=None):
        """Does [start, end) style range rng touch any version of branch?"""
        lo = parse_version(branch + ".0")
        last = last_rel.get(branch, (lo[0], lo[1], 999))
        start, endx, endi = rng
        if start is None and pub_ord is not None:
            lr = last_rel_ord.get(branch)
            if lr is not None and lr < pub_ord - OPEN_RANGE_YEARS * 365:
                return False  # branch long dead at disclosure: not news
        if start and start > last:
            return False
        if endx and endx <= lo:
            return False
        if endi and endi < lo:
            return False
        return True

    advisories, stats = [], {"skipped_rejected": 0, "skipped_curated": 0,
                             "skipped_no_signal": 0, "kept": 0,
                             "dropped_out_of_window": 0}
    for item in vulns:
        cve = item["cve"]
        cid = cve["id"]
        if cve.get("vulnStatus") == "Rejected":
            stats["skipped_rejected"] += 1
            continue
        if cid in curated_cves:
            stats["skipped_curated"] += 1
            continue
        ranges = []          # (start tuple|None, endExcl|None, endIncl|None)
        for cfg in cve.get("configurations", []):
            for m in iter_matches(cfg.get("nodes")):
                crit = m.get("criteria", "")
                if not crit.startswith("cpe:2.3:a:php:php:"):
                    continue
                if not m.get("vulnerable", True):
                    continue
                start = parse_version(m.get("versionStartIncluding")) or \
                    parse_version(m.get("versionStartExcluding"))
                endx = parse_version(m.get("versionEndExcluding"))
                endi = parse_version(m.get("versionEndIncluding"))
                if not (start or endx or endi):
                    v = cpe_version(crit)
                    t = parse_version(v)
                    if t:  # exact-version CPE: start == end == t
                        start, endi = t, t
                if start or endx or endi:
                    ranges.append((start, endx, endi))
        pub_ord = _d(cve.get("published", "")[:10])
        # NVD per-branch endExcluding ranges are structural: trust them
        # as-is. (The bogus floors this project once produced came
        # from php.net ChangeLog regression mentions, not from NVD.)
        nvd_fixed = {}
        for (start, endx, endi) in ranges:
            if endx:
                b = branch_of(endx)
                if b not in nvd_fixed or endx < nvd_fixed[b]:
                    nvd_fixed[b] = endx
        nvd_covered = set(nvd_fixed)
        for rng in ranges:
            for b in branch_list:
                if covers(rng, b, pub_ord):
                    nvd_covered.add(b)
        # ChangeLog candidates: accepted only for NVD-evidenced
        # branches, and only when their release date clusters with
        # this CVE's other fix dates (branch fixes ship together;
        # a mention years later is a regression note, not the fix).
        cl_cand = {}
        for v in cl_fixes.get(cid, ()):
            t = parse_version(v)
            if t:
                cl_cand.setdefault(branch_of(t), set()).add(t)
        cand_dates = []
        for t in list(nvd_fixed.values()) + \
                [t for vs in cl_cand.values() for t in vs]:
            o = _d(cl_dates.get(".".join(map(str, t))))
            if o is not None:
                cand_dates.append(o)
        anchor = min(cand_dates) if cand_dates else None
        fixed = {b: ".".join(map(str, t)) for b, t in nvd_fixed.items()}
        for b, vs in cl_cand.items():
            if b not in nvd_covered:
                continue
            for t in vs:
                o = _d(cl_dates.get(".".join(map(str, t))))
                if anchor is not None and o is not None and \
                        not (-60 <= o - anchor <= 400):
                    stats["dropped_out_of_window"] += 1
                    continue
                cur = parse_version(fixed[b]) if b in fixed else None
                if cur is None or t < cur:
                    fixed[b] = ".".join(map(str, t))
        affected = set(fixed) | nvd_covered
        if not affected:
            stats["skipped_no_signal"] += 1
            continue
        no_fix = sorted(affected - set(fixed),
                        key=lambda b: parse_version(b + ".0"))
        descs = [d["value"] for d in cve.get("descriptions", [])
                 if d.get("lang") == "en"]
        desc = descs[0] if descs else ""
        summary = re.sub(r"\s+", " ", desc).strip()
        if len(summary) > 500:
            summary = summary[:497].rsplit(" ", 1)[0] + "…"
        field, score, severity = pick_cvss(cve.get("metrics", {}))
        refs = [f"https://nvd.nist.gov/vuln/detail/{cid}",
                f"https://www.cve.org/CVERecord?id={cid}"]
        for r in cve.get("references", []):
            u = r.get("url", "")
            if "php.net" in u and u not in refs:
                refs.append(u)
            if len(refs) >= 6:
                break
        fixed_dates = [cl_dates[v] for v in
                       (parse_version(f) and f for f in fixed.values())
                       if v in cl_dates]
        published = min(fixed_dates) if fixed_dates else \
            cve.get("published", "")[:10]
        adv = {"id": cid, "cves": [cid], "title": short_title(desc),
               "summary": summary, "published": published,
               "references": refs, "fixed_releases": dict(
                   sorted(fixed.items(),
                          key=lambda kv: parse_version(kv[0] + ".0"))),
               "no_fix_branches": no_fix,
               "eol_below": min(affected,
                                key=lambda b: parse_version(b + ".0"))}
        if field and score is not None:
            adv[field] = score
        if severity:
            adv["severity"] = severity
        advisories.append(adv)
        stats["kept"] += 1

    def sort_key(a):
        return (a.get("published", ""), a.get("cvss_v4") or
                a.get("cvss_v3") or a.get("cvss_v2") or 0)
    advisories.sort(key=sort_key, reverse=True)
    return curated + advisories, stats, branch_list


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nvd-file")
    ap.add_argument("--changelog-dir")
    ap.add_argument("--out", default=DATA)
    ap.add_argument("--today")
    args = ap.parse_args()
    today = args.today or time.strftime("%Y-%m-%d")

    with open(DATA, encoding="utf-8") as f:
        existing = json.load(f)
    curated = [a for a in existing["advisories"]
               if not a["id"].startswith("CVE-")]
    curated_cves = {c for a in curated for c in a.get("cves", [])}

    vulns = fetch_nvd(args.nvd_file)
    cl_fixes, cl_dates = fetch_changelogs(args.changelog_dir)
    advisories, stats, branch_list = build(
        vulns, cl_fixes, cl_dates, curated, curated_cves, today)

    out = {"advisories": advisories,
           "source_notes": (
               "Curated advisories (e.g. php2shell) are maintained by "
               "hand. All per-CVE entries are generated by "
               "tools/build_core_db.py from the NIST NVD (CPE ranges "
               "for cpe:2.3:a:php:php) cross-checked against the "
               "php.net ChangeLogs' per-release fix lists; regenerate "
               "with tools/refresh_advisory_db.sh."),
           "updated": today}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, sort_keys=True, ensure_ascii=False)
        f.write("\n")
    per_branch = {}
    for a in advisories:
        for b in a.get("fixed_releases", {}):
            per_branch[b] = per_branch.get(b, 0) + 1
    print(json.dumps({"advisories": len(advisories),
                      "curated": len(curated), "stats": stats,
                      "branches": branch_list,
                      "fixed_per_branch": per_branch,
                      "out": args.out}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
