#!/usr/bin/env python3
"""Build phpscan/data/wp_plugins.json — the starter dataset of
high-impact WordPress plugin/theme vulnerabilities.

Sources (all public, fetched at build time):
  * NVD API 2.0 — affected-version ranges (CPE match criteria,
    with the record's own English description as a second range
    source) and CVSS scores for each curated CVE.
  * CVE.org registry — the CNA's structured affected ranges,
    a third range source for CVEs whose NVD record is missing
    configurations or points at an unrelated product (both
    occur; one seed CVE turned out to belong to an entirely
    different product in every registry).
  * CISA KEV catalog — flags CVEs known to be exploited in the wild
    (falls back to the phpatch threat swarm's kev_ids.json copy).

The curated slug/CVE list below is the editorial part: the plugins
and themes that CISA KEV and mass-exploitation reporting name again
and again. Every entry is verified at build time against all
three sources — a CVE that no source ties to this plugin with a
version range is dropped and reported, never silently kept. Each
stored clause records its source in "via".

Usage: python3 tools/refresh_wp_plugins.py [--sleep 6.5]
Re-run to refresh. Output: phpscan/data/wp_plugins.json
"""

import json
import os
import re
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "phpscan", "data", "wp_plugins.json")
KEV_FEED = ("https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json")
KEV_FALLBACK = os.path.expanduser(
    "~/workspace/phpatch-swarm/shared/kev_ids.json")
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"

# slug, kind, display name, [candidate CVEs], optional [aliases]
# — candidates are verified against NVD/CVE.org data at build
# time; aliases name the product's CPE forms when they differ
# from the slug (renamed plugins).
CURATED = [
    ("elementor", "plugin", "Elementor Website Builder",
     ["CVE-2022-29455", "CVE-2023-48700", "CVE-2023-48777"]),
    # CVE-2023-48777 is widely reported as an Elementor Pro
    # issue, but both registries (NVD + the CNA's CVE.org
    # record) name the product "Elementor Website Builder"
    # with range 3.3.0-3.18.1 — it is carried under the name
    # the registries give it, not the press name. CVE-2023-48700
    # stays a candidate to document its rejection: in every
    # registry it belongs to an unrelated product (Nautobot).
    ("essential-addons-for-elementor-lite", "plugin",
     "Essential Addons for Elementor", ["CVE-2023-32243"]),
    ("royal-elementor-addons", "plugin", "Royal Elementor Addons",
     ["CVE-2023-5360"]),
    ("wp-file-manager", "plugin", "File Manager",
     ["CVE-2020-25213"], ["file_manager"]),
    ("filester", "plugin", "Filester File Manager",
     ["CVE-2021-24925"]),
    ("duplicator", "plugin", "Duplicator", ["CVE-2020-11738"]),
    ("social-warfare", "plugin", "Social Warfare",
     ["CVE-2019-9978"]),
    ("litespeed-cache", "plugin", "LiteSpeed Cache",
     ["CVE-2024-28000"]),
    ("really-simple-ssl", "plugin", "Really Simple Security",
     ["CVE-2024-10924"], ["really_simple_security"]),
    ("give", "plugin", "GiveWP", ["CVE-2024-5932"]),
    ("bricks", "theme", "Bricks Builder", ["CVE-2024-25600"]),
    ("woocommerce-payments", "plugin", "WooCommerce Payments",
     ["CVE-2023-28121"]),
    ("woocommerce", "plugin", "WooCommerce", ["CVE-2021-32790"]),
    ("contact-form-7", "plugin", "Contact Form 7",
     ["CVE-2020-35489"]),
    ("updraftplus", "plugin", "UpdraftPlus", ["CVE-2022-0633"]),
    ("wpdiscuz", "plugin", "wpDiscuz", ["CVE-2020-24186"]),
    ("ultimate-member", "plugin", "Ultimate Member",
     ["CVE-2020-36170", "CVE-2023-3460"]),
    ("profile-builder", "plugin", "Profile Builder",
     ["CVE-2020-36171"]),
    ("advanced-custom-fields", "plugin", "Advanced Custom Fields",
     ["CVE-2023-3077"]),
    ("wp-fastest-cache", "plugin", "WP Fastest Cache",
     ["CVE-2023-6063"]),
    ("canto", "plugin", "Canto", ["CVE-2023-3452"]),
    ("LayerSlider", "plugin", "LayerSlider", ["CVE-2024-2879"]),
    ("easy-wp-smtp", "plugin", "Easy WP SMTP", ["CVE-2019-14949"]),
    ("wp-reset", "plugin", "WP Reset", ["CVE-2020-7048"]),
    ("metform", "plugin", "MetForm", ["CVE-2023-0084"]),
    ("mainwp-child", "plugin", "MainWP Child", ["CVE-2022-0594"]),
    ("ninja-forms", "plugin", "Ninja Forms", ["CVE-2021-24146"]),
    ("learnpress", "plugin", "LearnPress", ["CVE-2020-6010"]),
    ("download-manager", "plugin", "Download Manager",
     ["CVE-2021-25069"]),
    ("photo-gallery", "plugin", "Photo Gallery by 10Web",
     ["CVE-2022-0218"]),
    ("newsletter", "plugin", "Newsletter", ["CVE-2020-35932"]),
    ("quiz-and-survey-master", "plugin", "Quiz and Survey Master",
     ["CVE-2020-35951"]),
    ("modern-events-calendar-lite", "plugin",
     "Modern Events Calendar Lite", ["CVE-2021-24946"]),
    ("revslider", "plugin", "Slider Revolution",
     ["CVE-2014-9734"]),
]


def fetch_json(url, timeout=40):
    req = urllib.request.Request(
        url, headers={"User-Agent": "phpscan-dataset-builder"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def kev_set():
    try:
        d = fetch_json(KEV_FEED)
        return {v["cveID"] for v in d["vulnerabilities"]}, "CISA KEV feed"
    except Exception as e:
        print(f"KEV feed failed ({e}); using swarm fallback",
              file=sys.stderr)
        with open(KEV_FALLBACK, encoding="utf-8") as f:
            return set(json.load(f)), "swarm kev_ids.json fallback"


def cvss_of(cve):
    m = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if m.get(key):
            d = m[key][0]["cvssData"]
            return d.get("baseScore"), d.get("baseSeverity")
    return None, None


def _slug_tokens(text):
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if t}


def _squash(text):
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _product_matches(product, slug, aliases=()):
    """True when a CPE/CNA product name IS this plugin: squashed
    equality, a declared alias (for renamed plugins — Really
    Simple SSL is really_simple_security in CPE data; WP File
    Manager is file_manager), or a prefix relation on the
    squashed forms (give ~ givewp, metform ~
    metform_elementor_contact_form_builder).

    Deliberately strict — an earlier token-overlap version
    attributed the WP Database Backup CVE to Easy WP SMTP (the
    shared token was "wp") and a WP Database Reset CVE to WP
    Reset. A missed entry is recoverable on the next refresh; a
    wrong attribution makes the scanner lie."""
    p, s = _squash(product), _squash(slug)
    if not p or not s:
        return False
    if p == s or any(p == _squash(a) for a in aliases):
        return True
    if len(s) >= 4 and p.startswith(s):
        return True
    if len(p) >= 4 and s.startswith(p):
        return True
    return False


def clauses_of(cve, slug, aliases=()):
    """Extract (clauses, cpe_products) from NVD configurations.

    A clause is {"range": ">=6.0,<6.9", "fixed": "6.9"|None} built
    from one vulnerable CPE match whose product IS this plugin
    (see _product_matches)."""
    clauses, products = [], set()
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                crit = match["criteria"]
                parts = crit.split(":")
                if len(parts) < 6 or parts[2] != "a":
                    continue
                vendor, product, pinned = parts[3], parts[4], parts[5]
                if not _product_matches(product, slug, aliases):
                    continue
                products.add(f"{vendor}:{product}")
                lo, hi = [], []
                if match.get("versionStartIncluding"):
                    lo.append(">=" + match["versionStartIncluding"])
                if match.get("versionStartExcluding"):
                    lo.append(">" + match["versionStartExcluding"])
                fixed = None
                if match.get("versionEndExcluding"):
                    hi.append("<" + match["versionEndExcluding"])
                    fixed = match["versionEndExcluding"]
                if match.get("versionEndIncluding"):
                    hi.append("<=" + match["versionEndIncluding"])
                rng = ",".join(lo + hi)
                if not rng and pinned not in ("*", "-"):
                    rng = "==" + pinned
                if rng:
                    clauses.append({"range": rng, "fixed": fixed,
                                    "via": "nvd-cpe"})
    # de-dupe identical clauses
    seen, out = set(), []
    for c in clauses:
        if c["range"] not in seen:
            seen.add(c["range"])
            out.append(c)
    return out, products


_V = r"(\d+(?:\.\d+){0,3})"
_DESC_PATTERNS = [
    (re.compile(r"\bversions?\s+" + _V + r"\s+(?:to|through)\s+"
                + _V, re.I),
     lambda m: (f">={m.group(1)},<={m.group(2)}", None)),
    (re.compile(r"\bfrom\s+" + _V + r"\s+(?:to|through)\s+"
                + _V, re.I),
     lambda m: (f">={m.group(1)},<={m.group(2)}", None)),
    (re.compile(r"\bup to,? and including,?\s+" + _V, re.I),
     lambda m: (f"<={m.group(1)}", None)),
    (re.compile(r"\b" + _V + r"\s+and earlier\b", re.I),
     lambda m: (f"<={m.group(1)}", None)),
    (re.compile(r"\b(?:before|prior to)\s+" + _V, re.I),
     lambda m: (f"<{m.group(1)}", m.group(1))),
]


def desc_clauses(cve, slug, name, aliases=()):
    """Fallback for CVEs whose NVD record has no usable CPE data
    (missing configurations, or a CPE association pointing at an
    unrelated product — both occur in the wild). The English
    description must name the plugin (display name, a declared
    alias, or the squashed slug inside the squashed text), and
    its affected-range phrasing must match one of the standard
    patterns. Clauses carry via="nvd-description" so the
    provenance is auditable."""
    desc = ""
    for dd in cve.get("descriptions", []):
        if dd.get("lang") == "en":
            desc = dd["value"]
            break
    low = desc.lower()
    named = name.lower() in low or \
        any(a.lower() in low for a in aliases) or \
        _squash(slug) in _squash(desc)
    if not named:
        return []
    for pat, build in _DESC_PATTERNS:
        m = pat.search(desc)
        if m:
            rng, fixed = build(m)
            return [{"range": rng, "fixed": fixed,
                     "via": "nvd-description"}]
    return []


CVEORG = "https://cveawg.mitre.org/api/cve/{}"


def cveorg_clauses(cve_id, slug, name, aliases=()):
    """Third source: the CVE registry's own record (the CNA —
    usually Wordfence for WordPress plugins — publishes
    structured affected ranges there). Returns (clauses, title).
    The affected product/vendor or the title must name this
    plugin, same evidence rule as the other sources."""
    try:
        d = fetch_json(CVEORG.format(cve_id))
    except Exception:
        return [], None
    cna = d.get("containers", {}).get("cna", {})
    title = cna.get("title")
    clauses = []
    for aff in cna.get("affected", []):
        product = aff.get("product", "")
        vendor = aff.get("vendor", "")
        if not (_product_matches(product, slug, aliases) or
                _product_matches(vendor, slug, aliases) or
                (title and name.lower() in title.lower())):
            continue
        for v in aff.get("versions", []):
            if v.get("status") not in ("affected", None):
                continue
            fixed = None
            for ch in v.get("changes", []):
                if ch.get("status") == "unaffected":
                    fixed = ch.get("at")
                    break
            rng = None
            ver = (v.get("version") or "").strip()
            if v.get("lessThan"):
                rng, fixed = "<" + v["lessThan"], v["lessThan"]
            elif v.get("lessThanOrEqual"):
                rng = "<=" + v["lessThanOrEqual"]
            elif re.fullmatch(r"[<>]=?\s*\d+(?:\.\d+){0,3}"
                              r"(?:\s*,\s*[<>]=?\s*\d+(?:\.\d+)"
                              r"{0,3})?", ver):
                rng = re.sub(r"\s+", "", ver)
                m = re.search(r"<(\d+(?:\.\d+){0,3})", rng)
                if m:
                    fixed = m.group(1)
            if rng:
                clauses.append({"range": rng, "fixed": fixed,
                                "via": "cve.org"})
    return clauses, title


def main():
    sleep_s = 6.5
    if "--sleep" in sys.argv:
        sleep_s = float(sys.argv[sys.argv.index("--sleep") + 1])
    kev, kev_src = kev_set()
    plugins, dropped = {}, []
    for entry in CURATED:
        slug, kind, name, cves = entry[:4]
        aliases = entry[4] if len(entry) > 4 else []
        vulns = []
        for cve_id in cves:
            try:
                d = fetch_json(NVD.format(cve_id))
            except Exception as e:
                dropped.append((slug, cve_id, f"fetch failed: {e}"))
                continue
            time.sleep(sleep_s)  # NVD unauthenticated rate limit
            vs = d.get("vulnerabilities", [])
            if not vs:
                dropped.append((slug, cve_id, "no NVD record"))
                continue
            cve = vs[0]["cve"]
            clauses, products = clauses_of(cve, slug, aliases)
            org_title = None
            if not clauses:
                # CPE ranges are authoritative when present. The
                # looser description / CNA ranges only fill gaps:
                # stacked on top of CPE bounds, their boundary
                # disagreements (e.g. an unbounded "<=X" next to
                # a ">=A,<B") would widen the range beyond what
                # any single source claims.
                clauses = desc_clauses(cve, slug, name, aliases)
                org_clauses, org_title = cveorg_clauses(
                    cve_id, slug, name, aliases)
                clauses += org_clauses
                if any(">" in c["range"] for c in clauses):
                    # A bounded clause corroborates where the
                    # affected line starts; unbounded clauses
                    # would widen it below that on one source's
                    # say-so — drop them.
                    clauses = [c for c in clauses
                               if ">" in c["range"]]
            seen, uniq = set(), []
            for c in clauses:
                if c["range"] not in seen:
                    seen.add(c["range"])
                    uniq.append(c)
            clauses = uniq
            if not clauses:
                dropped.append((slug, cve_id,
                                "no verified range (NVD CPE, "
                                "NVD description, or CVE.org)"))
                continue
            score, sev = cvss_of(cve)
            desc = ""
            for dd in cve.get("descriptions", []):
                if dd.get("lang") == "en":
                    desc = dd["value"].split(". ")[0].strip()
                    break
            low = desc.lower()
            if org_title and name.lower() not in low and \
                    not any(a.lower() in low for a in aliases) and \
                    _squash(slug) not in _squash(desc):
                desc = org_title  # NVD text names another
                # product; the CNA title names this one
            vulns.append({
                "cve": cve_id, "title": desc[:220],
                "cvss": score, "severity": sev,
                "kev": cve_id in kev,
                "clauses": clauses,
                "cpe": sorted(products),
            })
            print(f"OK   {slug:42s} {cve_id}  "
                  f"{[c['range'] for c in clauses]}  "
                  f"kev={cve_id in kev} cvss={score}")
        if vulns:
            plugins[slug] = {"name": name, "kind": kind,
                             "vulnerabilities": vulns}
        else:
            print(f"DROP {slug}: no verified vulnerabilities")
    out = {
        "_meta": {
            "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                       time.gmtime()),
            "sources": [
                "NVD API 2.0 (CPE ranges, description ranges, "
                "CVSS, per CVE)",
                "CVE.org registry (CNA structured affected "
                "ranges, per CVE)",
                f"CISA KEV catalog via {kev_src} (kev flags)"],
            "refresh": "Re-run tools/refresh_wp_plugins.py "
                       "(curated slug/CVE list lives there; every "
                       "entry is re-verified against all three "
                       "sources at build time).",
            "scope": "Starter set: the WordPress plugins/themes "
                     "most named by CISA KEV and mass-exploitation "
                     "reporting. Absence of an entry is NOT a "
                     "clean bill of health for a plugin.",
        },
        "plugins": plugins,
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
    nv = sum(len(p["vulnerabilities"]) for p in plugins.values())
    print(f"\nwrote {OUT}: {len(plugins)} plugins, {nv} vulns")
    for slug, cve_id, why in dropped:
        print(f"dropped: {slug} {cve_id} — {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
