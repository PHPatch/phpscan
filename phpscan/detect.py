"""CMS / plugin detection for the external scan.

Everything here is passive fingerprinting or read-only checks of
well-known public files — the same evidence a browser or a search
engine can see. NO exploit probes, ever: versions are reported
only when the site itself discloses them (generator tags, asset
query strings, readme files, REST indexes). When a site hides a
version, the finding says exactly that — "detected, version
hidden" — and no version is ever guessed.

WordPress plugin/theme versions are matched against
data/wp_plugins.json, a starter dataset of the highest-impact
known vulnerabilities (built from NVD CPE ranges, KEV-flagged;
see tools/refresh_wp_plugins.py). Absence of a match is not a
clean bill of health — the dataset is deliberately narrow.
"""

import json
import os
import re

_DATA = os.path.join(os.path.dirname(__file__), "data",
                     "wp_plugins.json")
_PLUGIN_DB = None

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2,
                 "low": 3, "info": 4}


def _h(headers, name):
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return v
    return ""


# ----------------------------------------------------------------
# Dotted version handling (plugin versions are not strict semver:
# "6.3.0.1" is real, so compare arbitrary-length int tuples).
# ----------------------------------------------------------------

def parse_dotted(text):
    """Leading dotted-numeric version in `text` -> int tuple|None."""
    if text is None:
        return None
    m = re.match(r"\s*(\d+(?:\.\d+)*)", str(text))
    if not m:
        return None
    return tuple(int(p) for p in m.group(1).split("."))


def fmt_dotted(version):
    return ".".join(str(p) for p in version)


def _cmp(a, b):
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


_OPS = {">=": lambda c: c >= 0, ">": lambda c: c > 0,
        "<=": lambda c: c <= 0, "<": lambda c: c < 0,
        "==": lambda c: c == 0}


def _satisfies(version, clause):
    for part in clause.split(","):
        m = re.match(r"\s*(>=|<=|==|>|<)\s*(\S+)\s*$", part)
        if not m:
            return False
        rhs = parse_dotted(m.group(2))
        if rhs is None or not _OPS[m.group(1)](_cmp(version, rhs)):
            return False
    return True


def match_clause(version, clauses):
    """First clause ({"range", "fixed"}) the version falls in."""
    for clause in clauses or []:
        if _satisfies(version, clause.get("range", "")):
            return clause
    return None


# ----------------------------------------------------------------
# Plugin vulnerability dataset
# ----------------------------------------------------------------

def load_plugin_db():
    global _PLUGIN_DB
    if _PLUGIN_DB is None:
        try:
            with open(_DATA, encoding="utf-8") as f:
                _PLUGIN_DB = json.load(f).get("plugins", {})
        except Exception:
            _PLUGIN_DB = {}
    return _PLUGIN_DB


def _finding(kind, severity, title, detail, remediation, **extra):
    f = {"kind": kind, "severity": severity, "title": title,
         "detail": detail, "remediation": remediation}
    f.update(extra)
    return f


# ----------------------------------------------------------------
# Homepage fingerprinting (no extra requests)
# ----------------------------------------------------------------

_GEN_RES = (
    re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+'
               r'content=["\']([^"\']+)', re.I),
    re.compile(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+'
               r'name=["\']generator', re.I),
)
_ASSET_RE = re.compile(r'wp-content/(plugins|themes)/'
                       r'([A-Za-z0-9_\-]+)/([^"\'\s<>]+)')
_CORE_ASSET_RE = re.compile(r'wp-includes/[^"\'\s<>]*?'
                            r'[?&]ver=([0-9][0-9A-Za-z.\-]*)')
_NS_MAP = {"wc": "woocommerce", "wc-admin": "woocommerce",
           "elementor": "elementor", "yoast": "wordpress-seo",
           "jetpack": "jetpack"}


def _generators(body):
    out = []
    for rx in _GEN_RES:
        out += rx.findall(body or "")
    return out


def detect_from_homepage(headers, body):
    """Return (cms_hits, plugin_hits) from the homepage alone.

    cms_hits: {name: {"version": str|None, "version_source": str}}
    plugin_hits: {slug: {"kind", "version", "version_source"}}
    """
    body = body or ""
    low = body.lower()
    cms, plugins = {}, {}

    def cms_hit(name, version=None, source=None):
        cur = cms.setdefault(name, {"version": None,
                                    "version_source": None})
        if version and not cur["version"]:
            cur["version"] = version
            cur["version_source"] = source

    def plugin_hit(slug, kind, version=None, source=None):
        cur = plugins.setdefault(slug, {"kind": kind,
                                        "version": None,
                                        "version_source": None})
        if version and not cur["version"]:
            cur["version"] = version
            cur["version_source"] = source

    gens = _generators(body)
    gen_text = " | ".join(gens)
    xgen = _h(headers, "X-Generator")
    if xgen:
        gens.append(xgen)
        gen_text += " | " + xgen

    # --- WordPress ---
    if ("wp-content" in low or "wp-includes" in low
            or "wordpress" in gen_text.lower()
            or "api.w.org" in _h(headers, "Link")):
        cms_hit("WordPress")
        m = re.search(r'WordPress\s+([0-9]+(?:\.[0-9]+){0,2})',
                      gen_text)
        if m:
            cms_hit("WordPress", m.group(1), "generator tag")
        m = _CORE_ASSET_RE.search(body)
        if m:
            cms_hit("WordPress", m.group(1), "wp-includes asset")
        m = re.search(r'WooCommerce\s+([0-9]+(?:\.[0-9]+){0,2})',
                      gen_text)
        if m:
            plugin_hit("woocommerce", "plugin", m.group(1),
                       "generator tag")

    # --- Plugin / theme assets (passive, from page source) ---
    for kind, slug, rest in _ASSET_RE.findall(body):
        vm = re.search(r'[?&]ver=([0-9][0-9A-Za-z.\-]*)', rest)
        plugin_hit(slug, "theme" if kind == "themes" else "plugin",
                   vm.group(1) if vm else None,
                   "asset URL" if vm else None)

    # --- Drupal ---
    if ("drupal" in gen_text.lower() or "/core/modules/" in low
            or "drupalsettings" in low or "/core/misc/" in low):
        cms_hit("Drupal")
        m = re.search(r'Drupal\s+([0-9]+(?:\.[0-9]+){0,2})',
                      gen_text)
        if m:
            cms_hit("Drupal", m.group(1), "generator tag")

    # --- Joomla ---
    if ("joomla" in gen_text.lower() or "/media/jui/" in low
            or "/media/system/" in low):
        cms_hit("Joomla")
        m = re.search(r'Joomla!?\s+([0-9]+(?:\.[0-9]+){0,2})',
                      gen_text)
        if m:
            cms_hit("Joomla", m.group(1), "generator tag")

    # --- Magento ---
    magento_hdr = any(k.lower().startswith("x-magento")
                      for k in (headers or {}))
    if (magento_hdr or re.search(r'/static/version\d+/', body)
            or "magento" in low and "/static/" in low):
        cms_hit("Magento")

    # --- Laravel (framework; version is never disclosed) ---
    cookies = _h(headers, "Set-Cookie")
    if "laravel_session" in cookies or "XSRF-TOKEN" in cookies:
        cms_hit("Laravel")

    return cms, plugins


# ----------------------------------------------------------------
# Read-only probes that recover versions the homepage hides in
# plain sight (REST index, readme files, manifests). Each is a
# plain GET of a file the platform ships for public consumption.
# ----------------------------------------------------------------

def _ok(resp):
    return resp and resp.get("status") == 200 and resp.get("body")


def probe_versions(fetch, origin, cms, plugins):
    """Fill in versions via public files. Mutates cms/plugins."""
    if not fetch or not origin:
        return
    if "WordPress" in cms:
        r = fetch(origin + "/wp-json/")
        if _ok(r):
            try:
                idx = json.loads(r["body"])
                namespaces = idx.get("namespaces", [])
            except Exception:
                namespaces = []
            for ns in namespaces:
                slug = _NS_MAP.get(str(ns).split("/")[0])
                if slug:
                    cur = plugins.setdefault(
                        slug, {"kind": "plugin", "version": None,
                               "version_source": None})
                    cur.setdefault("via", "wp-json namespace")
        # readme.txt stable tags for plugins seen without a
        # version (dataset entries first — they matter most),
        # and style.css Version headers for themes.
        db = load_plugin_db()
        todo = [s for s, p in plugins.items()
                if p["kind"] == "plugin" and not p["version"]]
        todo.sort(key=lambda s: s not in db)
        for slug in todo[:5]:
            r = fetch(f"{origin}/wp-content/plugins/{slug}/"
                      "readme.txt")
            if _ok(r):
                m = re.search(r'(?im)^Stable tag:\s*'
                              r'([0-9][0-9A-Za-z.\-]*)', r["body"])
                if m:
                    plugins[slug]["version"] = m.group(1)
                    plugins[slug]["version_source"] = \
                        "plugin readme.txt"
        themes = [s for s, p in plugins.items()
                  if p["kind"] == "theme" and not p["version"]]
        for slug in themes[:2]:
            r = fetch(f"{origin}/wp-content/themes/{slug}/"
                      "style.css")
            if _ok(r):
                m = re.search(r'(?im)^\s*Version:\s*'
                              r'([0-9][0-9A-Za-z.\-]*)', r["body"])
                if m:
                    plugins[slug]["version"] = m.group(1)
                    plugins[slug]["version_source"] = \
                        "theme style.css"
    if "Drupal" in cms and not cms["Drupal"]["version"]:
        for path in ("/core/CHANGELOG.txt", "/CHANGELOG.txt"):
            r = fetch(origin + path)
            if _ok(r):
                m = re.search(r'Drupal\s+([0-9]+\.[0-9]+'
                              r'(?:\.[0-9]+)?)', r["body"][:4000])
                if m:
                    cms["Drupal"]["version"] = m.group(1)
                    cms["Drupal"]["version_source"] = \
                        "CHANGELOG.txt"
                    break
    if "Joomla" in cms and not cms["Joomla"]["version"]:
        r = fetch(origin + "/administrator/manifests/files/"
                           "joomla.xml")
        if _ok(r):
            m = re.search(r'<version>([0-9]+(?:\.[0-9]+){0,2})'
                          r'</version>', r["body"])
            if m:
                cms["Joomla"]["version"] = m.group(1)
                cms["Joomla"]["version_source"] = "joomla.xml"


# ----------------------------------------------------------------
# Findings
# ----------------------------------------------------------------

# CMS branches that receive no security fixes at all. WordPress is
# absent on purpose: the WordPress project backports security
# fixes to old branches, so "old WordPress" is not "end-of-life
# WordPress". (name -> {major: (eol_date, upgrade_target)})
_EOL = {
    "Drupal": {7: ("2025-01-05", "Drupal 10 or 11"),
               8: ("2021-11-17", "Drupal 10 or 11"),
               9: ("2023-11-01", "Drupal 10 or 11")},
    "Joomla": {3: ("2023-08-17", "Joomla 5")},
}


def plugin_findings(plugins):
    """Match detected plugin/theme versions against the dataset."""
    db = load_plugin_db()
    out = []
    for slug, hit in plugins.items():
        entry = db.get(slug)
        if not entry:
            continue
        name = entry.get("name", slug)
        version = hit.get("version")
        if not version:
            kev = [v["cve"] for v in entry["vulnerabilities"]
                   if v.get("kev")]
            if kev:
                out.append(_finding(
                    "plugin_version_hidden", "info",
                    f"{name} is installed; its version is hidden",
                    f"{name} has known exploited vulnerabilities "
                    f"({', '.join(kev)}), but the site does not "
                    "disclose the installed version, so exposure "
                    "cannot be confirmed from outside.",
                    f"Confirm the installed {name} version on the "
                    "server and update it to the latest release.",
                    slug=slug))
            continue
        vt = parse_dotted(version)
        if vt is None:
            continue
        for vuln in entry["vulnerabilities"]:
            clause = match_clause(vt, vuln.get("clauses"))
            if not clause:
                continue
            cvss = vuln.get("cvss")
            if vuln.get("kev"):
                sev = "critical"
            elif cvss and cvss >= 9:
                sev = "critical"
            elif cvss and cvss >= 7:
                sev = "high"
            elif cvss and cvss >= 4:
                sev = "medium"
            else:
                sev = "low"
            fixed = clause.get("fixed")
            if fixed:
                remediation = (f"Update {name} to {fixed} or "
                               f"later (fixes {vuln['cve']}).")
            else:
                remediation = (f"Update {name} to the latest "
                               f"release (fixes {vuln['cve']}).")
            hit.setdefault("vulnerabilities", []).append(
                vuln["cve"])
            out.append(_finding(
                "plugin_vulnerable", sev,
                f"Vulnerable {entry.get('kind', 'plugin')}: "
                f"{name} {version}",
                f"{name} {version} falls in the affected range "
                f"of {vuln['cve']}"
                + (" — a vulnerability known to be exploited in "
                   "the wild (CISA KEV)." if vuln.get("kev") else
                   ".")
                + (f" {vuln.get('title', '')}".rstrip()
                   if vuln.get("title") else ""),
                remediation, slug=slug, cve=vuln["cve"],
                kev=bool(vuln.get("kev")), cvss=cvss))
    return out


def cms_findings(cms):
    out = []
    for name, hit in cms.items():
        version = hit.get("version")
        if not version:
            continue
        vt = parse_dotted(version)
        eol = _EOL.get(name, {})
        if vt and vt[0] in eol:
            date, target = eol[vt[0]]
            out.append(_finding(
                "cms_eol", "high",
                f"{name} {version} is end-of-life",
                f"{name} {vt[0]}.x stopped receiving security "
                f"fixes on {date}; every vulnerability found "
                "since then is permanently unpatched on this "
                "branch.",
                f"Migrate the site to {target}.",
                cms=name))
        out.append(_finding(
            "version_disclosure", "low",
            f"{name} version {version} is publicly disclosed",
            f"The site discloses its exact {name} version "
            f"({hit.get('version_source') or 'public signals'}), "
            "which lets attackers fingerprint it against known "
            "vulnerabilities.",
            f"Suppress the {name} version in generator tags, "
            "readme files and manifests, and keep the CMS "
            "updated regardless.",
            cms=name))
    return out


def analyze(headers, body, fetch=None, origin=None, pre_cms=()):
    """Full detection pass. Returns (cms_info, plugins, findings).

    `fetch` is the scanner's guarded fetcher (url -> result dict);
    `origin` is the final URL's scheme://netloc. `pre_cms` carries
    names the caller already detected (e.g. phpBB) so they are
    represented in cms_info too."""
    cms, plugins = detect_from_homepage(headers, body)
    probe_versions(fetch, origin, cms, plugins)
    for name in pre_cms:
        cms.setdefault(name, {"version": None,
                              "version_source": None})
    cms_info = [{"name": n, "version": h["version"],
                 "version_source": h["version_source"]}
                for n, h in cms.items()]
    plugin_list = []
    for slug, hit in plugins.items():
        entry = load_plugin_db().get(slug, {})
        plugin_list.append({
            "slug": slug,
            "name": entry.get("name", slug),
            "kind": hit["kind"],
            "version": hit["version"],
            "version_source": hit["version_source"],
            "vulnerabilities": hit.get("vulnerabilities", []),
        })
    findings = plugin_findings(plugins) + cms_findings(cms)
    findings.sort(key=lambda f: SEVERITY_RANK[f["severity"]])
    return cms_info, plugin_list, findings


def apply_findings(verdict, findings):
    """Escalate the verdict for a confirmed critical/high
    finding (a known vulnerable plugin version, an exposed
    secret file, an end-of-life CMS): a non-actionable PHP
    verdict becomes 'vulnerable' — the condition is confirmed,
    not guessed — and the escalated verdict carries the
    findings plus the top finding's remediation. When nothing
    escalates, the verdict passes through verbatim: findings
    live in the scan result's own 'findings' list, and other
    verdicts' shape/text is not ours to change."""
    if not verdict or not findings:
        return verdict
    if verdict.get("status") in (None, "unreachable"):
        return verdict
    top = findings[0]
    actionable = ("vulnerable", "possibly_vulnerable", "eol")
    if top["severity"] in ("critical", "high") \
            and verdict["status"] not in actionable:
        verdict = dict(verdict)
        verdict["findings"] = findings
        orig = verdict.get("detail", "")
        verdict["status"] = "vulnerable"
        verdict["detail"] = (f"{top['title']}: {top['detail']}"
                             + (f" {orig}" if orig else ""))
        if not verdict.get("remediation"):
            verdict["remediation"] = top["remediation"]
    return verdict
