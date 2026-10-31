"""Version parsing and vulnerability verdicts.

A PHP build is judged against every advisory in data/cves.json. For each
advisory, supported branches have a fixed-release floor; anything older
is vulnerable, and any branch below the advisory's EOL line has no fix at
all (branch upgrade or offline are the only remedies).

The database holds one entry per PHP core CVE (plus hand-curated
bundles such as php2shell), so a version is normally judged against
hundreds of advisories at once: the verdict aggregates every match —
the headline is the most severe, the floor it names is the highest
fixed release for the branch (a branch's security releases are
cumulative, so that one upgrade addresses every fixable match), and
`findings` lists them all.
"""

import functools
import json
import os
import re

_DATA = os.path.join(os.path.dirname(__file__), "data", "cves.json")
_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


@functools.lru_cache(maxsize=1)
def _load_cached():
    with open(_DATA, encoding="utf-8") as f:
        return json.load(f)["advisories"]


def load_advisories():
    return _load_cached()


def _score(adv):
    return (adv.get("cvss_v4") or adv.get("cvss_v3")
            or adv.get("cvss_v2"))


def parse_version(text):
    """Extract the first x.y[.z] version from arbitrary text -> tuple|None."""
    if not text:
        return None
    m = _VERSION_RE.search(str(text))
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def fmt(version):
    return ".".join(str(p) for p in version)


def branch_of(version):
    return f"{version[0]}.{version[1]}"


_DISTRO_RE = re.compile(r"(ubuntu|~deb\d|\+deb\d|-deb\d|\.deb\d|debian)",
                        re.I)


_PRE_RE = re.compile(
    r"\d+\.\d+(?:\.\d+)?[-.]?(rc|alpha|beta|dev)\d*\b", re.I)


def is_prerelease(text):
    """True when a raw version string names a pre-release build
    (8.3.0RC1, 8.4.0-beta2, 8.5.0-dev): the version number is
    immediately followed by an RC/alpha/beta/dev marker. A
    pre-release predates the stable release of its own version,
    so it must never be judged AS that stable release. Distro
    suffixes (-1ubuntu2, ~deb12u1) do not match."""
    return bool(text and _PRE_RE.search(str(text)))


def distro_build(text):
    """True when a raw version string looks like a distribution
    package build (Ubuntu/Debian-style suffix). Distros backport
    security fixes without moving the upstream version, so a
    below-floor distro build is a 'check' signal, not proof."""
    return bool(text and _DISTRO_RE.search(str(text)))


def verdict_for(version, distro=False, advisories=None,
                prerelease=False):
    """Return a verdict dict for one PHP version tuple.

    status: 'patched' | 'vulnerable' | 'possibly_vulnerable' |
            'eol' | 'not_assessed' | 'unknown'
      patched    — at or above every advisory floor for its branch
      vulnerable — a patched release exists for its branch; it is below it
      possibly_vulnerable — same, but the build looks like a distro
                   package (backports may already carry the fix)
      eol        — branch is below an advisory's EOL line: no fix exists
      not_assessed — branch is newer than the advisory database
      unknown    — version could not be determined

    With more than one matching advisory, the verdict also carries
    `findings`: every match, worst first, each with its own floor
    (or None where the branch has no fix for that advisory).
    """
    if version is None:
        return {"status": "unknown", "version": None, "branch": None,
                "detail": "PHP version could not be determined."}
    if advisories is None:
        advisories = load_advisories()
    branch = branch_of(version)

    # Curated advisories (no no_fix_branches field) keep the original
    # blunt EOL semantics: a branch below their EOL line has no fix.
    for adv in advisories:
        if "no_fix_branches" in adv:
            continue
        eol_below = parse_version(adv["eol_below"])
        if (version[0], version[1]) < (eol_below[0], eol_below[1]):
            # The upgrade target is derived from the advisory's
            # own EOL line (the oldest branch that still receives
            # fixes), never a hard-coded branch number that goes
            # stale as branches age out.
            target = f"{eol_below[0]}.{eol_below[1]}"
            detail = (f"Branch {branch} is end-of-life for "
                      f"{adv['id']} ({adv.get('title')}): no "
                      "patched release exists for this branch, "
                      "and configuration changes can at best "
                      "mitigate the exposure. The only complete "
                      "remedies are a branch upgrade or taking "
                      "the site offline.")
            if distro:
                detail += (" This build looks like a distribution "
                           "package: the distro may still backport "
                           "fixes for this branch, so confirm via "
                           "the distro security tracker or the "
                           "on-server deep check.")
            return {"status": "eol", "version": fmt(version),
                    "branch": branch, "advisory": adv["id"],
                    "cves": adv["cves"], "detail": detail,
                    "remediation": (f"Upgrade to a supported PHP "
                                    f"branch ({target} or later) "
                                    "and apply its patched "
                                    "release, or take the site "
                                    "offline.")}

    problems, unpatched, assessed = [], [], False
    for adv in advisories:
        floor_txt = adv["fixed_releases"].get(branch)
        if floor_txt is not None:
            assessed = True
            floor = parse_version(floor_txt)
            # A pre-release OF the floor version (8.3.14RC1 vs a
            # floor of 8.3.14) predates the patched stable
            # release, so equality is not enough for it.
            if version < floor or (prerelease and version == floor):
                problems.append({"advisory": adv["id"],
                                 "title": adv.get("title"),
                                 "cves": adv["cves"],
                                 "cvss": _score(adv),
                                 "floor": floor_txt,
                                 "published": adv.get("published", "")})
        if branch in adv.get("no_fix_branches", []):
            assessed = True
            unpatched.append({"advisory": adv["id"],
                              "title": adv.get("title"),
                              "cves": adv["cves"],
                              "cvss": _score(adv),
                              "floor": None, "no_fix": True,
                              "published": adv.get("published", ""),
                              "fixed_elsewhere":
                                  bool(adv["fixed_releases"])})
    problems.sort(key=lambda p: (p["cvss"] or 0, p["published"]),
                  reverse=True)
    unpatched.sort(key=lambda p: (p["cvss"] or 0, p["published"]),
                   reverse=True)

    if problems:
        p = problems[0]
        eff_floor = max(problems,
                        key=lambda q: parse_version(q["floor"]))["floor"]
        detail = (f"PHP {fmt(version)} is below the patched "
                  f"release {eff_floor} for branch {branch} "
                  f"({', '.join(p['cves'])}).")
        if len(problems) > 1:
            detail += (f" {len(problems)} advisories in the database "
                       f"affect this version; upgrading to {eff_floor} "
                       "addresses every one that has a fix.")
        if unpatched:
            detail += (f" Note: {len(unpatched)} further "
                       f"advisor{'y' if len(unpatched) == 1 else 'ies'} "
                       f"affecting branch {branch} "
                       f"{'has' if len(unpatched) == 1 else 'have'} no "
                       "patched release for this branch at all.")
        if prerelease:
            detail += (" The disclosed build is a pre-release, "
                       "which predates the stable release of its "
                       "own version number, so it is judged "
                       "against the stable floors.")
        if distro:
            detail += (" This build looks like a distribution "
                       "package: distros backport security fixes "
                       "without changing the upstream version, so "
                       "treat this as a check signal, not proof — "
                       "confirm via the distro security tracker or "
                       "the on-server deep check.")
        remediation = (f"Upgrade PHP {branch} to {eff_floor} or later.")
        if distro:
            remediation += (" Confirm via the distro security tracker "
                            "that a backported fix is installed — a "
                            "distribution package may already be patched.")
        head = next(a for a in advisories if a["id"] == p["advisory"])
        return {"status": "possibly_vulnerable" if distro
                else "vulnerable",
                "version": fmt(version),
                "branch": branch, "advisory": p["advisory"],
                "cves": p["cves"],
                "cvss_v4": head.get("cvss_v4"),
                "cvss_v3": head.get("cvss_v3"),
                "floor": eff_floor, "detail": detail,
                "remediation": remediation,
                "findings": problems + unpatched}
    if unpatched:
        p = unpatched[0]
        findings = unpatched
        if p["fixed_elsewhere"]:
            detail = (f"Branch {branch} receives no fix for "
                      f"{p['advisory']} ({p['title']}): the patched "
                      "releases exist only on newer branches, so this "
                      "branch is end-of-life for this advisory.")
            if distro:
                detail += (" This build looks like a distribution "
                           "package: the distro may still backport "
                           "fixes for this branch, so confirm via "
                           "the distro security tracker or the "
                           "on-server deep check.")
            return {"status": "eol", "version": fmt(version),
                    "branch": branch, "advisory": p["advisory"],
                    "cves": p["cves"], "detail": detail,
                    "remediation": ("Upgrade to a supported PHP branch "
                                    "and apply its patched release, or "
                                    "take the site offline."),
                    "findings": findings}
        detail = (f"PHP {fmt(version)} is affected by {p['advisory']} "
                  f"({p['title']}), for which no patched release "
                  "exists on any branch yet.")
        if distro:
            detail += (" This build looks like a distribution "
                       "package: distros backport security fixes "
                       "without changing the upstream version, so "
                       "treat this as a check signal, not proof — "
                       "confirm via the distro security tracker or "
                       "the on-server deep check.")
        return {"status": "possibly_vulnerable" if distro
                else "vulnerable",
                "version": fmt(version),
                "branch": branch, "advisory": p["advisory"],
                "cves": p["cves"], "cvss_v4": None, "cvss_v3": None,
                "floor": None, "detail": detail,
                "remediation": ("No patched release exists yet. "
                                "Restrict access to the site and watch "
                                "for the next PHP security release on "
                                f"branch {branch}."),
                "findings": findings}
    if not assessed:
        return {"status": "not_assessed", "version": fmt(version),
                "branch": branch,
                "detail": f"PHP {fmt(version)} is on branch {branch}, "
                          "which is newer than this scanner's "
                          "advisory database, so its patch status "
                          "was not assessed. Update the advisory "
                          "data and scan again."}
    detail = (f"PHP {fmt(version)} is at or above every patched "
              "release floor for its branch. 'Patched' covers "
              "only the advisories in this database — it is "
              "not a general security guarantee.")
    if prerelease:
        detail += (" The disclosed build is a pre-release of its "
                   "version; it clears the floors for its branch, "
                   "but a pre-release is not a stable release and "
                   "should not be run in production.")
    return {"status": "patched", "version": fmt(version),
            "branch": branch, "detail": detail}


def fixed_tag_for(version, variant, advisories=None):
    """Official docker php image tag for the patched release of a branch.

    e.g. version (8,3,35), variant 'apache' -> 'php:8.3.36-apache'
    Returns None when no advisory floor applies.
    """
    v = verdict_for(version, advisories=advisories)
    if v["status"] in ("vulnerable", "possibly_vulnerable"):
        return f"php:{v['floor']}-{variant}"
    if v["status"] == "patched":
        return f"php:{fmt(version)}-{variant}"
    return None
