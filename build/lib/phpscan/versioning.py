"""Version parsing and vulnerability verdicts.

A PHP build is judged against every advisory in data/cves.json. For each
advisory, supported branches have a fixed-release floor; anything older
is vulnerable, and any branch below the advisory's EOL line has no fix at
all (branch upgrade or offline are the only remedies).
"""

import json
import os
import re

_DATA = os.path.join(os.path.dirname(__file__), "data", "cves.json")
_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def load_advisories():
    with open(_DATA, encoding="utf-8") as f:
        return json.load(f)["advisories"]


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


def distro_build(text):
    """True when a raw version string looks like a distribution
    package build (Ubuntu/Debian-style suffix). Distros backport
    security fixes without moving the upstream version, so a
    below-floor distro build is a 'check' signal, not proof."""
    return bool(text and _DISTRO_RE.search(str(text)))


def verdict_for(version, distro=False):
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
    """
    if version is None:
        return {"status": "unknown", "version": None, "branch": None,
                "detail": "PHP version could not be determined."}
    branch = branch_of(version)
    problems = []
    assessed = False
    for adv in load_advisories():
        eol_below = parse_version(adv["eol_below"])
        if (version[0], version[1]) < (eol_below[0], eol_below[1]):
            detail = (f"Branch {branch} is end-of-life for "
                      f"{adv['id']}: no patched release exists. "
                      "The php2shell vector can be only partially "
                      "mitigated at best by configuration "
                      "(session.upload_progress.enabled = Off); the "
                      "only complete remedies are a branch upgrade "
                      "or taking the site offline.")
            if distro:
                detail += (" This build looks like a distribution "
                           "package: the distro may still backport "
                           "fixes for this branch, so confirm via "
                           "the distro security tracker or the "
                           "on-server deep check.")
            return {"status": "eol", "version": fmt(version),
                    "branch": branch, "advisory": adv["id"],
                    "cves": adv["cves"], "detail": detail}
        floor_txt = adv["fixed_releases"].get(branch)
        if floor_txt is None:
            continue  # branch newer than the advisory knows
        assessed = True
        floor = parse_version(floor_txt)
        if version < floor:
            problems.append({"advisory": adv["id"], "cves": adv["cves"],
                             "cvss_v4": adv.get("cvss_v4"),
                             "floor": floor_txt})
    if problems:
        p = problems[0]
        detail = (f"PHP {fmt(version)} is below the patched "
                  f"release {p['floor']} for branch {branch} "
                  f"({', '.join(p['cves'])}).")
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
                "cves": p["cves"], "cvss_v4": p.get("cvss_v4"),
                "floor": p["floor"], "detail": detail}
    if not assessed:
        return {"status": "not_assessed", "version": fmt(version),
                "branch": branch,
                "detail": f"PHP {fmt(version)} is on branch {branch}, "
                          "which is newer than this scanner's "
                          "advisory database, so its patch status "
                          "was not assessed. Update the advisory "
                          "data and scan again."}
    return {"status": "patched", "version": fmt(version), "branch": branch,
            "detail": f"PHP {fmt(version)} is at or above every patched "
                      "release floor for its branch. 'Patched' covers "
                      "only the advisories in this database — it is "
                      "not a general security guarantee."}


def fixed_tag_for(version, variant):
    """Official docker php image tag for the patched release of a branch.

    e.g. version (8,3,35), variant 'apache' -> 'php:8.3.36-apache'
    Returns None when no advisory floor applies.
    """
    v = verdict_for(version)
    if v["status"] in ("vulnerable", "possibly_vulnerable"):
        return f"php:{v['floor']}-{variant}"
    if v["status"] == "patched":
        return f"php:{fmt(version)}-{variant}"
    return None
