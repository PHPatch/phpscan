"""Dependency audit: `phpscan audit <composer.lock>`.

Judges every package pinned in a composer.lock against published
advisories from three sources, in priority order:

  1. OSV (api.osv.dev, ecosystem "Packagist") — live queries, one
     batch call for the whole lock; only package names and versions
     are sent, never the lock file itself.
  2. FriendsOfPHP/security-advisories — the canonical PHP advisory
     database, vendored as data/friendsofphp.json (refresh path:
     tools/refresh_advisories.py). Always consulted, so the audit
     still works --offline and still works when OSV is unreachable.
  3. CISA's Known Exploited Vulnerabilities catalog — a cross
     reference only: a finding whose CVE is in KEV is flagged
     `kev: true`. Vendored as data/kev.json.

Version matching uses Composer semantics (constraint operators,
wildcards, caret/tilde ranges, pre-release ordering) implemented
below. Honesty rules, matching the rest of phpscan:

  - a range this code cannot parse is reported under `unassessed`,
    never guessed at;
  - a lock version that is not a comparable release string (e.g.
    `dev-master`) is reported under `unassessed`, never judged;
  - "no findings" means "no advisory in these sources matches" —
    the verdict detail says so, it is not a safety guarantee.

Exit codes: 0 — no findings; 1 — at least one finding;
2 — usage error or an input that cannot be audited at all
(missing/unparseable lock file); 3 — the audit completed but
under degraded evidence (OSV could not be consulted and nothing
else matched), so a clean result must not be trusted as complete.
"""

import json
import os
import re
import urllib.request

from . import __version__

_DATA = os.path.join(os.path.dirname(__file__), "data")
_OSV_BATCH = "https://api.osv.dev/v1/querybatch"
_OSV_VULN = "https://api.osv.dev/v1/vulns/"
_UA = f"phpscan/{__version__} (+https://phpatch.com/security)"


# ----------------------------------------------------------------
# Composer version handling
# ----------------------------------------------------------------

_STABILITY = {"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2,
              "rc": 3, "stable": 4, "patch": 5, "pl": 5, "p": 5}
_VER_RE = re.compile(
    r"^v?(\d+|[x*])(?:\.(\d+|[x*]))?(?:\.(\d+|[x*]))?"
    r"(?:\.(\d+|[x*]))?"
    r"(?:[-.]?(patch|alpha|beta|dev|rc|pl|a|b|p)"
    r"(?:[-.]?(\d+))?)?$", re.I)


class _Version:
    __slots__ = ("key", "parts", "given", "wildcard")

    def __init__(self, key, parts, wildcard):
        self.key = key          # comparable tuple
        self.parts = parts      # numeric components before any wildcard
        self.given = len(parts)
        self.wildcard = wildcard


def parse_version(text):
    """Parse a Composer version string -> _Version | None.

    Handles release tags (v1.2.3, 1.2), pre-release suffixes
    (1.0.0-RC1, 1.0.0pl1) and branch forms (1.2.x-dev, normalized
    the way Composer normalizes them: the wildcard position is
    padded with 9999999 and stability is dev). Returns None for
    strings that are not comparable releases (`dev-master`,
    `master`, commit hashes, ...).
    """
    if text is None:
        return None
    s = str(text).strip().lower().split("+")[0]
    if not s or s.startswith("dev-") or s in ("master", "main"):
        return None
    m = _VER_RE.match(s)
    if not m:
        return None
    raw = [g for g in m.groups()[:4] if g is not None]
    stab_word = m.group(5)
    stab_num = int(m.group(6) or 0)
    rank = _STABILITY[stab_word.lower()] if stab_word else 4
    wildcard = any(p in ("x", "*") for p in raw)
    parts = []
    for p in raw:
        if p in ("x", "*"):
            break
        parts.append(int(p))
    if rank == 0 and (wildcard or len(raw) < 3):
        # Branch version (1.2.x-dev, 1.2-dev): Composer pads the
        # open positions. An explicit 2.0.0-dev tag is NOT padded —
        # it is the dev build of that exact release and sorts
        # just below it.
        nums = [9999999 if p in ("x", "*") else int(p) for p in raw]
        nums += [9999999] * (4 - len(nums))
    else:
        full = [0 if p in ("x", "*") else int(p) for p in raw]
        nums = full + [0] * (4 - len(full))
    return _Version((tuple(nums), rank, stab_num), parts, wildcard)


def _fmt_ver(nums):
    n = list(nums)
    while len(n) > 3 and n[-1] == 0:
        n.pop()
    while len(n) < 3:
        n.append(0)
    return ".".join(str(x) for x in n)


class UnparseableConstraint(Exception):
    pass


_CMP_RE = re.compile(r"^(>=|<=|!=|==|>|<|=|\^|~)?(.*)$")


def _bound(text):
    v = parse_version(text)
    if v is None:
        raise UnparseableConstraint(f"bad version {text!r}")
    return v


def _wildcard_hi(parts):
    """Exclusive upper bound for a partial/wildcard version:
    increment the last given numeric component, zero the rest."""
    nums = list(parts)
    nums[-1] += 1
    nums += [0] * (4 - len(nums))
    return (tuple(nums), 4, 0)


def _range_for_partial(v):
    """[lo, hi) for a bare partial or wildcard version (1.2, 1.2.*)."""
    lo = (tuple(v.parts + [0] * (4 - len(v.parts))), 4, 0)
    return lo, _wildcard_hi(v.parts)


def _caret_hi(v):
    nums = list(v.parts) + [0] * (4 - len(v.parts))
    for i, n in enumerate(nums):
        if n != 0:
            nums[i] = n + 1
            for j in range(i + 1, 4):
                nums[j] = 0
            return (tuple(nums), 4, 0)
    nums[max(v.given - 1, 0)] += 1  # ^0.0 -> <0.1 ; ^0 -> <1
    return (tuple(nums), 4, 0)


def _tilde_hi(v):
    nums = list(v.parts) + [0] * (4 - len(v.parts))
    idx = 1 if v.given >= 2 else 0  # ~1.2.3 -> <1.3 ; ~1.2 -> <1.3 ; ~1 -> <2
    nums[idx] += 1
    for j in range(idx + 1, 4):
        nums[j] = 0
    return (tuple(nums), 4, 0)


def _eval_primitive(token, vkey):
    m = _CMP_RE.match(token)
    op, rest = m.group(1) or "", m.group(2)
    if not rest:
        raise UnparseableConstraint(f"missing version in {token!r}")
    v = _bound(rest)
    has_wild = v.wildcard
    if has_wild and not v.parts:
        if op in ("", "=", "=="):
            return True  # "*" matches everything
        if op == "!=":
            return False
        raise UnparseableConstraint(f"bare wildcard with {op!r}")
    if op == "^":
        lo = (tuple(v.parts + [0] * (4 - len(v.parts))),
              v.key[1], v.key[2])
        return lo <= vkey < _caret_hi(v)
    if op == "~":
        lo = (tuple(v.parts + [0] * (4 - len(v.parts))),
              v.key[1], v.key[2])
        return lo <= vkey < _tilde_hi(v)
    if has_wild or (not op and v.given < 3):
        if op in ("", "="):
            lo, hi = _range_for_partial(v)
            return lo <= vkey < hi
        if op == "!=":
            lo, hi = _range_for_partial(v)
            return not (lo <= vkey < hi)
        # Comparator against a wildcard: wildcards read as 0.
        return _apply(op, vkey, v.key)
    if not op:
        return vkey == v.key
    if op == "!=" and v.given < 3:
        lo, hi = _range_for_partial(v)
        return not (lo <= vkey < hi)
    return _apply(op, vkey, v.key)


def _apply(op, vkey, bound):
    if op in ("=", "=="):
        return vkey == bound
    if op == "!=":
        return vkey != bound
    if op == ">":
        return vkey > bound
    if op == ">=":
        return vkey >= bound
    if op == "<":
        return vkey < bound
    if op == "<=":
        return vkey <= bound
    raise UnparseableConstraint(f"bad operator {op!r}")


_HYPHEN_RE = re.compile(r"(\S+)\s+-\s+(\S+)")


def _expand_hyphen(group):
    def rep(m):
        lo_s, hi_s = m.group(1), m.group(2)
        hi = _bound(hi_s)
        if hi.given >= 3:
            return f">={lo_s},<={hi_s}"
        nums = list(hi.parts)
        nums[-1] += 1
        hi_txt = _fmt_ver(nums + [0] * (4 - len(nums)))
        return f">={lo_s},<{hi_txt}"
    prev = None
    while prev != group:
        prev = group
        group = _HYPHEN_RE.sub(rep, group, count=1)
    return group


def constraint_matches(constraint, vkey):
    """True/False for one Composer constraint expression against a
    parsed version key. Raises UnparseableConstraint on anything
    outside the grammar (comparators, wildcards, ^, ~, hyphen
    ranges, ||-unions, comma/space conjunctions)."""
    if constraint is None or str(constraint).strip() == "":
        raise UnparseableConstraint("empty constraint")
    text = _expand_hyphen(str(constraint))
    for group in re.split(r"\|\|?", text):
        group = group.strip()
        if not group:
            continue
        tokens = [t for t in re.split(r"[\s,]+", group) if t]
        ops = (">=", "<=", "!=", "==", ">", "<", "=", "^", "~")
        merged = []
        for t in tokens:  # an operator may stand alone: ">= 1.2"
            if merged and merged[-1] in ops:
                merged[-1] += t
            else:
                merged.append(t)
        if all(_eval_primitive(t, vkey) for t in merged):
            return True
    return False


def versions_match(versions, vkey):
    """A FriendsOfPHP branch entry: a list of constraint strings
    that are ANDed together (','-joined forms included)."""
    return constraint_matches(",".join(str(v) for v in versions),
                              vkey)


def branch_in_scope(branch, version):
    """Whether a FriendsOfPHP branch entry applies to a version.

    A numeric branch key ("7.12", "6.x", "8.5.x") scopes its
    constraint list to that release line: an unbounded "<7.12.1"
    listed under branch "7.12" says nothing about 6.5.5, and
    matching it anyway would print a verdict the evidence does
    not support. Non-numeric keys ("master", "dev-master", ...)
    carry no line scoping — their constraint lists bound
    themselves (e.g. "'>=7', '<7.4.4'"). Keys in any other shape
    are likewise left to their constraints.
    """
    if branch is None:
        return True
    key = str(branch).strip().lower()
    if key.endswith("-dev"):
        key = key[:-4]
    if key.startswith("v"):
        key = key[1:]
    comps = key.split(".")
    nums = []
    for c in comps:
        if c in ("x", "*"):
            nums.append(None)
        elif c.isdigit():
            nums.append(int(c))
        else:
            return True  # not a line key: constraints decide
    vnums = version.key[0]
    return all(want is None or vnums[i] == want
               for i, want in enumerate(nums))


def _derive_fixed(versions):
    """Best fixed-version claim from a matched constraint list:
    the smallest strict `<X` bound, else None (never guessed)."""
    best = None
    for text in versions:
        for token in re.split(r"[\s,]+", str(text)):
            m = re.match(r"^<(\d+(?:\.\d+){0,3})$", token)
            if m:
                v = parse_version(m.group(1))
                if v and (best is None or v.key < best[0]):
                    best = (v.key, _fmt_ver(v.key[0]))
    return best[1] if best else None


# ----------------------------------------------------------------
# Vendored data
# ----------------------------------------------------------------

def load_friendsofphp(path=None):
    with open(path or os.path.join(_DATA, "friendsofphp.json"),
              encoding="utf-8") as f:
        return json.load(f)


def load_kev(path=None):
    with open(path or os.path.join(_DATA, "kev.json"),
              encoding="utf-8") as f:
        d = json.load(f)
    return d, set(d["cves"])


# ----------------------------------------------------------------
# OSV client (live mode only)
# ----------------------------------------------------------------

def _osv_request(url, payload=None, timeout=20):
    data = None
    headers = {"User-Agent": _UA}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def osv_querybatch(packages, timeout=20):
    """packages: list of (name, version-string). Returns the
    aligned results list from OSV querybatch.

    Versions are sent exactly as the lock spells them, including
    a leading "v" (v6.5.5): OSV's Packagist matching normalizes
    that itself — verified live 2026-10-30, when querybatch
    returned identical vuln sets for 6.5.5 / v6.5.5 and
    5.6.2 / v5.6.2. Do not "fix" this by stripping the v; the
    expert-review hypothesis (P7) did not hold."""
    queries = [{"package": {"name": n, "ecosystem": "Packagist"},
                "version": v} for n, v in packages]
    out = []
    for i in range(0, len(queries), 1000):
        resp = _osv_request(_OSV_BATCH,
                            {"queries": queries[i:i + 1000]}, timeout)
        out.extend(resp.get("results") or [])
    return out


def osv_get_vuln(vuln_id, timeout=20):
    return _osv_request(_OSV_VULN + vuln_id, timeout=timeout)


def _osv_fixed(vuln, name, installed_key):
    best = None
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if (pkg.get("name") or "").lower() != name:
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if "fixed" in ev:
                    v = parse_version(ev["fixed"])
                    if v and v.key > installed_key and (
                            best is None or v.key < best[0]):
                        best = (v.key, _fmt_ver(v.key[0]))
    return best[1] if best else None


def _osv_severity(vuln):
    sev = (vuln.get("database_specific") or {}).get("severity")
    if sev:
        return sev
    for s in vuln.get("severity") or []:
        if s.get("score"):
            return s["score"]
    return None


def _osv_link(vuln):
    for ref in vuln.get("references") or []:
        if ref.get("type") in ("ADVISORY", "WEB") and ref.get("url"):
            return ref["url"]
    return None


# ----------------------------------------------------------------
# Audit
# ----------------------------------------------------------------

def _remediation(pkg, primary_id, fixed):
    if fixed:
        return (f"Run `composer update {pkg}` to upgrade {pkg} to "
                f"{fixed} or later, which fixes {primary_id}.")
    return (f"No fixed release is published for {primary_id}. Run "
            f"`composer update {pkg}` to confirm the newest release "
            f"is installed, and consider replacing or removing "
            f"{pkg} until a fix is available.")


def _finding(pkg, version, dev, fid, cve, title, severity, fixed,
             link, sources, aliases=()):
    f = {"package": pkg, "version": version, "dev": dev, "id": fid,
         "cve": cve, "aliases": list(aliases), "title": title,
         "severity": severity, "kev": False, "fixed": fixed,
         "link": link, "sources": list(sources)}
    f["remediation"] = _remediation(pkg, fid, fixed)
    return f


def parse_lock(lock):
    """composer.lock dict -> list of {name, version, dev}."""
    out = []
    for key, dev in (("packages", False), ("packages-dev", True)):
        entries = lock.get(key) or []
        if not isinstance(entries, list):
            raise ValueError(f"composer.lock: {key} is not a list")
        for e in entries:
            if isinstance(e, dict) and e.get("name") \
                    and e.get("version"):
                out.append({"name": str(e["name"]).lower(),
                            "version": str(e["version"]), "dev": dev})
    return out


def run_audit(lock_path, offline=False, osv_batch=None, osv_vuln=None,
              fop=None, kev=None, fail_on=None, include_packages=False,
              ignore_unrated=False):
    """Audit the composer.lock at `lock_path`. Returns
    (report_dict, exit_code). The osv_*/fop/kev parameters are
    dependency-injection seams for tests."""
    with open(lock_path, encoding="utf-8") as fh:
        lock = json.load(fh)
    if not isinstance(lock, dict) or "packages" not in lock:
        raise ValueError("not a composer.lock (no 'packages' key)")
    return audit_lock(lock, lock_path, offline=offline,
                      osv_batch=osv_batch, osv_vuln=osv_vuln,
                      fop=fop, kev=kev, fail_on=fail_on,
                      include_packages=include_packages,
                      ignore_unrated=ignore_unrated)


def audit_lock(lock, target, offline=False, osv_batch=None,
               osv_vuln=None, fop=None, kev=None, fail_on=None,
               include_packages=False, ignore_unrated=False):
    """Audit an already-parsed composer.lock dict. `target` is
    the label recorded in the report (a file path for the local
    audit, the source URL for an exposed lockfile judged by the
    external scan). Returns (report_dict, exit_code)."""
    pkgs = parse_lock(lock)

    if fop is None:
        fop = load_friendsofphp()
    kev_meta, kev_set = (kev if kev is not None else load_kev())
    fop_pkgs = fop.get("packages") or {}

    findings = {}
    unassessed = []

    def add(f):
        key = (f["package"], f["cve"] or f["id"])
        old = findings.get(key)
        if old is None:
            findings[key] = f
            return
        for s in f["sources"]:
            if s not in old["sources"]:
                old["sources"].append(s)
        for a in f["aliases"]:
            if a not in old["aliases"] and a != old["id"]:
                old["aliases"].append(a)
        if old["severity"] is None:
            old["severity"] = f["severity"]
        if old["fixed"] is None:
            old["fixed"] = f["fixed"]
        if old["link"] is None:
            old["link"] = f["link"]
        old["remediation"] = _remediation(old["package"], old["id"],
                                          old["fixed"])

    parseable = []
    for p in pkgs:
        v = parse_version(p["version"])
        if v is None:
            unassessed.append({
                "package": p["name"], "version": p["version"],
                "dev": p["dev"], "advisory": None,
                "reason": "version string is not a release version "
                          "this tool can compare (branch/dev build); "
                          "no verdict is claimed for this package"})
            continue
        p["_v"] = v
        parseable.append(p)

        # --- FriendsOfPHP (vendored, canonical) ---
        for adv in fop_pkgs.get(p["name"]) or []:
            matched, bad, fixed = False, None, None
            for rng in adv.get("ranges") or []:
                if not branch_in_scope(rng.get("branch"), v):
                    continue
                try:
                    if versions_match(rng["versions"], v.key):
                        matched = True
                        fixed = _derive_fixed(rng["versions"])
                        break
                except UnparseableConstraint as e:
                    bad = (rng["versions"], e)
            if matched:
                add(_finding(p["name"], p["version"], p["dev"],
                             adv["id"], adv.get("cve"),
                             adv.get("title") or adv["id"], None,
                             fixed, adv.get("link"),
                             ["friendsofphp"]))
            elif bad is not None:
                unassessed.append({
                    "package": p["name"], "version": p["version"],
                    "dev": p["dev"], "advisory": adv["id"],
                    "reason": f"affected range {bad[0]!r} could not "
                              f"be parsed ({bad[1]}); no verdict is "
                              f"claimed for this advisory"})

    # --- OSV (live, priority source) ---
    osv_status = {"status": "offline"} if offline else \
        {"status": "live"}
    if not offline and parseable:
        batch = osv_batch or osv_querybatch
        getv = osv_vuln or osv_get_vuln
        try:
            results = batch([(p["name"], p["version"])
                             for p in parseable])
            details = {}
            for p, res in zip(parseable, results):
                for stub in (res or {}).get("vulns") or []:
                    vid = stub.get("id")
                    if not vid:
                        continue
                    if vid not in details:
                        details[vid] = getv(vid)
                    vuln = details[vid]
                    if vuln.get("withdrawn"):
                        continue
                    aliases = vuln.get("aliases") or []
                    cve = next((a for a in aliases
                                if a.startswith("CVE-")),
                               vid if vid.startswith("CVE-") else None)
                    title = vuln.get("summary") or \
                        (vuln.get("details") or "").split("\n")[0] or vid
                    add(_finding(p["name"], p["version"], p["dev"],
                                 vid, cve, title,
                                 _osv_severity(vuln),
                                 _osv_fixed(vuln, p["name"], p["_v"].key),
                                 _osv_link(vuln), ["osv"],
                                 aliases=aliases))
        except Exception as e:  # degraded, disclosed — never silent
            osv_status = {"status": "error",
                          "detail": f"OSV lookup failed ({e}); "
                                    f"results below rest on the "
                                    f"vendored FriendsOfPHP snapshot "
                                    f"only"}

    # --- CISA KEV cross-reference ---
    for f in findings.values():
        if f["cve"] and f["cve"] in kev_set:
            f["kev"] = True

    flist = sorted(findings.values(),
                   key=lambda f: (f["package"], f["id"]))
    # Severity is normalized to one vocabulary across sources
    # (critical/high/medium/low/unknown) so consumers can gate
    # on it: an OSV severity word, an OSV CVSS v3 vector banded
    # by score, KEV membership counting as high, and "unknown"
    # where no source publishes a level. The raw per-source
    # strings (None / "HIGH" / a CVSS vector) were unusable for
    # gating — see severity_level() for the mapping.
    for f in flist:
        f["severity"] = severity_level(f) or "unknown"
    degraded = osv_status.get("status") == "error"
    n_dev = sum(1 for p in pkgs if p["dev"])
    if flist:
        verdict = {"status": "vulnerable", "findings": len(flist),
                   "detail": f"{len(flist)} known advisor"
                             f"{'y' if len(flist) == 1 else 'ies'} "
                             f"affect {len({f['package'] for f in flist})} "
                             f"locked package(s)."}
        if degraded:
            verdict["detail"] += (
                " OSV could not be consulted, so further "
                "advisories may exist that this audit did not "
                "see; these findings rest on the vendored "
                "FriendsOfPHP snapshot and the CISA KEV catalog.")
    elif degraded:
        # Never a clean verdict on partial evidence: OSV failed
        # and only the vendored snapshot was actually consulted,
        # so the detail names that source alone, the verdict is
        # marked incomplete, and the exit code (3) lets a CI
        # gate fail closed instead of passing on a degraded run.
        verdict = {"status": "no_findings_degraded", "findings": 0,
                   "incomplete": True,
                   "detail": "No advisory in the vendored "
                             "FriendsOfPHP snapshot matches the "
                             "locked versions — but OSV could not "
                             "be consulted (its lookup failed), "
                             "so this audit is incomplete: it is "
                             "not a clean result and not a "
                             "general security guarantee."}
    else:
        verdict = {"status": "no_findings", "findings": 0,
                   "detail": "No advisory in OSV or the vendored "
                             "FriendsOfPHP snapshot matches the "
                             "locked versions. That covers only the "
                             "advisories in those sources — it is "
                             "not a general security guarantee."}
    if unassessed:
        verdict["detail"] += (f" {len(unassessed)} package/advisory "
                              f"pair(s) could not be assessed and "
                              f"are listed under 'unassessed' — no "
                              f"verdict is claimed for them.")
    report = {
        "schema_version": 1,
        "target": target,
        "mode": "audit",
        "packages_scanned": len(pkgs) - n_dev,
        "dev_packages_scanned": n_dev,
        "sources": {
            "osv": osv_status,
            "friendsofphp": {
                "snapshot_date": fop.get("snapshot_date"),
                "commit": fop.get("commit")},
            "kev": {"snapshot_date": kev_meta.get("snapshot_date"),
                    "catalog_version": kev_meta.get("catalog_version")},
        },
        "findings": flist,
        "unassessed": unassessed,
        "verdict": verdict,
    }
    if include_packages:
        # Opt-in only: a lock's full package list is the owner's
        # dependency inventory, so reports carry counts and
        # findings by default, never the whole list.
        report["packages"] = [
            {"name": p["name"], "version": p["version"],
             "dev": p["dev"]} for p in pkgs]
    if not flist:
        return report, 3 if degraded else 0
    if fail_on is not None:
        threshold = _LEVEL_RANK[fail_on]

        def _meets(f):
            if f["severity"] == "unknown":
                # Unrated fails CLOSED. A source that publishes
                # no severity — every FriendsOfPHP-only finding —
                # is not evidence of low severity, so an unrated
                # finding counts as meeting every threshold: a
                # gate set even at 'low' must not pass on a
                # known-vulnerable dependency just because its
                # advisory carries no CVSS. --ignore-unrated is
                # the explicit opt-out for the opposite policy.
                return not ignore_unrated
            return _LEVEL_RANK.get(f["severity"], -1) >= threshold

        if any(_meets(f) for f in flist):
            return report, 1
        return report, 3 if degraded else 0
    return report, 1


# ----------------------------------------------------------------
# Severity levels for consumers of the audit (the external scan
# escalates its verdict on high/critical dependency findings, so
# it needs a level per finding in its own vocabulary)
# ----------------------------------------------------------------

_SEV_WORDS = {"critical": "critical", "high": "high",
              "moderate": "medium", "medium": "medium",
              "low": "low"}

# Gate levels for --fail-on, lowest to highest.
_LEVEL_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
FAIL_ON_LEVELS = tuple(_LEVEL_RANK)


def _cvss3_base_score(vector):
    """Base score for a CVSS v3.x vector string, or None when the
    string is not a complete, parseable v3 vector. Implements the
    FIRST 3.1 equations, including the official roundup."""
    metrics = {}
    for part in str(vector).strip().split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k.strip().upper()] = v.strip().upper()
    if not metrics.get("CVSS", "").startswith("3"):
        return None
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
        ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        scope_changed = metrics["S"] == "C"
        if scope_changed:
            pr = {"N": 0.85, "L": 0.68, "H": 0.50}[metrics["PR"]]
        else:
            pr = {"N": 0.85, "L": 0.62, "H": 0.27}[metrics["PR"]]
        c = {"H": 0.56, "L": 0.22, "N": 0.0}[metrics["C"]]
        i = {"H": 0.56, "L": 0.22, "N": 0.0}[metrics["I"]]
        a = {"H": 0.56, "L": 0.22, "N": 0.0}[metrics["A"]]
    except KeyError:
        return None
    isc = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (isc - 0.029) - 3.25 * (isc - 0.02) ** 15
        impact = max(impact, 0.0)
    else:
        impact = 6.42 * isc
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        base = 0.0
    elif scope_changed:
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)

    def roundup(x):
        int_input = int(x * 100000)
        if int_input % 10000 == 0:
            return int_input / 100000.0
        return (int(int_input / 10000) + 1) / 10.0

    return roundup(base)


def severity_level(f):
    """The severity level ('critical' | 'high' | 'medium' |
    'low') the published evidence supports for one audit finding,
    or None when no source states one.

    Order: an OSV severity word; a CVSS v3.x vector, scored and
    banded (>=9 critical, >=7 high, >=4 medium, else low); the
    CISA KEV cross-reference — a KEV-listed CVE is confirmed
    exploited in the wild, which this tool treats as 'high' for
    escalation purposes. A FriendsOfPHP-only finding whose
    sources publish no severity keeps None: no level is invented,
    and None never escalates anything."""
    sev = f.get("severity")
    if isinstance(sev, str):
        word = sev.strip().lower()
        if word in _SEV_WORDS:
            return _SEV_WORDS[word]
        if word.startswith("cvss:3"):
            score = _cvss3_base_score(sev)
            if score is not None:
                if score >= 9:
                    return "critical"
                if score >= 7:
                    return "high"
                if score >= 4:
                    return "medium"
                return "low"
    if f.get("kev"):
        return "high"
    return None


USAGE = ("usage: phpscan audit <composer.lock|directory> [--offline]"
         " [--fail-on <level>] [--ignore-unrated] "
         "[--include-packages]"
         "\n\nAudit the packages pinned in a composer.lock against "
         "OSV,\nthe vendored FriendsOfPHP advisory snapshot, and the "
         "CISA KEV\ncatalog. Prints one JSON report. Finding "
         "severities are normalized\nto critical/high/medium/low/"
         "unknown. --fail-on <level> (one of\ncritical, high, "
         "medium, low) makes the exit code 1 only when a\nfinding "
         "reaches that level. A finding whose sources publish no\n"
         "severity ('unknown' — every FriendsOfPHP-only finding) "
         "counts\nas reaching EVERY level: unrated fails closed, "
         "because no\nseverity published is not evidence of low "
         "severity. Pass\n--ignore-unrated for the opposite policy "
         "(unrated findings\nnever trip the gate). --include-packages "
         "adds the lock's full\npackage list to the report (counts "
         "and findings only, by default).\nExit codes: 0 = no "
         "findings (or none at the --fail-on level),\n1 = findings, "
         "2 = usage/input error, 3 = audit degraded\n(OSV "
         "unreachable, nothing else matched — do not trust as "
         "clean).")


def audit_main(argv):
    offline = False
    fail_on = None
    include_packages = False
    ignore_unrated = False
    positional = []
    argv = list(argv)
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--offline":
            offline = True
        elif a == "--include-packages":
            include_packages = True
        elif a == "--ignore-unrated":
            ignore_unrated = True
        elif a == "--fail-on" or a.startswith("--fail-on="):
            if a == "--fail-on":
                i += 1
                if i >= len(argv):
                    print(USAGE)
                    return 2
                fail_on = argv[i]
            else:
                fail_on = a.split("=", 1)[1]
            if fail_on not in _LEVEL_RANK:
                print(USAGE)
                return 2
        elif a.startswith("--"):
            print(USAGE)
            return 2
        else:
            positional.append(a)
        i += 1
    if len(positional) != 1:
        print(USAGE)
        return 2
    target = positional[0]
    if os.path.isdir(target):
        target = os.path.join(target, "composer.lock")
    if not os.path.isfile(target):
        print(json.dumps({"target": target, "mode": "audit",
                          "error": "composer.lock not found"}))
        return 2
    try:
        report, code = run_audit(target, offline=offline,
                                 fail_on=fail_on,
                                 include_packages=include_packages,
                                 ignore_unrated=ignore_unrated)
    except (OSError, ValueError) as e:
        print(json.dumps({"target": target, "mode": "audit",
                          "error": f"cannot audit this file: {e}"}))
        return 2
    print(json.dumps(report, indent=1))
    return code
