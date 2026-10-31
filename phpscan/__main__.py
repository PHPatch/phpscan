"""CLI: python3 -m phpscan [--offline] [--format json|text] <url> [more urls...]

Prints one verdict object per URL (JSON by default; --format
text prints the human-readable rendering). --offline keeps every
lookup local: in particular, an exposed composer.lock found by
the scan is audited against the vendored advisory snapshots
only, with no live OSV queries. `phpscan --version` prints the
version and exits 0.

Also: python3 -m phpscan hunt <webroot> [--include-vendor] —
read-only local compromise check (see phpscan/hunt.py); its
exit codes are 0 clean, 1 findings, 2 usage error, 3 clean but
incomplete (coverage was reduced — walk cap, hard cap, or
vendor packages scanned with high-severity rules only).

Also: python3 -m phpscan audit <composer.lock|dir> [--offline]
[--fail-on <level>] [--ignore-unrated] — dependency audit of a
composer.lock against OSV, the vendored FriendsOfPHP advisories
and the CISA KEV catalog (see phpscan/audit.py); exit codes are
0 no findings, 1 findings, 2 usage/input error, 3 audit
degraded (OSV unreachable and nothing else matched). Under
--fail-on, a finding with no published severity ('unknown')
counts as reaching every level — unrated fails closed — unless
--ignore-unrated is given.

Scan exit codes: 0 — scanned, no actionable finding, full
coverage; 1 — at least one target is vulnerable, possibly
vulnerable, or on an end-of-life branch, or carries a high-
severity compromise indicator; 3 — the scan was degraded
(the shared deadline starved probes, so part of the target was
never checked); 2 — usage error, or a target could not be
judged at all: unreachable, or `not_assessed` (its PHP branch
is newer than the advisory database, so the scanner cannot
judge it). When several targets are scanned, the codes combine
by PRECEDENCE, not by number: findings (1) outrank degraded
(3), which outranks cannot-judge (2), which outranks clean (0).
"""

import json
import sys

from . import __version__
from .scan import render_text, scan

_ACTIONABLE = ("vulnerable", "possibly_vulnerable", "eol")
_UNJUDGED = ("not_assessed", "unreachable")
# Exit-code precedence across targets: findings outrank
# degraded outrank cannot-judge outrank clean. Numeric max()
# cannot express this — it would rank degraded (3) above a
# real finding (1) — so per-target codes are merged through
# this rank table instead.
_PRECEDENCE = {1: 3, 3: 2, 2: 1, 0: 0}


def main(argv):
    argv = [a for a in argv if a != ""]
    if not argv:
        print(__doc__)
        return 2
    if any(a in ("-h", "--help") for a in argv):
        print(__doc__)
        return 0
    if "--version" in argv:
        # A flag, not a target: it must never fall through to
        # the scanner as a URL.
        print(f"phpscan {__version__}")
        return 0
    if argv[0] == "hunt":
        from .hunt import hunt_main
        return hunt_main(argv[1:])
    if argv[0] == "audit":
        from .audit import audit_main
        return audit_main(argv[1:])
    offline = "--offline" in argv
    if offline:
        argv = [a for a in argv if a != "--offline"]
    fmt = "json"
    kept = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--format" or a.startswith("--format="):
            if a == "--format":
                i += 1
                if i >= len(argv):
                    print(__doc__)
                    return 2
                fmt = argv[i]
            else:
                fmt = a.split("=", 1)[1]
        else:
            kept.append(a)
        i += 1
    argv = kept
    if fmt not in ("json", "text"):
        print(__doc__)
        return 2
    if not argv:
        print(__doc__)
        return 2
    def _merge(code, new):
        return new if _PRECEDENCE[new] > _PRECEDENCE[code] else code

    worst = 0
    for url in argv:
        try:
            # The plain one-argument call is the historical
            # shape; the offline keyword is passed only when the
            # flag was actually given.
            r = scan(url, offline=True) if offline else scan(url)
            if fmt == "text":
                print(render_text(r))
            else:
                print(json.dumps(r, indent=1))
            status = (r.get("verdict") or {}).get("status")
            candidates = {0}
            indicators = r.get("compromise_indicators") or []
            if any(i.get("severity") in ("critical", "high")
                   for i in indicators):
                # High-severity indicators make the run a
                # findings run. A low-severity "review
                # manually" note alone does not move the exit
                # code: the verdict text carries it.
                candidates.add(1)
            if status in _ACTIONABLE:
                candidates.add(1)
            elif status in _UNJUDGED:
                candidates.add(2)
            skipped = (r.get("coverage") or {}).get(
                "probes_skipped_deadline") or 0
            if skipped:
                # The shared deadline starved probes: this
                # target was judged under degraded evidence
                # (exit 3), never presented as a full clean.
                candidates.add(3)
            code = max(candidates, key=_PRECEDENCE.__getitem__)
            worst = _merge(worst, code)
        except Exception as e:  # one bad target must not kill the run
            print(json.dumps({"url": url, "error": str(e)}))
            worst = _merge(worst, 2)
    return worst


def cli():
    """Console-script entry point (the `phpscan` command)."""
    return main(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
