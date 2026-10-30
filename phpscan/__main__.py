"""CLI: python3 -m phpscan <url> [more urls...]

Prints one JSON verdict object per URL.

Also: python3 -m phpscan hunt <webroot> [--include-vendor] —
read-only local compromise check (see phpscan/hunt.py); its
exit codes are 0 clean, 1 findings, 2 usage error.

Also: python3 -m phpscan audit <composer.lock|dir> [--offline] —
dependency audit of a composer.lock against OSV, the vendored
FriendsOfPHP advisories and the CISA KEV catalog (see
phpscan/audit.py); exit codes are 0 no findings, 1 findings,
2 usage/input error.

Exit codes: 0 — scanned, no actionable finding; 1 — at least one
target is vulnerable, possibly vulnerable, or on an end-of-life
branch; 2 — usage error, or a target could not be judged at all:
unreachable, or `not_assessed` (its PHP branch is newer than the
advisory database, so the scanner cannot judge it). When several
targets are scanned, the worst code wins.
"""

import json
import sys

from .scan import scan

_ACTIONABLE = ("vulnerable", "possibly_vulnerable", "eol")
_UNJUDGED = ("not_assessed", "unreachable")


def main(argv):
    argv = [a for a in argv if a != ""]
    if not argv:
        print(__doc__)
        return 2
    if any(a in ("-h", "--help") for a in argv):
        print(__doc__)
        return 0
    if argv[0] == "hunt":
        from .hunt import hunt_main
        return hunt_main(argv[1:])
    if argv[0] == "audit":
        from .audit import audit_main
        return audit_main(argv[1:])
    worst = 0
    for url in argv:
        try:
            r = scan(url)
            print(json.dumps(r, indent=1))
            status = (r.get("verdict") or {}).get("status")
            if r.get("compromise_indicators"):
                worst = max(worst, 1)
            if status in _ACTIONABLE:
                worst = max(worst, 1)
            elif status in _UNJUDGED:
                worst = max(worst, 2)
        except Exception as e:  # one bad target must not kill the run
            print(json.dumps({"url": url, "error": str(e)}))
            worst = max(worst, 2)
    return worst


def cli():
    """Console-script entry point (the `phpscan` command)."""
    return main(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
