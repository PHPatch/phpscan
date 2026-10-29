"""CLI: python3 -m phpscan <url> [more urls...]

Prints one JSON verdict object per URL.

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
    if not argv:
        print(__doc__)
        return 2
    worst = 0
    for url in argv:
        try:
            r = scan(url)
            print(json.dumps(r, indent=1))
            status = (r.get("verdict") or {}).get("status")
            if status in _ACTIONABLE:
                worst = max(worst, 1)
            elif status in _UNJUDGED:
                worst = max(worst, 2)
        except Exception as e:  # one bad target must not kill the run
            print(json.dumps({"url": url, "error": str(e)}))
            worst = max(worst, 2)
    return worst


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
