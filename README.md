# phpscan — free open-source PHP vulnerability scanner

**Is your PHP version vulnerable to php2shell?** phpscan is a
free, disclosure-only scanner that answers that question for any
public website. It checks the PHP version a site discloses against
the fixed releases for **php2shell — CVE-2026-109618 /
CVE-2026-109619** (CVSS v4 9.2, unauthenticated remote code
execution in PHP core) — and, more generally, against the branch
floors in its advisory database.

It is the open-source scanner behind [phpatch.com](https://phpatch.com).

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Dependencies: zero](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](#what-it-does)
[![Tests](https://github.com/PHPatch/phpscan/actions/workflows/tests.yml/badge.svg)](https://github.com/PHPatch/phpscan/actions/workflows/tests.yml)

## What it does

- **Disclosure-only.** It reads what a site already discloses
  publicly — `X-Powered-By` / `Server` headers, `PHPSESSID` cookies,
  generator tags — plus a limited check for a publicly exposed
  phpinfo page at a few well-known paths. It never sends an exploit
  probe, a crafted payload, or anything designed to trigger the bug.
- **Honest verdicts.** If a site hides its version, the scanner
  says so (VERSION HIDDEN) instead of guessing. If a build looks
  like a distribution package, a below-floor version is reported
  as a check signal (POSSIBLY VULNERABLE), because distros backport
  fixes without changing the version string.
- **Public targets only.** The fetcher refuses loopback, private
  and link-local addresses (including cloud metadata endpoints),
  non-HTTP(S) schemes and ports other than 80/443, pins the
  validated IP, and re-validates every redirect — it is designed
  so it cannot be pointed at internal services. The refusals are
  exercised by the test suite in `tests/` on every push.
- **Zero dependencies.** Python 3.11+ standard library only.
- **CMS, plugin and config-hygiene checks.** The same scan also
  fingerprints the CMS (WordPress, Drupal, Joomla, Magento,
  Laravel), matches publicly disclosed plugin/theme versions
  against known-vulnerable ranges, and reports configuration
  exposures (`.git`, `.env`, directory listings, missing security
  headers) — every finding with a remediation. See below.
- **Exposed `composer.lock` audit.** If the site serves its
  `composer.lock` publicly, the scan reads it (bounded,
  defensively parsed) and runs the same dependency audit as
  `phpscan audit` against the locked versions — OSV,
  FriendsOfPHP and CISA KEV, vendored-only with `--offline` —
  merging the findings into the scan's verdict under
  `dependencies`, each stamped with the lockfile's URL as
  provenance. The exposure itself is reported as a finding.
  High/critical dependency findings escalate the verdict just
  like other critical findings. When no lock is served, the
  scan also tries `vendor/composer/installed.json` (Composer's
  own installed manifest). A lockfile too large for the
  bounded read is reported as "exposed; too large to audit
  fully" rather than silently skipped, and the report carries
  a scope note: versions in an exposed file may differ from
  what is actually deployed.

## Verdicts

Every scan returns one JSON object per URL. The `verdict.status`
field uses the vocabulary below (shown here in its display form).
Actionable verdicts (`vulnerable`, `possibly_vulnerable`, `eol`)
also carry a `remediation` field naming the upgrade that fixes
them; patched verdicts carry none.

| Verdict | JSON `status` | Meaning |
|---|---|---|
| **VULNERABLE** | `vulnerable` | The disclosed version is below the fixed release for its branch, and a patched release exists. |
| **POSSIBLY VULNERABLE** | `possibly_vulnerable` | Below the floor, but the build looks like a distribution package — distros backport fixes, so this is a check signal, not proof. |
| **PATCHED** | `patched` | The disclosed version is at or above every advisory floor for its branch. (Not a general security guarantee — only "not below the fixed releases in the database.") |
| **END OF LIFE** | `eol` | The branch is below the advisory's EOL line (< 8.2 for php2shell): no patched release exists. The only complete remedies are a branch upgrade or taking the site offline. |
| **VERSION HIDDEN** | `indeterminate` | PHP is present but the version is not disclosed, so patch status cannot be confirmed from outside. Most well-run sites land here. |
| **NOT ASSESSED** | `not_assessed` | The branch is newer than the advisory database, so the scanner cannot judge it. |

Two more statuses cover the scan itself: `no_php_detected` (no PHP
signals found) and `unreachable` (the site did not answer, or the
target was refused by the safety policy).

## Sample session

Recorded against a local test fixture that discloses
`X-Powered-By: PHP/8.3.20` — the output format is exactly what the
tool prints:

```console
$ python3 -m phpscan http://fixture.example
{
 "target": "http://fixture.example",
 "reachable": true,
 "http_status": 200,
 "final_url": "http://fixture.example",
 "error": null,
 "signals": {
  "x_powered_by": "PHP/8.3.20",
  "server": "Apache/2.4.62"
 },
 "php_version": "8.3.20",
 "version_source": "X-Powered-By",
 "cms": [],
 "phpinfo_exposed": false,
 "verdict": {
  "status": "vulnerable",
  "version": "8.3.20",
  "branch": "8.3",
  "advisory": "php2shell-2026-10",
  "cves": [
   "CVE-2026-109618",
   "CVE-2026-109619"
  ],
  "cvss_v4": 9.2,
  "floor": "8.3.36",
  "detail": "PHP 8.3.20 is below the patched release 8.3.36 for branch 8.3 (CVE-2026-109618, CVE-2026-109619)."
 }
}
$ echo $?
1
```

Exit code 1 = an actionable finding. A site that runs PHP but
hides its version returns the VERSION HIDDEN verdict instead
(verdict block shown; the rest of the object lists the signals it
did see):

```json
"verdict": {
 "status": "indeterminate",
 "detail": "PHP is present (fingerprinted) but the version is not disclosed, so the patch status cannot be confirmed from outside. Run the deep check (SSH, read-only) for a definitive verdict."
}
```

## Branch floors (php2shell)

A branch is PATCHED at or above its fixed release; anything below
it is VULNERABLE (or POSSIBLY VULNERABLE for distro builds):

| PHP branch | Fixed in |
|---|---|
| 8.2 | **8.2.35** |
| 8.3 | **8.3.36** |
| 8.4 | **8.4.27** |
| 8.5 | **8.5.12** |
| < 8.2 | No fix — **END OF LIFE** (branch upgrade or offline) |

The floors live in `phpscan/data/cves.json`, reviewed against
the php.net release announcements on every PHP security release
(see [Advisory data](#advisory-data)).

## Install

One line, from PyPI (Python 3.11+, standard library only — zero dependencies):

```bash
pip install phpscan
phpscan https://your-site.com
```

On systems that refuse with "externally-managed-environment" (Debian/Ubuntu
and Homebrew Pythons), use pipx or Docker instead — both are below.

For a CLI tool, pipx is the recommended route — it keeps phpscan's
dependencies isolated from your system Python:

```bash
python3 -m pip install --user pipx   # if you don't have pipx yet
pipx install phpscan
```

Docker:

```bash
docker run ghcr.io/phpatch/phpscan https://your-site.com
```

Also available as a GitHub Action (`PHPatch/phpscan-action@v1`), directly
from GitHub (`pip install git+https://github.com/PHPatch/phpscan.git`), or by
cloning this repo.

## Run it

From the clone, run it right there — no install step:

```bash
python3 -m phpscan https://your-site.com
```

Prefer a zip? Download `phpscan.zip` from phpatch.com, then
either install it and run from anywhere:

```bash
python3 -m pip install phpscan.zip
python3 -m phpscan https://your-site.com
```

or unzip and run in place:

```bash
unzip phpscan.zip
cd phpscan
python3 -m phpscan https://your-site.com
```

Output is one JSON object per URL: the verdict, the disclosed PHP
version and where it was disclosed, and CMS fingerprints —
including a `coverage` block reporting how many probes were
attempted, completed or skipped for the deadline, whether the
site is a catch-all host, and per-source audit status.
`--format text` prints a human-readable rendering instead.

Exit codes (for scripts and CI): **0** — scanned, no actionable
finding; **1** — at least one target is `vulnerable`,
`possibly_vulnerable`, or on an end-of-life branch; **2** — usage
error, or a target could not be judged at all: unreachable, or
`not_assessed` (its PHP branch is newer than the advisory
database, so the scanner cannot judge it). With several targets,
the worst code wins.

### Audit a composer.lock

Your PHP version is only half the surface — the other half is
what Composer installed. `phpscan audit` checks a project's
`composer.lock` against published advisories:

```bash
python3 -m phpscan audit path/to/composer.lock
python3 -m phpscan audit path/to/project/        # dir with a lock
python3 -m phpscan audit composer.lock --offline # vendored data only
python3 -m phpscan audit composer.lock --fail-on high  # exit 1 only at high+
```

Each locked package is matched against three sources: the
[OSV](https://osv.dev) API for the Packagist ecosystem (queried
live; only package names and versions are sent, batched), a
vendored snapshot of the
[FriendsOfPHP security-advisories](https://github.com/FriendsOfPHP/security-advisories)
database — the canonical PHP advisory source, with branch-scoped
Composer version matching, so an advisory listed for the 7.12
line never fires on 6.5.5 — and the
[CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
which flags findings that are known to be exploited in the wild.
Dev dependencies are included and flagged `"dev": true`.

Every finding carries a `remediation` — the exact
`composer update <package>` command and the fixed version it
reaches. Severities are normalized across all three sources to
`critical` / `high` / `medium` / `low` / `unknown` — a source
that publishes no severity never gets one invented for it.
`--fail-on <level>` makes the exit code 1 only when a finding
meets that level. An advisory whose published range can't be
parsed, or a locked version that isn't a release version, is
reported under `unassessed` instead of being guessed at. The
locked package list itself is not echoed into the report —
`--include-packages` opts in to that. Exit codes: **0** — no
findings; **1** — findings; **2** — missing or unparseable
lock; **3** — the audit was degraded: OSV could not be reached
and nothing else matched, so "no findings" would be a guess
(the verdict is `no_findings_degraded` and names only the
sources actually consulted).
The vendored snapshots are refreshed with
`tools/refresh_advisories.py` (see its docstring).

Prefer a browser? The same scan runs free at
[phpatch.com](https://phpatch.com) and includes a PDF report.

## How it compares

The php2shell scanners that appeared in October 2026 differ
mostly in **how they decide you are vulnerable** — and in whether
they try to trigger the bug to find out:

| Tool | Detection | Sends exploit triggers? | Remediation | License |
|---|---|---|---|---|
| **phpscan** (this repo) | Version fingerprint from what the site discloses; says "version hidden" instead of guessing | **No — never** | Structured `remediation` field in the verdict JSON, plus managed patch via [PHP Patch Assurance](https://phpatch.com): snapshot-first patch, verify, rollback, evidence report | MIT |
| OpenAI php2shell-checker | Version fingerprint from `X-Powered-By` / `Server` headers only | No | None | Apache-2.0 |
| Searchlight Cyber php2shell-scanner | Behavioral — crafted multipart probes force PHP out of memory and watch for the crash | **Yes, deliberately** | None | MIT |
| SamJUK php2shell-check | Behavioral, local — observes how the installed PHP binary terminates at its memory limit | Only against a throwaway local CLI process | None | MIT |
| squiblyza php_vuln_scan | Version fingerprint from headers/markup, plus version-disclosure hunting | No | Names fixed version in output | MIT |
| JoasASantos php2shell-scanner | Version fingerprint + subdomain recon + origin scan | Optional opt-in probe (README warns of DoS risk) | None | README states MIT; no LICENSE file |

Full criteria, the fairness notes (behavioral checks catch
backports; crash signals also misfire on some patched builds),
SSRF-safety comparison and an FAQ:
**[PHP vulnerability scanners compared](https://phpatch.com/compare)**.

## What it doesn't do

- **It doesn't patch anything.** The scanner is read-only and
  external; it cannot change your server.
- **It can't see a hidden version.** From outside, VERSION HIDDEN
  is the honest end of the road — a definitive verdict for those
  sites needs a read-only look on the server itself.
- **It doesn't monitor or alert.** It's a point-in-time check you
  run; it won't notice next month's advisory for you.
- **It isn't a general security audit.** It judges the disclosed
  PHP version against its advisory database — nothing more.

Patching, on-server verification, rollback, an evidence work
report, and monitoring are what the hosted service adds:
**[PHP Patch Assurance — phpatch.com](https://phpatch.com)**.

## Guides and further reading

- **[Self-hoster guides](https://phpatch.com/guides)** — update
  PHP in Docker and with apt, mod_php vs PHP-FPM, rollback,
  health checks, version checks, end-of-life upgrades, and
  patching without downtime, written from the patch flow the
  service itself uses.
- **[php2shell fix guide](https://phpatch.com/threats/php2shell)**
  — what php2shell is, who is affected, how to check and patch,
  the fixed releases, and the primary sources.
- **[Case study: mitbbs.ai](https://phpatch.com/case-studies/mitbbs-ai)**
  — how a bilingual news portal patched php2shell on disclosure
  night: 8.3.35 to 8.3.36 under mod_php, about 10 seconds of
  downtime, verified live, no compromise found.

## CMS, plugin and hygiene checks

Beyond the PHP version itself, every scan reports:

- **CMS detection** — WordPress, Drupal, Joomla, Magento and
  Laravel, fingerprinted from what the site itself discloses:
  generator tags, distinctive asset paths, response headers
  (Drupal's `X-Generator`, Magento's `X-Magento-*`), REST entry
  points (`/wp-json/`), and read-only version files
  (`CHANGELOG.txt`, the Joomla manifest). A version is reported
  only when the site discloses it; otherwise the result says
  "detected, version hidden" — versions are never guessed.
- **WordPress plugin/theme vulnerabilities** — versions disclosed
  in enqueued asset URLs, `readme.txt` stable tags, theme
  `style.css` headers and `/wp-json/` namespaces are matched
  against `phpscan/data/wp_plugins.json`: a vendored dataset of
  the most-exploited WordPress plugin vulnerabilities (affected
  ranges, fixed version, CVE, CVSS, CISA KEV flag), built from
  the NVD's CPE/description data cross-checked against the CISA
  KEV catalog. Refresh it with `tools/refresh_wp_plugins.py`.
  Known end-of-life CMS lines (Drupal 7/8/9, Joomla 3) are
  flagged as well.
- **Config hygiene** — an exposed phpinfo page, `X-Powered-By`
  version disclosure, missing security headers
  (`X-Content-Type-Options`, `X-Frame-Options` /
  `frame-ancestors`, `Referrer-Policy`, HSTS on HTTPS), a
  publicly served `.git/HEAD` or `.env` file, and directory
  listings on common upload/plugin directories. The `.env` /
  `.git` checks confirm exposure from the response's first bytes
  only — file contents are never copied into the report, only
  "exposed" plus the path.

Findings land in the scan result's `findings` list, ordered
by severity — KEV-listed plugin vulnerabilities first — and
every finding carries a `remediation`. A critical or high
finding escalates the verdict to `vulnerable` (the escalated
verdict carries the findings) even when the PHP version
itself is current; otherwise the PHP verdict passes through
unchanged.

## Authorized use

Only scan sites you own or have permission to scan. The hosted
scanner at phpatch.com additionally enforces rate limits and an
opt-out blocklist for site operators (see the Terms, section 8).

## Advisory data

`phpscan/data/cves.json` is the advisory database the scanner
judges against — the full PHP core CVE set (700+ advisories
across branches 4.3–8.5), each with per-branch fixed releases,
the branches it has no fix for, CVSS scores and references; the
hand-curated php2shell bundle sits alongside the per-CVE
entries. The file is generated, not hand-edited:
`tools/build_core_db.py` builds it from the NIST NVD's CPE
ranges for `cpe:2.3:a:php:php`, cross-checked against the
php.net ChangeLogs' per-release fix lists, and
`tools/refresh_advisory_db.sh` regenerates it (plus the public
feeds below) in one step. A verdict aggregates every advisory
that matches the disclosed version: the headline finding is
the most severe, the named floor is the branch's cumulative
patched release, and `findings` lists all of them.

The same database is published as a public feed for other
tools to consume — `feeds/php-advisories.json` (the full
database) and `feeds/php-advisories.atom` (Atom 1.0, the 50
most recent advisories), generated by `tools/build_feed.py`
and hosted at stable URLs on phpatch.com
(`https://phpatch.com/feeds/php-advisories.json` and
`https://phpatch.com/feeds/php-advisories.xml`).

Corrections are welcome as pull requests; every change to this
file requires maintainer review (see CODEOWNERS), because it
changes the verdicts the scanner gives.

A verdict of `patched` means only that the disclosed version is
not below the fixed releases in this database — it is not a
general security guarantee. A version below a floor on a
distribution build (Ubuntu/Debian packages) is a "check" signal,
not proof: distros backport fixes without changing the upstream
version, and the scanner says so when it detects a distro build.

## Support the project

phpscan is free and MIT-licensed, and the hosted scanner at
[phpatch.com](https://phpatch.com) is free for every site. If
the scanner, the threat desk or the daily Mega-Vuln Alert
reports helped you, you can chip in at
**[phpatch.com/donate](https://phpatch.com/donate)** — any
amount from $1, one-time, via Stripe. Donations fund phpscan
development, the free hosted scans and the public threat
research. Plainly stated on the page: PHPatch is operated by
Superstar Telecom LLC, a for-profit company, so donations are
voluntary support — not tax-deductible, and they buy no
product, service or entitlement.

## Scanned by phpscan badge

If you scan your site with phpscan, you can show it:

[![Scanned by phpscan](https://img.shields.io/badge/scanned%20by-phpscan-blue.svg)](https://phpatch.com)

```markdown
[![Scanned by phpscan](https://img.shields.io/badge/scanned%20by-phpscan-blue.svg)](https://phpatch.com)
```

## License

MIT. Not affiliated with the PHP Group. PHP is a trademark of the
PHP Group.
