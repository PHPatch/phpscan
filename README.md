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
pipx install phpscan
phpscan https://your-site.com
```

Also available as a Docker image (`docker run ghcr.io/phpatch/phpscan https://your-site.com`),
a GitHub Action (`PHPatch/phpscan-action@v1`), directly from GitHub
(`pip install git+https://github.com/PHPatch/phpscan.git`), or by cloning this repo.

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
version and where it was disclosed, and CMS fingerprints.

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
reaches. An advisory whose published range can't be parsed, or a
locked version that isn't a release version, is reported under
`unassessed` instead of being guessed at. Exit codes: **0** — no
findings; **1** — findings; **2** — missing or unparseable lock.
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
| **phpscan** (this repo) | Version fingerprint from what the site discloses; says "version hidden" instead of guessing | **No — never** | Via [PHP Patch Assurance](https://phpatch.com): snapshot-first patch, verify, rollback, evidence report | MIT |
| OpenAI php2shell-checker | Version fingerprint from `X-Powered-By` / `Server` headers only | No | None | Apache-2.0 |
| Searchlight Cyber php2shell-scanner | Behavioral — crafted multipart probes force PHP out of memory and watch for the crash | **Yes, deliberately** | None | No LICENSE file |
| SamJUK php2shell-check | Behavioral, local — observes how the installed PHP binary terminates at its memory limit | Only against a throwaway local CLI process | None | MIT |
| squiblyza php_vuln_scan | Version fingerprint from headers/markup, plus version-disclosure hunting | No | None | MIT |
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

## Authorized use

Only scan sites you own or have permission to scan. The hosted
scanner at phpatch.com additionally enforces rate limits and an
opt-out blocklist for site operators (see the Terms, section 8).

## Advisory data

`phpscan/data/cves.json` is the advisory database the scanner
judges against — branch floors, fixed releases, references and the
leak/exploitation timeline. Last updated 2026-10-22. Update
process: floors are reviewed against the php.net release
announcements on every PHP security release and at least monthly.
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
