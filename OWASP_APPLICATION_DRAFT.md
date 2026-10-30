# OWASP Project Application — DRAFT, NOT SUBMITTED

Prepared 2026-10-30. Do not submit until the gaps at the bottom
are resolved by the project owner.

## How submission works (researched 2026-10-30)

Source: OWASP Project Policy, "Starting a New Project"
(https://policy.owasp.org/operational/projects.html).

1. Read the Project Policy and the Project Handbook first
   (the policy requires prospective leaders to do this before
   submitting).
2. Submit the **New Project Request Form** on OWASP's service
   desk (linked from the policy page; hosted on
   owasporg.atlassian.net). Per the same policy, new projects
   "must be approved by the foundation, by submitting a request
   through Contact Us" (https://contact.owasp.org).
3. Projects are one of three types: **tool**, code, or
   documentation. phpscan applies as a **tool** project.
4. New projects enter at the **Incubator** maturity level and
   are reviewed by the OWASP Project Committee.
5. After approval, leaders must create the project's owasp.org
   home page within 30 days of GitHub access, and the project
   must ship at least one release per year to stay active.

Key policy requirements that shape this application:

- A project must have **2–5 recognized leaders**, and leaders
  must be **OWASP members**. Leadership is personal — it is
  not held by a company.
- New projects are required to use OWASP's official project
  source platform (the OWASP GitHub organization); an exception
  may be requested.
- Source must use an OSI-approved open-source license.
- Projects should use OWASP's recommended contributor
  agreement (DCO).

## Application text (draft)

**Project name:** OWASP phpscan

**Project type:** Tool

**License:** MIT (OSI-approved) —
https://github.com/PHPatch/phpscan/blob/main/LICENSE

**Repository:** https://github.com/PHPatch/phpscan

**Website:** https://phpatch.com

**Mission / purpose:**
phpscan is a free, open-source external vulnerability scanner
for PHP web sites. It tells a site owner, in one command,
whether their PHP version is exposed to known critical
vulnerabilities — starting with the php2shell remote code
execution vulnerabilities (CVE-2026-109618 and
CVE-2026-109619) — and names the exact upgrade that fixes
each finding.

**The problem it solves:**
Most PHP site owners have no cheap way to answer "am I already
exposed?" Commercial scanners are priced for enterprises, and
many free checks guess. When a site hides its PHP version,
phpscan says so honestly (`VERSION HIDDEN` / `not_assessed`)
instead of inventing a verdict, and every actionable verdict
carries a `remediation` field naming the fixing upgrade.

**How it works:**
Passive fingerprinting (headers, cookies, error behaviour)
plus a small set of limited, read-only path checks, matched
against a bundled advisory database. phpscan **never sends
exploit payloads or triggers** — that is a deliberate design
position and its main differentiator from exploit-verifying
scanners. It is written in Python (standard library only,
zero dependencies), runs offline against its bundled data,
and returns machine-readable JSON verdicts with documented
exit codes for CI use.

**Audience:** PHP site owners and small hosting operators;
DevOps/CI users (a GitHub Action, `PHPatch/phpscan-action`,
and a Docker image are published); security practitioners who
need a safe, non-intrusive first-pass check.

**Current state (October 2026):**
Version 1.4.4 released 2026-10-30 as the project's first
signed GitHub Release (PGP-signed artifacts, SBOM, changelog,
`SECURITY.md` with a disclosure SLA). Distributed via GitHub
Releases, a GHCR Docker image, and a GitHub Action; PyPI
publication via trusted publishing is in progress. The test
suite (43 tests) covers the fetch layer's SSRF hardening
(blocked address ranges, DNS-rebinding pinning, fetch
deadlines) as well as verdict logic.

**Roadmap:**
1. Composer lockfile audit (`phpscan audit`) against OSV and
   the FriendsOfPHP security-advisories database.
2. Full PHP core advisory database (all branches/CVEs),
   refreshed automatically.
3. CMS and plugin version detection (WordPress first).
4. A read-only compromise check (`phpscan hunt`: webshells,
   suspicious files, IOCs).
5. Configuration-hygiene checks (exposed phpinfo,
   `expose_php`, missing security headers).

**Relationship to the hosted service:**
phpscan is maintained by the team behind phpatch.com, a
hosted scan–patch–verify service. The scanner itself is and
will remain fully functional open source under MIT; the
hosted service adds patching and monitoring. This commercial
relationship is disclosed up front, per OWASP's
conflict-of-interest expectations.

**Why OWASP:**
PHP runs a large share of the web, yet OWASP's tool catalogue
has no PHP-specific exposure scanner. phpscan fills that gap
with a deliberately conservative, honesty-first design that
fits OWASP's "no false confidence" ethos, and its advisory
data work (a maintained, machine-readable PHP advisory
database) is reusable by other tools.

## Gaps to resolve before submitting (owner decisions)

1. **Named leaders (blocking).** The policy requires 2–5
   named individual leaders who are OWASP members; leadership
   cannot be held by Superstar Telecom LLC as a company.
   Supply: leader #1 (name, email, OWASP membership status)
   and at least one additional leader.
2. **Source platform (blocking).** New projects must use
   OWASP's GitHub organization or request an exception. Decide:
   request an exception to keep `PHPatch/phpscan`, or accept a
   repo home under the OWASP org (`OWASP/phpscan`) with the
   PHPatch repo as a mirror.
3. **DCO.** The policy expects OWASP's recommended DCO
   contributor agreement. Not yet enabled on the repo; enabling
   it (GitHub app / commit sign-off) is a small step the owner
   should approve.
4. **Leader email.** Leaders are expected to list an email on
   the project page (an @owasp.org address is issued after
   approval). `security@phpatch.com` is the interim contact.
