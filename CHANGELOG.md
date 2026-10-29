# Changelog

No version tags yet — history below is taken from the git log.
The package version in `pyproject.toml` is 1.4.4.

## Unreleased

- Actionable verdicts (`vulnerable`, `possibly_vulnerable`, `eol`)
  now carry a `remediation` field naming the upgrade that fixes
  them (distro builds point at the distro security tracker
  instead); patched verdicts carry none.
- README: `pip install git+https://github.com/PHPatch/phpscan.git`
  install path (verified by a clean-room venv install), and a
  "Scanned by phpscan" badge snippet.

## History

- 2026-10-25: README: link guides, php2shell fix guide, mitbbs.ai
  case study.
- 2026-10-23: Sponsor/donate path (`FUNDING.yml` + README support
  section).
- 2026-10-23: Rename phpatchscan -> phpscan (package, project
  metadata, docs, tests).
- 2026-10-22: README: verdict vocabulary, real sample session,
  branch floors, honest limits.
- 2026-10-22: README: badges + honest comparison table.
- 2026-10-22: README: lead with git clone install (clone-and-run,
  zero dependencies).
- 2026-10-22: Rename service: PHP Patch Service -> PHP Patch
  Assurance.
- 2026-10-22: Review round 4 follow-up: shared per-scan 40s
  deadline enforced by a socket watchdog, drip regression tests,
  `not_assessed` + `unreachable` as exit code 2, explicit
  blocked-range tests, security-page contact in the user agent,
  Dependabot for SHA-pinned Actions.
- 2026-10-22: pip-installable (`pyproject.toml`, setuptools,
  package data) + README install instructions.
- 2026-10-22: Review round 4: SSRF hardening (CGNAT + transition
  ranges, refusal reasons, no-connect mocks), total 40s fetch
  deadline, multi-IP fallback, duplicate Set-Cookie merge,
  origin-based phpinfo probes, `possibly_vulnerable` +
  `not_assessed` verdicts, honest EOL wording, CLI exit codes,
  CI permissions + SHA-pinned actions, reference URLs.
- 2026-10-22: SSRF test suite, `SECURITY.md`, `CODEOWNERS`, CI;
  fetcher deadline + distro caveat.
- 2026-10-22: Harden fetcher (review round 2) + honest wording.
- 2026-10-22: phpscan 1.0 — free external PHP vulnerability
  scanner (MIT).
