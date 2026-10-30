"""Compromise check — `phpscan hunt <webroot>`.

Answers "was I already hit?" for a site the operator OWNS. Local
mode walks a webroot tree read-only and grades what it finds:
known webshell fingerprints, backdoor idioms (request-input eval
and friends), PHP files where PHP should never live (upload /
media / cache dirs), double extensions, hidden PHP dotfiles, and
modification-time outliers against the tree's release cluster.

Every finding is a lead for review, not proof of compromise —
the report says so, and severities are tiered so a benign eval()
in a library lands at LOW instead of crying wolf.

A remote light mode also exists for the external scanner: it
checks a short list of famous shell paths for existence only.
A 200 there is an indicator to investigate, never a conclusion.

Safety: strictly read-only. Hunt never modifies, moves,
quarantines or executes anything it scans. vendor/ is skipped
unless --include-vendor is given.
"""

import hashlib
import json
import os
import re
import sys
import time

_DATA = os.path.join(os.path.dirname(__file__), "data", "iocs.json")

_PHP_EXTS = (".php", ".phtml", ".php3", ".php4", ".php5", ".phps", ".phar")
_MAX_FILE = 1024 * 1024          # content-scan cap per file
_MAX_FILES = 20000               # tree-walk cap
_REMEDIATION = (
    "Quarantine the file (move it out of the webroot; do not "
    "execute it), restore the site from a clean source, rotate "
    "all credentials (database, admin accounts, FTP/SSH, API "
    "keys), then patch the entry point that let it in — see "
    "https://phpatch.com for the patch service.")
_REVIEW_REMEDIATION = (
    "Review this file by hand. If it is not part of a known, "
    "clean release of your application or libraries, treat it "
    "as hostile: " + _REMEDIATION)


def load_iocs():
    with open(_DATA, encoding="utf-8") as f:
        return json.load(f)


def _finding(path, indicator, severity, detail):
    return {"file": path, "indicator": indicator,
            "severity": severity, "detail": detail,
            "remediation": _REMEDIATION if severity != "low"
            else _REVIEW_REMEDIATION}


def _is_phpish(name):
    low = name.lower()
    return low.endswith(_PHP_EXTS) or ".php" in low


def _content_of(path, cap):
    try:
        with open(path, "rb") as f:
            raw = f.read(cap)
    except OSError:
        return None
    if b"\x00" in raw[:4096]:        # binary — not PHP source
        return None
    return raw.decode("utf-8", "replace")


def hunt_local(root, include_vendor=False, max_file=_MAX_FILE,
               max_files=_MAX_FILES):
    """Walk `root` and return the hunt report dict (see hunt_main
    for the CLI). Pure and read-only; raises ValueError on a bad
    root so the caller can map it to a usage error."""
    if not os.path.isdir(root):
        raise ValueError(f"not a directory: {root}")
    iocs = load_iocs()
    fname_iocs = {e["name"]: e for e in iocs["filename_iocs"]}
    patterns = [(p["id"], re.compile(p["regex"]), p["severity"],
                 p["note"]) for p in iocs["content_patterns"]]
    hashes = set(iocs.get("hashes_sha256") or [])
    special = set(d.lower() for d in iocs["special_dirs"])

    findings, php_files = [], []     # php_files: (relpath, mtime)
    scanned, limited = 0, False
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        parts = [] if rel_dir == "." else rel_dir.split(os.sep)
        if not include_vendor and "vendor" in [p.lower()
                                               for p in parts]:
            dirnames[:] = []
            continue
        in_special = any(p.lower() in special for p in parts)
        for name in filenames:
            if scanned >= max_files:
                limited = True
                break
            full = os.path.join(dirpath, name)
            rel = name if rel_dir == "." else os.path.join(rel_dir, name)
            low = name.lower()
            if low in fname_iocs:
                e = fname_iocs[low]
                findings.append(_finding(
                    rel, f"filename:{low}", e["severity"],
                    f"Famous webshell filename ({e['note']})."))
            if not _is_phpish(name):
                continue
            scanned += 1
            try:
                st = os.stat(full)
            except OSError:
                continue
            php_files.append((rel, st.st_mtime))
            if in_special and low.endswith(_PHP_EXTS):
                findings.append(_finding(
                    rel, "php-in-special-dir", "high",
                    "Executable PHP inside an upload/media/cache "
                    "directory, where user-supplied files land and "
                    "PHP should never run."))
            if re.search(r"\.(php\d?|phtml)\.", low):
                findings.append(_finding(
                    rel, "double-extension", "medium",
                    "PHP extension mid-filename (e.g. .php.jpg): "
                    "misconfigured servers may execute it as PHP."))
            if name.startswith("."):
                findings.append(_finding(
                    rel, "hidden-php-dotfile", "medium",
                    "Hidden dotfile containing PHP — a classic "
                    "place to stash a backdoor out of plain sight."))
            if st.st_size > max_file:
                continue
            text = _content_of(full, max_file)
            if text is None:
                continue
            if hashes:
                digest = hashlib.sha256(
                    text.encode("utf-8", "replace")).hexdigest()
                if digest in hashes:
                    findings.append(_finding(
                        rel, "known-bad-hash", "critical",
                        "SHA-256 matches a published webshell "
                        "hash in the IOC set."))
            for pid, rx, sev, note in patterns:
                if rx.search(text):
                    findings.append(_finding(
                        rel, f"pattern:{pid}", sev,
                        f"{note} (matched /{rx.pattern}/)."))
    findings.extend(_mtime_outliers(php_files))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (order[f["severity"]], f["file"]))
    worst = findings[0]["severity"] if findings else None
    return {
        "target": os.path.abspath(root),
        "mode": "local",
        "scanned_php_files": scanned,
        "limits_hit": limited,
        "vendor_skipped": not include_vendor,
        "findings": findings,
        "verdict": {
            "status": "findings" if findings else "clean",
            "worst_severity": worst,
            "detail": (
                f"{len(findings)} indicator(s) found. Findings "
                "are leads for review, not proof of compromise: "
                "confirm each file against a clean copy of your "
                "site before acting."
                if findings else
                "No compromise indicators found in the scanned "
                "tree. That is evidence, not a guarantee: hunt "
                "checks known fingerprints and common backdoor "
                "idioms, and a clean result does not rule out a "
                "novel or database-resident compromise."),
        },
    }


def _mtime_outliers(php_files):
    """PHP files whose modification DAY sits far from the tree's
    dominant release cluster. Needs a real cluster (>= 5 files on
    one day) before it judges anything."""
    if len(php_files) < 5:
        return []
    by_day = {}
    for rel, mt in php_files:
        day = time.strftime("%Y-%m-%d", time.localtime(mt))
        by_day.setdefault(day, []).append(rel)
    cluster_day, members = max(by_day.items(),
                               key=lambda kv: len(kv[1]))
    if len(members) < 5:
        return []
    cluster_ts = time.mktime(time.strptime(cluster_day, "%Y-%m-%d"))
    out = []
    for rel, mt in php_files:
        day = time.strftime("%Y-%m-%d", time.localtime(mt))
        if day == cluster_day:
            continue
        day_ts = time.mktime(time.strptime(day, "%Y-%m-%d"))
        if abs(day_ts - cluster_ts) > 2 * 86400:
            out.append(_finding(
                rel, "mtime-outlier", "medium",
                f"Modified {day}, while the bulk of this tree "
                f"({len(members)} PHP files) carries {cluster_day} "
                "— a lone newer/older PHP file is what a dropped "
                "shell looks like after a release deploy."))
    return out


def remote_indicators(fetch, base, deadline=None):
    """Existence-only checks for famous shell paths, using the
    external scanner's guarded fetch (all SSRF policy applies).
    `fetch(url, deadline=...)` is scan._fetch. Returns a list of
    indicator dicts; a 200 means 'possible compromise indicator',
    never a conclusion (see data/iocs.json remote_note)."""
    out = []
    for path in load_iocs()["remote_paths"]:
        r = fetch(base + path, deadline=deadline)
        if r.get("status") == 200:
            out.append({
                "path": path, "status": 200,
                "indicator": "known-shell-path",
                "severity": "high",
                "detail": "A file with a known webshell name "
                          "answers at this public path. Indicative, "
                          "not conclusive — confirm with a local "
                          "`phpscan hunt` on the server.",
                "remediation": _REMEDIATION})
    return out


_USAGE = """usage: phpscan hunt <webroot> [--include-vendor]

Read-only compromise check of a webroot you own: known webshell
fingerprints, backdoor idioms, PHP in upload dirs, double
extensions, hidden PHP dotfiles, mtime outliers. Prints a JSON
report. Exit codes: 0 clean, 1 findings, 2 usage error."""


def hunt_main(argv):
    argv = [a for a in argv if a != ""]
    if any(a in ("-h", "--help") for a in argv):
        print(_USAGE)
        return 0
    include_vendor = "--include-vendor" in argv
    args = [a for a in argv if not a.startswith("--")]
    unknown = [a for a in argv if a.startswith("--")
               and a != "--include-vendor"]
    if len(args) != 1 or unknown:
        print(_USAGE, file=sys.stderr)
        return 2
    try:
        report = hunt_local(args[0], include_vendor=include_vendor)
    except ValueError as e:
        print(json.dumps({"target": args[0], "error": str(e)}))
        return 2
    print(json.dumps(report, indent=1))
    return 1 if report["findings"] else 0
