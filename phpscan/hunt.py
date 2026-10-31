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
checks a short list of famous shell paths, but only after a
catch-all control probe (a random nonexistent path), and a
200 counts only when the body carries a known shell
signature. Even then it is an indicator to investigate,
never a conclusion.

Safety: strictly read-only. Hunt never modifies, moves,
quarantines or executes anything it scans. Inside composer
package directories listed in vendor/composer/installed.json,
only the high-severity rules run by default (request-input
eval/exec, shell fingerprints, auto_prepend_file persistence,
known-bad hashes): planting a shell inside a real package is
the normal way to hide in vendor/, and a forged installed.json
must not be able to hide a tree from those rules. The noisy
rules (low/medium patterns, special-dir, double-extension,
dotfile and modification-time heuristics) are what is skipped
there, and the report says so, with counts. --include-vendor
runs every rule everywhere.
"""

import hashlib
import json
import os
import re
import secrets
import sys
import time

_DATA = os.path.join(os.path.dirname(__file__), "data", "iocs.json")

_PHP_EXTS = (".php", ".phtml", ".php3", ".php4", ".php5", ".phps", ".phar")
_MAX_FILE = 1024 * 1024          # "oversize" listing threshold
_HARD_CAP = 16 * 1024 * 1024     # streaming hard cap per file
_CHUNK = 256 * 1024              # streaming read chunk
_MAX_FILES = 20000               # tree-walk cap
# Severities whose rules run EVERYWHERE, including inside
# composer package directories: the unambiguous backdoor
# idioms. Anything noisier is what vendor mode reduces.
_HIGH_SEVS = ("critical", "high")
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


_CONFIG_FILES = (".user.ini", ".htaccess", "php.ini")
_PERSIST_RE = re.compile(
    r"(auto_prepend_file|auto_append_file)\s*(?:=|\s)\s*\"?"
    r"([^\s\"']+)", re.I)


def _scan_content(path, size, cap=_HARD_CAP):
    """Stream a file for content checks, in chunks, up to
    `cap` bytes (the hard cap, 16 MB by default). Returns
    (raw, text, scanned):

    - raw: the FULL raw bytes when the whole file was read
      (the only honest input to a SHA-256), else None;
    - text: the decoded content of everything read — the
      whole file when it fits the cap, NOT head+tail, so a
      payload padded into the middle of a multi-megabyte
      file is seen exactly like one at either end;
    - scanned: bytes actually read (== size when the file
      fits the cap, == cap when it does not; the remainder
      is reported by the caller as unscanned).

    raw and text are both None for binary/unreadable files."""
    try:
        chunks, got, complete = [], 0, False
        with open(path, "rb") as f:
            while got < cap:
                chunk = f.read(min(_CHUNK, cap - got))
                if not chunk:
                    complete = True
                    break
                if not chunks and b"\x00" in chunk[:4096]:
                    return None, None, 0  # binary — not PHP source
                chunks.append(chunk)
                got += len(chunk)
            else:
                complete = got >= size
    except OSError:
        return None, None, 0
    raw = b"".join(chunks)
    return (raw if complete else None), \
        raw.decode("utf-8", "replace"), got


def _installed_package_dirs(vendor_root):
    """Package directories under one vendor/ root, per its
    composer/installed.json: {posix relpath from the vendor
    root}. A directory is vendor content we may skip ONLY when
    it is one of these — anything else under vendor/ (a dropped
    shell in vendor/x/, say) is not in the manifest and gets
    scanned like any other directory. Missing/unparseable
    manifest -> empty set (nothing is skipped)."""
    manifest = os.path.join(vendor_root, "composer",
                            "installed.json")
    try:
        with open(manifest, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return set()
    pkgs = data.get("packages") if isinstance(data, dict) else data
    out = set()
    for p in pkgs or []:
        if not isinstance(p, dict):
            continue
        name = str(p.get("name") or "").strip("/")
        if name:
            out.add(name)
        install = p.get("install-path")
        if install:
            rel = os.path.normpath(
                os.path.join("composer", str(install)))
            out.add(rel.replace(os.sep, "/").strip("/"))
    return out


def hunt_local(root, include_vendor=False, max_file=_MAX_FILE,
               max_files=_MAX_FILES, hard_cap=_HARD_CAP):
    """Walk `root` and return the hunt report dict (see hunt_main
    for the CLI). Pure and read-only; raises ValueError on a bad
    root so the caller can map it to a usage error.

    `max_file` is the threshold above which a file is listed
    under 'oversize_files' (it is still scanned in full, by
    streaming); `hard_cap` is the per-file streaming cap —
    bytes past it are reported as unscanned, never silently
    dropped."""
    if not os.path.isdir(root):
        raise ValueError(f"not a directory: {root}")
    iocs = load_iocs()
    fname_iocs = {e["name"]: e for e in iocs["filename_iocs"]}
    # re.I throughout: PHP function names are case-insensitive,
    # so EVAL($_POST[..]) is the same backdoor as eval($_POST[..]).
    patterns = [(p["id"], re.compile(p["regex"], re.I),
                 p["severity"], p["note"])
                for p in iocs["content_patterns"]]
    hashes = set(iocs.get("hashes_sha256") or [])
    special = set(d.lower() for d in iocs["special_dirs"])

    findings, php_files = [], []     # php_files: (relpath, mtime)
    scanned, limited = 0, False
    oversize = []          # [{path, size, scanned_bytes}]
    unscanned = 0
    vendor_dirs = set()    # package dirs scanned reduced-rules
    vendor_files = 0       # files scanned with reduced rules
    pkg_dir_cache = {}

    def in_vendor_package(parts):
        """True when the directory `parts` (relative components)
        is, or sits inside, a composer package directory of the
        first vendor/ tree on the path, per that tree's
        composer/installed.json. Inside such a directory the
        noisy rules are reduced (see the walk) — never the
        high-severity ones, so neither a planted shell inside
        a real package nor a forged manifest can hide from
        them."""
        low_parts = [p.lower() for p in parts]
        if "vendor" not in low_parts:
            return False
        i = low_parts.index("vendor")
        if len(parts) <= i + 1:
            return False        # the vendor root itself
        vendor_root = os.path.join(root, *parts[:i + 1])
        if vendor_root not in pkg_dir_cache:
            pkg_dir_cache[vendor_root] = \
                _installed_package_dirs(vendor_root)
        sub = "/".join(parts[i + 1:])
        return any(sub == d or sub.startswith(d + "/")
                   for d in pkg_dir_cache[vendor_root])

    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        parts = [] if rel_dir == "." else rel_dir.split(os.sep)
        in_pkg = not include_vendor and in_vendor_package(parts)
        if in_pkg:
            vendor_dirs.add("/".join(parts))
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
                # A famous shell filename is a high-severity
                # signal even inside a package; the medium
                # dropper names (x.php, 1.php) are noisy there
                # and are part of the reduced set.
                if not in_pkg or e["severity"] in _HIGH_SEVS:
                    findings.append(_finding(
                        rel, f"filename:{low}", e["severity"],
                        f"Famous webshell filename ({e['note']})."))
            if low in _CONFIG_FILES:
                # Persistence check: auto_prepend/append_file in
                # .user.ini / .htaccess / php.ini makes the server
                # execute an attacker file on every request. It
                # runs everywhere, vendor packages included.
                try:
                    size = os.path.getsize(full)
                except OSError:
                    continue
                _raw, text, n_read = _scan_content(
                    full, size, hard_cap)
                if size > max_file:
                    oversize.append({"path": rel, "size": size,
                                     "scanned_bytes": n_read})
                    if text is not None:
                        unscanned += max(0, size - n_read)
                if text:
                    for m in _PERSIST_RE.finditer(text):
                        target = m.group(2)
                        if target.lower() in ("none", '""', "''"):
                            continue
                        findings.append(_finding(
                            rel, "auto-prepend-append", "high",
                            f"{m.group(1)} is set to {target} in "
                            f"{name}: the server executes that "
                            "file around every PHP request — a "
                            "classic persistence mechanism that "
                            "survives cleanup of the original "
                            "shell."))
                continue
            if not _is_phpish(name):
                continue
            scanned += 1
            try:
                st = os.stat(full)
            except OSError:
                continue
            if in_pkg:
                vendor_files += 1
            else:
                # The mtime heuristic does not run inside
                # packages: vendor files are excluded from the
                # release-cluster corpus entirely.
                php_files.append((rel, st.st_mtime))
                if in_special and low.endswith(_PHP_EXTS):
                    findings.append(_finding(
                        rel, "php-in-special-dir", "high",
                        "Executable PHP inside an upload/media/"
                        "cache directory, where user-supplied "
                        "files land and PHP should never run."))
                if re.search(r"\.(php\d?|phtml)\.", low):
                    findings.append(_finding(
                        rel, "double-extension", "medium",
                        "PHP extension mid-filename (e.g. "
                        ".php.jpg): misconfigured servers may "
                        "execute it as PHP."))
                if name.startswith("."):
                    findings.append(_finding(
                        rel, "hidden-php-dotfile", "medium",
                        "Hidden dotfile containing PHP — a "
                        "classic place to stash a backdoor out "
                        "of plain sight."))
            raw, text, n_read = _scan_content(
                full, st.st_size, hard_cap)
            if st.st_size > max_file:
                oversize.append({"path": rel, "size": st.st_size,
                                 "scanned_bytes": n_read})
                if text is not None:
                    unscanned += max(0, st.st_size - n_read)
            if text is None:
                continue
            if hashes and raw is not None:
                # SHA-256 over the RAW BYTES: hashing a decoded/
                # re-encoded text round-trip can never match a
                # published hash for a non-UTF-8 file. Runs
                # everywhere, vendor packages included.
                digest = hashlib.sha256(raw).hexdigest()
                if digest in hashes:
                    findings.append(_finding(
                        rel, "known-bad-hash", "critical",
                        "SHA-256 matches a published webshell "
                        "hash in the IOC set."))
            for pid, rx, sev, note in patterns:
                if in_pkg and sev not in _HIGH_SEVS:
                    # Reduced rules inside packages: the noisy
                    # medium/low idioms (preg_replace /e, plain
                    # eval) are skipped; the unambiguous
                    # high-severity backdoor idioms are not.
                    continue
                if rx.search(text):
                    findings.append(_finding(
                        rel, f"pattern:{pid}", sev,
                        f"{note} (matched /{rx.pattern}/)."))
    findings.extend(_mtime_outliers(php_files))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (order[f["severity"]], f["file"]))
    worst = findings[0]["severity"] if findings else None
    if findings:
        detail = (f"{len(findings)} indicator(s) found. Findings "
                  "are leads for review, not proof of compromise: "
                  "confirm each file against a clean copy of your "
                  "site before acting.")
    else:
        detail = ("No compromise indicators found in the scanned "
                  "tree. That is evidence, not a guarantee: hunt "
                  "checks known fingerprints and common backdoor "
                  "idioms, and a clean result does not rule out a "
                  "novel or database-resident compromise.")
    if oversize:
        detail += (f" {len(oversize)} file(s) larger than "
                   f"{max_file} bytes were scanned by streaming "
                   "and are listed under 'oversize_files' with "
                   "their sizes and scanned byte counts.")
        if unscanned:
            detail += (f" {unscanned} byte(s) past the "
                       f"{hard_cap}-byte per-file hard cap were "
                       "not scanned.")
    # The verdict text itself discloses any reduction of the
    # scan — a report field alone is not disclosure, because
    # the verdict is the part people read.
    incomplete_causes = []
    if limited:
        incomplete_causes.append(
            f"the {max_files}-file walk cap was reached")
    if vendor_files:
        detail += (
            f" {vendor_files} file(s) in {len(vendor_dirs)} "
            "vendor package director"
            f"{'y' if len(vendor_dirs) == 1 else 'ies'} were "
            "scanned with high-severity rules only: the noisy "
            "low/medium rules and the modification-time check "
            "do not run inside composer packages, so a shell "
            "that trips only those rules would not be reported "
            "there (pass --include-vendor to scan vendor in "
            "full).")
        incomplete_causes.append(
            "vendor packages were scanned with reduced rules")
    if unscanned:
        incomplete_causes.append(
            f"{unscanned} byte(s) exceeded the per-file hard "
            "cap and were not scanned")
    incomplete = bool(incomplete_causes)
    if incomplete:
        detail += (" This result is incomplete: "
                   + "; ".join(incomplete_causes) + ".")
    return {
        "schema_version": 1,
        "target": os.path.abspath(root),
        "mode": "local",
        "scanned_php_files": scanned,
        "oversize_files": oversize,
        "unscanned_bytes": unscanned,
        "limits_hit": limited,
        "vendor_skipped": vendor_files > 0,
        "vendor_partial_files": vendor_files,
        "vendor_partial_dirs": sorted(vendor_dirs),
        "incomplete": incomplete,
        "findings": findings,
        "verdict": {
            "status": "findings" if findings else "clean",
            "worst_severity": worst,
            "incomplete": incomplete,
            "detail": detail,
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


def _shell_fingerprints():
    """Compiled self-identification patterns of the known shell
    families (the shell-fingerprint-* content patterns)."""
    return [(p["id"], re.compile(p["regex"], re.I))
            for p in load_iocs()["content_patterns"]
            if p["id"].startswith("shell-fingerprint")]


def catch_all_control(fetch, base, deadline=None):
    """Soft-404 / catch-all control: request one random path
    that cannot exist (`/phpatch-<16 hex>.php`). Returns
    (catch_all, control_path) — catch_all is True when the
    site answers 200 for it, which means a bare 200 on any
    other probe path carries no information at all (SPAs, WAFs
    and custom error pages do this routinely)."""
    path = f"/phpatch-{secrets.token_hex(8)}.php"
    r = fetch(base + path, deadline=deadline)
    return bool(r and r.get("status") == 200), path


def remote_indicators(fetch, base, deadline=None, catch_all=None):
    """Checks for famous shell paths, using the external
    scanner's guarded fetch (all SSRF policy applies).
    `fetch(url, deadline=...)` is scan._fetch.

    A bare 200 is NOT evidence: the catch-all control runs
    first (unless the caller already ran it and passes
    `catch_all`), and a shell path is only reported as an
    indicator when its body carries a known shell family's
    self-identification signature — the same standard the
    local hunt applies. A signature-less 200 on a CATCH-ALL
    site is dropped: there, a 200 carries no information at
    all. On a site that is NOT a catch-all, the same 200 is
    path-specific, so it earns a low-severity "review
    manually" note instead of a silent drop — it is never
    dressed up as an indicator of compromise. Returns a list
    of indicator dicts; an indicator is still a lead, never
    a conclusion (see data/iocs.json remote_note)."""
    if catch_all is None:
        catch_all, _ = catch_all_control(fetch, base,
                                          deadline=deadline)
    fingerprints = _shell_fingerprints()
    out = []
    for path in load_iocs()["remote_paths"]:
        r = fetch(base + path, deadline=deadline)
        if not r or r.get("status") != 200:
            continue
        body = r.get("body") or ""
        sig = next((pid for pid, rx in fingerprints
                    if rx.search(body)), None)
        if sig is None:
            if not catch_all:
                out.append({
                    "path": path, "status": 200,
                    "indicator": "known-shell-path-unconfirmed",
                    "severity": "low",
                    "detail": "A file with a known webshell "
                              "name answers at this public "
                              "path, but its body carries no "
                              "known shell signature. This host "
                              "is not a catch-all (a random "
                              "nonexistent path does not answer "
                              "200), so the 200 is specific to "
                              "this path: the file may be an "
                              "empty placeholder, a honeypot, "
                              "or a shell family this scanner "
                              "has no fingerprint for. Worth a "
                              "manual look — not an indicator "
                              "of compromise by itself.",
                    "remediation": "Open the file on the "
                                   "server and check its "
                                   "contents, size and "
                                   "modification time; if it is "
                                   "not a deliberate placeholder "
                                   "or honeypot, treat it as "
                                   "hostile: " + _REMEDIATION})
            continue
        out.append({
            "path": path, "status": 200,
            "indicator": "known-shell-path",
            "severity": "high",
            "detail": "A file with a known webshell name "
                      "answers at this public path, and its "
                      f"body carries the {sig} shell signature. "
                      "Indicative, not conclusive — confirm "
                      "with a local `phpscan hunt` on the "
                      "server.",
            "remediation": _REMEDIATION})
    return out


_USAGE = """usage: phpscan hunt <webroot> [--include-vendor]

Read-only compromise check of a webroot you own: known webshell
fingerprints, backdoor idioms, PHP in upload dirs, double
extensions, hidden PHP dotfiles, mtime outliers. Prints a JSON
report. Exit codes: 0 clean, 1 findings, 2 usage error,
3 clean but incomplete (the walk cap was hit, bytes past the
per-file hard cap went unscanned, or vendor packages were
scanned with high-severity rules only — see --include-vendor;
an incomplete clean is not a full clean)."""


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
    if report["findings"]:
        return 1
    # No findings, but the scan did not cover everything it
    # claims to cover: the family convention is exit 3
    # (judged under degraded evidence), never a silent clean.
    return 3 if report.get("incomplete") else 0
