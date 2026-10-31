"""Step 1a — external scan (no credentials).

Fingerprints PHP from what a site discloses over HTTP: X-Powered-By /
Server headers, PHPSESSID cookies, CMS generator signals, and exposed
phpinfo pages. An exact version, when disclosed, is checked against the
patched-release floors.

One disclosure is also an audit input: if the site serves its
composer.lock publicly, the scan fetches it (bounded read, defensive
parse — the file is untrusted input) and runs the dependency audit
engine (phpscan/audit.py) against the locked versions, merging the
findings into the same verdict with the lockfile URL as provenance.
The exposure itself is a finding: it discloses exact dependency
versions. If the lockfile is absent, malformed, or too large, the
scan proceeds exactly as if it were not there.

Honest limit: most well-run sites suppress version headers. For those the
scan reports "PHP detected, version hidden — patch status cannot be
confirmed from outside" and recommends the credentialed deep check.
"""

import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
import urllib.parse

from . import __version__, audit, detect, hygiene, versioning

_UA = f"phpscan/{__version__} (+https://phpatch.com/security)"
_TIMEOUT = 12
_MAX_BODY = 512 * 1024
_MAX_REDIRECTS = 5
_PHPINFO_PATHS = ("/phpinfo.php", "/info.php", "/php-info.php", "/test.php")
_LOCK_PATH = "/composer.lock"
# Bounded read for the exposed lockfile: real-world locks run
# larger than a web page, so the cap is more generous than
# _MAX_BODY — but still a hard bound. A response past the cap
# arrives truncated, fails the defensive parse, and the scan
# proceeds exactly as if no lockfile were exposed.
_LOCK_MAX_BODY = 8 * 1024 * 1024

# Owner self-check guidance for the VERSION HIDDEN verdict
# (status "indeterminate"): the scan cannot assess a version the
# site does not disclose, but the site's owner can — in about a
# minute, server-side. Carried on the verdict as `remediation` +
# `next_steps` (JSON) and rendered as the "If this is your site"
# block in the text output.
_HIDDEN_REMEDIATION = "Version not disclosed — if this is your site, check the version server-side (php -v, your hosting panel, or a temporary phpinfo page you delete immediately after), then verify it against the PHPatch advisory feed. Full guide: https://phpatch.com/guides/version-hidden"
_HIDDEN_NEXT_STEPS = [
    "SSH or terminal: run `php -v` (note: CLI and web PHP can differ on some hosts — the panel method below shows the web version).",
    "Hosting panel: cPanel → MultiPHP Manager or 'Select PHP Version'; Plesk → Websites & Domains → PHP Settings — both show the PHP version serving your site.",
    "Temporary phpinfo: create check.php containing <?php phpinfo(); in your web root, open it in a browser, note the version, then DELETE the file immediately — a leftover phpinfo page is itself a serious exposure (phpscan flags it).",
    "Follow the full walkthrough: https://phpatch.com/guides/version-hidden — it covers checking your version against current advisories (feed: https://phpatch.com/feeds/php-advisories.json) and what to do if it's end-of-life.",
    "If the version is end-of-life or has known vulnerabilities, upgrade it or have it patched — see https://phpatch.com/patch.",
]
_HIDDEN_NOT_YOURS = "Not your site? A hidden version can't be assessed externally — that's by design, and it is not evidence the site is vulnerable."


class BlockedTarget(Exception):
    """Target refused by the scanner's SSRF/abuse policy."""


# Ranges that Python's is_global / is_private flags do not classify
# consistently across versions, checked explicitly: carrier-grade
# NAT (includes cloud metadata endpoints in that space), the IETF
# special-purpose /24, benchmarking space, the deprecated 6to4
# relay anycast, and the IPv6 transition prefixes whose embedded
# IPv4 destination could be non-public (NAT64 well-known prefix,
# Teredo).
_EXTRA_BLOCKED = [ipaddress.ip_network(n) for n in (
    "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15",
    "192.88.99.0/24", "64:ff9b::/96", "2001::/32")]


def _blocked(ip):
    """True unless the address is globally routable public space.

    Primary test is is_global (negated): it covers loopback,
    RFC1918, link-local (incl. cloud metadata 169.254.169.254),
    CGNAT, reserved and unspecified space across Python versions,
    which the individual is_private-style flags do not.
    """
    return (not ip.is_global or ip.is_multicast
            or any(ip in n for n in _EXTRA_BLOCKED))


def _public_ips(host):
    """Resolve a host and require EVERY answer to be a public IP.

    Blocks loopback, private, link-local (incl. cloud metadata
    169.254.169.254), reserved, multicast and unspecified addresses,
    so the public scanner can never be pointed at internal services.
    """
    try:
        infos = socket.getaddrinfo(host, None,
                                     proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise BlockedTarget(f"DNS lookup failed for {host}: {e}")
    ips = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        # Unwrap transition forms: the real TCP destination of an
        # IPv4-mapped (::ffff:a.b.c.d) or 6to4 (2002:xxxx::) address
        # is the embedded IPv4, so THAT is what must be checked —
        # the IPv6 spelling alone does not trip the IPv4 ranges.
        if isinstance(ip, ipaddress.IPv6Address):
            if ip.ipv4_mapped is not None:
                ip = ip.ipv4_mapped
            elif ip.sixtofour is not None:
                ip = ip.sixtofour
        if _blocked(ip):
            raise BlockedTarget(
                f"{host} resolves to a non-public address; "
                "the scanner only fetches public websites")
        if str(ip) not in ips:
            ips.append(str(ip))
    if not ips:
        raise BlockedTarget(f"DNS lookup returned nothing for {host}")
    return ips


class _PinnedHTTPS(http.client.HTTPSConnection):
    """HTTPS to a pinned IP, with SNI + certificate checks against
    the original hostname (defeats DNS-rebinding between the policy
    check and the connect)."""

    def __init__(self, ip, port, sni_host, timeout):
        super().__init__(ip, port, timeout=timeout,
                         context=ssl.create_default_context())
        self._sni_host = sni_host

    def connect(self):
        http.client.HTTPConnection.connect(self)
        self.sock = self._context.wrap_socket(
            self.sock, server_hostname=self._sni_host)


def _literal_refusal(host):
    """Refuse non-standard IP encodings: decimal (2130706433), hex
    (0x7f000001), octal parts (0177.0.0.1), short forms (127.1).
    Resolver libraries disagree on these spellings, so they never
    reach a resolver at all."""
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", host):
        return "hex-encoded IP addresses are refused"
    if re.fullmatch(r"[0-9.]+", host):
        parts = host.split(".")
        if len(parts) != 4 or any(
                not p.isdigit() or int(p) > 255 or
                (len(p) > 1 and p.startswith("0")) for p in parts):
            return "non-standard IP address forms are refused"
    return None


def _preflight(url):
    """Validate one fetch target. Called for the initial URL and
    for EVERY redirect hop, so a redirect cannot smuggle in a
    blocked scheme, port, credential or encoded address.
    Returns (error, parts, port); error is None when clean."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return "only http/https URLs are scanned", None, None
    if parts.username or parts.password:
        return "URLs with credentials are refused", None, None
    host = parts.hostname
    if not host:
        return "URL has no host", None, None
    refusal = _literal_refusal(host)
    if refusal:
        return refusal, None, None
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        port = -1
    if port not in (80, 443):
        return "only ports 80 and 443 are scanned", None, None
    return None, parts, port


_DEADLINE = 25  # total seconds allowed for one response body
_TOTAL_DEADLINE = 40  # total seconds for one whole SCAN: the
# homepage fetch and every probe share this single budget


def _kill_conn(conn):
    """Watchdog action at the total deadline: shut the socket down
    so any blocked read (header or body) fails at once. A per-read
    socket timeout alone cannot bound a slow drip — every byte
    that arrives inside the timeout re-arms the wait — so the
    deadline is enforced by killing the connection, not by hoping
    the reads notice the clock."""
    try:
        sock = getattr(conn, "sock", None)
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass
    except Exception:
        pass


def _read_capped(resp, budget=None, sock=None, max_body=None,
                 abort_check=None):
    """Read a response body up to `max_body` bytes (default
    _MAX_BODY) under a TOTAL deadline, so a slow-drip server
    cannot hold the scanner open one byte at a time under the
    per-read socket timeout. The cap applies to the raw bytes as
    received; the scanner never decompresses, so a compressed
    bomb never expands. `budget` (seconds remaining in the
    fetch's total deadline) can only shorten the read, never
    extend it past _DEADLINE. When `sock` is given, its timeout
    is recomputed from the remaining budget before every chunk
    read, so no single read can wait past the deadline either.
    `abort_check(prefix)` is consulted after each chunk with
    up to the first 4096 bytes read so far: a true result stops
    the read early (the caller has already seen enough to judge
    the body — e.g. an exposed-lockfile probe whose response is
    obviously an HTML page); None means "no evidence yet, keep
    reading"."""
    cap = _MAX_BODY if max_body is None else max_body
    chunks, got = [], 0
    secs = _DEADLINE if budget is None else min(_DEADLINE, budget)
    end = time.monotonic() + secs
    while got <= cap:
        remaining = end - time.monotonic()
        if remaining <= 0:
            break
        if sock is not None:
            try:
                sock.settimeout(max(0.1, min(_TIMEOUT, remaining)))
            except Exception:
                pass
        try:
            chunk = resp.read(min(65536, cap + 1 - got))
        except http.client.IncompleteRead as e:
            # Server/proxy closed mid-body (common behind CDNs);
            # the partial body is still a successful fetch.
            if e.partial:
                chunks.append(e.partial)
            break
        if not chunk:
            break
        chunks.append(chunk)
        got += len(chunk)
        if abort_check is not None \
                and abort_check(b"".join(chunks)[:4096]):
            break
    return b"".join(chunks)[:cap]


def _headers_dict(resp):
    """Response headers as a dict, merging duplicates (notably
    Set-Cookie) instead of letting dict() keep only the last one —
    a PHPSESSID on an earlier Set-Cookie line must still be seen."""
    out = {}
    for k, v in resp.getheaders():
        out[k] = f"{out[k]}, {v}" if k in out else v
    return out


def _fetch(url, ctx=None, deadline=None, max_body=None,
           early_abort=None):
    """Guarded fetch: http/https only, ports 80/443 only, no URL
    credentials, every redirect hop re-validated and IP-pinned,
    body capped, and a TOTAL deadline across connect + headers +
    body + all hops, so a slow-drip server cannot hold a worker
    open. `deadline` (a time.monotonic() timestamp) lets the
    caller share ONE budget across a whole scan — homepage plus
    all probes — instead of granting each fetch its own; without
    it, the fetch gets _TOTAL_DEADLINE to itself. The deadline is
    enforced by a watchdog that kills the socket at the deadline:
    per-read socket timeouts alone cannot stop a drip, because
    each byte that arrives inside the timeout re-arms the wait.
    When a host resolves to several public IPs, each is tried in
    turn on connection-level failures. `early_abort(headers,
    prefix)` may cut the body read short once the response is
    judgeable (see _read_capped). Returns the same dict shape
    as before."""
    current = url
    end = deadline if deadline is not None else \
        time.monotonic() + _TOTAL_DEADLINE
    for _hop in range(_MAX_REDIRECTS + 1):
        err, parts, port = _preflight(current)
        if err:
            return {"ok": False, "status": None, "final_url": current,
                    "headers": {}, "body": "", "error": err}
        host = parts.hostname
        try:
            ips = _public_ips(host)
        except BlockedTarget as e:
            return {"ok": False, "status": None, "final_url": current,
                    "headers": {}, "body": "", "error": str(e)}
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        host_hdr = host if port in (80, 443) and \
            parts.port is None else f"{host}:{port}"
        last_err = None
        redirected = False
        for ip in ips:
            remaining = end - time.monotonic()
            if remaining <= 0:
                return {"ok": False, "status": None,
                        "final_url": current, "headers": {}, "body": "",
                        "error": "scan timed out: total deadline "
                                 f"({_TOTAL_DEADLINE}s) exceeded"}
            timeout = max(1.0, min(_TIMEOUT, remaining))
            conn = None
            watchdog = None
            try:
                if parts.scheme == "https":
                    conn = _PinnedHTTPS(ip, port, host, timeout)
                else:
                    conn = http.client.HTTPConnection(ip, port,
                                                      timeout=timeout)
                conn.request("GET", path,
                             headers={"User-Agent": _UA,
                                      "Host": host_hdr,
                                      "Accept": "*/*",
                                      "Connection": "close"})
                if getattr(conn, "sock", None) is not None:
                    watchdog = threading.Timer(
                        max(0.0, end - time.monotonic()),
                        _kill_conn, args=(conn,))
                    watchdog.daemon = True
                    watchdog.start()
                resp = conn.getresponse()
                status = resp.status
                headers = _headers_dict(resp)
                location = None
                for k, v in headers.items():
                    if k.lower() == "location":
                        location = v
                if status in (301, 302, 303, 307, 308) and location:
                    current = urllib.parse.urljoin(current, location)
                    redirected = True
                    break
                abort_check = None
                if early_abort is not None:
                    abort_check = lambda prefix: early_abort(
                        headers, prefix)
                raw = _read_capped(resp, end - time.monotonic(),
                                   sock=getattr(conn, "sock", None),
                                   max_body=max_body,
                                   abort_check=abort_check)
                body = raw.decode("utf-8", "replace")
                return {"ok": status < 400, "status": status,
                        "final_url": current, "headers": headers,
                        "body": body,
                        "error": None if status < 400
                        else f"HTTP {status}"}
            except Exception as e:  # DNS, TLS, timeout, refused
                last_err = e
            finally:
                if watchdog is not None:
                    watchdog.cancel()
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
        if time.monotonic() >= end:
            return {"ok": False, "status": None,
                    "final_url": current, "headers": {}, "body": "",
                    "error": "scan timed out: total deadline "
                             f"({_TOTAL_DEADLINE}s) exceeded"}
        if redirected:
            continue
        return {"ok": False, "status": None, "final_url": current,
                "headers": {}, "body": "", "error": str(last_err)}
    return {"ok": False, "status": None, "final_url": current,
            "headers": {}, "body": "",
            "error": f"too many redirects (>{_MAX_REDIRECTS})"}



def _h(headers, name):
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return ""


_INSTALLED_PATH = "/vendor/composer/installed.json"

_SCOPE_NOTE = ("Scope: versions are taken from the exposed "
               "{name}, which may differ from what is actually "
               "deployed on the server.")


def _body_too_large(r, body):
    """True when the response was cut by the bounded read: a
    Content-Length past the cap, or a body that arrives at
    exactly the cap and then fails to parse."""
    cl = _h(r.get("headers") or {}, "Content-Length")
    try:
        if cl and int(cl) > _LOCK_MAX_BODY:
            return True
    except ValueError:
        pass
    return len((body or "").encode("utf-8", "replace")) \
        >= _LOCK_MAX_BODY


def _installed_to_lock(data):
    """Normalize vendor/composer/installed.json to a lock-shaped
    dict for the audit engine: a {"packages": [...]} mapping
    (Composer 2) or a bare package list (Composer 1), with the
    per-package dev-requirement flag split into packages-dev.
    Returns None for anything that is not recognizably that
    manifest."""
    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict) \
            and isinstance(data.get("packages"), list):
        entries = data["packages"]
    else:
        return None
    pkgs, dev_pkgs = [], []
    for e in entries:
        if isinstance(e, dict) and e.get("name") \
                and e.get("version"):
            (dev_pkgs if e.get("dev-requirement")
             else pkgs).append(e)
    if not pkgs and not dev_pkgs:
        return None
    return {"packages": pkgs, "packages-dev": dev_pkgs}


def _audit_exposed(fetch, url, path, prov_type, kind, noun,
                   to_lock, offline):
    """One exposed dependency file: fetch it (bounded read),
    prove it is what it claims to be (valid JSON, lock-shaped
    with a `packages` list — a catch-all 200 or an HTML page
    proves nothing), and audit its versions. Returns
    (lock_info, scan_findings); lock_info is None when no file
    is confirmed exposed there."""
    try:
        r = fetch(url)
    except Exception:
        return None, []
    if not r or r.get("status") != 200:
        return None, []
    body = r.get("body") or ""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        data = None
    lock = to_lock(data) if data is not None else None
    if lock is None:
        if data is None and _body_too_large(r, body) \
                and body.lstrip().startswith("{"):
            # Exposed, but past the bounded read: the honest
            # report is "exposed; too large to audit fully",
            # never a silent skip that looks like absence.
            info = {
                "source": prov_type, "source_url": url,
                "audit_status": "too_large_to_audit",
                "scope": _SCOPE_NOTE.format(name=noun),
                "packages_scanned": 0, "dev_packages_scanned": 0,
                "sources": {"osv": {"status": "not_run"},
                            "friendsofphp": {
                                "snapshot_date": None,
                                "commit": None},
                            "kev": {"snapshot_date": None,
                                    "catalog_version": None}},
                "findings": [], "unassessed": []}
            finding = {
                "kind": kind, "severity": "medium",
                "title": f"{noun} publicly exposed",
                "detail": f"The site's {noun} answers publicly "
                          f"at {path}, but its body exceeds the "
                          f"scan's bounded read "
                          f"({_LOCK_MAX_BODY} bytes): exposed; "
                          "too large to audit fully. The exposure "
                          "itself discloses the site's dependency "
                          "versions. "
                          + _SCOPE_NOTE.format(name=noun),
                "remediation": f"Remove {noun} from the web "
                               "root or deny access to it at "
                               "the web server (like /.env and "
                               "/.git), and deploy from a build "
                               "step that keeps composer files "
                               "outside the served tree.",
                "path": path,
                "provenance": {"type": prov_type, "url": url}}
            return info, [finding]
        return None, []
    try:
        report, _code = audit.audit_lock(lock, url, offline=offline)
    except (ValueError, TypeError, KeyError):
        return None, []

    provenance = {"type": prov_type, "url": url}
    for f in report["findings"]:
        f["provenance"] = dict(provenance)
    lock_info = {
        "source": prov_type,
        "source_url": url,
        "scope": _SCOPE_NOTE.format(name=noun),
        "packages_scanned": report["packages_scanned"],
        "dev_packages_scanned": report["dev_packages_scanned"],
        "sources": report["sources"],
        "findings": report["findings"],
        "unassessed": report["unassessed"],
    }

    total = report["packages_scanned"] + report["dev_packages_scanned"]
    out = [{
        "kind": kind, "severity": "medium",
        "title": f"{noun} publicly exposed",
        "detail": f"The site's {noun} answers publicly at "
                  f"{path}. It discloses the exact version "
                  f"of every dependency the site runs ({total} "
                  f"locked package(s)), which lets an attacker "
                  f"shop for a matching exploit instead of probing "
                  f"blind. The scan audited those versions; the "
                  f"results are under 'dependencies'. "
                  + _SCOPE_NOTE.format(name=noun),
        "remediation": f"Remove {noun} from the web root "
                       "or deny access to it at the web server "
                       "(like /.env and /.git), and deploy from a "
                       "build step that keeps composer files "
                       "outside the served tree.",
        "path": path,
        "provenance": dict(provenance)}]
    for f in report["findings"]:
        level = audit.severity_level(f)
        if level is None:
            # No published severity and not KEV-listed: the
            # finding stands in `dependencies` at full fidelity,
            # but it is not dressed up with a severity it does
            # not carry, and it does not escalate the verdict.
            continue
        detail = (f"{f['title']} — pinned version {f['version']} "
                  f"of {f['package']} in the exposed {noun} "
                  f"is affected by {f['id']}.")
        if f.get("kev"):
            detail += (" The CVE is in CISA's Known Exploited "
                       "Vulnerabilities catalog (confirmed "
                       "exploited in the wild).")
        if f.get("dev"):
            detail += " (Dev-only dependency.)"
        out.append({
            "kind": "vulnerable_dependency", "severity": level,
            "title": f"Vulnerable dependency: {f['package']} "
                     f"{f['version']} ({f['id']})",
            "detail": detail,
            "remediation": f["remediation"],
            "package": f["package"], "version": f["version"],
            "dev": f["dev"], "advisory_id": f["id"],
            "cve": f.get("cve"), "kev": bool(f.get("kev")),
            "fixed": f.get("fixed"),
            "provenance": dict(provenance)})
    return lock_info, out


def _lock_early_abort(headers, prefix):
    """Early-abort predicate for the exposed-lockfile probe.
    A composer.lock is a JSON document: if the response's
    Content-Type says HTML, or its first non-whitespace byte is
    not '{', the body is not a lockfile and the remaining bytes
    (up to the 8 MB cap) are worthless — stop reading. Returns
    True to abort, False to keep reading, None while the prefix
    is all whitespace (no evidence yet)."""
    ctype = ""
    if headers:
        ctype = (headers.get("content-type") or "").lower()
    if "text/html" in ctype:
        return True
    stripped = prefix.lstrip()
    if not stripped:
        return None
    return stripped[:1] != b"{"


def _exposed_lock(fetch, base, offline=False):
    """Audit a publicly exposed dependency file, if one is
    really there: /composer.lock first, then
    /vendor/composer/installed.json (which reflects what is
    actually installed, and is exposed by the same class of
    misconfiguration). Returns (lock_info, scan_findings):
    lock_info is the value for the result's "dependencies" key
    — None whenever neither file is confirmed exposed — and
    scan_findings carries the exposure finding plus one
    vulnerable-dependency finding per audit finding whose
    severity the published evidence supports.

    The fetched body is untrusted input: JSON parsing is
    defensive, the structure must validate as a lock (a dict
    with a `packages` list) before anything is believed, and
    the package list itself is never echoed into output —
    counts and findings only. Every merged finding is stamped
    with its provenance: the exposed file and its URL."""
    info, out = _audit_exposed(
        fetch, base + _LOCK_PATH, _LOCK_PATH,
        "exposed_composer_lock", "composer_lock_exposed",
        "composer.lock",
        lambda d: d if isinstance(d, dict)
        and isinstance(d.get("packages"), list) else None,
        offline)
    if info is not None or out:
        return info, out
    return _audit_exposed(
        fetch, base + _INSTALLED_PATH, _INSTALLED_PATH,
        "exposed_installed_json", "installed_json_exposed",
        "installed.json", _installed_to_lock, offline)


def scan(url, offline=False):
    if not re.match(r"^https?://", url):
        url = "https://" + url
    # One deadline for the WHOLE scan: the homepage fetch and all
    # four phpinfo probes draw from the same _TOTAL_DEADLINE
    # budget, so a scan can never run ~5x the deadline.
    end = time.monotonic() + _TOTAL_DEADLINE
    home = _fetch(url, deadline=end)
    result = {"schema_version": 1,
              "target": url, "reachable": home["ok"],
              "http_status": home["status"], "final_url": home["final_url"],
              "error": home.get("error"), "signals": {},
              "php_version": None, "version_source": None,
              "cms": [], "cms_info": [], "plugins": [],
              "findings": [], "phpinfo_exposed": False,
              "dependencies": None,
              "coverage": {"probes_attempted": 0,
                           "probes_completed": 0,
                           "probes_skipped_deadline": 0,
                           "catch_all": False, "sources": {}},
              "verdict": None,
              "compromise_indicators": []}
    if not home["ok"] and home["status"] is None:
        result["verdict"] = {"status": "unreachable",
                             "detail": f"Site did not answer: "
                                       f"{home.get('error')}"}
        return result

    headers, body = home["headers"], home["body"]
    xpb = _h(headers, "X-Powered-By")
    server = _h(headers, "Server")
    cookies = _h(headers, "Set-Cookie")
    gen = _h(headers, "X-Generator")
    if xpb:
        result["signals"]["x_powered_by"] = xpb
    if server:
        result["signals"]["server"] = server
    if "PHPSESSID" in cookies:
        result["signals"]["phpsessid_cookie"] = True
    if gen:
        result["signals"]["x_generator"] = gen

    # CMS fingerprints — same discipline as detect.py: a bare
    # substring mention in prose is not a fingerprint. A hit
    # needs a generator/header signal, a path in tag/attribute
    # context, or two independent substrings.
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+'
                  r'content=["\']([^"\']+)', body, re.I)
    meta_gen = m.group(1) if m else ""
    low = body.lower()
    if "wordpress" in meta_gen.lower() \
            or detect._in_tag_context(body, "wp-content/") \
            or detect._in_tag_context(body, "wp-includes/") \
            or ("wp-content" in low and "wp-includes" in low):
        result["cms"].append("WordPress")
    if "powered by phpbb" in low \
            or detect._in_tag_context(body, "styles/prosilver"):
        result["cms"].append("phpBB")
    if "joomla" in meta_gen.lower() \
            or detect._in_tag_context(body, "/media/jui/"):
        result["cms"].append("Joomla")
    if "drupal" in gen.lower() \
            or detect._in_tag_context(body, "/core/modules/"):
        result["cms"].append("Drupal")
    if meta_gen:
        result["signals"]["meta_generator"] = meta_gen

    # Exact version disclosure: headers first
    raw_version_text = ""
    for src, text in (("X-Powered-By", xpb), ("Server", server)):
        v = versioning.parse_version(re.search(r"PHP/(\S+)", text).group(1)) \
            if re.search(r"PHP/(\S+)", text) else None
        if v:
            result["php_version"] = versioning.fmt(v)
            result["version_source"] = src
            raw_version_text = re.search(r"PHP/(\S+)", text).group(1)
            break

    # phpinfo probes — an exposed phpinfo both leaks the exact version
    # and is itself a finding, so the probes run on every scan (the
    # footprint is the four well-known paths, nothing more). Probes
    # are built from the final URL's ORIGIN only: appending a probe
    # path to a deep final URL (…/en/index.php?x=1) would request a
    # nonsense URL and miss a real exposed phpinfo at the root.
    _fp = urllib.parse.urlsplit(home["final_url"])
    base = f"{_fp.scheme}://{_fp.netloc}"

    # Coverage accounting (the family's completeness contract):
    # every probe fetch after the homepage goes through
    # _probe_fetch, which counts what was attempted, what
    # actually completed with an HTTP answer, and what the
    # shared deadline starved — so a report can never silently
    # present un-run probes as negative results.
    coverage = result["coverage"]

    def _probe_fetch(url, ctx=None, deadline=None, max_body=None,
                     early_abort=None):
        coverage["probes_attempted"] += 1
        try:
            if max_body is not None or early_abort is not None:
                r = _fetch(url, deadline=end, max_body=max_body,
                           early_abort=early_abort)
            else:
                r = _fetch(url, deadline=end)
        except TypeError:
            # Fetch doubles written before the max_body parameter.
            r = _fetch(url, deadline=end)
        if r and r.get("status") is not None:
            coverage["probes_completed"] += 1
        elif r and "deadline" in str(r.get("error") or ""):
            coverage["probes_skipped_deadline"] += 1
        return r

    # Soft-404 / catch-all control, before any existence probe
    # trusts a 200: one random path that cannot exist. The
    # result feeds the coverage block and the shell-path
    # checks (which additionally require a shell signature in
    # the body — see hunt.remote_indicators).
    from . import hunt as _hunt_mod
    catch_all, _control_path = _hunt_mod.catch_all_control(
        _probe_fetch, base, deadline=end)
    coverage["catch_all"] = catch_all

    for path in _PHPINFO_PATHS:
        probe = _probe_fetch(base + path)
        b = probe["body"]
        if probe["status"] == 200 and "phpinfo()" in b and \
                re.search(r"PHP Version\s*&?#?\w*\s*([0-9]+\.[0-9]+\.[0-9]+)", b):
            vm = re.search(r"PHP Version[^0-9]*([0-9]+\.[0-9]+\.[0-9]+)", b)
            result["phpinfo_exposed"] = True
            result["signals"]["phpinfo_path"] = path
            if vm and result["php_version"] is None:
                result["php_version"] = vm.group(1)
                result["version_source"] = f"phpinfo ({path})"
                raw_version_text = vm.group(0)
            break

    # Compromise light-check: a short list of famous webshell
    # paths, probed through the same guarded fetch. A path is
    # reported only when its body carries a known shell
    # signature (the catch-all control above has already run);
    # a bare 200 proves nothing. An indicator is a lead to
    # investigate with the local `phpscan hunt`, never a
    # conclusion on its own.
    result["compromise_indicators"] = _hunt_mod.remote_indicators(
        _probe_fetch, base, deadline=end, catch_all=catch_all)

    # CMS/plugin detection + config hygiene (detect.py /
    # hygiene.py): the extra read-only probes (REST index,
    # readme files, /.git/HEAD, /.env, directory indexes) draw
    # from the same shared scan deadline as everything else.
    cms_info, plugin_list, findings = detect.analyze(
        headers, body, _probe_fetch, base, pre_cms=result["cms"])
    for info in cms_info:
        if info["name"] not in result["cms"]:
            result["cms"].append(info["name"])
    result["cms_info"] = cms_info
    result["plugins"] = plugin_list
    findings += hygiene.header_findings(headers, _fp.scheme)
    findings += hygiene.exposure_probes(_probe_fetch, base,
                                         result["cms"])

    # Exposed composer.lock: the exposure is a hygiene finding,
    # and the locked versions are audited by the dependency
    # engine and merged into this same report. The read is
    # bounded (_LOCK_MAX_BODY); test doubles written before the
    # max_body parameter fall back to the standard cap.
    def _probe_lock(u):
        return _probe_fetch(u, max_body=_LOCK_MAX_BODY,
                            early_abort=_lock_early_abort)

    lock_info, lock_findings = _exposed_lock(_probe_lock, base,
                                             offline=offline)
    result["dependencies"] = lock_info
    if lock_info:
        coverage["sources"] = {
            "osv": lock_info["sources"]["osv"]["status"],
            "friendsofphp": "ok"}
    findings += lock_findings
    if result["phpinfo_exposed"]:
        findings.append(hygiene.phpinfo_finding(
            result["signals"].get("phpinfo_path",
                                  "/phpinfo.php")))
    findings.sort(key=lambda f: detect.SEVERITY_RANK[
        f["severity"]])
    result["findings"] = findings

    vtuple = versioning.parse_version(result["php_version"])
    if vtuple:
        result["verdict"] = versioning.verdict_for(
            vtuple,
            distro=versioning.distro_build(raw_version_text),
            prerelease=versioning.is_prerelease(raw_version_text))
    elif result["signals"] or result["cms"]:
        result["verdict"] = {
            "status": "indeterminate",
            "detail": "PHP is present (fingerprinted) but the version is "
                      "not disclosed, so the patch status cannot be "
                      "confirmed from outside. Run the deep check (SSH, "
                      "read-only) for a definitive verdict.",
            "remediation": _HIDDEN_REMEDIATION,
            "next_steps": list(_HIDDEN_NEXT_STEPS)}
    else:
        result["verdict"] = {
            "status": "no_php_detected",
            "detail": "No PHP signals found. The site may not run PHP, or "
                      "may hide every fingerprint."}
    result["verdict"] = detect.apply_findings(
        result["verdict"], result["findings"])
    return result


def render_text(r):
    lines = [f"Target:      {r['target']}",
             f"Reachable:   {r['reachable']} (HTTP {r['http_status']})",
             f"Final URL:   {r['final_url']}"]
    if r["cms"]:
        lines.append(f"CMS:         {', '.join(r['cms'])}")
    if r["php_version"]:
        lines.append(f"PHP version: {r['php_version']} "
                     f"(via {r['version_source']})")
    if r["phpinfo_exposed"]:
        lines.append("!! phpinfo page is publicly exposed — remove it.")
    for ind in r.get("compromise_indicators") or []:
        lines.append(f"!! Possible compromise indicator: {ind['path']} "
                     "answers in public. Indicative only — confirm "
                     "with `phpscan hunt` on the server.")
    for f in r.get("findings") or []:
        lines.append(f"FINDING [{f['severity'].upper()}]: "
                     f"{f['title']}")
        lines.append(f"             Fix: {f['remediation']}")
    deps = r.get("dependencies")
    if deps:
        total = deps["packages_scanned"] + deps["dev_packages_scanned"]
        lines.append(f"Dependencies: {total} package(s) audited from "
                     f"the exposed composer.lock "
                     f"({deps['source_url']})")
        for f in deps["findings"]:
            level = audit.severity_level(f)
            tag = level.upper() if level else "UNRATED"
            lines.append(f"  DEP [{tag}]: {f['package']} "
                         f"{f['version']} — {f['id']}: {f['title']}")
            lines.append(f"             Fix: {f['remediation']}")
        if deps["unassessed"]:
            lines.append(f"  ({len(deps['unassessed'])} package/"
                         "advisory pair(s) could not be assessed; "
                         "no verdict is claimed for them.)")
    v = r["verdict"]
    lines.append(f"VERDICT:     {v['status'].upper()}")
    lines.append(f"             {v['detail']}")
    if v["status"] == "indeterminate":
        lines.append("NEXT:        Most well-run sites hide their PHP "
                     "version, so an outside scan cannot be certain. "
                     "For a certain answer, run the read-only deep "
                     "check on the server (it only reads versions and "
                     "changes nothing):")
        lines.append("               phppatch deepcheck --host "
                     "root@your-server")
        lines.append("             Site ownership is verified before "
                     "any deeper check. This scan used passive fingerprinting and limited, read-only path checks only — no exploit probes.")
        lines.append("             If this is your site:")
        for i, step in enumerate(_HIDDEN_NEXT_STEPS, 1):
            lines.append(f"               {i}. {step}")
        lines.append(f"             {_HIDDEN_NOT_YOURS}")
    return "\n".join(lines)
