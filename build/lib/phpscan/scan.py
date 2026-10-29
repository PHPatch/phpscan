"""Step 1a — external scan (no credentials).

Fingerprints PHP from what a site discloses over HTTP: X-Powered-By /
Server headers, PHPSESSID cookies, CMS generator signals, and exposed
phpinfo pages. An exact version, when disclosed, is checked against the
patched-release floors.

Honest limit: most well-run sites suppress version headers. For those the
scan reports "PHP detected, version hidden — patch status cannot be
confirmed from outside" and recommends the credentialed deep check.
"""

import http.client
import ipaddress
import re
import socket
import ssl
import threading
import time
import urllib.parse

from . import versioning

_UA = "phpscan/1.4.4 (+https://phpatch.com/security)"
_TIMEOUT = 12
_MAX_BODY = 512 * 1024
_MAX_REDIRECTS = 5
_PHPINFO_PATHS = ("/phpinfo.php", "/info.php", "/php-info.php", "/test.php")


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


def _read_capped(resp, budget=None, sock=None):
    """Read a response body up to _MAX_BODY bytes under a TOTAL
    deadline, so a slow-drip server cannot hold the scanner open
    one byte at a time under the per-read socket timeout. The cap
    applies to the raw bytes as received; the scanner never
    decompresses, so a compressed bomb never expands. `budget`
    (seconds remaining in the fetch's total deadline) can only
    shorten the read, never extend it past _DEADLINE. When `sock`
    is given, its timeout is recomputed from the remaining budget
    before every chunk read, so no single read can wait past the
    deadline either."""
    chunks, got = [], 0
    secs = _DEADLINE if budget is None else min(_DEADLINE, budget)
    end = time.monotonic() + secs
    while got <= _MAX_BODY:
        remaining = end - time.monotonic()
        if remaining <= 0:
            break
        if sock is not None:
            try:
                sock.settimeout(max(0.1, min(_TIMEOUT, remaining)))
            except Exception:
                pass
        try:
            chunk = resp.read(min(65536, _MAX_BODY + 1 - got))
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
    return b"".join(chunks)[:_MAX_BODY]


def _headers_dict(resp):
    """Response headers as a dict, merging duplicates (notably
    Set-Cookie) instead of letting dict() keep only the last one —
    a PHPSESSID on an earlier Set-Cookie line must still be seen."""
    out = {}
    for k, v in resp.getheaders():
        out[k] = f"{out[k]}, {v}" if k in out else v
    return out


def _fetch(url, ctx=None, deadline=None):
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
    turn on connection-level failures. Returns the same dict
    shape as before."""
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
                raw = _read_capped(resp, end - time.monotonic(),
                                   sock=getattr(conn, "sock", None))
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


def scan(url):
    if not re.match(r"^https?://", url):
        url = "https://" + url
    # One deadline for the WHOLE scan: the homepage fetch and all
    # four phpinfo probes draw from the same _TOTAL_DEADLINE
    # budget, so a scan can never run ~5x the deadline.
    end = time.monotonic() + _TOTAL_DEADLINE
    home = _fetch(url, deadline=end)
    result = {"target": url, "reachable": home["ok"],
              "http_status": home["status"], "final_url": home["final_url"],
              "error": home.get("error"), "signals": {},
              "php_version": None, "version_source": None,
              "cms": [], "phpinfo_exposed": False, "verdict": None}
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

    # CMS fingerprints
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+'
                  r'content=["\']([^"\']+)', body, re.I)
    meta_gen = m.group(1) if m else ""
    low = body.lower()
    if "wp-content" in low or "wp-includes" in low or \
            "wordpress" in meta_gen.lower():
        result["cms"].append("WordPress")
    if "powered by phpbb" in low or "styles/prosilver" in low:
        result["cms"].append("phpBB")
    if "joomla" in meta_gen.lower() or "/media/jui/" in low:
        result["cms"].append("Joomla")
    if "drupal" in gen.lower() or "/core/modules/" in low:
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
    for path in _PHPINFO_PATHS:
        probe = _fetch(base + path, deadline=end)
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

    vtuple = versioning.parse_version(result["php_version"])
    if vtuple:
        result["verdict"] = versioning.verdict_for(
            vtuple,
            distro=versioning.distro_build(raw_version_text))
    elif result["signals"] or result["cms"]:
        result["verdict"] = {
            "status": "indeterminate",
            "detail": "PHP is present (fingerprinted) but the version is "
                      "not disclosed, so the patch status cannot be "
                      "confirmed from outside. Run the deep check (SSH, "
                      "read-only) for a definitive verdict."}
    else:
        result["verdict"] = {
            "status": "no_php_detected",
            "detail": "No PHP signals found. The site may not run PHP, or "
                      "may hide every fingerprint."}
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
    return "\n".join(lines)
