"""SSRF checklist tests for the phpscan fetcher.

Every target from the public SSRF review checklist (2026-10-22)
is a named case here. Tests are hermetic: the resolver and the
HTTP connections are stubbed, so no test touches the network.
Run: python3 -m unittest discover -s tests
"""

import gzip
import io
import socket
import threading
import time
import unittest
from contextlib import redirect_stdout
from unittest import mock

from phpscan import __main__ as cli
from phpscan import scan, versioning

PUBLIC = "93.184.216.34"
META = "169.254.169.254"
LOOP = "127.0.0.1"


def gai_map(mapping):
    def _gai(host, port, *a, **k):
        if host not in mapping:
            raise socket.gaierror(f"no stub answer for {host}")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 (mapping[host], 0))]
    return _gai


def gai_smart(host, port, *a, **k):
    """Literal IPs answer as themselves; known names map; the
    rest fail DNS (as a resolver disagreement would surface)."""
    try:
        import ipaddress
        ipaddress.ip_address(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, 0))]
    except ValueError:
        pass
    table = {"localhost": LOOP, "localhost.": LOOP,
             "metadata.google.internal": META,
             "example.com": PUBLIC,
             "127.0.0.1.nip.io": LOOP, "localtest.me": LOOP}
    if host in table:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 (table[host], 0))]
    raise socket.gaierror(f"no stub answer for {host}")


class FakeResp:
    def __init__(self, status=200, headers=(), chunks=(b"ok",)):
        self.status = status
        self._headers = list(headers)
        self._chunks = list(chunks)

    def getheaders(self):
        return list(self._headers)

    def read(self, n=-1):
        if not self._chunks:
            return b""
        c = self._chunks.pop(0)
        if n is not None and n >= 0 and len(c) > n:
            self._chunks.insert(0, c[n:])
            return c[:n]
        return c


class FakeConn:
    instances = []
    responder = staticmethod(lambda conn: FakeResp())

    def __init__(self, host, port, timeout=None, **kw):
        self.host, self.port = host, port
        FakeConn.instances.append(self)

    def request(self, method, path, headers=None):
        self.req = (method, path)

    def getresponse(self):
        # Dispatch through the instance's own class: a subclass may
        # carry its own responder (FakePinned does). Hard-coding
        # FakeConn.responder here made every test share one mutable
        # class attribute, so the suite's result depended on which
        # test ran last — green under unittest's alphabetical order,
        # red under pytest's definition order.
        return type(self).responder(self)

    def close(self):
        pass


class FakePinned(FakeConn):
    def __init__(self, ip, port, sni_host, timeout):
        super().__init__(ip, port, timeout=timeout)
        self.sni_host = sni_host


class LiteralRefusals(unittest.TestCase):
    URLS = [
        "http://127.0.0.1/", "http://localhost/", "http://localhost./",
        "http://127.1/", "http://2130706433/", "http://0x7f000001/",
        "http://017700000001/", "http://0/", "http://[::1]/",
        "http://[::ffff:127.0.0.1]/", "http://[::ffff:7f00:1]/",
        "http://10.0.0.1/", "http://172.16.0.1/", "http://192.168.1.1/",
        "http://100.64.0.1/", "http://169.254.169.254/",
        "http://[fd00:ec2::254]/", "http://metadata.google.internal/",
    ]

    def test_every_spelling_refused(self):
        for url in self.URLS:
            with mock.patch.object(scan.socket, "getaddrinfo", gai_smart):
                r = scan._fetch(url)
            self.assertFalse(r["ok"], url)
            self.assertTrue(r["error"], url)

    def test_refusals_say_why(self):
        # A refusal must assert its REASON (an earlier suite only
        # asserted "not ok + some error", which let a 12-second
        # timeout pass as a refusal). Resolved-address refusals say
        # "non-public"; encoded-literal refusals say "refused".
        for url in ("http://100.64.0.1/", "http://192.168.1.1/",
                    "http://169.254.169.254/", "http://localtest.me/"):
            with mock.patch.object(scan.socket, "getaddrinfo", gai_smart):
                r = scan._fetch(url)
            self.assertIn("non-public", r["error"], url)
        # The resolved IP must not leak back into the message: for
        # a name, the internal answer stays private.
        with mock.patch.object(scan.socket, "getaddrinfo", gai_smart):
            r = scan._fetch("http://localtest.me/")
        self.assertNotIn("127.0.0.1", r["error"])
        for url in ("http://127.1/", "http://2130706433/",
                    "http://0x7f000001/"):
            with mock.patch.object(scan.socket, "getaddrinfo", gai_smart):
                r = scan._fetch(url)
            self.assertIn("refused", r["error"], url)


class ParserTricks(unittest.TestCase):
    def test_tricks_refused(self):
        urls = ["http://example.com\\@127.0.0.1/",
                "http://127.0.0.1#@example.com/",
                "http://user:pass@example.com/",
                "http://example.com:8080/",
                "ftp://example.com/", "file:///etc/passwd",
                "gopher://example.com/"]
        for url in urls:
            with mock.patch.object(scan.socket, "getaddrinfo", gai_smart):
                r = scan._fetch(url)
            self.assertFalse(r["ok"], url)
            self.assertTrue(r["error"], url)


class ResolvingNames(unittest.TestCase):
    def test_names_resolving_private_refused(self):
        for host in ("127.0.0.1.nip.io", "localtest.me"):
            with mock.patch.object(scan.socket, "getaddrinfo", gai_smart):
                r = scan._fetch(f"http://{host}/")
            self.assertFalse(r["ok"], host)

    def test_public_name_passes(self):
        with mock.patch.object(scan.socket, "getaddrinfo", gai_smart):
            self.assertEqual(scan._public_ips("example.com"), [PUBLIC])


class Redirects(unittest.TestCase):
    def setUp(self):
        FakeConn.instances = []

    def _run(self, responder, url="http://example.com/"):
        FakeConn.responder = staticmethod(responder)
        with mock.patch.object(scan.socket, "getaddrinfo", gai_smart), \
                mock.patch.object(scan.http.client, "HTTPConnection",
                                  FakeConn):
            return scan._fetch(url)

    def test_redirect_to_metadata_refused_before_connect(self):
        r = self._run(lambda c: FakeResp(
            302, [("Location", "http://169.254.169.254/")]))
        self.assertFalse(r["ok"])
        self.assertIn("non-public", r["error"])
        self.assertEqual(len(FakeConn.instances), 1)

    def test_redirect_loop_stops(self):
        r = self._run(lambda c: FakeResp(
            302, [("Location", "http://example.com/")]))
        self.assertFalse(r["ok"])
        self.assertIn("too many redirects", r["error"])

    def test_redirect_to_file_scheme_refused(self):
        r = self._run(lambda c: FakeResp(
            302, [("Location", "file:///etc/passwd")]))
        self.assertFalse(r["ok"])
        self.assertIn("http/https", r["error"])

    def test_redirect_to_bad_port_refused(self):
        r = self._run(lambda c: FakeResp(
            302, [("Location", "http://example.com:8080/")]))
        self.assertFalse(r["ok"])
        self.assertIn("80 and 443", r["error"])


class RebindingAndPinning(unittest.TestCase):
    def test_rebinding_second_answer_never_used(self):
        calls = []

        def flip(host, port, *a, **k):
            calls.append(host)
            ip = PUBLIC if len(calls) == 1 else LOOP
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

        FakeConn.instances = []
        FakeConn.responder = staticmethod(lambda c: FakeResp(200))
        with mock.patch.object(scan.socket, "getaddrinfo", flip), \
                mock.patch.object(scan.http.client, "HTTPConnection",
                                  FakeConn):
            r = scan._fetch("http://example.com/")
        self.assertTrue(r["ok"])
        self.assertEqual(FakeConn.instances[0].host, PUBLIC)

    def test_https_pins_ip_and_checks_cert_against_hostname(self):
        seen = {}

        class Rec(FakePinned):
            def __init__(self, ip, port, sni_host, timeout):
                super().__init__(ip, port, sni_host, timeout)
                seen.update(ip=ip, sni=sni_host)

        FakePinned.responder = staticmethod(lambda c: FakeResp(200))
        with mock.patch.object(scan.socket, "getaddrinfo", gai_smart), \
                mock.patch.object(scan, "_PinnedHTTPS", Rec):
            r = scan._fetch("https://example.com/")
        self.assertTrue(r["ok"])
        self.assertEqual(seen, {"ip": PUBLIC, "sni": "example.com"})


class ResourceCaps(unittest.TestCase):
    def test_body_capped(self):
        big = FakeResp(200, chunks=[b"A" * (scan._MAX_BODY + 5000)])
        self.assertEqual(len(scan._read_capped(big)), scan._MAX_BODY)

    def test_gzip_never_expanded(self):
        bomb = gzip.compress(b"A" * 200000)
        resp = FakeResp(200, [("Content-Encoding", "gzip")], [bomb])
        raw = scan._read_capped(resp)
        self.assertLessEqual(len(raw), scan._MAX_BODY)
        self.assertNotEqual(raw, b"A" * 200000)

    def test_total_deadline_stops_slow_drip(self):
        class Drip:
            def read(self, n=-1):
                return b"x"

        with mock.patch.object(scan, "_DEADLINE", -1):
            self.assertEqual(scan._read_capped(Drip()), b"")


class DistroWording(unittest.TestCase):
    def test_distro_detection(self):
        self.assertTrue(versioning.distro_build("8.3.6-0ubuntu0.24.04.3"))
        self.assertTrue(versioning.distro_build("8.2.20-1~deb12u1"))
        self.assertFalse(versioning.distro_build("8.3.36"))
        self.assertFalse(versioning.distro_build(None))

    def test_distro_verdict_is_check_not_proof(self):
        v = versioning.verdict_for((8, 3, 6), distro=True)
        self.assertEqual(v["status"], "possibly_vulnerable")
        self.assertIn("check signal, not proof", v["detail"])

    def test_patched_is_not_a_general_guarantee(self):
        v = versioning.verdict_for((8, 3, 36))
        self.assertEqual(v["status"], "patched")
        self.assertIn("not a general security guarantee", v["detail"])


class BlockedRanges(unittest.TestCase):
    """Ranges the old is_private-based check missed (found by the
    2026-10-22 review): CGNAT / shared address space (incl. cloud
    metadata endpoints living there), benchmarking space, the
    deprecated 6to4 relay anycast, and the NAT64 / Teredo
    transition prefixes. Each must be refused by ADDRESS POLICY —
    with the reason in the message — and no connection may be
    attempted at all."""
    URLS = ["http://100.64.0.1/", "http://100.100.100.200/",
            "http://198.18.0.5/", "http://192.88.99.1/",
            "http://[64:ff9b::c000:201]/", "http://[2001::1]/"]

    def test_blocked_with_reason_and_no_connect(self):
        for url in self.URLS:
            boom = mock.Mock(
                side_effect=AssertionError("connect attempted"))
            with mock.patch.object(scan.socket, "getaddrinfo",
                                   gai_smart), \
                    mock.patch.object(scan.http.client,
                                      "HTTPConnection", boom), \
                    mock.patch.object(scan, "_PinnedHTTPS", boom):
                r = scan._fetch(url)
            self.assertFalse(r["ok"], url)
            self.assertIn("non-public", r["error"], url)


class VersionBoundaries(unittest.TestCase):
    def test_floor_boundaries(self):
        cases = [((8, 2, 34), "vulnerable"), ((8, 2, 35), "patched"),
                 ((8, 3, 35), "vulnerable"), ((8, 3, 36), "patched"),
                 ((8, 5, 11), "vulnerable"), ((8, 5, 12), "patched")]
        for version, want in cases:
            self.assertEqual(
                versioning.verdict_for(version)["status"], want,
                version)

    def test_eol_branch_wording(self):
        v = versioning.verdict_for((8, 1, 34))
        self.assertEqual(v["status"], "eol")
        self.assertIn("partially", v["detail"])
        self.assertIn("offline", v["detail"])

    def test_eol_distro_caveat(self):
        v = versioning.verdict_for((8, 1, 2), distro=True)
        self.assertEqual(v["status"], "eol")
        self.assertIn("distribution", v["detail"])

    def test_unknown_newer_branch_not_assessed(self):
        v = versioning.verdict_for((8, 9, 1))
        self.assertEqual(v["status"], "not_assessed")


class ScanFixtures(unittest.TestCase):
    """Fixture-driven scan() runs: _fetch is stubbed, so scan()'s
    own logic (verdict wiring, probe construction) is exercised
    without any network."""

    def _home(self, **kw):
        d = {"ok": True, "status": 200,
             "final_url": "https://example.com/",
             "headers": {}, "body": "<html></html>", "error": None}
        d.update(kw)
        return d

    def test_header_version_verdict(self):
        calls = []

        def fake_fetch(url, ctx=None, deadline=None):
            calls.append(url)
            if len(calls) == 1:
                return self._home(
                    headers={"X-Powered-By": "PHP/8.3.35"})
            return self._home(status=404, ok=False,
                              error="HTTP 404")

        with mock.patch.object(scan, "_fetch", fake_fetch):
            r = scan.scan("https://example.com/")
        self.assertEqual(r["php_version"], "8.3.35")
        self.assertEqual(r["verdict"]["status"], "vulnerable")

    def test_probes_built_from_origin_not_final_path(self):
        calls = []

        def fake_fetch(url, ctx=None, deadline=None):
            calls.append(url)
            if len(calls) == 1:
                return self._home(
                    final_url="https://example.com/en/index.php?x=1")
            return self._home(status=404, ok=False,
                              error="HTTP 404")

        with mock.patch.object(scan, "_fetch", fake_fetch):
            scan.scan("https://example.com/en/index.php?x=1")
        probes = calls[1:]
        self.assertTrue(probes)
        for p in probes:
            self.assertTrue(p.startswith("https://example.com/"), p)
            self.assertNotIn("index.php", p)

    def test_phpinfo_fixture_marks_exposed(self):
        body = ("<html><title>phpinfo()</title>"
                "PHP Version 8.3.35</html>")

        def fake_fetch(url, ctx=None, deadline=None):
            if "phpinfo.php" in url:
                return self._home(body=body)
            return self._home()

        with mock.patch.object(scan, "_fetch", fake_fetch):
            r = scan.scan("https://example.com/")
        self.assertTrue(r["phpinfo_exposed"])
        self.assertEqual(r["php_version"], "8.3.35")


class FetchBehavior(unittest.TestCase):
    def setUp(self):
        FakeConn.instances = []

    def test_duplicate_set_cookie_headers_all_kept(self):
        FakeConn.responder = staticmethod(lambda c: FakeResp(200, [
            ("Set-Cookie", "PHPSESSID=abc; path=/"),
            ("Set-Cookie", "other=1; path=/")], [b"ok"]))
        with mock.patch.object(scan.socket, "getaddrinfo",
                               gai_smart), \
                mock.patch.object(scan.http.client, "HTTPConnection",
                                  FakeConn):
            r = scan._fetch("http://example.com/")
        sc = scan._h(r["headers"], "Set-Cookie")
        self.assertIn("PHPSESSID", sc)
        self.assertIn("other=1", sc)

    def test_second_ip_tried_when_first_refuses(self):
        def gai2(host, port, *a, **k):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                     ("93.184.216.34", 0)),
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "",
                     ("93.184.216.35", 0))]

        class Flaky(FakeConn):
            def request(self, method, path, headers=None):
                if self.host == "93.184.216.34":
                    raise OSError("connection refused")
                super().request(method, path, headers)

        FakeConn.responder = staticmethod(lambda c: FakeResp(200))
        with mock.patch.object(scan.socket, "getaddrinfo", gai2), \
                mock.patch.object(scan.http.client, "HTTPConnection",
                                  Flaky):
            r = scan._fetch("http://example.com/")
        self.assertTrue(r["ok"])
        self.assertEqual([c.host for c in FakeConn.instances],
                         ["93.184.216.34", "93.184.216.35"])

    def test_total_deadline_bounds_connect_timeout(self):
        seen = {}

        class Slow(FakeConn):
            def __init__(self, host, port, timeout=None, **kw):
                super().__init__(host, port, timeout=timeout)
                seen["timeout"] = timeout

            def getresponse(self):
                raise socket.timeout("timed out")

        with mock.patch.object(scan, "_TOTAL_DEADLINE", 3), \
                mock.patch.object(scan.socket, "getaddrinfo",
                                  gai_smart), \
                mock.patch.object(scan.http.client, "HTTPConnection",
                                  Slow):
            r = scan._fetch("http://example.com/")
        self.assertFalse(r["ok"])
        self.assertLessEqual(seen["timeout"], 3)
        self.assertIn("timed out", r["error"])


class BlockedRangesExplicit(unittest.TestCase):
    """The two addresses the round-4 review named explicitly: a
    CGNAT address deep inside 100.64.0.0/10 and the deprecated
    6to4 relay anycast 192.88.99.1. Each is refused by policy and
    no connection is attempted."""

    def _refused(self, url):
        boom = mock.Mock(side_effect=AssertionError("connect tried"))
        with mock.patch.object(scan.socket, "getaddrinfo", gai_smart), \
                mock.patch.object(scan.http.client, "HTTPConnection",
                                  boom), \
                mock.patch.object(scan, "_PinnedHTTPS", boom):
            r = scan._fetch(url)
        self.assertFalse(r["ok"], url)
        self.assertIn("non-public", r["error"], url)

    def test_cgnat_deep_address_refused(self):
        self._refused("http://100.100.100.200/")

    def test_6to4_relay_anycast_refused(self):
        self._refused("http://192.88.99.1/")


class _FakeSock:
    """Stands in for a connected socket: the watchdog's shutdown
    releases whatever is blocked reading from it."""

    def __init__(self):
        self.killed = threading.Event()
        self.timeouts = []

    def settimeout(self, t):
        self.timeouts.append(t)

    def shutdown(self, how):
        self.killed.set()

    def close(self):
        self.killed.set()


class DripTests(unittest.TestCase):
    """Slow-drip regression tests (round-4 review, H4): a server
    that trickles bytes must not hold the scanner past the total
    deadline — not in the headers, not in the body, and not by
    multiplying the budget across the homepage plus probes. The
    deadline is scaled down to 1s so the tests stay fast."""

    def setUp(self):
        FakeConn.instances = []

    def test_header_drip_aborts_at_deadline(self):
        class DripConn(FakeConn):
            def __init__(self, host, port, timeout=None, **kw):
                super().__init__(host, port, timeout=timeout)
                self.sock = _FakeSock()

            def getresponse(self):
                # One header byte at a time, far slower than any
                # single-read timeout: only the watchdog killing
                # the socket can end this wait.
                if not self.sock.killed.wait(30):
                    raise AssertionError("watchdog never fired")
                raise OSError("socket shut down by watchdog")

        with mock.patch.object(scan, "_TOTAL_DEADLINE", 1.0), \
                mock.patch.object(scan.socket, "getaddrinfo",
                                  gai_smart), \
                mock.patch.object(scan.http.client, "HTTPConnection",
                                  DripConn):
            t0 = time.monotonic()
            r = scan._fetch("http://example.com/")
            elapsed = time.monotonic() - t0
        self.assertFalse(r["ok"])
        self.assertIn("deadline", r["error"])
        self.assertLess(elapsed, 5)

    def test_body_drip_aborts_near_deadline(self):
        class DripResp(FakeResp):
            def read(self, n=-1):
                time.sleep(0.3)
                return b"x"

        FakeConn.responder = staticmethod(lambda c: DripResp(200))
        with mock.patch.object(scan, "_TOTAL_DEADLINE", 1.0), \
                mock.patch.object(scan.socket, "getaddrinfo",
                                  gai_smart), \
                mock.patch.object(scan.http.client, "HTTPConnection",
                                  FakeConn):
            t0 = time.monotonic()
            r = scan._fetch("http://example.com/")
            elapsed = time.monotonic() - t0
        self.assertTrue(r["ok"])
        self.assertLess(elapsed, 3)

    def test_deadline_is_per_scan_not_per_fetch(self):
        # The homepage answers instantly; every probe drips its
        # headers. If each fetch got its own budget, the four
        # probes alone would take ~4s at the scaled deadline —
        # one shared scan budget keeps the whole scan near 1s.
        class MixedConn(FakeConn):
            count = 0

            def __init__(self, host, port, timeout=None, **kw):
                super().__init__(host, port, timeout=timeout)
                MixedConn.count += 1
                self.n = MixedConn.count
                self.sock = _FakeSock()

            def getresponse(self):
                if self.n == 1:
                    return FakeResp(200, [], [b"<html></html>"])
                if not self.sock.killed.wait(30):
                    raise AssertionError("watchdog never fired")
                raise OSError("socket shut down by watchdog")

        MixedConn.count = 0
        with mock.patch.object(scan, "_TOTAL_DEADLINE", 1.0), \
                mock.patch.object(scan.socket, "getaddrinfo",
                                  gai_smart), \
                mock.patch.object(scan.http.client, "HTTPConnection",
                                  MixedConn):
            t0 = time.monotonic()
            scan.scan("http://example.com/")
            elapsed = time.monotonic() - t0
        self.assertGreater(MixedConn.count, 1)  # probes did run
        self.assertLess(elapsed, 3)


class CliExitCodes(unittest.TestCase):
    """Exit-code contract (see phpscan/__main__.py and the
    README): 0 clean, 1 actionable, 2 usage error or a target
    the scanner could not judge at all — unreachable, or
    not_assessed (branch newer than the advisory database)."""

    def _run(self, statuses):
        results = iter({"verdict": {"status": s}} for s in statuses)
        with mock.patch.object(cli, "scan",
                               lambda url: next(results)), \
                redirect_stdout(io.StringIO()):
            return cli.main(["http://x"] * len(statuses))

    def test_clean_statuses_exit_0(self):
        for s in ("patched", "indeterminate", "no_php_detected"):
            self.assertEqual(self._run([s]), 0, s)

    def test_actionable_statuses_exit_1(self):
        for s in ("vulnerable", "possibly_vulnerable", "eol"):
            self.assertEqual(self._run([s]), 1, s)

    def test_not_assessed_exit_2(self):
        self.assertEqual(self._run(["not_assessed"]), 2)

    def test_unreachable_exit_2(self):
        self.assertEqual(self._run(["unreachable"]), 2)

    def test_worst_code_wins(self):
        self.assertEqual(self._run(["vulnerable", "not_assessed"]), 2)
        self.assertEqual(self._run(["patched", "vulnerable"]), 1)

    def test_no_args_is_usage_error(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main([]), 2)


class Remediation(unittest.TestCase):
    def test_vulnerable_names_floor(self):
        v = versioning.verdict_for((8, 3, 20))
        self.assertEqual(v["status"], "vulnerable")
        self.assertIn("8.3.36", v["remediation"])

    def test_distro_points_at_tracker(self):
        v = versioning.verdict_for((8, 3, 20), distro=True)
        self.assertEqual(v["status"], "possibly_vulnerable")
        self.assertIn("distro security tracker", v["remediation"])

    def test_eol_names_upgrade_or_offline(self):
        v = versioning.verdict_for((8, 1, 34))
        self.assertEqual(v["status"], "eol")
        self.assertIn("offline", v["remediation"])

    def test_patched_has_no_remediation(self):
        v = versioning.verdict_for((8, 3, 36))
        self.assertEqual(v["status"], "patched")
        self.assertNotIn("remediation", v)


if __name__ == "__main__":
    unittest.main()
