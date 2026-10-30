"""Config-hygiene checks from external signals only.

Headers are read off the homepage response; exposures are
confirmed with plain read-only GETs of the handful of paths every
scanner checks (/.git/HEAD, /.env, directory indexes). For the
file exposures only the first bytes are examined — just enough to
confirm the file type — and findings report the PATH ONLY: file
contents are never copied into output. Every finding carries a
remediation line (the project's hard rule).
"""

import re


def _h(headers, name):
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return v
    return ""


def _finding(kind, severity, title, detail, remediation, **extra):
    f = {"kind": kind, "severity": severity, "title": title,
         "detail": detail, "remediation": remediation}
    f.update(extra)
    return f


def header_findings(headers, scheme):
    """Findings from the homepage's response headers alone."""
    out = []
    xpb = _h(headers, "X-Powered-By")
    if xpb:
        out.append(_finding(
            "version_disclosure", "low",
            "X-Powered-By header discloses server software",
            "The X-Powered-By response header advertises the "
            "server-side platform (and, where present, its exact "
            "version) to every visitor, which lets attackers "
            "fingerprint the site against known vulnerabilities.",
            "Set expose_php = Off in php.ini and strip the "
            "X-Powered-By header at the web server or proxy."))
    missing = []
    if _h(headers, "X-Content-Type-Options").strip().lower() \
            != "nosniff":
        missing.append("X-Content-Type-Options")
    csp = _h(headers, "Content-Security-Policy")
    if not _h(headers, "X-Frame-Options") \
            and "frame-ancestors" not in csp:
        missing.append("X-Frame-Options / CSP frame-ancestors")
    if not _h(headers, "Referrer-Policy"):
        missing.append("Referrer-Policy")
    if scheme == "https" \
            and not _h(headers, "Strict-Transport-Security"):
        missing.append("Strict-Transport-Security")
    if missing:
        out.append(_finding(
            "security_headers", "low",
            "Missing security response headers",
            "The homepage response lacks: "
            + ", ".join(missing)
            + ". These headers are cheap, standard hardening "
              "against MIME sniffing, clickjacking, referrer "
              "leakage and protocol downgrade.",
            "Add the missing headers at the web server or CDN "
            "(e.g. X-Content-Type-Options: nosniff, "
            "X-Frame-Options: SAMEORIGIN, Referrer-Policy: "
            "strict-origin-when-cross-origin, and "
            "Strict-Transport-Security on HTTPS)."))
    return out


def phpinfo_finding(path):
    return _finding(
        "phpinfo_exposed", "medium",
        "phpinfo() page publicly exposed",
        f"A phpinfo() page answers publicly at {path}. It "
        "discloses the exact PHP version, loaded extensions, "
        "file paths and configuration values — a full blueprint "
        "for attacking the site.",
        "Remove the phpinfo file from the web root; if it is "
        "needed for debugging, restrict it to localhost or "
        "authenticated access only.",
        path=path)


_ENV_KEY = re.compile(r"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*=")


def exposure_probes(fetch, origin, cms_names=()):
    """Read-only exposure checks: /.git/HEAD, /.env, and
    directory listings on the detected CMS's upload/plugin dirs.
    `fetch` is the scanner's guarded fetcher."""
    out = []
    if not fetch or not origin:
        return out

    r = fetch(origin + "/.git/HEAD")
    body = (r or {}).get("body") or ""
    if (r or {}).get("status") == 200 \
            and re.match(r"ref:\s+refs/", body[:64]):
        out.append(_finding(
            "git_exposed", "high",
            "Git repository exposed (/.git/HEAD)",
            "The site's .git directory is web-accessible: "
            "/.git/HEAD answers with a ref. The full source "
            "history — including anything ever committed, such "
            "as configuration or credentials — can be "
            "reconstructed by anyone.",
            "Block access to /.git in the web server config "
            "(nginx: location ^~ /.git { deny all; } — Apache: "
            "RedirectMatch 404 /\\.git) or move the repository "
            "outside the web root.",
            path="/.git/HEAD"))

    r = fetch(origin + "/.env")
    body = (r or {}).get("body") or ""
    if (r or {}).get("status") == 200 \
            and not body.lstrip().startswith("<") \
            and "<html" not in body[:300].lower() \
            and _ENV_KEY.search(body):
        out.append(_finding(
            "env_exposed", "critical",
            "Environment file exposed (/.env)",
            "A .env file is web-accessible at /.env. Files of "
            "this type typically hold database credentials, API "
            "keys and the application secret — treat every value "
            "it contains as compromised. (The scanner confirmed "
            "the file type only; it does not copy the contents.)",
            "Remove .env from the web root, deny access to "
            "dotfiles at the web server, and rotate every secret "
            "the file contained.",
            path="/.env"))

    listing_paths = []
    if "WordPress" in cms_names:
        listing_paths += ["/wp-content/uploads/",
                          "/wp-content/plugins/"]
    if "Joomla" in cms_names:
        listing_paths.append("/images/")
    if "Drupal" in cms_names:
        listing_paths.append("/sites/default/files/")
    for path in listing_paths[:3]:
        r = fetch(origin + path)
        body = (r or {}).get("body") or ""
        if (r or {}).get("status") == 200 \
                and ("Index of /" in body
                     or "<title>Index of" in body):
            out.append(_finding(
                "directory_listing", "medium",
                f"Directory listing enabled on {path}",
                f"{path} answers with a directory index, "
                "enumerating every uploaded file for anyone — "
                "including files never linked anywhere.",
                "Disable directory listing (Apache: Options "
                "-Indexes; nginx: autoindex off) or place an "
                "index file / deny rule in this directory.",
                path=path))
    return out
