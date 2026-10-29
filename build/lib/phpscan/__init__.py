"""phpscan — the free, open-source external PHP scanner from
PHP Patch Assurance (https://phpatch.com).

Passive fingerprinting plus limited, read-only checks of a few
well-known paths (the phpinfo exposure probes): it reads what a
site already discloses publicly (headers, generator tags, exposed
phpinfo pages) and judges any disclosed PHP version against the
advisory database in data/cves.json. It never runs exploit probes.

When a site hides its PHP version — most well-run sites do — the
verdict is an honest INDETERMINATE, with the path to a certain
answer (a read-only server check) explained at https://phpatch.com.
"""

__version__ = "1.4.4"
