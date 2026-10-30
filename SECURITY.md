# Security

Report vulnerabilities in this scanner — or in the hosted
service — through https://phpatch.com/security or by email to
security@phpatch.com. Please do not open public issues for
vulnerabilities.

The hosted service's disclosure policy, access model and data
retention are published at https://phpatch.com/security.

## Response commitments

- **Acknowledgement:** within 2 business days of your report.
- **Critical vulnerabilities:** a fix or mitigation within
  7 days of acknowledgement.
- **High-severity vulnerabilities:** a fix or mitigation within
  30 days of acknowledgement.

Lower-severity issues are fixed in the normal release flow.
We will credit reporters who ask to be credited, and we will
not pursue legal action against researchers who follow this
policy.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.4.x | Yes |
| < 1.4 | No — please upgrade |

## Signing key

Releases are signed with the PHPatch Security PGP key:

- **Key:** `PHPatch Security <security@phpatch.com>`
- **Fingerprint:** `BAA1 586A AD37 18C0 CE41 D288 FE23 A624 54E3 5307`
- **Public key:** [`pgp-key.asc`](pgp-key.asc) in this repository

Verify a release artifact with:

```sh
gpg --import pgp-key.asc
gpg --verify phpscan-<version>.tar.gz.asc phpscan-<version>.tar.gz
```
