# Security policy

TraceVault handles evidence from compromised systems, so its own security matters. Thank you for
helping keep it trustworthy.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**. Only the maintainer can see the report.

Please include:

- the TraceVault version (`tracevault --version`) and Python version
- what an attacker could achieve, and the steps or input files to reproduce it
- any evidence data in **sanitized** form (no real hostnames, accounts or IPs from a live incident)

You should get an acknowledgement within 7 days. Fixes for confirmed issues are released as soon
as practical, and you will be credited in the release notes unless you prefer not to be.

## Supported versions

Only the latest release receives security fixes.

| Version | Supported |
|---|---|
| 0.4.x | yes |
| < 0.4 | no |

## What counts as a vulnerability

TraceVault treats **all evidence content as attacker-controlled**. Log lines, event fields, file
names and collector manifests can all be crafted by whoever compromised the machine. In scope:

- **Code or script injection** from evidence content into the dashboard or the HTML report (XSS).
- **Path traversal** or writes outside the case folder, through case IDs, evidence names,
  collector manifests or dataset archives.
- **Defeating the chain of custody:** changing evidence, ledger entries or suppressions without
  `tracevault verify` reporting it, or making a tampered collection pass `ingest-collection`.
- **Hiding attacker activity** with crafted input that makes a parser or rule silently skip events
  it should process, beyond ordinary detection gaps.
- **Denial of service** from small inputs, such as a regular expression or record that makes
  parsing hang.
- The **Windows collector** doing anything beyond reading event logs and writing to its output
  folder.

Out of scope:

- The dashboard has **no authentication by design** and binds to `127.0.0.1`. Exposing it on a
  network yourself is not a vulnerability.
- The examiner name typed in the dashboard is recorded as given, not verified.
- Detection gaps and false positives. Please report those as normal issues using the
  "False positive" or "Detection request" forms.
