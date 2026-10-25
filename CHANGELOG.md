# Changelog

## 0.2.0 - 2026-10-25

First standalone release, extracted from its original repository with full history.

- **Packaging:** `pip install .` provides a `tracevault` command. Sample cases and dataset
  manifests ship inside the package. Licensed under Apache-2.0.
- **Analyst suppressions:** findings can be suppressed as a false positive or expected activity,
  for one finding or for every finding of a rule matching chosen values. Each decision is a
  custody-ledger entry and appears in the report.
- **Large cases:** the dashboard loads only the events behind findings and pages the full
  timeline with search. Verification is cached with a Re-verify control.
- **Sysmon and Windows endpoint coverage:** Winlogbeat and NXLog JSON, clock-offset
  correction, de-duplication of Security 4688 and Sysmon 1, and 10 endpoint rules.
- **Measured accuracy:** `tracevault validate` scores the rules against OTRF
  Security-Datasets. 82% detection on held-out data before tuning; see docs/VALIDATION.md.
- **Identities and posture:** accounts are linked across systems with a status per identity.
  Posture findings (for example AWS root use) are kept out of the attack story.
- **Cloud and SaaS:** AWS CloudTrail, Microsoft 365 and Okta parsers with 15 identity and
  cloud rules.

## 0.1.0

- Prototype: Linux, web and Windows log parsing, JSON rule engine, hash-chained chain of custody,
  HTML report and local dashboard.
