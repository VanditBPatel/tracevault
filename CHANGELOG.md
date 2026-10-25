# Changelog

## 0.5.0 - 2026-10-25

- **Linux evidence collector** (`collect-tracevault.sh`, bash, nothing to install): copies
  `/var/log` auth, syslog/messages, auditd, web access logs and wtmp/btmp byte-for-byte,
  including rotated `.gz` files; exports the systemd journal for a time window; and writes the
  same hash manifest as the Windows collector. `--root` collects from a mounted disk image. It
  never follows symlinks out of `/var/log`. Get it with `tracevault collector-script linux`.
- TraceVault reads **gzip-compressed logs** directly, so rotated logs are ingested as collected.
- **journalctl output** is parsed: `-- …` marker lines are skipped and `+0000` / `+05:30`
  offsets are converted to UTC.
- CI runs the Linux collector as root on a real Ubuntu runner after writing a simulated SSH brute
  force into the journal, and checks it is detected; it also checks that a tampered collection
  is refused.
- `.gitattributes` keeps shell scripts LF so they run on Linux when checked out on Windows.

## 0.4.2 - 2026-10-25

- **New rule TV-040 "Service launched encoded PowerShell"** (critical, T1569.002): the Windows
  service manager starting encoded PowerShell (directly or through `cmd.exe`), or a service
  installed whose command runs it. This is the mark of PsExec, Impacket smbexec, Empire and
  Cobalt Strike remote execution. It accepts every abbreviation of `-EncodedCommand` and ignores
  `-ExecutionPolicy`. On 28 attack datasets it fires only in the two PsExec-style ones, and their
  risk scores go from 47 (medium) and 53 (high) to 80 and 82 (critical). This resolves the one
  level drop caused by the 0.4.1 risk change. Nothing else changes.

## 0.4.1 - 2026-10-25

- **Risk score counts behaviours, not alerts.** Each detection rule counts once; further findings
  of the same rule add at most 50% of its weight; distinct behaviours combine as independent
  evidence. A clean laptop with 6 harmless service installs went from 62 (high) to 22 (medium).
  The demo breaches stay at 100. Across 28 attack datasets one dropped a level (`psexec_service`,
  high to medium). Details in docs/VALIDATION.md.
- **"Why this risk score"**: every score comes with its reasons and each behaviour's contribution,
  shown in the dashboard, the report and the CLI.

## 0.4.0 - 2026-10-25

- **Redesigned dashboard:** light and dark themes (following the system setting, with a toggle),
  Overview / Findings / Timeline / Custody tabs, a numbered "What happened" storyline,
  identities shown as people, a clickable ATT&CK kill chain that filters findings, finding cards
  with inline evidence, severity filters with counts and search, and notices and inline forms
  instead of browser pop-ups. Works at phone width. Still fully offline: no web fonts, CDNs or
  icon libraries.
- **Redesigned incident report:** a cover with a risk gauge, case facts and an integrity seal; a
  plain-language executive summary generated only from the analysis; numbered storyline;
  identities and indicators tables; ATT&CK coverage; finding cards with evidence tables; posture
  and analyst decisions; full chain of custody; and method and limitations. Prints cleanly to
  PDF (A4) with page numbers, keeps headings with their content, and starts Findings and Custody
  on new pages. A "Print or save as PDF" button is shown on screen.
- **Repeated identical findings are grouped:** single-event findings with the same rule, host,
  event kind and message become one finding with a count and first/last time (for example an
  endpoint agent installing the same service 24 times a day). Every event is kept as evidence,
  and anything that differs stays separate. On a real laptop collection this turned 36 findings
  into 6; across the 28 validation datasets, 73 into 62, with detection scores unchanged.
- `tracevault validate` says when datasets are missing instead of silently reporting "n/a".
- The open case and tab are part of the URL (`#CASE-002/findings`), so views can be linked.
- Storyline keeps rule titles in their original case ("AWS console login without MFA").
- Case IDs are checked with a full match (a trailing newline used to pass), Windows device names
  such as `CON` are rejected, and the resolved case folder must sit inside the cases root.
  Found by CodeQL.
- Public-repo files: security policy, contributing guide, issue forms, PR checklist, CodeQL and
  Dependabot. Sample data uses reserved `.example` domains.

## 0.3.0 - 2026-10-25

- **Windows evidence collector** (`Collect-TraceVault.ps1`, Windows PowerShell 5.1 and 7):
  exports Security, System and Sysmon for a time window as JSON Lines, with a hash manifest.
  Read-only on the host. Output is identical record for record to a full XML parse, at about
  500 events/s.
- **`tracevault ingest-collection`**: verifies every collected file against the manifest
  before ingesting (all or nothing) and records the collection in the custody ledger.
- **`tracevault collector-script windows`**: writes the collector for copying to a host.
- Collector manifests are checked the same way on every OS: file names containing `/`, `\` or
  `:` are rejected (a backslash is not a separator on Linux).
- Known noise seen on a real laptop: endpoint security suites (for example McAfee) and Store-app
  updates install services repeatedly, so TV-022 fires often. Suppress per case; grouping
  repeated identical installs is a planned improvement.

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
