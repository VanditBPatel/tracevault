# TraceVault

[![tests](https://github.com/VanditBPatel/tracevault/actions/workflows/tests.yml/badge.svg)](https://github.com/VanditBPatel/tracevault/actions/workflows/tests.yml)

**Evidence-first Digital Forensics & Incident Response (DFIR) triage for lean security teams.**

TraceVault takes raw artifacts from a suspected breach — Linux auth logs, web server logs,
Windows event logs, and the cloud/SaaS logs where startup breaches usually happen (AWS CloudTrail,
Microsoft 365, Okta) — and in seconds produces:

- a **super-timeline** merging every artifact into one UTC-normalized sequence
- **explainable detections** mapped to MITRE ATT&CK, each linked to the exact evidence events
- a **kill-chain view**, IOC list, risk score and plain-English storyline
- a **tamper-evident chain of custody**: every file is SHA-256 hashed on acquisition and every
  action is written to a hash-chained ledger, so any later change to evidence or records is detected
- a **printable incident report** and a local investigation **dashboard**

It uses only the Python 3.10+ standard library. There are no dependencies and nothing calls the
internet, so it is safe to drop on an IR jump box.

> Business plan, market and roadmap: [docs/BUSINESS.md](docs/BUSINESS.md) ·
> Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) ·
> Measured accuracy: [docs/VALIDATION.md](docs/VALIDATION.md) · License: Apache-2.0

## Install

From a checkout of this repository:

```bash
python -m pip install .
```

This installs the `tracevault` command. With no install at all, `python -m tracevault` works
the same from the repository root.

## Quick start

```bash
tracevault demo
```

```bash
tracevault serve
```

Then open http://127.0.0.1:8765. The demo loads two realistic sample breaches:

- **CASE-001** (`tracevault/samples/case-001`, on-prem): SSH brute force on a web server, root shell,
  web-shell upload, lateral movement to a finance workstation, LSASS credential dumping,
  persistence, data exfiltration and log clearing.
- **CASE-002** (`tracevault/samples/case-002`, cloud identity): Okta password spray, MFA push bombing until
  the user approves, login from a second country, a hidden mailbox forwarding rule and OAuth app
  consent in Microsoft 365, then in AWS: recon, a backdoor IAM user with admin rights, a customer
  data bucket made public, and CloudTrail switched off.

## Collecting evidence from a Windows host

The collector is a single PowerShell script. It needs no install, so copy it to the suspect
machine. Get it with:

```bash
tracevault collector-script windows
```

On the host, from an **elevated** PowerShell (the Security log needs Administrator rights):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Collect-TraceVault.ps1 -Examiner "J. Doe"
```

- It exports Security, System and Sysmon (if installed) for the last 72 hours by default
  (`-Since` / `-Until` to change), as JSON Lines that TraceVault reads.
- It writes `manifest.json` with each file's SHA-256, the host, account, time window and whether
  it ran elevated, and lists every channel it could not read and why.
- `-IncludeEvtx` also keeps native `.evtx` copies for preservation. `-MaxEvents` caps very busy
  logs (newest kept).
- It only reads logs and writes into its output folder. It changes no settings and sends nothing
  over the network. `-ExecutionPolicy Bypass` applies to that one PowerShell process only.
- Speed: about 500 events/s on a laptop with Windows PowerShell 5.1. It reads with
  `EventLogReader`; `Get-WinEvent` renders every message and was about 15x slower.

Copy the output folder to the analyst machine, then:

```bash
tracevault ingest-collection IR-2026-014 TraceVault-WS01-20261025T060158Z
```

Every file is checked against the hashes recorded on the host. If any file is missing or
altered, **nothing** is ingested. The collection details are logged as an `evidence.collection`
custody entry, so the chain of custody starts at collection, not at ingest.

## Working a real case

```bash
tracevault case-new IR-2026-014 --title "Payroll server alert" --examiner "J. Doe"
tracevault ingest IR-2026-014 /evidence/auth.log /evidence/web-01_access.log /evidence/DC01_security.jsonl
tracevault analyze IR-2026-014
tracevault verify IR-2026-014
tracevault anchor IR-2026-014
```

| Command | What it does |
|---|---|
| `case-new` | Create a case workspace and open its custody ledger |
| `ingest` | Hash the original, copy it read-only into the case, re-hash, log both |
| `ingest-collection` | Verify a collector folder against its manifest, then ingest all of it (or nothing) |
| `collector-script` | Write the Windows collector script, to copy to a host |
| `analyze` | Parse all evidence, run detections, write `analysis.json` + `report.html` |
| `verify` | Re-check the whole ledger chain and every evidence hash (exit code 2 on failure) |
| `anchor` | Print the ledger head hash, to timestamp externally (notary, RFC 3161 TSA, blockchain) |
| `scan` | Triage loose files without a case (`--json` for pipelines; exit 1 if anything fires) |
| `suppress` / `unsuppress` / `suppressions` | Record, withdraw and list analyst suppressions (custody-logged) |
| `validate` | Score the rules against public attack datasets (`--fetch` downloads them, hashes verified) |
| `serve` | Local dashboard on 127.0.0.1 |

Cases live in `./cases` by default. To use another folder, put `--cases <dir>` before the
command, e.g. `tracevault --cases D:\ir serve`.

### Supported evidence

| Format | How to export | Detected by |
|---|---|---|
| Linux syslog / `auth.log` (classic or ISO timestamps) | copy `/var/log/auth.log`, `/var/log/secure` | content |
| Apache / Nginx combined access log | name it `<host>_access.log` to tag the host | content |
| Windows Security / System / **Sysmon** events as JSON (array or JSON Lines) | `Get-WinEvent ... \| ConvertTo-Json`, Winlogbeat or NXLog JSON exports | JSON keys |
| AWS CloudTrail | S3 log objects (`{"Records": [...]}`), CloudTrail Lake / Athena JSON | JSON keys |
| Microsoft 365 unified audit log | Purview → Audit → Export (CSV with `AuditData` column), or `Search-UnifiedAuditLog` AuditData JSON | CSV header / JSON keys |
| Okta System Log | `GET /api/v1/logs` output (JSON array or JSON Lines) | JSON keys |

Windows events understood: Security 4624, 4625, 4688, 4697, 4698, 4720, 4732, 1102; System 7045;
Sysmon 1 (process), 3 (network), 7 (image load), 8 (remote thread), 10 (process access),
11 (file create), 12–14 (registry), 22 (DNS). Exports often store local time without a zone,
so TraceVault learns each file's offset from Sysmon's `UtcTime` and corrects the other events.
A process logged by both Security 4688 and Sysmon 1 is counted once.

Cloud events are normalized into the same model as everything else: sign-ins become
`auth.success` / `auth.failure` (so brute-force rules work across Okta, M365, AWS and SSH alike),
denied AWS calls become `cloud.denied`, Okta MFA pushes and rejections become `mfa.push` / `mfa.deny`.
The "host" of a cloud event is its tenant: `aws:<account-id>`, `m365`, `okta`.

## Detection rules

Rules live in [tracevault/rules.json](tracevault/rules.json) — readable by analysts and reviewable
in a pull request. 38 rules ship today: 25 for hosts, web servers and Windows endpoints (10 of
them for Windows endpoint techniques seen through Sysmon / process auditing), and 13 for cloud and
identity (one of them a posture rule). Four rule types:

- `match` — one event meets the conditions (e.g. encoded PowerShell, CloudTrail stopped)
- `threshold` — N events from one entity in a burst (e.g. password brute force); add
  `"distinct": "user"` to count different accounts instead (password spraying)
- `followed_by` — a burst then a follow-up event from the same entity (e.g. MFA denials → successful login)
- `field_change` — a field changes between consecutive events within a window (e.g. logins from
  two countries — impossible travel)

Conditions are case-insensitive regexes or numeric comparisons (`{"gt": 10000000}`). Use your
own rule pack with `--rules my-rules.json`.

Match specs can also use `any` (at least one block must hold) and `not` (exclusions; a list
of blocks excludes an event only when every condition in one block holds). That is how
known-benign activity is tuned out narrowly.

Add `"category": "posture"` to a rule for risky practice that isn't proof of compromise (e.g. AWS
root use). Posture findings are listed separately and never feed the attack storyline, risk score,
IOCs or attacker window.

## Tuning a case: suppressions

Every environment has its own noise. When an analyst reviews a finding and decides it is a
false positive or authorized activity (an admin task, a pentest), they suppress it in the
dashboard (the **Suppress** button on each finding) or from the command line:

```bash
tracevault suppress IR-2026-014 --rule TV-030 --where source_image="C:\WindowsAzure\GuestAgent_2.7\CollectGuestLogs.exe" --reason "Azure VM agent log collection, confirmed with cloud team"
```

- Scope is either **this finding only** (matched by event fingerprints, so it survives adding
  evidence) or **every finding of that rule** where chosen field values match.
- A reason and the examiner's name are required. Each suppression is a `finding.suppress` entry
  in the hash-chained custody ledger, and is withdrawn with `unsuppress` (also logged), so
  changing one later breaks verification.
- Suppressed findings leave the storyline, risk score, IOCs and identities. They stay listed,
  with who/why/when, in the dashboard and in a "Suppressed by analyst" section of the report.

Suppressions apply to one case. They never change the shared rules in `rules.json`.

## Large cases

The dashboard downloads only the events behind findings. The full timeline is paged and
searchable on the server (`/api/cases/<id>/events`). Measured on a 59,399-event OTRF case:
the case opens in about 0.3 s (16 KB instead of 34 MB) and the full timeline view creates about
1,300 page elements instead of 297,000. Custody verification re-hashes all evidence, so its
result is cached and shown with a "checked at" time and a **Re-verify** button. Analysis still
holds every event in memory and in `analysis.json`, so very large cases (millions of events)
will need a database-backed store.

## Identities

One person shows up under many names: `priya` in AWS, `priya@acme.io` in Okta and Microsoft 365,
`ACME\priya` on Windows. TraceVault links them into one identity automatically (lowercase, strip
`DOMAIN\` and `@domain`) and gives each a status from attacker-attributed evidence only:
**created** (backdoor account), **compromised** (attacker login succeeded), **targeted** (only
failed logins / MFA prompts) or **involved**.

When auto-linking is wrong or incomplete, put an identity map in the case folder as
`cases/<id>/identities.json` (or pass `--identities` to `scan`). The map always wins:

```json
{"Priya Shah": ["priya", "priya@acme.io", "p.shah"], "Sam (vendor)": ["sam@vendor.example"]}
```

The map's SHA-256 is written to the custody ledger with each analysis, so the linking used for a
report is on record.

## Measured accuracy

The Windows rules are scored against public attack recordings from OTRF Security-Datasets
with `tracevault validate --fetch`. On 11 held-out datasets they had never been
tuned on, the rules detected **82%** of expected techniques on the first run. They also raised
false alarms from Windows background services and a cloud VM agent, which were then tuned out.
Full method, per-dataset tables and limitations: [docs/VALIDATION.md](docs/VALIDATION.md).

## Tests

```bash
python -m unittest discover -s tests -v
```

Covers parsers, every bundled rule against the sample breach, false-positive checks on benign
activity, and custody tamper scenarios (edited evidence, edited/deleted ledger entries, planted files).

## Project layout

```
tracevault/            the package
  parsers.py           artifact parsers -> normalized Event
  detections.py        JSON rule engine (match / threshold / followed_by / field_change)
  rules.json           bundled ATT&CK-mapped rules
  analysis.py          risk score, kill chain, IOCs, narrative
  identities.py        cross-system identity linking and status
  suppressions.py      analyst suppressions, replayed from the custody ledger
  custody.py           case workspace + hash-chained custody ledger
  workflow.py          case-level operations used by CLI and server
  report.py            printable HTML report
  server.py            stdlib HTTP dashboard + JSON API
  validate.py          accuracy scoring against public datasets
  web/index.html       dashboard UI
  collectors/          Collect-TraceVault.ps1 (Windows evidence collector)
  samples/case-00x/    sample breach evidence used by `tracevault demo`
  datasets/            validation manifests (otrf = tuning set, otrf-holdout = held-out set)
tests/                 unittest suite
docs/                  business plan, architecture, validation results
.github/workflows/     CI: tests on Linux and Windows, Python 3.10-3.13
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Security notes

- The dashboard binds to `127.0.0.1` and has no authentication — do not expose it on a network.
  The examiner name typed in the dashboard is recorded as given, not verified.
- All log content is treated as attacker-controlled and HTML-escaped in the report and UI.
- Case IDs are validated to prevent path traversal.
- Evidence copies are set read-only; integrity is still enforced by hashes, not file permissions.
