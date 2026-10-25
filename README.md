# TraceVault

**Evidence-first Digital Forensics & Incident Response (DFIR) triage for lean security teams.**

TraceVault takes raw artifacts from a suspected breach — Linux auth logs, web server logs,
Windows event logs — and in seconds produces:

- a **super-timeline** merging every artifact into one UTC-normalized sequence
- **explainable detections** mapped to MITRE ATT&CK, each linked to the exact evidence events
- a **kill-chain view**, IOC list, risk score and plain-English storyline
- a **tamper-evident chain of custody**: every file is SHA-256 hashed on acquisition and every
  action is written to a hash-chained ledger, so any later change to evidence or records is detected
- a **printable incident report** and a local investigation **dashboard**

It is pure Python 3.10+ standard library: no installs, no internet, safe to drop on an IR jump box.

> Business plan, market and roadmap: [docs/BUSINESS.md](docs/BUSINESS.md) ·
> Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Quick start

```bash
python -m tracevault demo
```

```bash
python -m tracevault serve
```

Then open http://127.0.0.1:8765. The demo loads a realistic sample breach (`samples/case-001`):
an SSH brute force on a web server, a root shell, web-shell upload, lateral movement to a finance
workstation, LSASS credential dumping, persistence, data exfiltration and log clearing.

## Working a real case

```bash
python -m tracevault case-new IR-2026-014 --title "Payroll server alert" --examiner "J. Doe"
python -m tracevault ingest IR-2026-014 /evidence/auth.log /evidence/web-01_access.log /evidence/DC01_security.jsonl
python -m tracevault analyze IR-2026-014
python -m tracevault verify IR-2026-014
python -m tracevault anchor IR-2026-014
```

| Command | What it does |
|---|---|
| `case-new` | Create a case workspace and open its custody ledger |
| `ingest` | Hash the original, copy it read-only into the case, re-hash, log both |
| `analyze` | Parse all evidence, run detections, write `analysis.json` + `report.html` |
| `verify` | Re-check the whole ledger chain and every evidence hash (exit code 2 on failure) |
| `anchor` | Print the ledger head hash, to timestamp externally (notary, RFC 3161 TSA, blockchain) |
| `scan` | Triage loose files without a case (`--json` for pipelines; exit 1 if anything fires) |
| `serve` | Local dashboard on 127.0.0.1 |

All commands accept `--cases <dir>` (default `./cases`).

### Supported evidence

| Format | How to export | Detected by |
|---|---|---|
| Linux syslog / `auth.log` (classic or ISO timestamps) | copy `/var/log/auth.log`, `/var/log/secure` | content |
| Apache / Nginx combined access log | name it `<host>_access.log` to tag the host | content |
| Windows event log as JSON Lines | `Get-WinEvent -LogName Security \| Select TimeCreated,Id,... \| ConvertTo-Json -Compress` per line | content (`{` first char) |

Windows events understood: 4624, 4625, 4688, 4698, 4720, 4732, 7045, 1102.

## Detection rules

Rules live in [tracevault/rules.json](tracevault/rules.json) — readable by analysts and reviewable
in a pull request. Three rule types:

- `match` — one event meets the conditions (e.g. encoded PowerShell)
- `threshold` — N events from one entity in a burst (e.g. password brute force)
- `followed_by` — a burst then a follow-up event from the same entity (e.g. brute force → successful login)

Conditions are case-insensitive regexes or numeric comparisons (`{"gt": 10000000}`). Use your
own rule pack with `--rules my-rules.json`.

## Tests

```bash
python -m unittest discover -s tests -v
```

Covers parsers, every bundled rule against the sample breach, false-positive checks on benign
activity, and custody tamper scenarios (edited evidence, edited/deleted ledger entries, planted files).

## Project layout

```
tracevault/
  parsers.py      artifact parsers -> normalized Event
  detections.py   JSON rule engine (match / threshold / followed_by)
  rules.json      bundled ATT&CK-mapped rules
  analysis.py     risk score, kill chain, IOCs, narrative
  custody.py      case workspace + hash-chained custody ledger
  workflow.py     case-level operations used by CLI and server
  report.py       printable HTML report
  server.py       stdlib HTTP dashboard + JSON API
  web/index.html  dashboard UI
samples/case-001  sample breach evidence
tests/            unittest suite
docs/             business plan and architecture
```

## Security notes

- The dashboard binds to `127.0.0.1` and has no authentication — do not expose it on a network.
- All log content is treated as attacker-controlled and HTML-escaped in the report and UI.
- Case IDs are validated to prevent path traversal.
- Evidence copies are set read-only; integrity is still enforced by hashes, not file permissions.
