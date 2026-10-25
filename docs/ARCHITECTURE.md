# Architecture

```
 evidence files ──► custody.Case.ingest ──► cases/<id>/evidence/ (read-only copies)
                         │                         │
                         ▼                         ▼
                   ledger.jsonl ◄──────── parsers.parse_files ──► [Event, ...] (UTC, sorted, E00001..)
                (hash chain)                       │
                         ▲                         ▼
                         │                 detections.run(rules.json) ──► [Finding, ...]
                         │                         │
                         │                         ▼
                         │                 analysis.analyze ──► analysis.json
                         │                         │            (risk, kill chain, IOCs, narrative, timeline)
                         │                         ▼
                         └──────────────── report.render ──► report.html
                                                   │
                                     server.py (127.0.0.1) + web/index.html
```

## Data model

- **Event** — one normalized record: `ts` (UTC), `source` file, `kind` (e.g. `auth.failure`,
  `process.create`, `web.request`), `host`, `user`, `src_ip`, `message`, `raw`, parser `fields`.
- **Finding** — a rule hit: rule metadata (severity, ATT&CK tactic/technique), summary, and the
  list of Events that caused it. Findings never exist without evidence.
  - `category`: `attack` (drives storyline, risk, IOCs, attacker window) or `posture` (reported
    separately as risky practice).
  - `context`: evidence shown for comparison but not attributed to the attacker — e.g. the user's
    normal login in an impossible-travel pair. IOCs and identity status use only attributed events.
- **Identity** — aliases of one person across systems (`identities.py`), auto-linked by name or
  set by `cases/<id>/identities.json`, with a status: created / compromised / targeted / involved.

## Chain of custody

Each ledger entry:

```json
{"seq": 3, "ts": "...", "actor": "J. Doe", "action": "evidence.ingest",
 "evidence": "web-01_auth.log", "sha256": "<file hash>", "details": {...},
 "prev_hash": "<entry_hash of seq 2>", "entry_hash": "sha256(canonical JSON of this entry minus entry_hash)"}
```

`verify()` detects: edited entries (hash mismatch), deleted or reordered entries (seq / prev_hash
break), modified evidence (re-hash mismatch), missing evidence, and files that appear in the case
without ever being logged. `anchor()` exposes the head hash, which commits to the entire history.

## Extending

- **New artifact type:** add a `parse_<fmt>(path) -> list[Event]` in `parsers.py`, register it in
  `PARSERS`, and teach `detect_format` to recognize it.
- **New detection:** add an object to `rules.json` (or a separate file passed with `--rules`).
  Add a sample line to `samples/` and an assertion in `tests/`.
