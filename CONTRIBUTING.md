# Contributing to TraceVault

Contributions are welcome, especially new detection rules, parsers for more log sources, and
reports of false positives from real environments.

For security problems, follow [SECURITY.md](SECURITY.md) instead of opening an issue.

## Development setup

TraceVault uses only the Python standard library (3.10+). There is nothing else to install.

```bash
git clone https://github.com/VanditBPatel/tracevault.git
```

```bash
cd tracevault
```

```bash
python -m pip install -e .
```

```bash
python -m unittest discover -s tests -v
```

`tracevault demo` builds two sample cases, and `tracevault serve` opens the dashboard on
http://127.0.0.1:8765. CI runs the tests on Linux and Windows with Python 3.10–3.13, plus the
Windows collector on a real runner. Please make sure the tests pass locally first.

## Adding or changing a detection rule

Rules live in [tracevault/rules.json](tracevault/rules.json). The rule types (`match`,
`threshold`, `followed_by`, `field_change`) and the `any` / `not` blocks are described in the
[README](README.md#detection-rules).

1. **Map it to MITRE ATT&CK.** Set `tactic`, `technique` and `technique_name`, and write a
   one-sentence `description` an analyst can act on.
2. **Add evidence that should trigger it.** Use a sample case under `tracevault/samples/`, or a
   small fixture inside the test.
3. **Add a test** that the rule fires on that evidence, and one that a look-alike benign event
   does not.
4. **Measure it on public attack data** for Windows rules:

   ```bash
   tracevault validate --fetch
   ```

   ```bash
   tracevault validate --manifest otrf-holdout --fetch
   ```

   Include both scorecards in the pull request. If a rule needs an exclusion, keep it as narrow
   as possible and say in `description` what it hides. Never tune against the held-out set and
   then quote its score as out-of-sample. See [docs/VALIDATION.md](docs/VALIDATION.md).

## Adding a parser

Add `parse_<format>(path) -> list[Event]` in [tracevault/parsers.py](tracevault/parsers.py),
register it in `PARSERS`, and teach `detect_format` to recognize it by content, not by file name.
Normalize timestamps to UTC and map logins to `auth.success` / `auth.failure`, so the existing
cross-source rules apply.

## Test data rules

Sample data in this repository is public. Never commit evidence from a real incident, even
"anonymized". Make it up, and use only reserved values:

- domains: `example`, `*.example`, `example.com` / `.org` / `.net` (RFC 2606)
- IPv4: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737), or private ranges
- AWS account IDs: `111122223333` and other AWS documentation IDs

## Pull requests

- Keep each pull request to one change, with tests.
- Explain *why* in the description, especially for detection changes: the threat, the evidence,
  and the false-positive risk.
- All log content is attacker-controlled. Anything that renders it must escape it, and anything
  that turns it into a path must validate it.

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE), the same license as the project.
