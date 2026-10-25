## What and why

<!-- What does this change, and why? For detection changes: the threat, the evidence, and the false-positive risk. -->

## Checklist

- [ ] Tests added or updated, and `python -m unittest discover -s tests` passes
- [ ] Detection changes: `tracevault validate` and `tracevault validate --manifest otrf-holdout` scorecards are pasted below
- [ ] Any new exclusion is as narrow as possible, and its rule `description` says what it hides
- [ ] Sample or test data is made up and uses reserved domains, IPs and account IDs (see CONTRIBUTING.md)
- [ ] Anything that displays log content escapes it; anything that turns it into a path validates it
