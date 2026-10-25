# Detection validation on public attack data

TraceVault's Windows rules were measured against recordings of real attack techniques from the
[OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) project. Each recording is a
lab Windows host (Sysmon + Security log) captured while one technique was executed, plus all the
ordinary background activity of that machine.

Reproduce with:

```bash
tracevault validate --fetch
```

```bash
tracevault validate --manifest otrf-holdout --fetch
```

Downloads (about 15 MB for both sets) go to `~/.tracevault/datasets`, or `$TRACEVAULT_DATA` if
set. They are verified against the SHA-256 hashes pinned in the manifests
(`tracevault/datasets/`), and only `.json` files are extracted.

## How it is scored

For each dataset the manifest lists the rules that **should** fire. After a run, every other
rule that fired is either:

- a **known artifact** of how the data was captured. TV-024 "Security log cleared" fires on
  every OTRF recording because the authors clear the log before each capture;
- **reviewed as genuine attacker activity** (`also_ok`, with the reason written next to it);
- or **unexplained**, which counts against the rules until a person reviews the actual events.

**Detection rate** = expected detections that fired / expected detections.

## Results

### Out-of-sample result: the honest headline

11 datasets (130,650 events) were held out. Their expectations were written before the first
run, and the rules had never been tuned on them. Results of that single run:

| Datasets | Events | Expected detections | Detected | Detection rate | Unexplained rule hits |
|---|---|---|---|---|---|
| 11 | 130,650 | 11 | 9 | **82%** | 10 (in 5 datasets) |

When the 10 unexplained hit groups were reviewed against the raw events:

| Verdict | Findings | What it was |
|---|---|---|
| Genuine attacker activity | 9 | PsExec service, Empire's encoded-PowerShell stagers launched by the technique, the attacker's own scheduled task |
| **False positive** | **78** | 38 Windows per-user service installs and Defender's driver (TV-022); 33 reads of LSASS by Azure's `CollectGuestLogs.exe` VM agent (TV-030); 4 harmless `reg export HKLM\SYSTEM\...` subkey exports (TV-032); 2 built-in Windows Update tasks (TV-025); 1 Defender `Run` value (TV-034) |

Misses (2): `mshta.exe` running a local `.hta` whose path contained spaces, and a CMSTP
UAC bypass. TraceVault had no CMSTP coverage at the time.

**What this means:** on attack techniques it had not been tuned for, TraceVault caught about 4
in 5. Out of the box it also raised about 78 false alarms over roughly 130k events, mostly from
Windows' own background services and a cloud VM agent. Expect a similar round of tuning in
every new environment. That is normal for detection rules, and it is why the rule format
supports narrow exclusions.

### Tuning set: how the rules got here

17 datasets (58,246 events) were used to develop and tune the rules.

| Run | What changed | Detection rate | Unexplained |
|---|---|---|---|
| 1 | Rules as first written, before seeing any data | 70% (14/20) | 3 |
| 2 | **Parser only.** 4 datasets use NXLog's export format (`EventTime`) and had parsed to zero events | 95% (19/20) | 4: 3 reviewed as genuine, 1 false positive (`dwm.exe` → `csrss.exe` remote thread) |
| 3 | Rule fixes. SAM rule accepts `/` as well as `\` (the attacker wrote `C:\windows/system32/config/SAM`); dwm excluded from the injection rule; Security 4688 / Sysmon 1 duplicates merged so each process counts once | 100% (20/20) | 0 |

### After tuning on the held-out set (in-sample, so not an accuracy claim)

The held-out findings above were then used to tune. The exclusions are listed in each rule's
`description`, and coverage for local `.hta` files and CMSTP was added. Both sets now score
**100% with 0 unexplained hits**. These later runs are *in-sample*: they show the tuning worked
on this data, not how well the rules generalise. The 82% above is the number to quote.

## Risk score calibration

The original risk score added every finding as independent evidence. A clean laptop collection
(24 hours of Security and System logs from the maintainer's own machine, no attack) produced 6
"New service installed" findings from security software and app updates. Those 6 findings from 1
rule scored **62 (high)**.

The score now counts distinct behaviours (rules) and caps the effect of repeats (see the
README). Results on every case available, before and after:

| Case | Findings | Rules | Tactics | Before | After |
|---|---|---|---|---|---|
| Clean laptop, 24 h | 6 medium | 1 | 1 | 62 high | **22 medium** |
| CASE-001 demo (on-prem breach) | 19 | 13 | 9 | 100 critical | 100 critical |
| CASE-002 demo (cloud takeover) | 16 | 15 | 7 | 100 critical | 100 critical |
| 28 OTRF attack datasets | 1–6 each | | 1–3 | 4 critical, 19 high, 4 medium, 1 low | 4 critical, 18 high, 5 medium, 1 low |

**One attack dataset dropped a level.** `psexec_service` went from 58 (high) to 47 (medium). Its
three findings come from two rules: the same encoded-PowerShell stager seen twice, plus a service
install. That follows directly from not letting repeats add up, and we accept the trade-off. A
rule that recognises "a new service launching encoded PowerShell" as one strong combined
behaviour would be the right fix, rather than weighting repeats again.

Limits: there is only one benign collection (one laptop, one day), so calibration on more
ordinary machines (servers, domain controllers, developer workstations) is still needed.

## Limits of this evaluation

- **Small:** 28 datasets and 31 expected detections. One more miss moves the rate by several points.
- **Narrow:** single-technique lab recordings lasting minutes, mostly simulated with Empire, on a
  few Windows 10 / Server hosts in Azure. Real environments have far more background
  software, and so more false positives.
- **Windows only.** The Linux, web, AWS, Microsoft 365 and Okta rules are not covered here.
  The next step for those is replaying real attack tooling, for example Stratus Red Team for
  AWS CloudTrail.
- **Precision is only partly measured.** False positives are counted only against the
  background noise in these recordings. There is no long benign-only baseline yet.
- **Trade-offs of the tuning:** excluding services hosted in `svchost -k <group>` also hides a
  malicious service registered into a svchost group (a known, rarer technique). Excluding the
  Azure log collector assumes its path can't be planted by an attacker.
