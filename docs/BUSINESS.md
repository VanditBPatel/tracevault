# TraceVault — Startup Plan

*Evidence-first incident response for companies that can't afford a forensics team.*

> Figures marked **[validate]** are working assumptions for the founding team to confirm with
> primary research (customer interviews, insurer conversations, analyst reports) before fundraising.

---

## 1. The problem

When a small or mid-sized company is breached, the first 48 hours decide the outcome — and
that is exactly when they are least equipped:

1. **No in-house DFIR skills.** Most SMBs and startups have an IT generalist or a single security
   engineer, not a forensic examiner.
2. **Expensive, slow outside help.** Incident-response retainers and emergency engagements are
   priced for enterprises, and responders often need days to collect and process evidence.
3. **Evidence gets destroyed.** Well-meaning staff reboot servers, clear logs or "clean up"
   before anyone has preserved what happened, ruining insurance claims and legal options.
4. **Insurers and regulators now demand proof.** Cyber-insurance claims, breach-notification
   laws and contracts increasingly require a defensible account of *what* happened and *when*,
   with evidence whose integrity can be demonstrated.

## 2. The solution

TraceVault is a **triage-and-preservation platform** that lets a non-specialist do the first,
most important hour of incident response correctly:

| Step | What TraceVault does |
|---|---|
| **Preserve** | Hashes and copies evidence into a case with a tamper-evident custody ledger |
| **Reconstruct** | Merges logs from Linux, Windows and web servers into one super-timeline |
| **Detect** | Runs explainable, ATT&CK-mapped rules; every finding links to its raw evidence |
| **Explain** | Produces a risk score, kill-chain view and plain-English storyline |
| **Hand off** | Exports a court- and insurer-ready report a professional responder can pick up instantly |

## 3. What's new (innovation)

1. **Verifiable chain of custody by default.** Each action is a link in a SHA-256 hash chain; the
   ledger head can be anchored to an external timestamp authority or a public blockchain, giving
   cryptographic proof that evidence and records have not changed since a point in time. Most
   SMB tooling has no custody story at all.
2. **Explainable over black-box.** Detections are human-readable JSON rules; the storyline is
   generated only from findings, so every sentence traces to evidence. That matters in front of an
   insurer, auditor or court — and avoids the "hallucinated narrative" risk of pure-LLM tools.
3. **Zero-install, offline-first.** Runs from a USB stick or jump box with only Python — no agents
   to deploy *after* the breach, no evidence leaving the network unless the customer chooses.
4. **Context-aware attribution.** The same behaviour is classified differently depending on where
   it originates (e.g. a brute-forced login from inside the network is lateral movement, not initial
   access), giving a more accurate attack narrative automatically.
5. **Built for the hand-off.** Output is structured for the next responder: a professional firm
   can start from a verified timeline instead of spending day one on collection.

## 4. Who it's for

| Segment | Pain | Why they buy |
|---|---|---|
| **Startups & SMBs (20–1,000 staff)** | No security team; a breach is existential | Do the right thing in hour one; cut emergency IR spend |
| **Managed Service Providers (MSPs / MSSPs)** | Many clients, few forensic specialists | One tool across every client; billable IR offering |
| **Cyber-insurance carriers & brokers** | Claims lack reliable evidence; IR panel costs rise | Faster, cheaper, more defensible claims |
| **Boutique IR / law firms** | Collection and timeline building is slow, manual work | Start engagements from verified data |

**Beachhead:** MSPs serving SMBs. One sale reaches dozens of end customers, MSPs already hold the
trust relationship, and they need a repeatable IR service line.

## 5. Business model

| Tier | For | Includes | Indicative price **[validate]** |
|---|---|---|---|
| **Community** | Students, researchers, small teams | CLI, core rules, local dashboard (open source) | Free |
| **Pro** | In-house IT / security teams | Extended rule packs, more artifact types, PDF export, updates | per seat / month |
| **MSP** | Service providers | Multi-tenant console, per-client cases, white-label reports | per managed endpoint / month |
| **Insurer / Enterprise** | Carriers, large orgs | Claims portal, anchoring service, SSO, API, SLAs | annual contract |

Additional revenue: **evidence anchoring as a service** (per-case notarization), paid rule packs
for specific threats (ransomware families, cloud identity attacks), and training/certification.

Open-core keeps adoption friction near zero and builds community trust — important in security,
where buyers want to inspect what touches their evidence.

## 6. Go-to-market

1. **Open-source launch** of the community edition; publish detection content and sample cases.
2. **MSP design partners** (5–10) using TraceVault on real incidents in exchange for feedback and
   case studies.
3. **Insurance channel**: position TraceVault as a pre-breach readiness requirement / premium
   discount and as the first step of a claim.
4. **Content-led growth**: write-ups of real attack patterns, free "first hour of a breach" guides,
   conference talks and CTF challenges built on TraceVault.

## 7. Competitive landscape

| Category | Examples | Where TraceVault differs |
|---|---|---|
| Enterprise forensic suites | Magnet AXIOM, EnCase, X-Ways | Priced and built for trained examiners; TraceVault targets generalists |
| Open-source DFIR tooling | Velociraptor, Plaso/log2timeline, KAPE, Timesketch | Powerful but expert-oriented and multi-component; TraceVault is one-command triage with custody built in |
| EDR / XDR forensics modules | CrowdStrike, SentinelOne, Microsoft Defender | Require agents deployed *before* the incident; many SMBs don't have them |
| Cloud forensics startups | e.g. Cado-style platforms | Cloud-first; TraceVault starts from on-prem/hybrid SMB reality and runs offline |

Defensibility over time: the **detection content library**, **custody/anchoring network** trusted by
insurers, and **MSP distribution**.

## 8. Product roadmap

| Phase | Timeline **[validate]** | Milestones |
|---|---|---|
| **MVP (this repo)** | Now | Linux/web/Windows logs plus AWS CloudTrail, Microsoft 365 and Okta; 29 rules incl. MFA fatigue, impossible travel, BEC forwarding rules, cloud log tampering; custody ledger, report, dashboard |
| **v0.2 Collect** | +3 months | Native EVTX parsing, live-response collector scripts, Google Workspace, Entra ID sign-in logs, GCP/Azure activity logs |
| **v0.3 Correlate** | +6 months | Sigma rule import, entity graph, IOC enrichment (threat intel feeds), YARA on files |
| **v1.0 Platform** | +9–12 months | Multi-tenant MSP console, team collaboration, public anchoring service, insurer claims export |
| **v1.x Assist** | +12–18 months | LLM co-pilot that *drafts* report sections strictly grounded in findings, with every claim cited to evidence IDs |

## 9. Key metrics

- Time from evidence ingest to first verified finding (target: minutes, not days)
- Detection rate and false positives on public attack datasets. The first measurement is
  **82%** of techniques detected on held-out OTRF Security-Datasets recordings, with false
  positives from Windows background services that were then tuned out
  ([VALIDATION.md](VALIDATION.md)). Grow the benchmark and publish each release's score.
- Cases handed to professional responders without re-collection
- MSP accounts, managed endpoints, monthly active cases
- Net revenue retention and insurer-channel conversion

## 10. Team needed

- **DFIR lead** — practitioner credibility, detection content, expert-witness experience
- **Platform engineer** — parsers, scale, multi-tenant backend
- **Security product designer** — making expert workflows usable by generalists
- **Channel / partnerships** — MSP and insurer relationships

## 11. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Detection gaps lead to missed activity | Open rule format, community contributions, Sigma import, clear "triage not full forensics" positioning |
| Legal admissibility questioned | Follow established evidence-handling guidance (e.g. ISO/IEC 27037, NIST SP 800-86), independent review of custody design |
| Large vendors bundle similar features | Stay agent-less, offline, MSP- and insurer-native; move fast on content |
| Handling sensitive customer data | Local-first by default; any cloud features opt-in, encrypted, region-pinned |

## 12. The ask (template)

Pre-seed funding to cover **[validate: amount / runway]** for: two engineering hires, a DFIR lead,
MSP design-partner programme, and a third-party security and legal review of the custody model.
