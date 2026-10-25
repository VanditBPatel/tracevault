"""Self-contained incident report: one HTML file that reads well on screen and prints cleanly to
PDF (A4 or Letter). No external resources, so it can be emailed, archived or attached to a claim.

Everything taken from evidence is attacker-controlled and goes through escape().
"""

from __future__ import annotations

from datetime import datetime
from html import escape
from typing import Any

SEV_ORDER = ["critical", "high", "medium", "low"]
SEV_COLORS = {"critical": "#e11d48", "high": "#c2410c", "medium": "#b45309", "low": "#2563eb"}
STATUS = {"created": ("Created by attacker", "#e11d48"), "compromised": ("Compromised", "#c2410c"),
          "targeted": ("Targeted", "#b45309"), "involved": ("Involved", "#64748b")}
ACTIONS = {"case.create": "Case opened", "evidence.ingest": "Evidence acquired",
           "evidence.collection": "Collection verified", "analysis.run": "Analysis run",
           "report.export": "Report exported", "finding.suppress": "Finding suppressed",
           "finding.unsuppress": "Suppression withdrawn"}
MAX_EVIDENCE = 8


def _e(value: Any) -> str:
    return escape("" if value is None else str(value))


def _badge(text: str, color: str) -> str:
    return f'<span class="badge" style="--c:{color}">{_e(text)}</span>'


def _sev(sev: str) -> str:
    return _badge(sev, SEV_COLORS.get(sev, "#64748b"))


def _dt(iso: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _when(iso: str | None, with_date: bool = True) -> str:
    d = _dt(iso)
    if not d:
        return "-"
    return d.strftime("%d %b %Y, %H:%M UTC" if with_date else "%H:%M:%S")


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _gauge(score: int, color: str) -> str:
    r, v = 34, max(0, min(100, int(score)))
    c = 2 * 3.14159 * r
    return (f'<svg class="gauge" viewBox="0 0 84 84" aria-hidden="true"><circle cx="42" cy="42" r="{r}" fill="none" '
            f'stroke="#e5e9f0" stroke-width="9"/><circle cx="42" cy="42" r="{r}" fill="none" stroke="{color}" '
            f'stroke-width="9" stroke-linecap="round" stroke-dasharray="{c * v / 100:.1f} {c:.1f}" '
            f'transform="rotate(-90 42 42)"/><text x="42" y="49" text-anchor="middle" font-size="22" '
            f'font-weight="800" fill="#0f172a">{v}</text></svg>')


# --------------------------------------------------------------------------- narrative

def executive_summary(result: dict[str, Any], verification: dict[str, Any]) -> list[str]:
    """Plain-language paragraph(s) built only from analysis data - no free text is invented."""
    stats, risk = result["stats"], result["risk"]
    attack = [f for f in result["findings"] if not f.get("suppressed") and f.get("category", "attack") == "attack"]
    sources = len(stats.get("by_source", {}))
    out = []
    if not attack:
        out.append(f"TraceVault analysed {stats['events']:,} events from {_plural(sources, 'evidence file')} and "
                   f"found no attacker activity.")
    else:
        start, end = _dt(stats["dwell"][0]), _dt(stats["dwell"][1])
        if start and end and start.date() == end.date():
            window = f"between {start:%H:%M} and {end:%H:%M} UTC on {start:%d %B %Y}"
        elif start and end:
            window = f"between {start:%d %B %Y %H:%M} and {end:%d %B %Y %H:%M} UTC"
        else:
            window = "in the evidence"
        sev = stats["by_severity"]
        top = ", ".join(f"{sev[s]} {s}" for s in SEV_ORDER if sev.get(s))
        hosts = [h["value"] for h in result["iocs"]["hosts"]]
        out.append(f"TraceVault found {_plural(len(attack), 'finding')} of attacker activity ({top}) {window}, "
                   f"across {_plural(len(hosts), 'system')} ({', '.join(hosts)}). "
                   f"The overall risk is {risk['level']} ({risk['score']}/100).")
        idents = result.get("identities", [])
        comp = [i["identity"] for i in idents if i["status"] == "compromised"]
        made = [i["identity"] for i in idents if i["status"] == "created"]
        parts = []
        if comp:
            parts.append(f"{_plural(len(comp), 'identity')} appear{'s' if len(comp) == 1 else ''} compromised "
                         f"({', '.join(comp)})")
        if made:
            parts.append(f"the attacker created {_plural(len(made), 'account')} ({', '.join(made)})")
        tactics = [t["tactic"] for t in result["attack_chain"] if t["count"]]
        if tactics:
            parts.append(f"the activity spans {len(tactics)} of 14 MITRE ATT&CK tactics, from "
                         f"{tactics[0]} to {tactics[-1]}")
        if parts:
            sentence = "; ".join(parts)
            out.append(sentence[0].upper() + sentence[1:] + ".")
        ips = [x["value"] for x in result["iocs"]["ips"] if x.get("external")]
        if ips:
            it = "it" if len(ips) == 1 else "them"
            out.append(f"External {'address' if len(ips) == 1 else 'addresses'} involved: {', '.join(ips)}. "
                       f"Consider blocking {it} and searching other systems for {it}.")
    if verification.get("ok"):
        out.append(f"All {_plural(len(verification.get('evidence', [])), 'evidence file')} still match the hashes "
                   f"recorded when they were acquired, and the custody ledger ({verification.get('entries')} entries) "
                   f"is intact.")
    else:
        out.append("WARNING: the integrity check failed - evidence or custody records changed after they were "
                   "recorded. See section 7 before relying on this report.")
    return out


# --------------------------------------------------------------------------- render

def render(result: dict[str, Any], ledger: list[dict[str, Any]], verification: dict[str, Any],
           revoked: list[dict[str, Any]] | None = None) -> str:
    case = result.get("case", {})
    stats, risk = result["stats"], result["risk"]
    events = {e["id"]: e for e in result["timeline"]}
    risk_color = SEV_COLORS.get(risk["level"], "#64748b")
    findings = result["findings"]
    attack = [f for f in findings if not f.get("suppressed") and f.get("category", "attack") == "attack"]
    posture = [f for f in findings if not f.get("suppressed") and f.get("category", "attack") != "attack"]
    suppressed = [f for f in findings if f.get("suppressed")]
    dwell = stats.get("dwell")

    # ---------- cover
    facts = [
        ("Case", f'<span class="mono">{_e(case.get("id"))}</span>'),
        ("Examiner", _e(case.get("examiner"))),
        ("Case opened", _e(_when(case.get("created_at")))),
        ("Report generated", _e(_when(result.get("generated_at")))),
        ("Evidence", f"{_plural(len(stats.get('by_source', {})), 'file')}, {stats['events']:,} events"),
        ("Attacker activity", _e(f"{_when(dwell[0])} to {_when(dwell[1], False)[:5]} UTC") if dwell else "None detected"),
    ]
    integrity = (f'<div class="seal ok">&#10003; Evidence integrity verified</div>' if verification.get("ok")
                 else f'<div class="seal bad">&#9888; Integrity check failed</div>')
    cover = f"""
    <section class="cover">
      <div class="brandline"><span class="logo">&#9670;</span> TraceVault <span class="muted">Incident report</span></div>
      <h1>{_e(case.get("title"))}</h1>
      <div class="cover-grid">
        <div class="risk">{_gauge(risk["score"], risk_color)}
          <div><div class="label">Overall risk</div><div class="risk-level" style="color:{risk_color}">{_e(risk["level"].title())}</div>
          <div class="muted">{risk["score"]} out of 100</div></div></div>
        <dl class="facts">{"".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in facts)}</dl>
      </div>
      <div class="stats">
        <div><b>{len(attack)}</b><span>findings</span></div>
        {"".join(f'<div><b style="color:{SEV_COLORS[s]}">{stats["by_severity"].get(s, 0)}</b><span>{s}</span></div>' for s in SEV_ORDER)}
        <div><b>{sum(1 for i in result.get("identities", []) if i["status"] in ("compromised", "created"))}</b><span>accounts affected</span></div>
      </div>
      {integrity}
      <nav class="toc"><b>Contents</b><ol>
        <li><a href="#summary">Executive summary</a></li><li><a href="#story">What happened</a></li>
        <li><a href="#people">Identities and indicators</a></li><li><a href="#attack">MITRE ATT&amp;CK coverage</a></li>
        <li><a href="#findings">Findings</a></li><li><a href="#review">Posture and analyst review</a></li>
        <li><a href="#custody">Evidence and chain of custody</a></li><li><a href="#method">Method and limitations</a></li></ol></nav>
    </section>"""

    # ---------- summary & story
    summary = "".join(f"<p>{_e(p)}</p>" for p in executive_summary(result, verification))
    contrib_rows = "".join(
        f"<tr><td>{_sev(c['severity'])}</td><td>{_e(c['title'])}</td><td class='num'>{c['findings']}</td>"
        f"<td class='num'>{c['points']}</td></tr>" for c in risk.get("contributors", [])[:8])
    risk_why = ""
    if risk.get("reasons"):
        risk_why = (f'<div class="why"><div class="label">How the risk score was reached</div><ul>'
                    + "".join(f"<li>{_e(x)}</li>" for x in risk["reasons"]) + "</ul>"
                    + (f"<table><thead><tr><th>Severity</th><th>Behaviour (rule)</th><th class='num'>Findings</th>"
                       f"<th class='num'>Points</th></tr></thead><tbody>{contrib_rows}</tbody></table>"
                       if contrib_rows else "")
                    + '<p class="small muted">Each distinct behaviour counts once; further findings of the same rule add '
                      "at most 50% of its weight. Behaviours combine as independent evidence, so different stages of an "
                      "attack raise the score far more than repeats.</p></div>")
    steps = []
    for line in result["narrative"]:
        if line.startswith(("Compromised identities:", "Accounts created by the attacker:")):
            continue
        head, sep, rest = line.partition(" - from ")
        if sep:
            when, _, what = rest.partition(" UTC: ")
            steps.append(f'<li><b>{_e(head)}</b> <span class="muted">from {_e(when)} UTC</span><div>{_e(what)}</div></li>')
        else:
            steps.append(f"<li>{_e(line)}</li>")

    # ---------- people & indicators
    ident_rows = "".join(
        f"<tr><td><b>{_e(i['identity'])}</b></td><td>{_badge(*STATUS.get(i['status'], (i['status'], '#64748b')))}</td>"
        f"<td>{_e(', '.join(i['systems']))}</td><td class='mono'>{_e(', '.join(i['aliases']))}</td>"
        f"<td class='num'>{i['findings']}</td></tr>"
        for i in result.get("identities", []))
    ip_rows = "".join(
        f"<tr><td class='mono'>{_e(x['value'])}</td><td>{'External' if x['external'] else 'Internal'}</td>"
        f"<td class='num'>{x['findings']}</td></tr>" for x in result["iocs"]["ips"])
    host_rows = "".join(
        f"<tr><td class='mono'>{_e(x['value'])}</td><td class='num'>{x['findings']}</td></tr>"
        for x in result["iocs"]["hosts"])

    # ---------- ATT&CK
    chain = "".join(
        f'<div class="tactic{" hit" if t["count"] else ""}" style="--c:{SEV_COLORS.get(t["max_severity"] or "", "#cbd5e1")}">'
        f'<b>{_e(t["tactic"])}</b>'
        + (f'<span class="n">{t["count"]}</span><span class="mono small">{_e(" ".join(x["id"] for x in t["techniques"]))}</span>'
           if t["count"] else "")
        + "</div>"
        for t in result["attack_chain"])

    # ---------- findings
    def finding_block(f: dict[str, Any], label: str) -> str:
        ctx = set(f.get("context_event_ids", []))
        ev_rows = []
        repeats = int(f.get("occurrences", 1) or 1)
        # Identical repeats: list the event once; the repeat line below gives count and span.
        shown = f["event_ids"][:1] if repeats > 1 else f["event_ids"][:MAX_EVIDENCE]
        for eid in shown:
            e = events.get(eid)
            if not e:
                continue
            note = ' <i class="muted">(context, not attributed to the attacker)</i>' if eid in ctx else ""
            ev_rows.append(f"<tr><td class='mono'>{_e(eid)}</td><td class='mono'>{_e(_when(e['ts'], False))}</td>"
                           f"<td class='mono'>{_e(e['host'])}</td><td>{_e(e['message'])}{note}</td></tr>")
        more = len(f["event_ids"]) - MAX_EVIDENCE
        if repeats > 1:
            ev_rows.append(f"<tr><td colspan='4'><b>Identical event repeated {repeats} times</b> between "
                           f"{_e(_when(f['ts'], False))} and {_e(_when(f.get('last_ts'), False))} UTC "
                           f"(events {_e(f['event_ids'][0])} to {_e(f['event_ids'][-1])}).</td></tr>")
        elif more > 0:
            ev_rows.append(f"<tr><td colspan='4' class='muted'>... and {more} more events (see analysis.json)</td></tr>")
        ents = f["entities"]["hosts"] + f["entities"]["users"] + f["entities"]["ips"]
        return f"""
        <article class="finding" style="--c:{SEV_COLORS.get(f['severity'], '#64748b')}">
          <header><span class="fid">{label}</span> {_sev(f['severity'])} <h3>{_e(f['title'])}</h3>
            {_badge(f"x{repeats}", "#0d9488") if repeats > 1 else ""}
            <span class="muted when">{_e(_when(f['ts']))}</span></header>
          <p class="fsum">{_e(f['summary'])}</p>
          <p class="meta"><span class="tech">{_e(f['technique'])}</span> {_e(f['technique_name'])} &middot; {_e(f['tactic'])}
            &middot; rule <span class="mono">{_e(f['rule_id'])}</span></p>
          <p class="muted small">{_e(f['description'])}</p>
          {f'<p class="small"><b>Entities:</b> <span class="mono">{_e(", ".join(ents))}</span></p>' if ents else ""}
          <table class="ev"><thead><tr><th>Event</th><th>Time</th><th>Host</th><th>Evidence</th></tr></thead><tbody>{"".join(ev_rows)}</tbody></table>
        </article>"""

    finding_html = "".join(finding_block(f, f"F{i:02d}") for i, f in enumerate(attack, 1)) or \
        '<p class="empty">No attacker activity was detected.</p>'
    posture_html = "".join(finding_block(f, f"P{i:02d}") for i, f in enumerate(posture, 1))
    sup_rows = "".join(
        f"<tr><td>{_sev(f['severity'])}</td><td><b>{_e(f['title'])}</b><div class='muted small'>{_e(f['summary'])}</div></td>"
        f"<td><b>{_e(f['suppressed']['id'])}</b> {'False positive' if f['suppressed']['verdict'] == 'false_positive' else 'Expected activity'}"
        f"<div class='small'>{_e(f['suppressed']['reason'])}</div><div class='muted small'>{_e(f['suppressed']['scope'])}</div></td>"
        f"<td>{_e(f['suppressed']['by'])}<div class='muted small'>{_e(_when(f['suppressed']['at']))}</div></td></tr>"
        for f in suppressed)
    withdrawn = "".join(
        f"<li><b>{_e(s['id'])}</b> ({_e(s['reason'])}) withdrawn by {_e(s['revoked_by'])} on "
        f"{_e(_when(s['revoked_at']))}: {_e(s['revoke_reason'])}</li>" for s in revoked or [])

    # ---------- custody
    ev_files = "".join(
        f"<tr><td class='mono'>{_e(x['file'])}</td><td class='mono hash'>{_e(x['expected'])}</td>"
        f"<td>{_badge('Match', '#059669') if x['ok'] else _badge('Changed', '#e11d48')}</td></tr>"
        for x in verification.get("evidence", []))
    ledger_rows = []
    for e in ledger:
        d = e.get("details") or {}
        what = e.get("evidence") or (f"{d.get('id', '')} {d.get('rule_id', '')} {d.get('reason', '')}".strip()
                                     if d.get("id") else d.get("host") or "")
        ledger_rows.append(
            f"<tr><td class='num'>{e['seq']}</td><td class='mono'>{_e(str(e['ts']).replace('T', ' ')[:19])}</td>"
            f"<td>{_e(e['actor'])}</td><td>{_e(ACTIONS.get(e['action'], e['action']))}</td><td>{_e(what)}</td>"
            f"<td class='mono hash'>{_e(e['entry_hash'][:16])}</td></tr>")
    problems = "".join(f"<li>{_e(p)}</li>" for p in verification.get("problems", []))
    custody_banner = (
        f'<div class="banner ok"><b>&#10003; Chain of custody intact.</b> All {len(verification.get("evidence", []))} evidence '
        f'files match their acquisition hashes and all {verification.get("entries")} ledger entries chain correctly. '
        f'Checked {_e(_when(verification.get("checked_at")))}.</div>' if verification.get("ok") else
        f'<div class="banner bad"><b>&#9888; Integrity check failed.</b> Checked {_e(_when(verification.get("checked_at")))}.'
        f'<ul>{problems}</ul></div>')

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Incident report {_e(case.get("id"))} - {_e(case.get("title"))}</title>
<style>
  :root {{ --text:#0f172a; --text2:#334155; --muted:#64748b; --line:#e2e8f0; --soft:#f5f7fb; --accent:#0d9488; }}
  * {{ box-sizing: border-box; }}
  html {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
  body {{ margin: 0; background: #eef2f7; color: var(--text); font: 13.5px/1.55 "Inter","Segoe UI",system-ui,-apple-system,Roboto,sans-serif; }}
  .page {{ max-width: 920px; margin: 28px auto; background: #fff; border-radius: 14px; box-shadow: 0 8px 40px rgb(15 23 42 / .10); padding: 48px 56px; }}
  h1 {{ font-size: 28px; line-height: 1.2; letter-spacing: -.02em; margin: 10px 0 22px; }}
  h2 {{ font-size: 19px; letter-spacing: -.01em; margin: 0 0 4px; display: flex; align-items: baseline; gap: 10px; }}
  h2 .no {{ color: var(--accent); font-size: 14px; font-weight: 800; }}
  h3 {{ font-size: 15px; margin: 0; display: inline; }}
  section {{ margin-top: 40px; }}
  section > .lead {{ color: var(--muted); margin: 0 0 16px; font-size: 12.5px; }}
  .muted {{ color: var(--muted); }} .small {{ font-size: 12px; }}
  .mono {{ font-family: "JetBrains Mono","Cascadia Code",Consolas,ui-monospace,monospace; font-size: 11.5px; }}
  .hash {{ word-break: break-all; }}
  .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .badge {{ display: inline-block; padding: 1px 8px; border-radius: 6px; font-size: 10.5px; font-weight: 800; letter-spacing: .04em;
            text-transform: uppercase; color: var(--c); background: color-mix(in srgb, var(--c) 13%, #fff); white-space: nowrap; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12.5px; }}
  th {{ text-align: left; font-size: 10.5px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); padding: 7px 8px; border-bottom: 1.5px solid var(--line); }}
  td {{ padding: 7px 8px; border-bottom: 1px solid var(--line); vertical-align: top; overflow-wrap: anywhere; }}
  tr {{ break-inside: avoid; }}

  .cover {{ margin-top: 0; }}
  .brandline {{ font-weight: 800; font-size: 14px; display: flex; gap: 8px; align-items: center; }}
  .brandline .muted {{ font-weight: 500; }}
  .logo {{ color: #fff; background: linear-gradient(135deg, #0d9488, #6366f1); width: 26px; height: 26px; border-radius: 8px; display: inline-grid; place-items: center; font-size: 13px; }}
  .cover-grid {{ display: grid; grid-template-columns: 260px 1fr; gap: 28px; align-items: center; padding: 22px; border: 1px solid var(--line); border-radius: 14px; background: var(--soft); }}
  .risk {{ display: flex; gap: 16px; align-items: center; }}
  .gauge {{ width: 92px; height: 92px; flex: none; }}
  .label {{ font-size: 11px; text-transform: uppercase; letter-spacing: .07em; color: var(--muted); font-weight: 700; }}
  .risk-level {{ font-size: 28px; font-weight: 800; line-height: 1.1; }}
  .facts {{ display: grid; grid-template-columns: 140px 1fr; gap: 6px 14px; margin: 0; font-size: 13px; }}
  .facts dt {{ color: var(--muted); }} .facts dd {{ margin: 0; font-weight: 600; }}
  .stats {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 10px; margin: 16px 0; }}
  .stats div {{ border: 1px solid var(--line); border-radius: 12px; padding: 12px 14px; }}
  .stats b {{ display: block; font-size: 24px; line-height: 1.1; }} .stats span {{ font-size: 11.5px; color: var(--muted); text-transform: capitalize; }}
  .seal {{ display: inline-block; padding: 7px 14px; border-radius: 99px; font-weight: 700; font-size: 12.5px; }}
  .seal.ok {{ color: #047857; background: #d1fae5; }} .seal.bad {{ color: #be123c; background: #ffe4e6; }}
  .toc {{ margin-top: 24px; padding: 16px 20px; border-radius: 12px; background: var(--soft); font-size: 13px; }}
  .toc ol {{ margin: 8px 0 0; padding-left: 20px; columns: 2; }} .toc a {{ color: var(--text2); text-decoration: none; }}

  .summary p {{ font-size: 14.5px; line-height: 1.65; margin: 0 0 10px; color: var(--text2); }}
  .summary p:first-child {{ font-size: 16px; color: var(--text); }}
  .steps {{ margin: 0; padding: 0; list-style: none; counter-reset: s; }}
  .steps li {{ position: relative; padding: 0 0 14px 38px; break-inside: avoid; }}
  .steps li::before {{ counter-increment: s; content: counter(s); position: absolute; left: 0; top: 0; width: 24px; height: 24px; border-radius: 50%;
                       background: #e6fffa; color: #0f766e; font-weight: 800; font-size: 12px; display: grid; place-items: center; }}
  .steps li div {{ color: var(--text2); }}
  .grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 22px; }}
  .chain {{ display: grid; grid-template-columns: repeat(7, 1fr); gap: 6px; }}
  .tactic {{ border: 1px solid var(--line); border-radius: 9px; padding: 8px; min-height: 70px; font-size: 10.5px; color: #94a3b8; display: flex; flex-direction: column; gap: 3px; }}
  .tactic b {{ font-weight: 700; }}
  .tactic.hit {{ color: var(--text); border-color: color-mix(in srgb, var(--c) 50%, #fff); background: color-mix(in srgb, var(--c) 8%, #fff); }}
  .tactic .n {{ font-size: 18px; font-weight: 800; color: var(--c); line-height: 1; }}

  .finding {{ position: relative; border: 1px solid var(--line); border-left: 4px solid var(--c); border-radius: 10px; padding: 14px 16px; margin: 12px 0; break-inside: avoid; }}
  .finding header {{ display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }}
  .finding .fid {{ font-weight: 800; color: var(--muted); font-size: 12px; }}
  .finding .when {{ margin-left: auto; font-size: 12px; }}
  .finding p {{ margin: 6px 0 0; }} .fsum {{ font-size: 13.5px; }}
  .finding .meta {{ font-size: 12px; color: var(--text2); }}
  .tech {{ font-family: Consolas, ui-monospace, monospace; font-size: 11px; padding: 1px 6px; border-radius: 5px; background: #eef2f7; }}
  .ev {{ margin-top: 10px; }} .ev th, .ev td {{ padding: 5px 6px; font-size: 11.5px; }}
  .empty {{ padding: 18px; border: 1px dashed var(--line); border-radius: 10px; color: var(--muted); text-align: center; }}
  .banner {{ padding: 12px 16px; border-radius: 10px; margin-bottom: 14px; font-size: 13px; }}
  .banner.ok {{ background: #ecfdf5; border: 1px solid #a7f3d0; }} .banner.bad {{ background: #fff1f2; border: 1px solid #fecdd3; }}
  .method p {{ color: var(--text2); margin: 0 0 8px; }}
  .why {{ margin-top: 16px; padding: 14px 18px; border-radius: 12px; background: var(--soft); break-inside: avoid; }}
  .why ul {{ margin: 6px 0 10px; padding-left: 20px; color: var(--text2); }} .why table {{ background: #fff; border-radius: 8px; }}
  .print-only {{ display: none; }}
  .footer {{ margin-top: 40px; padding-top: 14px; border-top: 1px solid var(--line); color: var(--muted); font-size: 11.5px; display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap; }}
  .printbar {{ position: sticky; top: 0; z-index: 5; display: flex; justify-content: center; gap: 10px; padding: 10px; background: rgb(238 242 247 / .9); backdrop-filter: blur(8px); }}
  .printbar button {{ font: inherit; font-weight: 700; border: 0; border-radius: 9px; padding: 8px 16px; background: #0d9488; color: #fff; cursor: pointer; }}

  @media (max-width: 760px) {{
    .page {{ margin: 0; border-radius: 0; padding: 26px 18px; }}
    .cover-grid, .grid2 {{ grid-template-columns: 1fr; }} .stats {{ grid-template-columns: repeat(3, 1fr); }}
    .chain {{ grid-template-columns: repeat(2, 1fr); }} .toc ol {{ columns: 1; }} .facts {{ grid-template-columns: 120px 1fr; }}
  }}
  @page {{ size: A4; margin: 16mm 14mm 18mm; @bottom-left {{ content: "TraceVault incident report - {_e(case.get("id"))}"; font-size: 8pt; color: #64748b; }}
           @bottom-right {{ content: "Page " counter(page) " of " counter(pages); font-size: 8pt; color: #64748b; }} }}
  @media print {{
    body {{ background: #fff; font-size: 11.5px; }} .page {{ box-shadow: none; margin: 0; padding: 0; max-width: none; border-radius: 0; }}
    .printbar, .toc, .footer {{ display: none; }}
    .print-only {{ display: block; }}
    section {{ margin-top: 26px; }} section.break {{ break-before: page; margin-top: 0; }}
    /* Keep headings, intro lines and table labels with what follows them. */
    h2, section > .lead, .label {{ break-after: avoid; page-break-after: avoid; }}
    .steps li:first-child, table thead {{ break-before: avoid; }}
    a {{ color: inherit; text-decoration: none; }}
  }}
</style></head>
<body>
<div class="printbar"><button type="button" onclick="window.print()">Print or save as PDF</button></div>
<main class="page">
  {cover}

  <section id="summary" class="summary">
    <h2><span class="no">1</span> Executive summary</h2>
    {summary}
    {risk_why}
  </section>

  <section id="story">
    <h2><span class="no">2</span> What happened</h2>
    <p class="lead">In MITRE ATT&amp;CK order. Every line is built from findings in section 5.</p>
    <ol class="steps">{"".join(steps) or "<li>No attacker activity was detected.</li>"}</ol>
  </section>

  <section id="people">
    <h2><span class="no">3</span> Identities and indicators</h2>
    <p class="lead">Accounts are linked across systems into one identity. Status comes from attacker-attributed evidence only.</p>
    {f'<table><thead><tr><th>Identity</th><th>Status</th><th>Systems</th><th>Seen as</th><th class="num">Findings</th></tr></thead><tbody>{ident_rows}</tbody></table>' if ident_rows else '<p class="empty">No identities involved.</p>'}
    <div class="grid2" style="margin-top:18px">
      <div><div class="label">IP addresses</div>{f'<table><thead><tr><th>Address</th><th>Scope</th><th class="num">Findings</th></tr></thead><tbody>{ip_rows}</tbody></table>' if ip_rows else '<p class="muted">None.</p>'}</div>
      <div><div class="label">Hosts and tenants</div>{f'<table><thead><tr><th>Host</th><th class="num">Findings</th></tr></thead><tbody>{host_rows}</tbody></table>' if host_rows else '<p class="muted">None.</p>'}</div>
    </div>
  </section>

  <section id="attack">
    <h2><span class="no">4</span> MITRE ATT&amp;CK coverage</h2>
    <p class="lead">Tactics with findings are highlighted, coloured by their most severe finding.</p>
    <div class="chain">{chain}</div>
  </section>

  <section id="findings" class="break">
    <h2><span class="no">5</span> Findings <span class="muted" style="font-size:13px;font-weight:500">{len(attack)}</span></h2>
    <p class="lead">Each finding lists the evidence events that triggered it (first {MAX_EVIDENCE}). Times are UTC.</p>
    {finding_html}
  </section>

  <section id="review">
    <h2><span class="no">6</span> Posture and analyst review</h2>
    <p class="lead">Risky practice that is not attacker activity, and findings an analyst reviewed and suppressed. Neither counts towards the risk score.</p>
    {posture_html or '<p class="muted">No posture issues observed.</p>'}
    <div class="label" style="margin-top:16px">Suppressed by analyst</div>
    {f'<table><thead><tr><th>Severity</th><th>Finding</th><th>Decision</th><th>By</th></tr></thead><tbody>{sup_rows}</tbody></table>' if sup_rows else '<p class="muted">None.</p>'}
    {f'<div class="label" style="margin-top:12px">Withdrawn suppressions</div><ul class="small">{withdrawn}</ul>' if withdrawn else ""}
  </section>

  <section id="custody" class="break">
    <h2><span class="no">7</span> Evidence and chain of custody</h2>
    <p class="lead">Every file is SHA-256 hashed when acquired. Every action is a hash-chained ledger entry, so later changes are detected.</p>
    {custody_banner}
    <div class="label">Evidence files</div>
    <table><thead><tr><th>File</th><th>SHA-256 at acquisition</th><th>Now</th></tr></thead><tbody>{ev_files}</tbody></table>
    <div class="label" style="margin-top:18px">Ledger</div>
    <p class="small muted">Head hash (commits to the entire history): <span class="mono hash">{_e(verification.get("head") or "-")}</span></p>
    <table><thead><tr><th class="num">#</th><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Subject</th><th>Entry hash</th></tr></thead>
      <tbody>{"".join(ledger_rows)}</tbody></table>
  </section>

  <section id="method" class="method">
    <h2><span class="no">8</span> Method and limitations</h2>
    <p>TraceVault parsed {stats['events']:,} events from {_plural(len(stats.get('by_source', {})), 'evidence file')} into one
      UTC timeline and ran explainable detection rules mapped to MITRE ATT&amp;CK. The summary and storyline are generated only
      from those findings; nothing in this report is free-written.</p>
    <p>This is triage, not a full forensic examination. Rules detect known patterns and can miss novel activity or flag
      benign activity. Absence of a finding is not proof of absence. On public attack datasets the Windows rules detected
      82% of techniques they had not been tuned on (see the project's docs/VALIDATION.md).</p>
    <p class="small muted print-only">Generated by {_e(result["tool"]["name"])} {_e(result["tool"]["version"])} on
      {_e(_when(result.get("generated_at")))}. Ledger head <span class="mono hash">{_e(verification.get("head") or "-")}</span>.</p>
  </section>

  <div class="footer"><span>Generated by {_e(result["tool"]["name"])} {_e(result["tool"]["version"])} on {_e(_when(result.get("generated_at")))}</span>
    <span>Case {_e(case.get("id"))} &middot; ledger head <span class="mono">{_e((verification.get("head") or "-")[:16])}</span></span></div>
</main>
</body></html>
"""
