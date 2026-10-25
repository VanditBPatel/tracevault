"""Self-contained, printable HTML incident report."""

from __future__ import annotations

from html import escape
from typing import Any

SEV_COLORS = {"low": "#3b82f6", "medium": "#eab308", "high": "#f97316", "critical": "#dc2626"}


def _badge(sev: str | None) -> str:
    if not sev:
        return ""
    return f'<span class="badge" style="background:{SEV_COLORS.get(sev, "#64748b")}">{escape(sev)}</span>'


def render(result: dict[str, Any], ledger: list[dict[str, Any]], verification: dict[str, Any]) -> str:
    case = result.get("case", {})
    stats = result["stats"]
    risk = result["risk"]
    events = {e["id"]: e for e in result["timeline"]}

    chain = "".join(
        f'<div class="tactic {"hit" if t["count"] else ""}">'
        f'<div class="tname">{escape(t["tactic"])}</div>'
        f'<div class="tcount">{t["count"] or ""}</div>'
        + "".join(f"<div class=tech>{escape(x['id'])}</div>" for x in t["techniques"])
        + "</div>"
        for t in result["attack_chain"]
    )

    findings_rows = []
    for i, f in enumerate(result["findings"], start=1):
        evidence = "".join(
            f'<li><code>{escape(eid)}</code> {escape(events[eid]["ts"][11:19])} '
            f'<span class="muted">{escape(events[eid]["source"])}</span> {escape(events[eid]["message"])}</li>'
            for eid in f["event_ids"][:8]
        )
        more = len(f["event_ids"]) - 8
        if more > 0:
            evidence += f'<li class="muted">... and {more} more events</li>'
        findings_rows.append(f"""
        <div class="finding">
          <div class="fhead">{_badge(f["severity"])} <b>F{i:02d} &middot; {escape(f["title"])}</b>
            <span class="muted">{escape(f["rule_id"])} &middot; {escape(f["technique"])} {escape(f["technique_name"])}
            &middot; {escape(f["tactic"])}</span></div>
          <div>{escape(f["summary"])}</div>
          <div class="muted small">{escape(f["description"])}</div>
          <ul class="evidence">{evidence}</ul>
        </div>""")

    ioc_rows = "".join(
        f"<tr><td>IP</td><td><code>{escape(x['value'])}</code></td>"
        f"<td>{'external' if x['external'] else 'internal'}</td><td>{x['findings']}</td></tr>"
        for x in result["iocs"]["ips"]
    ) + "".join(
        f"<tr><td>Account</td><td><code>{escape(x['value'])}</code></td><td></td><td>{x['findings']}</td></tr>"
        for x in result["iocs"]["users"]
    ) + "".join(
        f"<tr><td>Host</td><td><code>{escape(x['value'])}</code></td><td></td><td>{x['findings']}</td></tr>"
        for x in result["iocs"]["hosts"]
    )

    ledger_rows = "".join(
        f"<tr><td>{e['seq']}</td><td>{escape(e['ts'])}</td><td>{escape(e['actor'])}</td>"
        f"<td>{escape(e['action'])}</td><td>{escape(e.get('evidence') or '')}</td>"
        f"<td><code>{escape((e.get('sha256') or '')[:16])}</code></td>"
        f"<td><code>{escape(e['entry_hash'][:16])}</code></td></tr>"
        for e in ledger
    )

    integrity = (
        '<span class="ok">VERIFIED</span> - ledger chain intact and all evidence hashes match'
        if verification["ok"] else
        '<span class="bad">FAILED</span><ul>' + "".join(f"<li>{escape(p)}</li>" for p in verification["problems"]) + "</ul>"
    )

    dwell = stats.get("dwell") or ["-", "-"]
    narrative = "".join(f"<li>{escape(line)}</li>" for line in result["narrative"])

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Incident Report {escape(case.get("id", ""))}</title>
<style>
  body {{ font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: #0f172a; margin: 0; background: #fff; }}
  main {{ max-width: 980px; margin: 0 auto; padding: 32px 20px 64px; }}
  h1 {{ margin: 0 0 4px; font-size: 26px; }} h2 {{ margin: 36px 0 12px; font-size: 18px; border-bottom: 2px solid #0f172a; padding-bottom: 4px; }}
  .muted {{ color: #64748b; }} .small {{ font-size: 12px; }}
  .badge {{ color: #fff; border-radius: 4px; padding: 1px 7px; font-size: 11px; text-transform: uppercase; font-weight: 700; }}
  .kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-top: 20px; }}
  .kpi {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px; }} .kpi b {{ display: block; font-size: 24px; }}
  .chain {{ display: grid; grid-template-columns: repeat(7, 1fr); gap: 6px; }}
  .tactic {{ border: 1px solid #e2e8f0; border-radius: 6px; padding: 6px; font-size: 11px; min-height: 64px; color: #94a3b8; }}
  .tactic.hit {{ border-color: #dc2626; background: #fef2f2; color: #0f172a; }}
  .tname {{ font-weight: 700; }} .tcount {{ font-size: 18px; font-weight: 700; color: #dc2626; }} .tech {{ font-family: ui-monospace, monospace; }}
  .finding {{ border-left: 3px solid #0f172a; padding: 8px 12px; margin: 12px 0; background: #f8fafc; page-break-inside: avoid; }}
  .fhead {{ margin-bottom: 4px; }}
  .evidence {{ margin: 6px 0 0; padding-left: 18px; font-size: 12px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }} th, td {{ text-align: left; padding: 5px 6px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
  code {{ font-family: ui-monospace, Consolas, monospace; font-size: 12px; }}
  .ok {{ color: #15803d; font-weight: 700; }} .bad {{ color: #dc2626; font-weight: 700; }}
  @media (max-width: 700px) {{ .chain {{ grid-template-columns: repeat(2, 1fr); }} }}
  @media print {{ main {{ padding: 0; }} }}
</style></head>
<body><main>
  <div class="muted small">TraceVault {escape(result["tool"]["version"])} &middot; generated {escape(result["generated_at"])}</div>
  <h1>Incident Report &mdash; {escape(case.get("title", ""))}</h1>
  <div class="muted">Case <b>{escape(case.get("id", ""))}</b> &middot; examiner {escape(case.get("examiner", ""))} &middot; opened {escape(case.get("created_at", ""))}</div>

  <div class="kpis">
    <div class="kpi">Risk score<b style="color:{SEV_COLORS[risk["level"]]}">{risk["score"]}/100</b>{_badge(risk["level"])}</div>
    <div class="kpi">Findings<b>{stats["findings"]}</b>{stats["by_severity"]["critical"]} critical, {stats["by_severity"]["high"]} high</div>
    <div class="kpi">Events analysed<b>{stats["events"]}</b>{stats["flagged_events"]} flagged</div>
    <div class="kpi">Attacker activity<b style="font-size:15px">{escape(dwell[0][11:16])} &rarr; {escape(dwell[1][11:16])}</b>UTC, {escape(dwell[0][:10])}</div>
  </div>

  <h2>1. Executive summary</h2>
  <ul>{narrative}</ul>

  <h2>2. MITRE ATT&amp;CK coverage</h2>
  <div class="chain">{chain}</div>

  <h2>3. Findings</h2>
  {"".join(findings_rows) or "<p>No findings.</p>"}

  <h2>4. Indicators of compromise</h2>
  <table><tr><th>Type</th><th>Value</th><th>Scope</th><th>Findings</th></tr>{ioc_rows}</table>

  <h2>5. Evidence integrity &amp; chain of custody</h2>
  <p>{integrity}</p>
  <p class="small muted">Ledger head: <code>{escape(verification.get("head") or "-")}</code></p>
  <table><tr><th>#</th><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Evidence</th><th>SHA-256</th><th>Entry hash</th></tr>{ledger_rows}</table>
</main></body></html>
"""
