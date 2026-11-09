"""
Case report: one run as a single, self-contained HTML page to hand to a manager or attach to a takedown request.
The run at a glance, the top alerts with their evidence, the risk profiles, an infrastructure snapshot per domain and
the IOCs. No scripts and no external files; every value is escaped. Print it to PDF from the browser (print styles
included).
"""
import html
from datetime import datetime, timezone

import pandas as pd

from core.run_history import SEVERITY_ORDER
from integrations.enrichment import extract_iris_profile

CONFIDENCE_ORDER = ["High", "Medium", "Low"]
SEVERITY_COLORS = {"Critical": "#b91c1c", "High": "#dc2626", "Medium-High": "#ea580c", "Medium": "#d97706",
                   "Low": "#2563eb"}
PROFILE_COLUMNS = ["Domain", "Unified Risk", "Base Domain Risk Score", "Alerts", "DIF Breakdown"]
EVIDENCE_CHARS = 700            # evidence text kept per alert (the rest is in the app and the data export)
CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { font: 14px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #111827;
       background: #fff; margin: 0; }
main { max-width: 1100px; margin: 0 auto; padding: 32px 24px 48px; }
h1 { font-size: 26px; margin: 0 0 4px; } h2 { font-size: 18px; margin: 32px 0 8px; padding-bottom: 4px;
     border-bottom: 2px solid #e5e7eb; }
.meta { color: #4b5563; margin: 0 0 16px; } .muted { color: #6b7280; font-size: 12px; }
.notes { background: #f9fafb; border-left: 4px solid #4f46e5; padding: 10px 14px; white-space: pre-wrap; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }
.card { border: 1px solid #e5e7eb; border-radius: 8px; padding: 10px 12px; }
.card b { display: block; font-size: 22px; } .card span { color: #6b7280; font-size: 12px; }
table { width: 100%; border-collapse: collapse; font-size: 12.5px; margin-top: 6px; }
th, td { text-align: left; vertical-align: top; padding: 6px 8px; border-bottom: 1px solid #e5e7eb; }
th { background: #f3f4f6; font-weight: 600; } tr { break-inside: avoid; }
td.mono, .mono { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; word-break: break-all; }
.pill { display: inline-block; color: #fff; border-radius: 10px; padding: 1px 8px; font-size: 11.5px;
        font-weight: 600; white-space: nowrap; }
.evidence { white-space: pre-wrap; color: #374151; }
.nowrap { white-space: nowrap; }
@media print { main { padding: 0; } h2 { break-after: avoid; } a { color: inherit; } }
"""


def _e(value):
    """Escaped text; empty for None / NaN."""
    if value is None or (not isinstance(value, (list, dict, str)) and pd.isna(value)):
        return ""
    return html.escape(str(value))


def _date(value, fmt="%Y-%m-%d"):
    stamp = pd.to_datetime(value, errors="coerce", utc=True)
    return "" if pd.isna(stamp) else stamp.strftime(fmt)


NOWRAP = {"Created", "Expires", "First seen", "Last seen", "Severity"}   # columns kept on one line


def _table(headers, rows, mono=()):
    """An HTML table; `rows` hold already-escaped cell HTML; columns named in `mono` use a fixed-width font."""
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)

    def cell(header, value):
        classes = " ".join(name for name, on in (("mono", header in mono), ("nowrap", header in NOWRAP)) if on)
        return f'<td class="{classes}">{value}</td>' if classes else f"<td>{value}</td>"

    body = "".join("<tr>" + "".join(cell(h, v) for h, v in zip(headers, row)) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def top_alerts(alerts, limit):
    """The `limit` most severe alerts (severity, then confidence, then domain)."""
    if alerts is None or alerts.empty:
        return pd.DataFrame()
    frame = alerts.copy()
    frame["_sev"] = frame["Severity"].map({s: i for i, s in enumerate(SEVERITY_ORDER)}).fillna(len(SEVERITY_ORDER))
    conf = frame["Confidence"] if "Confidence" in frame else pd.Series("", index=frame.index)
    frame["_conf"] = conf.map({c: i for i, c in enumerate(CONFIDENCE_ORDER)}).fillna(len(CONFIDENCE_ORDER))
    frame = frame.sort_values(["_sev", "_conf", "Domain"], kind="stable")
    return frame.drop(columns=["_sev", "_conf"]).head(limit)


def _evidence(alert):
    parts = [str(alert.get(col) or "").strip() for col in ("Threat Logic", "Triggering IOCs")]
    text = "\n".join(part for part in parts if part and part.lower() != "nan")
    return text if len(text) <= EVIDENCE_CHARS else text[:EVIDENCE_CHARS].rstrip() + " …"


def infrastructure_rows(enrichment, domains):
    """Per domain from its Iris Investigate record: registrar, created / expires, IPs with ASN and country, name
    servers and MX hosts."""
    rows = []
    for domain in domains:
        obj = (enrichment or {}).get(domain)
        if not obj:
            continue
        profile = extract_iris_profile(obj)
        ips = [f"{ip['ip']}" + (f" (AS{ip['asn']}" + (f", {ip['country']}" if ip.get("country") else "") + ")"
                                 if ip.get("asn") else "") for ip in profile["ips"]]
        rows.append({"Domain": domain, "Registrar": profile["registrar"], "Created": _date(profile["create_date"]),
                     "Expires": _date(profile["expiration_date"]), "IPs": ips, "Name servers": profile["name_servers"],
                     "MX": profile["mx_hosts"]})
    return rows


def _list_cell(values, limit=8):
    values = list(values or [])
    shown = "<br>".join(_e(v) for v in values[:limit])
    return shown + (f'<br><span class="muted">+{len(values) - limit} more</span>' if len(values) > limit else "")


def build_case_report(meta, alerts, profiles, infrastructure, iocs, sources=None, top=25, max_iocs=500):
    """
    The report as one HTML string. `meta`: title, analyst, notes, targets, run (created), window, origin;
    `alerts`: the active (not suppressed) alerts; `profiles`: risk profiles; `infrastructure`: infrastructure_rows();
    `iocs`: collect_iocs() rows; `sources`: run_overview() of the lookups (optional).
    """
    alerts = alerts if alerts is not None else pd.DataFrame()
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    targets = list(meta.get("targets") or [])
    title = meta.get("title") or "Case report"
    facts = [f"Targets: {', '.join(targets[:10])}" + (f" (+{len(targets) - 10} more)" if len(targets) > 10 else ""),
             f"Run: {_date(meta.get('created'), '%Y-%m-%d %H:%M UTC')}" if meta.get("created") else "",
             f"Analysis window: {meta['window']}" if meta.get("window") else "",
             f"Data: {meta['origin']}" if meta.get("origin") else "",
             f"Analyst: {meta['analyst']}" if meta.get("analyst") else "", f"Generated {generated}"]
    parts = [f"<h1>{_e(title)}</h1>", '<p class="meta">' + " · ".join(_e(f) for f in facts if f) + "</p>"]
    if meta.get("notes"):
        parts.append(f'<h2>Summary</h2><div class="notes">{_e(meta["notes"])}</div>')

    by_sev = alerts["Severity"].value_counts().to_dict() if not alerts.empty else {}
    cards = [("Domains analyzed", len(targets)), ("Alerts", len(alerts))]
    cards += [(f"{s} alerts", by_sev[s]) for s in SEVERITY_ORDER if by_sev.get(s)]
    if profiles is not None and not profiles.empty and "Unified Risk" in profiles:
        risk = pd.to_numeric(profiles["Unified Risk"], errors="coerce").max()
        cards.append(("Highest unified risk", "" if pd.isna(risk) else f"{risk:.0f}"))
    if "Status" in alerts and (alerts["Status"] == "Malicious").any():
        cards.append(("Marked malicious", int((alerts["Status"] == "Malicious").sum())))
    if sources and sources.get("Lookups"):
        cards.append(("Lookups answered", f"{sources['Answered']:.0%} of {sources['Lookups']:,}"))
    parts.append("<h2>At a glance</h2><div class=\"cards\">" + "".join(
        f'<div class="card"><b>{_e(f"{v:,}" if isinstance(v, int) else v)}</b><span>{_e(k)}</span></div>'
        for k, v in cards) + "</div>")

    shown = top_alerts(alerts, top)
    parts.append(f"<h2>Top alerts ({len(shown):,} of {len(alerts):,})</h2>")
    if shown.empty:
        parts.append('<p class="muted">No alerts in this run (with the filters and window applied).</p>')
    else:
        rows = []
        for alert in shown.to_dict("records"):
            sev = str(alert.get("Severity") or "")
            pill = f'<span class="pill" style="background:{SEVERITY_COLORS.get(sev, "#6b7280")}">{_e(sev)}</span>'
            rows.append([pill, _e(alert.get("Domain")), _e(alert.get("Threat Type")), _e(alert.get("Confidence")),
                         _e(alert.get("MITRE ATT&CK")), _e(alert.get("Status")),
                         f'<div class="evidence">{_e(_evidence(alert))}</div>'])
        parts.append(_table(["Severity", "Domain", "Threat", "Confidence", "MITRE ATT&CK", "Status", "Evidence"], rows))

    if profiles is not None and not profiles.empty:
        profiles = profiles.copy()
        counts = alerts["Domain"].value_counts() if not alerts.empty else pd.Series(dtype=int)
        profiles["Alerts"] = profiles["Domain"].map(counts).fillna(0).astype(int)
        columns = [c for c in PROFILE_COLUMNS if c in profiles]
        frame = profiles.sort_values("Unified Risk", ascending=False) if "Unified Risk" in profiles else profiles
        rows = [[_e(f"{v:.0f}" if isinstance(v, float) and not pd.isna(v) else v) for v in row]
                for row in frame[columns].itertuples(index=False)]
        parts.append("<h2>Risk by domain</h2>" + _table(columns, rows))

    if infrastructure:
        rows = [[_e(r["Domain"]), _e(r["Registrar"]), _e(r["Created"]), _e(r["Expires"]), _list_cell(r["IPs"]),
                 _list_cell(r["Name servers"]), _list_cell(r["MX"])] for r in infrastructure]
        parts.append("<h2>Infrastructure snapshot</h2><p class=\"muted\">Current registration and hosting from Iris "
                     "Investigate.</p>" + _table(["Domain", "Registrar", "Created", "Expires", "IPs", "Name servers",
                                                  "MX"], rows))

    if iocs is not None and not iocs.empty:
        frame = iocs.head(max_iocs)
        rows = [[_e(r.get("Type")), _e(r.get("Value")), _e(r.get("Domain")), _e(_date(r.get("First Seen"))),
                 _e(_date(r.get("Last Seen")))] for r in frame.to_dict("records")]
        note = (f'<p class="muted">The first {max_iocs:,} of {len(iocs):,}; the Data Export page has them all.</p>'
                if len(iocs) > max_iocs else "")
        parts.append(f"<h2>Indicators ({len(iocs):,})</h2>{note}"
                     + _table(["Type", "Value", "Domains", "First seen", "Last seen"], rows, mono=("Value",)))

    parts.append(f'<p class="muted" style="margin-top:32px">Generated {generated} by DomainTools Analytics and '
                 "Detection from DomainTools data (Iris Investigate, Domain History, passive DNS, certificates, "
                 "VPNDB). Alerts are leads for an analyst to confirm, not verdicts.</p>")
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<title>{_e(title)}</title><style>{CSS}</style></head><body><main>{''.join(parts)}</main></body></html>")
