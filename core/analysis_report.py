"""
The analysis report: the whole run as one self-contained HTML page, structured like the app, at one of three levels
(LEVELS): High level (the critical findings and what needs attention, short tables), Detailed (every severity, tables up
to a few hundred rows, as many IOCs as the analyst picks) and Complete (every row, every IOC).

  Header        title, analyst, run, analysis window (time interval), data sources, description / summary
  High level    the run at a glance: key numbers, verdicts, the most severe findings, linked domains
  Overview      Summary, Domain profiles (risk radar, DIF, infrastructure per domain), Alerts (heatmap, ATT&CK)
  Infrastructure DNS & hosting, VPNDB, Tor network, BGP, CNAME chains, Certificates
  Hunt          Hunt map, Hostname inventory, Subdomain triage, Domain similarity
  Supporting    every detection with its full evidence (the facts behind the alerts), data-source outcomes
  Appendices    every IOC, every lookup as a query / command (each optional)

Every level offers every section; the level sets how much each writes. Sections are picked by key (SECTIONS). Section builders read only what the run already holds (no API calls); a section
without data says so in one line. The views' figure builders are reused so the charts match the app.
"""
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

import pandas as pd

from core.intel_data import SEVERITY_ORDER, SEVERITY_RANK
from core.report_html import CHARTS_EMBED, Builder, e

PARTS = ["High level", "Overview", "Infrastructure", "Hunt", "Supporting evidence", "Appendices"]


@dataclass(frozen=True)
class Section:
    key: str
    part: str
    label: str
    help: str
    default: bool = True


SECTIONS = [
    Section("high_level", "High level", "At a glance", "Key numbers, verdicts, the most severe findings and linked "
                                                       "domains"),
    Section("attention", "High level", "Needs attention", "The critical and high findings and everything else to act "
                                                          "on: verdicts, high-risk domains, routing, exits, takeover-prone "
                                                          "CNAMEs, expiring certificates, data gaps"),
    Section("summary", "Overview", "Summary", "Domains with their risk drivers, analysis details, alerts by category, "
                                              "shared infrastructure, weekly activity, lifecycle and data health"),
    Section("profiles", "Overview", "Domain profiles", "Risk radar, DIF fingerprints and a card per domain "
                                                       "(registration, hosting, routing, VPNDB, alerts)"),
    Section("cert_profiles", "Overview", "Certificate profiles", "Certificate families and anomalies, then the "
                                                                 "certificates that stand out most, field by field: "
                                                                 "anatomy, shape, flags, related certificates"),
    Section("alerts", "Overview", "Alerts", "Alert heatmap, ATT&CK treemap and techniques, Iris risk components, the "
                                            "alerts by severity"),
    Section("dns", "Infrastructure", "DNS & hosting", "IPs, hosting networks, name servers, MX, TXT apps and how they "
                                                      "changed over time"),
    Section("vpndb", "Infrastructure", "VPNDB", "VPN / proxy / Tor verdicts on the hosting IPs and CIDR targets"),
    Section("tor", "Infrastructure", "Tor network", "Tor exits among the hosting IPs and the networks that carry them"),
    Section("bgp", "Infrastructure", "BGP", "Routing findings, announced prefixes, origins and upstreams"),
    Section("cname", "Infrastructure", "CNAME chains", "CNAMEs and the services they point to"),
    Section("resolution", "Infrastructure", "DNS resolution", "The DNS tree resolved to IP addresses (CNAME, MX, NS, "
                                                               "SPF) and its dangling records"),
    Section("certs", "Infrastructure", "Certificates", "Certificates by issuer and over time, self-signed, JA4X"),
    Section("hunt_map", "Hunt", "Hunt map", "The runs of the hunt and the values they followed"),
    Section("hostnames", "Hunt", "Hostname inventory", "Hostnames with their flags"),
    Section("triage", "Hunt", "Subdomain triage", "Subdomains ranked by how suspicious they look"),
    Section("similarity", "Hunt", "Domain similarity", "Similar pairs, clusters and the indicators they share"),
    Section("evidence", "Supporting evidence", "Detections and evidence", "Every active detection with its threat "
                                                                          "logic and triggering facts"),
    Section("sources", "Supporting evidence", "Data sources", "How every source's lookups went"),
    Section("iocs", "Appendices", "IOCs", "The run's indicators ranked by the most severe alert behind them (as many "
                                          "as the level allows)"),
    Section("lookups", "Appendices", "All lookups", "Every lookup as a query, CLI or curl command", default=False),
]
SECTIONS_BY_KEY = {s.key: s for s in SECTIONS}


@dataclass(frozen=True)
class Level:
    """How much a report writes. `rows` caps every table (None: each table's own cap; "all": no cap), `cards` the
    domain cards, `severities` the alerts listed and the evidence (None: every severity), `iocs` the default number of
    IOCs (None: every IOC), `detail` whether secondary charts and per-domain detail tables are drawn."""
    key: str
    label: str
    help: str
    rows: object
    cards: object
    severities: tuple
    iocs: object
    alerts: int
    detail: bool


HIGH, DETAILED, COMPLETE = "high", "detailed", "complete"
LEVELS = {
    HIGH: Level(HIGH, "High level overview", "For management and customers: the critical and high findings, what needs "
                "attention and the key charts. Tables keep their first 15 rows; IOCs are the ones behind critical and "
                "high alerts.", rows=15, cards=10, severities=("Critical", "High"), iocs=50, alerts=25, detail=False),
    DETAILED: Level(DETAILED, "Detailed report", "For analysts: every severity, every chart, tables up to a few hundred "
                    "rows and as many IOCs as you choose, most severe first.", rows=None, cards=60, severities=None,
                    iocs=500, alerts=100, detail=True),
    COMPLETE: Level(COMPLETE, "Complete report", "Everything: every row of every table, every alert with its evidence, "
                    "every IOC. Can be large for big runs.", rows="all", cards=None, severities=None, iocs=None,
                    alerts=None, detail=True),
}


@dataclass
class ReportContext:
    ds: object
    collected: object
    alerts: pd.DataFrame                        # active alerts (suppressed left out), for the current filters
    profiles: pd.DataFrame
    correlation: object = None
    created: object = None
    window: str = ""
    thresholds: dict = field(default_factory=dict)
    verdicts: dict = field(default_factory=dict)
    hunt: dict = None                           # {"hunt", "links", "open_steps"} when the run belongs to a hunt
    similarity: dict = field(default_factory=dict)   # {"weights", "threshold", "min_rare", "runs"}
    origin: str = ""
    timezone: str = "UTC"
    view: object = None                         # the AlertView (new since the last analysis)
    threats: object = None                      # the engine result (domain hopping)
    level: Level = LEVELS[DETAILED]
    ioc_limit: object = None                    # IOCs listed (None: every IOC)
    sections: tuple = ()                        # the chosen section keys (Needs attention links to them)


IOC_SEVERITY_COLUMNS = ["Severity", "Basis", "Alerts"]
_TOKENS = re.compile(r"[\s,;|()\[\]{}'\"<>=]+")


def _tokens(text):
    return {t.strip(".").lower() for t in _TOKENS.split(str(text or "")) if t.strip(".")}


def ioc_severity(iocs, alerts):
    """
    The IOCs with the most severe alert behind each, most severe first: Severity, Basis ("Alert evidence": an alert
    cites the value in its evidence or triggering IOCs; "Domain alert": an alert on one of its domains) and Alerts (how
    many). IOCs without an alert come last with no severity.
    """
    frame = iocs.copy() if iocs is not None else pd.DataFrame()
    if frame.empty:
        return frame.reindex(columns=list(frame.columns) + IOC_SEVERITY_COLUMNS)
    worst = len(SEVERITY_ORDER)
    cited, by_domain = {}, {}

    def note(store, key, rank):
        best, count = store.get(key, (worst, 0))
        store[key] = (min(best, rank), count + 1)
    if alerts is not None and not alerts.empty:
        for alert in alerts.to_dict("records"):
            rank = SEVERITY_RANK.get(alert.get("Severity"), worst)
            note(by_domain, str(alert.get("Domain", "")).lower(), rank)
            values = _tokens(alert.get("Triggering IOCs"))
            evidence = alert.get("Evidence")
            for record in evidence if isinstance(evidence, list) else []:
                if isinstance(record, dict) and record.get("Artifact"):
                    values.add(str(record["Artifact"]).strip().lower())
            for value in values:
                note(cited, value, rank)
    severity, basis, counts = [], [], []
    for value, domains in zip(frame["Value"].astype(str).str.lower(), frame.get("Domain", "").astype(str)):
        direct = cited.get(value.strip())
        domain = min((by_domain[d.strip().lower()] for d in domains.split(",") if d.strip().lower() in by_domain),
                     default=None)
        if direct and (not domain or direct[0] <= domain[0]):
            rank, how, count = direct[0], "Alert evidence", direct[1]
        elif domain:
            rank, how, count = domain[0], "Domain alert", domain[1]
        else:
            rank, how, count = worst, "", 0
        severity.append(SEVERITY_ORDER[rank] if rank < worst else "")
        basis.append(how)
        counts.append(count)
    frame = frame.assign(Severity=severity, Basis=basis, Alerts=counts)
    order = frame.assign(_r=frame["Severity"].map(SEVERITY_RANK).fillna(worst),
                         _b=(frame["Basis"] != "Alert evidence").astype(int))
    order = order.sort_values(["_r", "_b", "Alerts", "Type", "Value"], ascending=[True, True, False, True, True],
                              kind="stable")
    rest = [c for c in frame.columns if c not in IOC_SEVERITY_COLUMNS]
    return order[IOC_SEVERITY_COLUMNS[:1] + rest[:2] + IOC_SEVERITY_COLUMNS[1:] + rest[2:]].reset_index(drop=True)


def report_iocs(iocs, alerts, severities=None, limit=None):
    """The IOCs a report lists: ranked (ioc_severity), only those of `severities` when given, the first `limit`."""
    ranked = ioc_severity(iocs, alerts)
    if severities and not ranked.empty:
        ranked = ranked[ranked["Severity"].isin(severities)]
    return ranked.head(limit) if limit else ranked


def _sources_text(statuses):
    frame = pd.DataFrame(statuses or [], columns=["Source", "Status", "Detail"])
    if frame.empty:
        return []
    rows = []
    for source, group in frame.groupby("Source", sort=False):
        cached = int(group["Detail"].astype(str).str.contains("From cache").sum())
        failed = int((group["Status"] == "Error").sum())
        text = f"{source}: {len(group):,} lookup(s)"
        if cached:
            text += f", {cached:,} from cache"
        if failed:
            text += f", {failed:,} failed"
        rows.append(text)
    return rows


def _span(ds):
    dates = []
    for frame, column in ((getattr(ds, "events_utc", None), "Date"), (getattr(ds, "pdns_utc", None), "First Seen")):
        if frame is not None and not frame.empty and column in frame:
            dates.append(pd.to_datetime(frame[column], errors="coerce", utc=True).dropna())
    dates = pd.concat(dates) if dates else pd.Series(dtype="datetime64[ns, UTC]")
    return (dates.min(), dates.max()) if not dates.empty else (None, None)


def header_html(meta, ctx):
    """Title, then a definition list: analyst, run, window and records' time span, targets, data sources, generated,
    and the analyst's description."""
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    targets = list(ctx.ds.selected_domains)
    first, last = _span(ctx.ds)
    created = pd.to_datetime(ctx.created, errors="coerce", utc=True) if ctx.created else None
    rows = [("Analyst", meta.get("analyst")),
            ("Organisation / case", meta.get("case")),
            ("Run", created.strftime("%Y-%m-%d %H:%M UTC") if created is not None and pd.notna(created) else ""),
            ("Analysis window", ctx.window or "All time"),
            ("Records span", f"{first:%Y-%m-%d} → {last:%Y-%m-%d}" if first is not None else ""),
            ("Targets", f"{len(targets):,}: " + ", ".join(targets[:15]) + (f" (+{len(targets) - 15} more)"
                                                                           if len(targets) > 15 else "")),
            ("Data", ctx.origin),
            ("Generated", generated)]
    dl = "".join(f"<dt>{e(k)}</dt><dd>{e(v)}</dd>" for k, v in rows if v)
    sources = _sources_text(getattr(ctx.collected, "statuses", None))
    if sources:
        dl += "<dt>Data sources</dt><dd>" + "<br>".join(e(s) for s in sources) + "</dd>"
    level = getattr(ctx, "level", None)
    parts = [f'<header class="hero"><span class="level">{e(level.label if level else "Analysis report")}</span>'
             f"<h1>{e(meta.get('title') or 'Analysis report')}</h1>", f'<dl class="header-grid">{dl}</dl></header>']
    if meta.get("summary"):
        parts.append(f'<p class="notes-title">Description / summary</p><div class="notes">{e(meta["summary"])}</div>')
    parts.append('<p class="disclaimer">Alerts are leads for an analyst to confirm, not verdicts. Every timestamp is '
                 "UTC. The report follows the analysis window and the view filters and leaves out suppressed alerts."
                 + (f" {e(level.help)}" if level else "") + "</p>")
    return "".join(parts)


def build_analysis_report(ctx, meta, sections, charts=CHARTS_EMBED, top_alerts=50):
    """The report as one HTML string with the chosen `sections` (keys of SECTIONS, in the report's order), at the
    context's level (ctx.level)."""
    from views import report_sections  # the section builders reuse the views' figure builders

    level = ctx.level
    more = ("the Detailed or Complete report and the Data export have them all" if level.key == HIGH else
            "the Complete report and the Data export have them all")
    builder = Builder(charts=charts, row_cap=level.rows if isinstance(level.rows, int) else None,
                      unlimited=level.rows == "all", detail=level.detail, level=level.label, more=more)
    chosen = [s for s in SECTIONS if s.key in set(sections)]
    ctx.sections = tuple(s.key for s in chosen)
    current = None
    for section in chosen:
        if section.part != current:
            builder.part(section.part)
            current = section.part
        builder.next_anchor = f"sec-{section.key}"
        render = getattr(report_sections, f"section_{section.key}")
        try:
            if section.key in ("alerts", "evidence"):
                render(builder, ctx, top_alerts if level.alerts else None)
            else:
                render(builder, ctx)
        except Exception as error:   # one section failing never loses the whole report
            builder.section(section.label)
            builder.callout(f"This section could not be built: {type(error).__name__}: {error}")
    builder.raw('<p class="muted" style="margin-top:40px">Generated by DomainTools Analytics and Detection from '
                "DomainTools data (Iris Investigate, Domain History, passive DNS, certificates, VPNDB, BGPDB). "
                "No API query is made to build this report.</p>")
    return builder.html(meta.get("title") or "Analysis report", header_html(meta, ctx))
