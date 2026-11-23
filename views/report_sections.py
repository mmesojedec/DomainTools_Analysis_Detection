"""
Section builders of the analysis report (core.analysis_report): one function per section, `section_<key>(b, ctx)`.
They write to a core.report_html.Builder and reuse the pages' pure data and figure builders, so the report shows the
same numbers and charts as the app. No Streamlit call and no API query here.
"""
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from core import bgp
from core import similarity as sim
from core.anonymizers import ANONYMIZER_CATEGORIES, anonymizer_rows, crosscheck, for_domains, shared_exit, tor_tables
from core.cname import cname_links, dataset_cname_map, order_by_domain
from core.export import dataset_iocs
from core.helpers import extract_ip_addresses, ip_network_bucket
from core.hunt_stats import (
    alerts_by_category,
    cluster_callouts,
    data_health,
    glance_stats,
    lifecycle_stats,
    shared_infrastructure,
    weekly_activity,
)
from core.intel_data import ISO2_TO_ISO3, SEVERITY_COLORS, SEVERITY_ORDER
from core.lookup_queries import build_lookup_queries
from core.next_steps import SEVERITY_RANK
from core.risk_profile import drivers_text, score_drivers
from core.self_signed import self_signed_certificates
from integrations.enrichment import extract_iris_profile

SECTION_LABELS = {"profiles": "Domain profiles", "summary": "Summary", "bgp": "BGP", "vpndb": "VPNDB", "tor": "Tor network",
                  "cname": "CNAME chains", "resolution": "DNS resolution", "certs": "Certificates", "triage": "Subdomain triage", "dns": "DNS & hosting",
                  "sources": "Data sources"}
ALERT_COLUMNS = ["Severity", "Domain", "Threat Type", "Confidence", "Category", "MITRE ATT&CK", "Status"]
MAX_ROWS = 300            # rows per table in the Detailed report (the report level may lower or lift it)
EVIDENCE_ROWS = {"high": 100, "detailed": 2000}   # evidence records per level (the Complete report has all)


def _empty(frame):
    return frame is None or not isinstance(frame, pd.DataFrame) or frame.empty


def _ranked(alerts):
    if _empty(alerts):
        return pd.DataFrame(columns=ALERT_COLUMNS)
    return alerts.assign(_r=alerts["Severity"].map(SEVERITY_RANK).fillna(9)) \
        .sort_values(["_r", "Domain"], kind="stable").drop(columns="_r")


def _with_status(alerts):
    return alerts if "Status" in alerts.columns else alerts.assign(Status="New")


def _listed(ctx, alerts):
    """The alerts a level lists (the High level report: critical and high only)."""
    severities = ctx.level.severities
    if not severities or _empty(alerts):
        return alerts
    return alerts[alerts["Severity"].isin(severities)]


def _severity_text(ctx):
    severities = ctx.level.severities
    return " and ".join(s.lower() for s in severities) if severities else ""


def _world(frame, value, scale, title=""):
    if "ISO3" not in frame:
        frame = frame.assign(ISO3=frame["Country"].map(ISO2_TO_ISO3))
    frame = frame.dropna(subset=["ISO3"])
    if frame.empty:
        return None
    fig = px.choropleth(frame, locations="ISO3", color=value, hover_name="Country", color_continuous_scale=scale,
                        title=title)
    fig.update_geos(showframe=False, showcoastlines=True, projection_type="natural earth", showcountries=True)
    fig.update_layout(margin=dict(t=40 if title else 10, l=0, r=0, b=0))
    return fig


# ---- High level -------------------------------------------------------------------------------------------------------

def section_high_level(b, ctx):
    from views.risk_view import shown_vectors
    alerts, profiles = ctx.alerts, ctx.profiles
    b.section("At a glance", "The run in a few numbers and the findings that matter most.")
    stats = glance_stats(ctx.ds, alerts)
    cutoff = (ctx.thresholds or {}).get("high_risk_score", 70)
    cards = [("Domains analyzed", stats["Domains"]), ("Active alerts", len(alerts))]
    cards += [(f"{s} alerts", stats["Alerts"][s]) for s in SEVERITY_ORDER if stats["Alerts"][s]]
    if not _empty(profiles):
        risk = pd.to_numeric(profiles["Unified Risk"], errors="coerce")
        cards += [("Highest unified risk", f"{risk.max():.0f} / 100" if risk.notna().any() else ""),
                  (f"High-risk domains (≥ {cutoff})", f"{int((risk >= cutoff).sum())} of {len(profiles)}"),
                  ("Distinct infrastructure profiles (DIF)", int(profiles["DIF Fingerprint"].nunique()))]
        vectors = shown_vectors(profiles)
        if vectors:
            cards.append(("Primary threat driver", profiles[vectors].mean().idxmax()))
    verdicts = pd.Series(ctx.verdicts or {}, dtype=object)
    if not verdicts.empty:
        cards += [(f"Marked {name}", int((verdicts == name).sum())) for name in ("Malicious", "Suspicious", "Benign")
                  if (verdicts == name).any()]
    b.cards(cards)
    b.heading("Key findings")
    findings = [f"{a['Severity']} · {a['Domain']} · {a['Threat Type']}" for _, a in _ranked(alerts).head(8).iterrows()]
    b.bullets(findings or ["No active alert for the current filters."])
    flagged = anonymizer_rows(ctx.ds.anonymizers) if not _empty(ctx.ds.anonymizers) else pd.DataFrame()
    extra = []
    if not flagged.empty:
        counts = flagged["Category"].value_counts()
        extra.append("VPNDB: " + ", ".join(f"{n} {c} exit(s)" for c, n in counts.items()) + " among the hosting IPs.")
    if not _empty(ctx.ds.bgp_origins):
        from views.bgp_page import brief
        extra += [f"BGP: {line}" for line in brief(ctx.ds)]
    extra += [f"Linked domains ({c['Strength'].lower()}): {c['Text']}" for c in cluster_callouts(ctx.correlation)]
    b.bullets(extra)


def _attention_items(ctx):
    """What needs attention, as (severity, title, detail, section key), one area at a time (an area that fails to
    compute is left out rather than losing the list)."""
    ds, items = ctx.ds, []

    def area(build):
        try:
            items.extend(i for i in build() if i)
        except Exception:   # an area missing its data never loses the others
            pass

    def verdicts():
        verdicts = pd.Series(ctx.verdicts or {}, dtype=object)
        for name, severity in (("Malicious", "Critical"), ("Suspicious", "High")):
            marked = sorted(verdicts[verdicts == name].index)
            if marked:
                yield (severity, f"{len(marked)} domain(s) marked {name}", ", ".join(marked[:12]), "profiles")

    def risky():
        profiles = ctx.profiles
        if _empty(profiles):
            return
        cutoff = (ctx.thresholds or {}).get("high_risk_score", 70)
        scored = profiles.assign(_r=pd.to_numeric(profiles["Unified Risk"], errors="coerce"))
        high = scored[scored["_r"] >= cutoff].sort_values("_r", ascending=False)
        if not high.empty:
            yield ("High", f"{len(high)} high-risk domain(s) (unified risk ≥ {cutoff})",
                   ", ".join(f"{d} ({r:.0f})" for d, r in zip(high["Domain"].head(12), high["_r"])), "profiles")

    def new_alerts():
        view = ctx.view
        mask = getattr(view, "new_mask", None)
        if mask is not None and int(mask.sum()):
            new = view.active[mask.reindex(view.active.index, fill_value=False)]
            severe = int(new["Severity"].isin(["Critical", "High"]).sum())
            yield ("High" if severe else "Medium", f"{len(new)} alert(s) new since the last analysis",
                   f"{severe} critical or high" if severe else "None critical or high", "summary")

    def routing():
        if _empty(ds.bgp_origins):
            return
        found = bgp.findings(ds.bgp_origins, ds.bgp_asns, ds.bgp_routes)
        if _empty(found):
            return
        for (finding, severity), group in found.groupby(["Finding", "Severity"], sort=False):
            if severity in ("Critical", "High", "Medium-High", "Medium"):
                where = ", ".join(dict.fromkeys(group["Prefix"].dropna().astype(str))) if "Prefix" in group else ""
                yield (severity, f"BGP: {finding} ({len(group)})", where[:300], "bgp")

    def exits():
        if _empty(ds.anonymizers):
            return
        flagged = anonymizer_rows(ds.anonymizers)
        for category, group in flagged.groupby("Category", sort=False):
            providers = ", ".join(dict.fromkeys(group["Provider"].dropna().astype(str).replace("", pd.NA).dropna()))
            yield ("High" if "Tor" in str(category) else "Medium", f"{len(group)} {category} exit(s) among the hosting "
                   "IPs", f"Providers: {providers[:240]}" if providers else "", "tor" if "Tor" in str(category)
                   and "tor" in ctx.sections else "vpndb")

    def cnames():
        cmap = dataset_cname_map(ds)
        if _empty(cmap):
            return
        current = cmap[cmap["Current"]]
        for kind, severity in (("Takeover-prone", "High"), ("Dynamic DNS / tunnel", "Medium")):
            hits = current[current["Service Type"] == kind]
            if not hits.empty:
                yield (severity, f"{hits['Hostname'].nunique()} {kind.lower()} CNAME(s)",
                       ", ".join(hits["Hostname"].astype(str).unique()[:10]), "cname")
        dead = current[current["Outcome"] == "Dead end"]
        if not dead.empty:
            yield ("Medium", f"{dead['Hostname'].nunique()} CNAME dead end(s)",
                   ", ".join(dead["Hostname"].astype(str).unique()[:10]), "cname")

    def dangling():
        from core import resolver as res
        tree = res.dataset_tree(ds)[0]
        rows = tree[tree["Status"] == res.DANGLING] if not tree.empty else tree
        labels = {"NS": "NS record(s): zone takeover", "MX": "MX record(s): mail interception",
                  "CNAME": "CNAME(s): subdomain takeover", "TXT": "SPF include(s): mail spoofing"}
        for (kind, severity), group in rows.groupby(["Type", "Severity"], sort=False):
            yield (severity, f"{len(group)} dangling {labels.get(kind, kind)}",
                   ", ".join(f"{n} → {', '.join(d)}" for n, d in zip(group["Name"], group["Dangling"]))[:300],
                   "resolution")

    def certificates():
        if _empty(ds.ssl):
            return
        selfsigned = self_signed_certificates(ds.ssl.drop_duplicates(["Domain", "Hash", "Source"]), ds.selected_domains)
        if not selfsigned.empty:
            yield ("Medium", f"{len(selfsigned)} self-signed certificate(s)",
                   ", ".join(selfsigned["Domain"].astype(str).unique()[:10]) if "Domain" in selfsigned else "",
                   "certs")

    def lifecycle():
        life = lifecycle_stats(ds)
        for key, severity, text in (("Registered recently", "Medium", "registered in the last {d} days"),
                                    ("Domains expiring", "Low", "expiring within {d} days"),
                                    ("Certificates expiring", "Low", "certificate(s) expiring within {d} days")):
            values = life.get(key) or []
            if values:
                label = text.format(d=life["Days"])
                noun = "" if "certificate" in label else "domain(s) "
                yield (severity, f"{len(values)} {noun}{label}",
                       ", ".join(f"{name} ({when:%Y-%m-%d})" for name, when in values[:10]), "summary")

    def triage():
        if _empty(ds.hostname_inventory):
            return
        from views.triage_view import dataset_triage
        found = dataset_triage(ds)
        high = found[found["Level"] == "High"] if not _empty(found) else pd.DataFrame()
        if not high.empty:
            column = "Subdomain" if "Subdomain" in high else high.columns[0]
            yield ("Medium", f"{len(high)} highly suspicious subdomain name(s)",
                   ", ".join(high[column].astype(str).head(10)), "triage")

    def linked():
        strong = [c for c in cluster_callouts(ctx.correlation, limit=10) if c["Strength"].lower() == "strong"]
        for callout in strong[:5]:
            yield ("Medium", "Strongly linked domains", callout["Text"], "dns")

    def gaps():
        from core.api_usage import attention_rows
        rows = attention_rows(getattr(ctx.collected, "statuses", None))
        if not _empty(rows):
            sources = ", ".join(dict.fromkeys(rows["Source"].astype(str))) if "Source" in rows else ""
            yield ("Low", f"{len(rows)} lookup(s) failed or stopped at a limit: the data may be incomplete", sources,
                   "sources")

    for build in (verdicts, risky, new_alerts, routing, exits, dangling, cnames, certificates, lifecycle, triage, linked,
                  gaps):
        area(build)
    return sorted(items, key=lambda item: SEVERITY_RANK.get(item[0], 9))


def section_attention(b, ctx):
    alerts = _with_status(ctx.alerts)
    b.section("Needs attention", "The critical and high findings per domain, then everything else to act on, most "
                                 "severe first.")
    severe = alerts[alerts["Severity"].isin(["Critical", "High"])] if not alerts.empty else alerts
    if severe.empty:
        b.text("No critical or high alert for the current filters.")
    else:
        risk = (ctx.profiles.set_index("Domain")["Unified Risk"] if not _empty(ctx.profiles) else pd.Series(dtype=float))
        rows = []
        for domain, group in severe.groupby("Domain"):
            ranked = _ranked(group)
            rows.append({"Severity": ranked["Severity"].iloc[0], "Domain": domain,
                         "Critical": int((group["Severity"] == "Critical").sum()),
                         "High": int((group["Severity"] == "High").sum()),
                         "Unified Risk": risk.get(domain), "Verdict": (ctx.verdicts or {}).get(domain, "New"),
                         "Threat Types": ", ".join(dict.fromkeys(ranked["Threat Type"].astype(str)))})
        frame = pd.DataFrame(rows).sort_values(["Critical", "High", "Unified Risk"], ascending=False)
        b.heading(f"Critical and high alerts: {len(severe):,} on {len(frame):,} domain(s)")
        b.table(frame, max_rows=MAX_ROWS)
    items = _attention_items(ctx)
    if not items:
        return
    b.heading("Also to act on")
    links = set(ctx.sections or ())
    cards = []
    for severity, title, detail, key in items:
        color = SEVERITY_COLORS.get(severity, "#64748b")
        go_to = (f'<a href="#sec-{key}">{_e(SECTION_LABELS.get(key, key))} →</a>' if key in links else "")
        cards.append(f'<div class="att"><span class="dot" style="background:{color}" title="{_e(severity)}"></span>'
                     f'<div><b>{_e(title)}</b><span class="muted">{_e(detail)}</span></div>{go_to}</div>')
    limit = b.rows(None)
    if limit and len(cards) > limit:
        cards = cards[:limit]
    b.raw('<div class="attention">' + "".join(cards) + "</div>")


# ---- Overview ---------------------------------------------------------------------------------------------------------

def section_summary(b, ctx):
    from views.summary_view import activity_figure, category_figure, domain_overview
    ds, alerts = ctx.ds, ctx.alerts
    b.section("Summary", "Every domain with what drives its risk, the analysis details and the run statistics, as on "
                         "the Summary page.")
    b.heading("Domains")
    b.table(domain_overview(ctx.profiles, alerts, ctx.verdicts, ds.anonymizers), max_rows=MAX_ROWS)
    stats = glance_stats(ds, alerts)
    b.heading("Analysis details")
    b.cards([(k, stats[k]) for k in ("Domains", "IPs", "ASNs", "Name servers", "Certificates", "Self-signed",
                                     "Hostnames", "Passive DNS records")])
    if stats["First event"] is not None:
        b.note(f"Records first seen {stats['First event']:%Y-%m-%d} → {stats['Last event']:%Y-%m-%d}.")
    if not _empty(ds.anonymizers):
        flagged = anonymizer_rows(ds.anonymizers)
        b.subheading("VPNDB")
        b.cards([("IPs checked", len(ds.anonymizers))]
                + [(c, int((flagged["Category"] == c).sum())) for c in ANONYMIZER_CATEGORIES
                   if (flagged["Category"] == c).any()])
    if not _empty(ds.bgp_origins):
        found = bgp.findings(ds.bgp_origins, ds.bgp_asns, ds.bgp_routes)
        summary = bgp.summary(ds.bgp_origins, ds.bgp_asns, ds.bgp_routes, found)
        b.subheading("BGP")
        b.cards([("IPs routed", summary["ips"]), ("Prefixes", summary["prefixes"]),
                 ("Origin networks", summary["origins"]), ("Routing findings", len(found))])
    callouts = cluster_callouts(ctx.correlation, limit=10)
    if callouts:
        b.heading("Linked domains")
        b.bullets([f"{c['Strength']} · {c['Text']}" for c in callouts])
    b.heading("Top alerts")
    b.table(_with_status(_ranked(alerts)).head(10), columns=ALERT_COLUMNS)
    b.heading("Run statistics")
    counts = alerts_by_category(alerts)
    if not counts.empty:
        b.subheading("Alerts by category")
        b.figure(category_figure(counts), height=max(240, 40 * counts["Category"].nunique() + 120))
    shared = shared_infrastructure(ds)
    if not shared.empty:
        b.subheading("Top shared infrastructure")
        b.table(shared.drop(columns="Domain List").assign(**{"Domains using it": shared["Domain List"]}))
    activity = weekly_activity(ds) if b.detail else pd.DataFrame()
    if not activity.empty:
        b.subheading("Activity per week")
        b.figure(activity_figure(activity), height=280, secondary=True)
    life = lifecycle_stats(ds)
    health = data_health(getattr(ctx.collected, "statuses", None))

    def dated(items):
        return ", ".join(f"{name} ({when:%Y-%m-%d})" for name, when in items[:8]) or "none"
    b.subheading("Lifecycle and data health")
    b.bullets([f"Newest domain: {life['Newest domain'][0]} ({life['Newest domain'][1]:%Y-%m-%d})"
               if life["Newest domain"] else "",
               f"Registered in the last {life['Days']} days: {dated(life['Registered recently'])}",
               f"Domains expiring within {life['Days']} days: {dated(life['Domains expiring'])}",
               f"Certificates expiring within {life['Days']} days: {dated(life['Certificates expiring'])}",
               f"Lookups: {health['Lookups']:,} ({health['OK']:,} OK, {health['Partial']:,} partial, "
               f"{health['No data']:,} no data, {health['Failed']:,} failed, {health['Cached']:,} from cache)"])
    view = ctx.view
    if view is not None and getattr(view, "new_mask", None) is not None and int(view.new_mask.sum()):
        b.heading("New since the last analysis")
        new = view.active[view.new_mask.reindex(view.active.index, fill_value=False)]
        b.table(new, columns=["Severity", "Domain", "Threat Type", "Confidence"], max_rows=MAX_ROWS)


def section_profiles(b, ctx):
    from views.profile_view import latest_dns
    from views.risk_view import radar_figure
    profiles, ds = ctx.profiles, ctx.ds
    b.section("Domain profiles", "The Digital Risk Vector Profile, the infrastructure fingerprints (DIF) and one card "
                                 "per domain, riskiest first.")
    if _empty(profiles):
        b.note("No risk profile in this run.")
        return
    b.heading("Digital Risk Vector Profile")
    b.figure(radar_figure(profiles, grid="rgba(0, 0, 0, 0.12)"), height=460)
    b.heading("Infrastructure fingerprints (DIF)")
    closest = sim.closest_dif(profiles)
    ledger = profiles[["Domain", "Unified Risk", "Base Domain Risk Score", "DIF Fingerprint", "DIF Breakdown"]] \
        .assign(**{"Closest DIF": profiles["Domain"].map(closest).fillna("")}) \
        .sort_values("Unified Risk", ascending=False)
    b.table(ledger, max_rows=MAX_ROWS)
    ranked = profiles.sort_values("Unified Risk", ascending=False)
    cards = ctx.level.cards or len(ranked)
    if len(ranked) > cards:
        b.note(f"Cards for the {cards} riskiest of {len(ranked):,} domains.")
    alerts = _with_status(ctx.alerts)
    for row in ranked.head(cards).to_dict("records"):
        domain = row["Domain"]
        mine = _ranked(alerts[alerts["Domain"] == domain]) if not alerts.empty else alerts
        iris = extract_iris_profile((ds.enrichment or {}).get(domain, {}))
        b.raw(f'<div class="domain-card"><h4>{_e(domain)}</h4>')
        b.cards([("Unified risk", f"{row['Unified Risk']:.0f}" if pd.notna(row.get("Unified Risk")) else ""),
                 ("DomainTools risk", f"{row['Base Domain Risk Score']:.0f}"
                  if pd.notna(row.get("Base Domain Risk Score")) else ""),
                 ("Alerts", len(mine)), ("Verdict", (ctx.verdicts or {}).get(domain, "New"))])
        drivers = drivers_text(score_drivers(row, ctx.alerts))
        b.note(f"DIF {row.get('DIF Fingerprint', '')} · {row.get('DIF Breakdown', '')}"
               + (f" · Risk drivers: {drivers}" if drivers else ""))
        facts = [f"Registrar: {iris['registrar']}" if iris["registrar"] else "",
                 f"Created: {iris['create_date']:%Y-%m-%d}" if pd.notna(iris["create_date"]) else "",
                 f"Expires: {iris['expiration_date']:%Y-%m-%d}" if pd.notna(iris["expiration_date"]) else "",
                 f"Name servers: {', '.join(iris['name_servers'])}" if iris["name_servers"] else "",
                 f"MX: {', '.join(iris['mx_hosts'])}" if iris["mx_hosts"] else "",
                 f"Web server: {iris['server_type']}" if iris["server_type"] else "",
                 f"Redirects to: {iris['redirect_domain']}" if iris["redirect_domain"] else ""]
        b.bullets(facts)
        if iris["ips"]:
            b.table(pd.DataFrame(iris["ips"]).rename(columns={"ip": "IP", "count": "Domains on IP (Iris)",
                                                              "asn": "ASN", "isp": "ISP", "country": "Country"}))
        if not _empty(ds.anonymizers):
            vpndb = for_domains(ds.anonymizers, [domain])
            if not vpndb.empty:
                b.subheading("VPNDB")
                b.table(vpndb, columns=["IP", "Category", "Provider", "Confidence", "Sharing", "ASN", "Country"])
        if not _empty(ds.bgp_origins):
            routing = bgp.for_domain(bgp.ip_table(ds.bgp_origins, ds.bgp_routes, None, ds.enrichment), domain)
            if not routing.empty:
                b.subheading("BGP routing")
                b.table(routing, columns=["IP", "Prefix", "Origin", "AS Name", "Status", "Upstream", "Findings"])
        dns = latest_dns(ds.pdns_utc, domain) if b.detail else pd.DataFrame()
        if not dns.empty:
            b.subheading("Latest DNS records")
            b.table(dns, max_rows=25)
        if not mine.empty:
            b.subheading("Alerts")
            listed = _listed(ctx, mine)
            b.table(listed if not listed.empty else mine, columns=ALERT_COLUMNS, max_rows=25)
        b.raw("</div>")


def _e(text):
    from core.report_html import e
    return e(text)


CERT_PROFILES = {"high": 3, "detailed": 10}    # certificates profiled per level (the Complete report: all)


def section_cert_profiles(b, ctx):
    from core import cert_profile as cp
    b.section("Certificate profiles", "The run's certificates that stand out most (by their most severe flag, then "
                                      "newest), each field by field: the field map of its X.509 structure, the flags "
                                      "and the certificates related to it.")
    certs = cp.certificates(ctx.ds.ssl)
    if certs.empty:
        b.note("No certificate in the analysis window.")
        return
    limit = CERT_PROFILES.get(ctx.level.key)
    ranked = cp.riskiest(certs, limit=limit)
    if limit and len(certs) > limit:
        b.note(f"The {limit} of {len(certs):,} certificates that stand out most.")
    for cert in ranked.to_dict("records"):
        related = cp.related_certificates(cert, certs)
        found = cp.flags(cert, related=related)
        b.heading(cp.label(cert))
        b.cards([("Domains", cp.text(cert.get("Domains"))), ("Issuer", cp.text(cert.get("Issuer Org"))
                                                            or cp.text(cert.get("Issuer"))),
                 ("Validation", cp.text(cert.get("Validation Level")).upper()),
                 ("Key", f"{cp.text(cert.get('Public Key Algo'))} {cp.text(cert.get('Public Key Bits'))}".strip()),
                 ("Flags", len(found))])
        if found.empty:
            b.text("Nothing stands out in this certificate.")
        else:
            b.table(found)
        b.dot(cp.field_map(cert, found))
        if b.detail:
            fields = cp.field_rows(cert)
            b.table(fields[fields["Value"] != ""], columns=["Section", "Field", "Value"], exact=True)
        if not related.empty:
            b.subheading("Related certificates")
            b.table(related, max_rows=MAX_ROWS)


def section_alerts(b, ctx, top=50):
    from views.alert_tools import heatmap_figure, mitre_figure, mitre_matrix, tactic_rows
    alerts = _with_status(ctx.alerts)
    b.section("Alerts", "Where the alerts are, which ATT&CK techniques they map to, DomainTools risk components and "
                        "the most severe alerts. Every alert with its evidence is under Supporting evidence.")
    if alerts.empty:
        b.note("No active alert for the current filters.")
        return
    fig, n_domains = heatmap_figure(alerts)
    b.heading("Alert heatmap")
    b.figure(fig, height=max(320, n_domains * 34 + 220))
    rows = tactic_rows(alerts)
    if not rows.empty:
        b.heading("MITRE ATT&CK")
        b.figure(mitre_figure(rows), height=520)
        b.table(mitre_matrix(rows))
    risk = ctx.ds.risk
    if not _empty(risk) and {"Domain", "Score", "Component"} <= set(risk.columns):
        b.heading("DomainTools risk components")
        fig = px.bar(risk, x="Domain", y="Score", color="Component", barmode="group",
                     title="Domain Risk Score by Component")
        b.figure(fig, height=420)
        b.table(risk[risk["Component"] != "Overall Risk"], max_rows=MAX_ROWS)
    listed = _ranked(_listed(ctx, alerts))
    shown = min(top, len(listed)) if top else len(listed)
    which = f"{_severity_text(ctx).capitalize()} alerts" if ctx.level.severities else "Alerts by severity"
    b.heading(f"{which} ({shown:,} of {len(alerts):,} alerts)")
    if listed.empty:
        b.note(f"No {_severity_text(ctx)} alert; the Detailed report lists the other {len(alerts):,}.")
    b.table(listed, columns=ALERT_COLUMNS, max_rows=top, exact=True)
    by_type = alerts.groupby(["Threat Type", "Severity"]).agg(Alerts=("Domain", "size"),
                                                               Domains=("Domain", "nunique")).reset_index()
    b.subheading("Alert types")
    b.table(by_type.sort_values("Alerts", ascending=False))


# ---- Infrastructure ---------------------------------------------------------------------------------------------------

def section_dns(b, ctx):
    from views.campaign_view import _hosting_rows
    from visualizations.network_graph import build_graph_elements, graph_figure
    ds = ctx.ds
    b.section("DNS & hosting", "Current hosting from Iris Investigate, how the infrastructure changed over time in "
                               "passive DNS and Domain History, and the infrastructure the domains share.")
    hosting = _hosting_rows(ds) if ds.enrichment else pd.DataFrame()
    if not hosting.empty:
        b.heading("Hosting footprint")
        geo = hosting.groupby("Country").agg(IPs=("IP", "nunique"), Domains=("Domain", "nunique")).reset_index()
        b.figure(_world(geo, "IPs", "Reds", "Hosting IPs by country"), height=420)
        labels, index, links = [], {}, {}

        def node(name):
            if name not in index:
                index[name] = len(labels)
                labels.append(name)
            return index[name]
        for _, row in hosting.iterrows():
            asn = f"{row['ASN']} · {row['ISP'][:28]}"
            for a, z in ((row["Domain"], asn), (asn, f"IP: {row['IP']}")):
                links[(node(a), node(z))] = links.get((node(a), node(z)), 0) + 1
        fig = go.Figure(go.Sankey(node=dict(label=labels, pad=12, thickness=16),
                                  link=dict(source=[k[0] for k in links], target=[k[1] for k in links],
                                            value=list(links.values()), color="rgba(116, 133, 144, 0.35)")))
        fig.update_layout(title_text="Domain ➔ ASN / ISP ➔ IP", font_size=11)
        b.figure(fig, height=max(400, hosting["IP"].nunique() * 18 + 100), secondary=True)
        b.table(hosting, max_rows=MAX_ROWS)
    combined = ds.combined
    if b.detail and not _empty(combined) and {"Date", "Field", "Domain"} <= set(combined.columns):
        b.heading("Change events over time")
        fig = px.scatter(combined, x="Date", y="Field", color="Domain",
                         symbol="Data Source" if "Data Source" in combined else None,
                         title="Change Event Distribution")
        fig.update_traces(marker=dict(size=9, opacity=0.8))
        b.figure(fig, height=460, secondary=True)
        ips = combined[combined["Field"].astype(str).str.contains("A|IP", regex=True)].copy()
        ips["IP"] = ips["Value"].astype(str).map(extract_ip_addresses)
        ips = ips.explode("IP").dropna(subset=["IP"])
        if not ips.empty:
            ips["Network"] = ips["IP"].map(ip_network_bucket)
            clusters = ips.groupby(["Domain", "Network", "IP"]).size().reset_index(name="Observations")
            fig = px.treemap(clusters, path=[px.Constant("Infrastructure"), "Domain", "Network", "IP"],
                             values="Observations", color="Network",
                             title="Infrastructure map (Domain ➔ Network ➔ IP)")
            b.figure(fig, height=480, secondary=True)
    pdns = ds.pdns_norm
    if b.detail and not _empty(pdns) and {"Date", "Count", "Domain"} <= set(pdns.columns):
        area = pdns.dropna(subset=["Date"]).assign(Day=lambda d: pd.to_datetime(d["Date"]).dt.date)
        area = area.groupby(["Day", "Domain"])["Count"].sum().reset_index()
        if not area.empty:
            b.heading("Passive DNS query volume")
            b.figure(px.area(area, x="Day", y="Count", color="Domain"), height=380, secondary=True)
    correlation = ctx.correlation
    artifacts = getattr(correlation, "artifacts", None)
    if not _empty(artifacts):
        nodes, edges = build_graph_elements(artifacts, shared_only=True,
                                            domain_cluster=getattr(correlation, "domain_cluster", None))
        if not _empty(nodes) and not _empty(edges):
            b.heading("Infrastructure graph (shared artifacts)")
            b.figure(graph_figure(nodes, edges, "Domains and the artifacts they share"), height=560)
    clusters = getattr(correlation, "clusters", None) or []
    if clusters:
        b.heading("Infrastructure clusters")
        b.table(pd.DataFrame([{"Cluster": c["Cluster"], "Strength": c["Strength"], "Size": c["Size"],
                               "Domains": ", ".join(c["Domains"]),
                               "Shared": "; ".join(f"{k}: {', '.join(v[:5])}" for k, v in
                                                   c["Shared Artifacts"].items())} for c in clusters]))
    hops = getattr(ctx.threats, "hops", None)
    if not _empty(hops):
        b.heading("Domain hopping")
        b.table(hops, max_rows=MAX_ROWS)
    if not _empty(ds.txt_apps):
        b.heading("TXT apps and verifications")
        b.table(ds.txt_apps, max_rows=MAX_ROWS)


def section_vpndb(b, ctx):
    from views.vpndb_page import category_heatmap, exit_countries, flow_figure, provider_bars
    ds = ctx.ds
    b.section("VPNDB", "VPNDB's verdict on the hosting IPs: which are VPN, proxy, residential-proxy or Tor exits, and "
                       "who operates them.")
    table = ds.anonymizers
    if _empty(table) and _empty(ds.prefixes):
        b.note("VPNDB was not checked in this run.")
        return
    if not _empty(table):
        flagged = anonymizer_rows(table)
        b.cards([("IPs checked", len(table))]
                + [(c, int((flagged["Category"] == c).sum())) for c in ANONYMIZER_CATEGORIES]
                + [("Shared exits", int(flagged.apply(shared_exit, axis=1).sum()) if not flagged.empty else 0)])
        if flagged.empty:
            b.text("VPNDB attributes none of the checked IPs to a VPN, proxy or Tor.")
        else:
            b.subheading("Domain → provider → exit")
            b.figure(flow_figure(flagged), height=max(340, 26 * len(flagged) + 120))
            if b.detail:
                b.subheading("Checked IPs by domain and category")
                b.figure(category_heatmap(table), height=max(320, 40 * table["Domains"].nunique() + 160))
                b.subheading("Exits per provider")
                b.figure(provider_bars(flagged), height=340)
            geo = exit_countries(flagged)
            if not geo.empty:
                b.subheading("Exit countries")
                b.figure(_world(geo, "Exits", "Oranges"), height=380)
            b.subheading("VPN, proxy and Tor exits")
            b.table(flagged, columns=["IP", "Domains", "Category", "Provider", "Confidence", "Tor", "Sharing",
                                      "IOC Value", "ASN", "AS Organization", "Country", "Last Seen", "Basis"],
                    max_rows=MAX_ROWS)
        check = crosscheck(table, ds.enrichment)
        if not check.empty:
            b.subheading("Iris cross-check")
            b.table(check, max_rows=MAX_ROWS)
    if not _empty(ds.prefixes):
        b.subheading("CIDR targets")
        b.table(ds.prefixes, max_rows=MAX_ROWS)
    if not _empty(ds.exit_neighbours):
        b.subheading("Other domains on dedicated exits")
        b.table(ds.exit_neighbours, max_rows=MAX_ROWS)


def section_tor(b, ctx):
    from views.tor_page import run_tor_networks
    overview = ctx.ds.tor_overview
    b.section("Tor network", "The Tor relay list placed with VPNDB's routing and country tables, and the run's "
                             "networks among the Tor exit networks.")
    if not overview:
        b.note("No Tor overview in this run (it comes with the VPNDB check).")
        return
    counts = overview.get("counts") or {}
    b.cards([(label, counts.get(key, 0)) for label, key in (
        ("Relays", "relays"), ("Exit relays", "exitRelays"), ("Exit addresses", "exitAddresses"),
        ("Exit networks", "exitNetworks"), ("New exits (30 d)", "newExitRelays30d"))])
    tables = tor_tables(overview)
    hits = run_tor_networks(ctx.ds, tables["Networks"])
    b.subheading("Networks of the run that carry Tor exit traffic")
    if hits.empty:
        b.note("None of the run's networks carries Tor exit traffic.")
    else:
        b.table(hits)
    for name, label in (("Networks", "organization"), ("Countries", "country")):
        frame = tables[name]
        if frame.empty or label not in frame:
            continue
        top = frame.head(15).copy()
        top["Label"] = (("AS" + top["asn"].astype(str) + " ") if "asn" in top else "") + top[label].astype(str)
        fig = px.bar(top.iloc[::-1], x="Exit share %", y="Label", orientation="h",
                     title=f"Tor exit traffic by {'network' if name == 'Networks' else 'country'}")
        fig.update_layout(yaxis_title="", xaxis_title="% of Tor exit traffic")
        b.figure(fig, height=440, secondary=True)


def section_bgp(b, ctx):
    from views.bgp_page import brief, path_graph, sankey_figure, timeline_figure
    ds = ctx.ds
    b.section("BGP", "Who announces the hosting IPs (BGPDB), whether RPKI and the IRR allow it, and the routing "
                     "findings.")
    if _empty(ds.bgp_origins):
        b.note("BGPDB was not checked in this run.")
        return
    found = bgp.findings(ds.bgp_origins, ds.bgp_asns, ds.bgp_routes)
    ips = bgp.ip_table(ds.bgp_origins, ds.bgp_routes, found, ds.enrichment)
    stats = bgp.summary(ds.bgp_origins, ds.bgp_asns, ds.bgp_routes, found)
    b.cards([("IPs routed", stats["ips"]), ("Prefixes", stats["prefixes"]), ("Origin networks", stats["origins"]),
             ("Upstream networks", stats["upstreams"]), ("Unauthorized announcements", stats["unauthorized"])])
    b.bullets(brief(ds, found, limit=10))
    if not _empty(found):
        b.subheading("Routing findings")
        b.table(found, max_rows=MAX_ROWS)
    b.subheading("Hosting IPs")
    b.table(ips, max_rows=MAX_ROWS)
    fig, nodes = sankey_figure(ds.bgp_origins, ds.bgp_routes)
    if nodes:
        b.subheading("Routing map: domain → prefix → origin → upstream")
        b.figure(fig, height=max(420, nodes * 22))
    if b.detail and ds.bgp_origins["First Seen"].notna().any():
        b.subheading("Origin timeline")
        b.figure(timeline_figure(ds.bgp_origins), height=max(320, 30 * ds.bgp_origins["Prefix"].nunique() + 140),
                 secondary=True)
    if not _empty(ds.bgp_routes):
        prefixes = list(dict.fromkeys(found["Prefix"].dropna())) if not _empty(found) else []
        prefixes = (prefixes or list(ds.bgp_routes["Prefix"].value_counts().index))[:5 if b.detail else 2]
        for prefix in prefixes:
            source = path_graph(ds.bgp_routes[ds.bgp_routes["Prefix"] == prefix], ds.bgp_origins, ds.bgp_asns)
            if source:
                b.subheading(f"AS paths towards {prefix}")
                b.dot(source)
    if not _empty(ds.bgp_asns):
        b.subheading("Origin and upstream networks")
        b.table(ds.bgp_asns, max_rows=MAX_ROWS)
    if not _empty(ds.anonymizers):
        exits = bgp.vpndb_ip_match(ips, ds.anonymizers)
        if not _empty(exits):
            b.subheading("VPNDB match: exits and their routing")
            b.table(exits, max_rows=MAX_ROWS)
    if not _empty(ds.bgp_neighbours):
        b.subheading("Neighbouring prefixes")
        b.table(ds.bgp_neighbours, max_rows=MAX_ROWS)


def section_cname(b, ctx):
    from views.cname_view import _chain_graph
    ds = ctx.ds
    b.section("CNAME chains", "Every CNAME record of the analysis window, the service its target runs on and where "
                              "the chain ends.")
    cmap = order_by_domain(dataset_cname_map(ds), ds.selected_domains)
    if cmap.empty:
        b.note("No CNAME record for the analyzed domains in the analysis window.")
        return
    current = cmap[cmap["Current"]]
    b.cards([("Hostnames with a CNAME", cmap["Hostname"].nunique()),
             ("Current external", int(current["External"].sum())),
             ("Dead ends", int((current["Outcome"] == "Dead end").sum())),
             ("Takeover-prone", int((current["Service Type"] == "Takeover-prone").sum())),
             ("Dynamic DNS / tunnel", int((cmap["Service Type"] == "Dynamic DNS / tunnel").sum()))])
    b.table(cmap.drop(columns=[c for c in cmap.columns if c.startswith("_")]), max_rows=MAX_ROWS)
    b.subheading("Chain map")
    b.dot(_chain_graph(current if not current.empty else cmap, ds.timezone))
    links = cname_links(cmap, ds.selected_domains, ds.cname_rdata)
    if not _empty(links):
        b.subheading("Cross-domain links")
        b.table(links, max_rows=MAX_ROWS)


def section_resolution(b, ctx):
    from core import resolver as res
    from views.resolver_view import tree_graph
    b.section("DNS resolution", "The analyzed domains' DNS tree (passive DNS) resolved record by record to IP "
                                "addresses: CNAME chains, MX and NS hosts, SPF includes. A dangling record points to a "
                                "name that resolves nowhere: whoever claims it receives what points to it.")
    tree, todo, routing = res.dataset_tree(ctx.ds)
    if tree.empty:
        b.note("No current A, AAAA, CNAME, MX, NS or SPF record in the passive DNS of the analysis window.")
        return
    counts = res.summary(tree)
    b.cards([("Names", counts["Names"]), ("Records", counts["Records"]), ("Resolve to IPs", counts["Resolves"]),
             ("Dangling", counts["Dangling"]), ("Stale", counts["Stale"]), ("Critical", counts["Critical"]), ("High", counts["High"]),
             ("Not resolved yet", counts["Pending"]), ("With warnings", counts["Warnings"])])
    if todo:
        b.callout(f"{len(todo):,} name(s) were not looked up in DNSDB yet (DNS resolution page → Resolve): records that "
                  "reach them are Not resolved yet, and could be dangling too.")
    shown = res.display(tree)
    dangling = shown[shown["Status"] == res.DANGLING]
    b.heading(f"Dangling records ({len(dangling):,})")
    b.note(res.DANGLING_DEFINITION)
    if dangling.empty:
        b.text("No dangling record found.")
    else:
        b.table(dangling, columns=["Severity", "Domain", "Name", "Type", "Dangling", "Service", "Reason", "Last Seen"],
                max_rows=MAX_ROWS)
    stale = shown[shown["Status"] == res.STALE]
    if not stale.empty:
        b.subheading(f"Stale records ({len(stale):,}): target missing, but not claimable")
        b.table(stale, columns=["Domain", "Name", "Type", "Stale", "Service", "Reason", "Last Seen"], max_rows=MAX_ROWS)
    other = tree[tree["Status"] != res.RESOLVES]
    if not other.empty:
        b.subheading("Graph: dangling and unresolved records")
        b.dot(tree_graph(other, limit=40 if b.detail else 15))
    warned = shown[shown["Warnings"] != ""]
    if not warned.empty:
        b.subheading("Warnings")
        b.table(warned, columns=["Domain", "Name", "Type", "Records", "Warnings"], max_rows=MAX_ROWS)
    if b.detail:
        b.subheading("Resolution tree")
        b.table(shown, columns=["Severity", "Domain", "Name", "Type", "Status", "Records", "Targets", "IPv4", "IPv6",
                                "Origins", "Path", "Last Seen"], max_rows=MAX_ROWS)
    origins = res.origins(tree, routing)
    if not origins.empty:
        b.subheading("Origin networks (BGPDB: RPKI / IRR, visibility)")
        b.table(origins, max_rows=MAX_ROWS)


def section_certs(b, ctx):
    from views.ssl_view import san_treemap_records
    ds = ctx.ds
    b.section("Certificates", "The certificates of the analysis window: issuers, sources, SAN sprawl, self-signed "
                              "certificates and JA4X.")
    if _empty(ds.ssl):
        b.note("No certificate in the analysis window.")
        return
    unique = ds.ssl.drop_duplicates(["Domain", "Hash", "Source"])
    selfsigned = self_signed_certificates(unique, ds.selected_domains)
    keys = unique["Public Key SHA256"].nunique() if "Public Key SHA256" in unique else ""
    b.cards([("Certificates", unique["Hash"].nunique()), ("Unique keys", keys), ("Self-signed", len(selfsigned))])
    records, _ = san_treemap_records(unique)
    if records:
        fig = px.treemap(pd.DataFrame(records), path=["Target Domain", "Certificate", "SAN Domain"], values="Count",
                         color="Certificate", title="Certificate infrastructure map (SANs)")
        b.figure(fig, height=480)
    for column, title in (("Issuer", "Issuing CAs"), ("Source", "Certificates by data source")):
        if column in unique:
            counts = unique[column].fillna("Unknown").value_counts().reset_index()
            counts.columns = [column, "Count"]
            b.figure(px.pie(counts, names=column, values="Count", hole=0.4, title=title), height=340,
                     secondary=column == "Source")
    if not selfsigned.empty:
        b.subheading("Self-signed certificates")
        b.table(selfsigned, max_rows=MAX_ROWS)
    if "JA4X" in unique:
        from core import ja4x
        summary = ja4x.summary(unique)
        if not _empty(summary):
            b.subheading("JA4X")
            b.table(summary, max_rows=MAX_ROWS)
    if b.detail:
        from core import cert_profile as cp
        breakdown = cp.field_breakdown(cp.certificates(ds.ssl))
        if not breakdown.empty:
            b.subheading("Field breakdown: how often each field is filled, common and rare values")
            b.table(breakdown, exact=True)
    b.subheading("Certificates")
    b.table(unique, columns=["Domain", "Common Name", "Issuer", "Validation Level", "Not Before", "Not After",
                             "Public Key Algo", "Public Key Bits", "SAN Count", "Source", "Hash"], max_rows=MAX_ROWS)


# ---- Hunt -------------------------------------------------------------------------------------------------------------

def section_hunt_map(b, ctx):
    b.section("Hunt map", "The runs of the hunt this run belongs to and the values each run followed.")
    hunt = ctx.hunt
    if not hunt:
        b.note("This run is not part of a saved hunt.")
        return
    b.svg(hunt.get("svg"))
    if not _empty(hunt.get("runs")):
        b.table(hunt["runs"])


def section_hostnames(b, ctx):
    inventory = ctx.ds.hostname_inventory
    b.section("Hostname inventory", "Every hostname of the analyzed domains (full passive DNS history and "
                                    "certificates), flagged ones first.")
    if _empty(inventory):
        b.note("No hostname inventory in this run.")
        return
    flags = inventory["Flags"].astype(str)
    b.cards([("Hostnames", len(inventory)), ("Flagged", int((flags.str.strip() != "").sum())),
             ("With certificates", int((pd.to_numeric(inventory["Certificates"], errors="coerce") > 0).sum()))])
    ordered = inventory.assign(_f=(flags.str.strip() == "").astype(int)).sort_values(["_f", "Hostname"]) \
        .drop(columns="_f")
    b.table(ordered, max_rows=MAX_ROWS)


def section_triage(b, ctx):
    from views.triage_view import dataset_triage
    b.section("Subdomain triage", "Subdomains ranked by how suspicious their names look (random labels, brands, "
                                  "embedded domains, sensitive words).")
    triage = dataset_triage(ctx.ds) if not _empty(ctx.ds.hostname_inventory) else pd.DataFrame()
    if _empty(triage):
        b.note("No subdomain to triage.")
        return
    b.cards([(level, int((triage["Level"] == level).sum())) for level in ("High", "Medium", "Low")]
            + [("Subdomains", len(triage))])
    b.table(triage[triage["Level"].isin(["High", "Medium"])], max_rows=MAX_ROWS)


def section_similarity(b, ctx):
    from views.similarity_view import indicator_graph
    settings = ctx.similarity or {}
    weights = settings.get("weights") or sim.DEFAULT_WEIGHTS
    threshold = settings.get("threshold", sim.DEFAULT_THRESHOLD)
    min_rare = settings.get("min_rare", 1)
    b.section("Domain similarity", f"How alike the domains are built (infrastructure similarity, not attribution). "
                                   f"Threshold {threshold} %, at least {min_rare} rare shared value(s).")
    domains = [d for d in ctx.ds.selected_domains if "/" not in str(d)][:300]
    feats, iris_counts = sim.domain_features(ctx.ds, ctx.profiles, domains)
    if len(feats) < 2:
        b.note("Similarity needs at least two domains.")
        return
    counts = sim.value_counts(feats, iris_counts, settings.get("runs"))
    pairs = sim.pair_scores(feats, counts, weights)
    shown = sim.passing(pairs, threshold, min_rare)
    groups = sim.clusters(pairs, sorted(feats), threshold, min_rare)
    b.cards([("Domains compared", len(feats)), ("Pairs scored", len(pairs)), ("Similar pairs", len(shown)),
             ("Clusters", len(groups))])
    if not shown.empty:
        b.subheading("Similar pairs")
        b.table(shown, max_rows=MAX_ROWS)
    names = ([d for g in groups for d in g] + sorted(set(feats) - {d for g in groups for d in g}))[:60]
    if len(names) > 1 and not pairs.empty:
        grid = sim.matrix(pairs, names)
        fig = px.imshow(grid.values, x=names, y=names, zmin=0, zmax=100, color_continuous_scale="Blues",
                        labels={"color": "Similarity %"}, aspect="auto")
        b.subheading("Similarity matrix")
        b.figure(fig, height=max(380, 22 * len(names) + 140))
    for number, group in enumerate(groups, 1):
        indicators = sim.cluster_indicators(group, feats, counts)
        rows = sim.cluster_pairs(group, feats, pairs)
        mean = rows["Similarity %"].dropna().mean() if not rows.empty else 0
        b.heading(f"Cluster {number} · {len(group)} domains · average {mean:.0f} % · {len(indicators)} shared "
                  "indicators")
        b.text(", ".join(group))
        if not indicators.empty and len(group) <= 25:
            b.dot(indicator_graph(group, indicators))
        if not indicators.empty:
            b.subheading("Shared indicators")
            b.table(indicators.assign(**{"Domain List": indicators["Domain List"].map(", ".join)}),
                    max_rows=MAX_ROWS)
        b.subheading("Shared between each pair")
        b.table(rows, max_rows=MAX_ROWS)


# ---- Supporting evidence and appendices -------------------------------------------------------------------------------

def section_evidence(b, ctx, top=None):
    alerts = _with_status(ctx.alerts)
    severities = _severity_text(ctx)
    b.section("Detections and evidence", (f"The {severities} detections" if severities else "Every active detection")
              + " with the facts behind them: the threat logic and the triggering records.")
    listed = _ranked(_listed(ctx, alerts))
    if listed.empty:
        b.note(f"No {severities} alert for the current filters." if severities else
               "No active alert for the current filters.")
        return
    limit = top if severities else None    # the Detailed and Complete reports keep every detection here
    b.table(listed, columns=ALERT_COLUMNS + ["Threat Logic", "Triggering IOCs"], mono=("Triggering IOCs",),
            max_rows=limit, exact=True)
    from core.alert_grouping import alert_evidence
    records = alert_evidence(listed.head(limit) if limit else listed)
    if not records.empty:
        b.subheading(f"Evidence records ({len(records):,})")
        b.table(records, max_rows=EVIDENCE_ROWS.get(ctx.level.key), exact=True)


def section_sources(b, ctx):
    from core.api_usage import attention_rows, source_stats
    statuses = getattr(ctx.collected, "statuses", None)
    b.section("Data sources", "How every source's lookups went (OK, partial, no data, errors) and what came from the "
                              "cache.")
    if not statuses:
        b.note("No lookup status in this run.")
        return
    stats = source_stats(statuses)
    stats = stats.assign(Answered=(stats["Answered"] * 100).round().astype(int).astype(str) + " %")
    b.table(stats)
    attention = attention_rows(statuses)
    if not attention.empty:
        b.subheading("Lookups that failed or stopped at a limit")
        b.table(attention, max_rows=MAX_ROWS)


def section_iocs(b, ctx):
    from core.analysis_report import ioc_severity
    iocs = dataset_iocs(ctx.ds)
    ranked = ioc_severity(iocs, _with_status(ctx.alerts))
    severities = ctx.level.severities
    listed = ranked[ranked["Severity"].isin(severities)] if severities and not ranked.empty else ranked
    limit = ctx.ioc_limit
    shown = min(limit, len(listed)) if limit else len(listed)
    title = "All IOCs" if shown == len(ranked) else "IOCs"
    b.section(f"{title} ({shown:,} of {len(ranked):,})",
              "The run's indicators, most severe first: each takes the most severe alert that cites it in its evidence "
              "(Alert evidence) or, failing that, the most severe alert on its domain (Domain alert)."
              + (f" Only the IOCs behind {_severity_text(ctx)} alerts." if severities else ""))
    if not ranked.empty:
        counts = ranked["Severity"].replace("", "No alert").value_counts()
        b.cards([(name, int(counts.get(name, 0))) for name in [*SEVERITY_ORDER, "No alert"] if counts.get(name, 0)])
    b.table(listed, mono=("Value",), max_rows=limit, exact=True,
            more="raise the IOC limit, pick the Complete report, or use the Data export")


def section_lookups(b, ctx):
    queries = build_lookup_queries(ctx.collected, ctx.created)
    b.section(f"All lookups ({len(queries):,})", "Every lookup the run made, as a query, domaintools CLI or curl "
                                                 "command to repeat outside the app.")
    b.table(queries, mono=("Query", "Command"), note_more=False, exact=True)
