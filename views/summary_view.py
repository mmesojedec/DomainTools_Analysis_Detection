"""
Summary page: the analysis in numbers and where the hunt goes next. Every domain with what drives its risk, the
analysis details, top alerts, triage status, what to check next, the strongest leads, linked domains, run statistics,
and what is new since the last analysis, each one click from the page that shows it.
"""
import time

import pandas as pd
import plotly.express as px
import streamlit as st

from core.anonymizers import PROXY, RESIDENTIAL, TOR, VPN, anonymizer_rows, shared_exit
from core.cname import dataset_cname_map
from core.helpers import md_escape
from core.hunt_stats import (
    alerts_by_category,
    cluster_callouts,
    data_health,
    glance_stats,
    lifecycle_stats,
    shared_infrastructure,
    weekly_activity,
)
from core.hunt_tree import hunt_trail, trail_text
from core.idn import has_ace, to_unicode
from core.next_steps import SEVERITY_RANK, next_steps
from core.persistence import find_watch, load_all_runs, load_settings, remove_watch, save_watch
from core.pivots import top_leads
from core.risk_profile import drivers_text, score_drivers
from core.triage import STATUS_HELP, domain_verdicts, load_triage, open_alerts, triage_counts
from core.use_cases import PROFILES_SETTING, find_case
from integrations.cache import age_text
from views import navigation
from views.alert_tools import HEATMAP_SEVERITY_COLORS, SEVERITY_ORDER
from views.anonymizer_view import alerts_button, domain_verdict_text, ip_check_only, render_ip_check, render_networks, selectable_table
from views.collection_progress import PROGRESS_KEY, render_last_collection
from views.common import chart, selected_rows, selection_key
from views.history_cap import render_history_cap_notice
from views.hunt_actions import analyze_button, current_run_id, iris_button
from views.hunt_plan_view import first_step, plan, render_suggested_hunt
from views.idn_display import display_name, enabled
from views.pivot_view import dataset_pivots
from views.risk_view import render_kpi_banner
from views.ssl_view import CERT_TAB_KEY, SELF_SIGNED_TAB

SIGNAL_BADGES = {"Strong": "green", "Useful": "blue"}
DIFF_KINDS = ["IP", "Name Server", "MX", "Certificate", "Web Tracker", "Hostname"]


def domain_overview(profiles, alerts, verdicts=None, anonymizers=None):
    """One row per domain: risk, what drives it, alerts, the worst severity, the most severe alert and the verdict;
    with VPNDB verdicts, how many of its IPs are VPN, proxy or Tor exits."""
    columns = ["Domain", "Unified Risk", "Verdict", "Alerts", "Open", "Worst Severity", "Top Alert", "Risk Drivers",
               "DIF Fingerprint"]
    if profiles is None or profiles.empty:
        return pd.DataFrame(columns=columns)
    verdicts = verdicts or {}
    rows = []
    for row in profiles.to_dict("records"):
        mine = alerts[alerts["Domain"] == row["Domain"]] if not alerts.empty else alerts
        ranked = mine.assign(_r=mine["Severity"].map(SEVERITY_RANK).fillna(9)).sort_values("_r") if not mine.empty else mine
        still_open = open_alerts(mine)
        rows.append({"Domain": row["Domain"], "Unified Risk": row["Unified Risk"],
                     "Verdict": verdicts.get(row["Domain"], "New"), "Alerts": len(mine),
                     "Open": len(still_open) if still_open is not None else len(mine),
                     "Worst Severity": ranked.iloc[0]["Severity"] if not ranked.empty else "",
                     "Top Alert": ranked.iloc[0]["Threat Type"] if not ranked.empty else "",
                     "Risk Drivers": drivers_text(score_drivers(row, alerts)),
                     "DIF Fingerprint": row.get("DIF Fingerprint", "")})
    frame = pd.DataFrame(rows, columns=columns)
    if anonymizers is not None and not anonymizers.empty:
        frame.insert(frame.columns.get_loc("Top Alert") + 1, "VPNDB",
                     frame["Domain"].map(lambda d: domain_verdict_text(anonymizers, d)))
    return frame.sort_values(["Unified Risk", "Alerts"], ascending=False).reset_index(drop=True)


def render_use_case_plan():
    """The steps of the use case picked on the Start page: links to tick off as you go, with the share done."""
    case = find_case(st.session_state.get("use_case"), load_settings().get(PROFILES_SETTING))
    if case is None:
        return
    with st.container(border=True):
        steps = [(number, key, text) for number, (key, text) in enumerate(case.steps, 1)
                 if navigation.page(key) is not None]
        state = f"plan_step::{case.key}::{current_run_id()}"
        done = sum(bool(st.session_state.get(f"{state}::{number}")) for number, _, _ in steps)
        st.markdown(f"**{case.title}** — " + ("your plan" if case.steps else "custom profile in use"))
        if steps:
            st.progress(done / len(steps), text=f"{done} of {len(steps)} step(s) done")
        for number, key, text in steps:
            c_check, c_link = st.columns([0.4, 8], vertical_alignment="center")
            c_check.checkbox("Done", key=f"{state}::{number}", label_visibility="collapsed",
                             help="Tick the step once you have done it (kept for this run)")
            navigation.link(key, label=f"{number}. {text}", container=c_link)
        c1, c2 = st.columns([1, 4])
        if c1.button("Clear plan", key="clear_use_case"):
            st.session_state.pop("use_case", None)
            st.rerun()
        navigation.link("home", label="Pick another use case", container=c2)


def _render_hunt_trail():
    run_id = current_run_id()
    if not run_id:
        return
    trail = hunt_trail(load_all_runs(), run_id)
    if len(trail) > 1:
        c_text, c_link = st.columns([5, 1], vertical_alignment="center")
        c_text.markdown(":material/account_tree: **Hunt trail:** " + trail_text(trail))
        navigation.link("hunt_tree", label="Hunt tree", container=c_link, icon=":material/park:")


def _metric(column, label, value, page=None, link=None, help_text=None):
    column.metric(label, value, help=help_text)
    if page:
        navigation.link(page, label=link, container=column)


def _render_glance(ds, alerts):
    """The run in numbers, each linked to the page that lists them."""
    stats = glance_stats(ds, alerts)
    st.subheader("Analysis Details", help="What this analysis covers, in the analysis window. Each number links to "
                                           "the page that lists it.")
    severity = [f":{color}-badge[{stats['Alerts'][name]} {name}]" for name, color in
                (("Critical", "red"), ("High", "orange"), ("Medium-High", "orange"), ("Medium", "violet"),
                 ("Low", "blue")) if stats["Alerts"][name]]
    c_alerts, c_span = st.columns([3, 2])
    c_alerts.markdown("**Alerts:** " + (" ".join(severity) if severity else ":green-badge[none]"))
    if stats["First event"] is not None:
        c_span.markdown(f"**Records first seen:** {stats['First event']:%Y-%m-%d} → {stats['Last event']:%Y-%m-%d}",
                        help="Oldest and newest first-seen date of the records in the analysis window: a record "
                             "first seen years ago that is still active stays in a short window.")
    row1 = st.columns(4)
    _metric(row1[0], "Domains", f"{stats['Domains']:,}", "profile", "Profiles")
    _metric(row1[1], "IPs", f"{stats['IPs']:,}", "dns", "Hosting", "Unique IPs in passive DNS and Iris Investigate")
    _metric(row1[2], "ASNs", f"{stats['ASNs']:,}", "dns", "Hosting networks", "Hosting networks of the current IPs "
                                                                                "(Iris Investigate)")
    _metric(row1[3], "Name servers", f"{stats['Name servers']:,}", "dns", "Name servers")
    row2 = st.columns(4)
    _metric(row2[0], "Certificates", f"{stats['Certificates']:,}", "certs", "Certificates")
    _metric(row2[1], "Self-signed", f"{stats['Self-signed']:,}",
            help_text="Self-signed certificates, rated Critical to Low on the Certificates page")
    if navigation.page("certs") is not None:
        if row2[1].button("Self-Signed tab", key="summary_self_signed", type="tertiary",
                          icon=":material/verified_user:"):
            navigation.open_tab("certs", CERT_TAB_KEY, SELF_SIGNED_TAB)
    _metric(row2[2], "Hostnames", f"{stats['Hostnames']:,}", "hostnames", "Hostname Inventory",
            "Distinct names in passive DNS")
    _metric(row2[3], "Passive DNS records", f"{stats['Passive DNS records']:,}", "raw", "Raw Records")
    _render_vpndb_glance(ds)


def _render_vpndb_glance(ds):
    """The VPNDB row of Analysis Details: the checked hosting IPs and the anonymizer exits among them."""
    table = ds.anonymizers
    if table is None or table.empty:
        return
    flagged = anonymizer_rows(table)
    st.markdown("**VPNDB** · which VPN or proxy provider operates behind the hosting IPs",
                help="The run's public IPv4 hosting addresses checked in VPNDB. Shared exits identify the service, "
                     "not the actor; dedicated ones (few users) are worth pivoting on.")
    row3 = st.columns(4)
    _metric(row3[0], "IPs checked", f"{len(table):,}", "vpndb", "VPNDB page",
            "Current Iris IPs and passive DNS addresses of the domains (public IPv4, no CDN)")
    _metric(row3[1], "VPN / proxy exits", f"{int(flagged['Category'].isin((VPN, PROXY, 'Relay')).sum()):,}",
            help_text="Commercial VPN, datacenter proxy and relay exits")
    _metric(row3[2], "Residential proxy exits", f"{int((flagged['Category'] == RESIDENTIAL).sum()):,}",
            help_text="Home or mobile connections rented out as proxy exits")
    _metric(row3[3], "Tor relays / exits", f"{int((flagged['Category'] == TOR).sum()):,}")
    if not flagged.empty:
        shared = int(flagged.apply(shared_exit, axis=1).sum())
        st.caption(f"{len(flagged)} anonymizer exit(s)" + (f", {shared} shared (they identify the service, not the "
                                                           "actor)" if shared else ""))
        selectable_table(flagged[["IP", "Domains", "Category", "Provider", "Confidence", "Sharing", "IOC Value",
                                  "AS Organization", "Country"]], "summary_vpndb", table, ds=ds)
        alerts_button("summary_vpndb")


def _render_triage_status(alerts, verdicts):
    counts = triage_counts(alerts)
    st.subheader("Hunt status", help="Your decisions on the alerts (Alerts page, in each group) and on domains "
                                      "(Domain profile). They are kept between runs, so a rerun shows what is still "
                                      "open. " + STATUS_HELP.replace("**", ""))
    columns = st.columns(5)
    columns[0].metric("Open alerts", f"{counts['New'] + counts['Investigating']:,}",
                      help="New and Investigating: still need a decision")
    columns[1].metric("Investigating", f"{counts['Investigating']:,}")
    columns[2].metric("Benign", f"{counts['Benign']:,}")
    columns[3].metric("Malicious", f"{counts['Malicious']:,}", help="Confirmed bad; exported as confirmed indicators")
    malicious = [d for d, s in verdicts.items() if s == "Malicious"]
    columns[4].metric("Domains marked malicious", f"{len(malicious):,}", help=", ".join(malicious) or None)
    if counts["New"] + counts["Investigating"]:
        navigation.link("alerts", label="Review the open alerts")


def _render_next_steps(ctx, alerts, new_alerts, start=None):
    view, profiles = ctx.view, ctx.profiles
    steps = next_steps(open_alerts(alerts), profiles, dataset_cname_map(ctx.ds), ctx.collected.statuses, new_alerts,
                       len(view.resolved), ctx.thresholds["high_risk_score"])
    first = first_step(start)   # the first indicator to confirm (Suggested hunt), after the serious-alerts step
    if first:
        steps = sorted([*steps, first], key=lambda step: step["rank"])
    st.subheader("What to check next", help="Built from the open alerts (not yet marked Benign or Malicious), the "
                                             "riskiest domain, CNAME chains and the lookups.")
    if not steps:
        st.caption("Nothing stands out: no open serious alerts, no open CNAME chains and every lookup succeeded.")
    for i, step in enumerate(steps):
        if navigation.page(step["page"]) is None:
            continue
        c_text, c_button = st.columns([5, 1], vertical_alignment="center")
        c_text.markdown(f"{step['icon']} {step['text']}")
        navigation.jump_button(step["page"], f"Open {navigation.title(step['page'])}", step["state"],
                               button_key=f"next_step::{i}", container=c_button, width="stretch")


def _render_leads(ds):
    """The strongest pivots of the run, each one click from a new run or an Iris search."""
    leads = top_leads(dataset_pivots(ds))
    st.subheader("Leads to follow", help="The rarest values the run's domains have (Pivot Ranking): shared by only a "
                                         "few hundred domains in Iris, so they often lead to the same operator. "
                                         "Values two or more of your domains share come first.")
    if leads is None or leads.empty:
        st.caption("No strong or useful pivots: Iris Investigate found no rare shared value for these domains.")
        return
    for i, lead in leads.iterrows():
        count = f"{int(lead['Iris Domains']):,} domains in Iris" if pd.notna(lead["Iris Domains"]) else "count unknown"
        shared = f" · shared by **{lead['Run Domains']}** of your domains" if lead["Run Domains"] > 1 else \
            f" · {md_escape(lead['Shared With'])}"
        c_text, c_analyze, c_iris = st.columns([4, 1.3, 1], vertical_alignment="center")
        c_text.markdown(f":{SIGNAL_BADGES.get(lead['Signal'], 'gray')}-badge[{lead['Signal']}] **{lead['Type']}** "
                        f"`{lead['Value']}` · {count}{shared}")
        if lead["Analyze As"]:
            analyze_button([lead["Analyze As"]], f"{lead['Type']} {lead['Value']}", key=f"lead_hunt::{i}",
                           container=c_analyze, label="Analyze", width="stretch")
        iris_button(lead["Iris Search"], key=f"lead_iris::{i}", container=c_iris, width="stretch")
    navigation.link("pivots", label="All pivots, ranked")


def _render_clusters(correlation):
    callouts = cluster_callouts(correlation)
    if not callouts:
        return
    st.subheader("Linked domains", help="Domains that share a certificate, public key or tracker, or both an IP and a "
                                        "name server: probably run by the same operator.")
    for callout in callouts:
        color = "green" if callout["Strength"] == "Strong" else "blue"
        st.markdown(f":{color}-badge[{callout['Strength']}] **{callout['Size']} domains:** "
                    f"{md_escape(callout['Text'])}")
    navigation.link("dns", label="Infrastructure clusters and graph")


def _render_domains(profiles, alerts, verdicts, anonymizers=None):
    st.subheader("Domains", help="Select a domain to open its profile. Risk drivers: the parts of the Unified Risk "
                                 "score, largest first (0.4 × the DomainTools score, 0.3 × each risk vector, with "
                                 "its most severe alert).")
    overview = domain_overview(profiles, alerts, verdicts, anonymizers)
    if not enabled() and overview["Domain"].map(has_ace).any():   # switch off: the Unicode form next to xn-- names
        overview.insert(1, "Unicode", overview["Domain"].map(lambda d: to_unicode(d) if has_ace(d) else ""))
    event = st.dataframe(overview, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
                         key=selection_key("summary_domains", overview["Domain"]), column_config={
        "Unified Risk": st.column_config.ProgressColumn("Unified risk", min_value=0, max_value=100, format="%d"),
        "Verdict": st.column_config.Column("Verdict", help="Your verdict on the domain (Domain profile)"),
        "Alerts": st.column_config.NumberColumn("Alerts"),
        "Open": st.column_config.NumberColumn("Open", help="Alerts not yet marked Benign or Malicious"),
        "Worst Severity": st.column_config.Column("Worst severity"),
        "Top Alert": st.column_config.Column("Top alert", width="medium"),
        "VPNDB": st.column_config.Column("VPNDB", width="medium", help="The domain's checked IPs VPNDB attributes to "
                                                                      "a VPN, proxy or Tor exit, and by whom"),
        "Risk Drivers": st.column_config.Column("Risk drivers", width="large",
                                                help="Points each part adds to the Unified Risk score"),
    })
    rows = selected_rows(event, overview)
    if rows:
        navigation.jump_button("profile", f"Open the profile of {display_name(overview.iloc[rows[0]]['Domain'])}",
                               {"profile_domain": overview.iloc[rows[0]]["Domain"]}, button_key="summary_open_profile",
                               type="primary", icon=":material/domain:")


def _render_top_alerts(alerts):
    st.subheader("Top alerts", help="The ten most severe active alerts with their triage status. The Alerts page "
                                    "has all of them with their evidence.")
    if alerts.empty:
        st.caption("No active alerts in the analysis window.")
        return
    top = alerts.assign(_r=alerts["Severity"].map(SEVERITY_RANK).fillna(9)).sort_values("_r").head(10)
    st.dataframe(top[[c for c in ("Domain", "Threat Type", "Severity", "Confidence", "Status", "Category")
                      if c in top.columns]], hide_index=True, width="stretch")
    navigation.link("alerts", label=f"All {len(alerts):,} alert(s) with their evidence")


def _render_statistics(ds, alerts):
    st.subheader("Run statistics")
    c_category, c_shared = st.columns(2)
    with c_category:
        st.markdown("**Alerts by category**", help="Where the risk comes from, coloured by severity")
        counts = alerts_by_category(alerts)
        if counts.empty:
            st.caption("No alerts.")
        else:
            fig = px.bar(counts, x="Alerts", y="Category", color="Severity", orientation="h",
                         color_discrete_map=HEATMAP_SEVERITY_COLORS,
                         category_orders={"Severity": SEVERITY_ORDER,
                                          "Category": list(counts["Category"].cat.categories)})
            fig.update_layout(margin=dict(t=30, l=10, r=10, b=10), legend_title_text="", yaxis_title="",
                              xaxis_title="", legend=dict(orientation="h", y=1.02, yanchor="bottom", x=0))
            chart(fig, key="summary_categories", height=max(220, 40 * counts["Category"].nunique() + 120))
    with c_shared:
        st.markdown("**Top shared infrastructure**", help="The most used hosting networks, registrars, name servers "
                                                          "and certificate issuers. Shared: two or more of your "
                                                          "domains use it, a lead to one operator unless it is a big "
                                                          "provider.")
        shared = shared_infrastructure(ds)
        if shared.empty:
            st.caption("No hosting, registrar, name server or issuer data.")
        else:
            st.dataframe(shared, hide_index=True, width="stretch", height=min(420, 35 * (len(shared) + 1) + 3),
                         column_config={"Shared": st.column_config.CheckboxColumn("Shared"),
                                        "Domains": st.column_config.NumberColumn("Domains"),
                                        "Domain List": st.column_config.Column("Domains using it", width="medium")})
    activity = weekly_activity(ds)
    st.markdown("**Activity per week**", help="Registrations, name-server and IP changes, new certificates and new "
                                              "hostnames of all domains together (the last 52 weeks of the analysis "
                                              "window). Bursts stand out.")
    if activity.empty:
        st.caption("No dated activity in the analysis window.")
    else:
        fig = px.line(activity, x="Week", y="Events", color="Activity", markers=False)
        fig.update_layout(margin=dict(t=10, l=10, r=10, b=10), legend_title_text="", xaxis_title="",
                          legend=dict(orientation="h", y=-0.25))
        chart(fig, key="summary_activity", height=260)
    _render_lifecycle_and_health(ds)


def _dated(items, limit=5):
    return ", ".join(f"{md_escape(name)} ({when:%Y-%m-%d})" for name, when in items[:limit]) + \
        (f" … +{len(items) - limit}" if len(items) > limit else "")


def _render_lifecycle_and_health(ds):
    life = lifecycle_stats(ds)
    health = data_health(st.session_state.get("collected").statuses if st.session_state.get("collected") else [],
                         st.session_state.get(PROGRESS_KEY))
    c_life, c_health = st.columns(2)
    with c_life.container(border=True):
        st.markdown("**Lifecycle**")
        newest = life["Newest domain"]
        lines = [f"Newest domain: **{md_escape(newest[0])}**, registered {newest[1]:%Y-%m-%d}" if newest
                 else "Newest domain: no registration date (Iris Investigate)"]
        days = life["Days"]
        lines.append(f"Registered in the last {days} days: **{len(life['Registered recently'])}**"
                     + (f" — {_dated(life['Registered recently'])}" if life["Registered recently"] else ""))
        lines.append(f"Domains expiring within {days} days: **{len(life['Domains expiring'])}**"
                     + (f" — {_dated(life['Domains expiring'])}" if life["Domains expiring"] else ""))
        lines.append(f"Certificates expiring within {days} days: **{len(life['Certificates expiring'])}**"
                     + (f" — {_dated(life['Certificates expiring'])}" if life["Certificates expiring"] else ""))
        st.markdown("\n".join(f"- {line}" for line in lines))
    with c_health.container(border=True):
        st.markdown("**Data health**")
        oldest = health["Oldest cached"]
        parts = [f"{health['Lookups']:,} lookups: **{health['OK']:,} OK**",
                 f":orange[{health['Partial']:,} partial]" if health["Partial"] else "",
                 f"{health['No data']:,} with no data" if health["No data"] else "",
                 f":red[{health['Failed']:,} failed]" if health["Failed"] else "",
                 f":violet[{health['Cached']:,} from cache]" if health["Cached"] else ""]
        st.markdown(", ".join(p for p in parts if p))
        render_history_cap_notice(ds.selected_domains, compact=True)
        if oldest:
            st.caption(f"Oldest cached result fetched {age_text(time.time() - oldest)} ago.")
        if health["Partial"]:
            st.caption("Partial: a lookup stopped at its limit, so older records may be missing.")
        navigation.link("sources", label="Every lookup's status")


def _render_since_last_run(view, new_alerts, targets):
    watch = find_watch(targets)
    st.subheader("What's new since the last analysis", help="Compared with the previous saved analysis of this "
                                                            "exact target list. Watch the list to rerun it from Run "
                                                            "History and see only what changed.")
    c_watch, c_note = st.columns([1.2, 4], vertical_alignment="center")
    if watch:
        c_note.caption(f"Watched as **{md_escape(watch['name'])}** (Runs & Diffs → Watched lists).")
        if c_watch.button("Stop watching", key="summary_unwatch", icon=":material/visibility_off:"):
            remove_watch(targets)
            st.rerun()
    elif c_watch.button("Watch this list", key="summary_watch", icon=":material/visibility:",
                        help="Saves the target list so you can rerun it from Runs & Diffs; each rerun shows what is "
                             "new here."):
        save_watch(", ".join(targets[:3]) + (f" +{len(targets) - 3}" if len(targets) > 3 else ""), targets)
        st.toast("Watching this target list.")
        st.rerun()
    if not view.previous_snapshot:
        st.caption("No earlier run of this target list yet: the next run shows what changed.")
        return
    diff = view.artifact_diff
    added = diff[diff["Change"] == "Added"] if diff is not None and not diff.empty else pd.DataFrame(
        columns=["Domain", "Artifact", "Value", "Change"])
    columns = st.columns(2 + len(DIFF_KINDS))
    columns[0].metric("New alerts", new_alerts)
    columns[1].metric("Resolved", len(view.resolved))
    for column, kind in zip(columns[2:], DIFF_KINDS):
        column.metric(f"New {kind.lower()}s" if kind != "MX" else "New MX", int((added["Artifact"] == kind).sum()))
    if not added.empty:
        with st.expander(f"{len(added):,} new value(s)"):
            st.dataframe(added[["Domain", "Artifact", "Value"]], hide_index=True, width="stretch")
    if new_alerts:
        new = view.active[view.new_mask.reindex(view.active.index, fill_value=False)]
        st.dataframe(new[["Domain", "Threat Type", "Severity", "Confidence"]], hide_index=True, width="stretch")
    navigation.link("history", label="Compare runs")


def render_summary(ctx, window_banner):
    ds, view, profiles = ctx.ds, ctx.view, ctx.profiles
    alerts = view.active
    verdicts = domain_verdicts(load_triage(), ds.selected_domains)
    st.header("Summary", help="The analysis in numbers and where the hunt goes next: every domain, the analysis "
                              "details, top alerts, triage status, what to check next, leads, linked domains and "
                              "what changed since the last analysis.")
    if ip_check_only(ds):   # IP check use case: VPNDB verdicts only
        render_ip_check(ds, alerts)
        render_use_case_plan()
        return
    window_banner()
    _render_hunt_trail()
    render_kpi_banner(profiles, ctx.thresholds["high_risk_score"])
    _render_domains(profiles, alerts, verdicts, ds.anonymizers)
    if ds.prefixes is not None and not ds.prefixes.empty:   # CIDR targets (VPNDB)
        render_networks(ds)
    _render_glance(ds, alerts)
    _render_top_alerts(alerts)
    if not alerts.empty:
        _render_triage_status(alerts, verdicts)
    render_use_case_plan()
    render_last_collection()

    new_alerts = int(view.new_mask.sum()) if view.new_mask is not None else 0
    leads, start, children = plan(ds, alerts)
    _render_next_steps(ctx, alerts, new_alerts, start)
    render_suggested_hunt(ds, alerts, leads, start, children)
    _render_leads(ds)
    _render_clusters(ctx.threats.correlation)
    _render_statistics(ds, alerts)
    _render_since_last_run(view, new_alerts, list(ctx.collected.targets))

