"""Lens 2: Infrastructure & DNS tracking visuals."""
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from config import DT_GREEN, DT_ORANGE, DT_SLATE
from core.helpers import extract_ip_addresses, ip_network_bucket, md_escape
from integrations.domain_history import calculate_lifespans_for_dh
from integrations.enrichment import extract_web_trackers
from views.common import chart, table

DAYS_ORDER = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
IP_FIELDS = {f"{prefix}: {name}" for prefix in ("DH", "pDNS") for name in ("A", "AAAA", "IP", "A RECORD", "NAME_SERVER", "NS")}
NEXUS_FIELDS = {f"{prefix}: {name}" for prefix in ("DH", "pDNS")
                for name in ("A", "AAAA", "IP", "A RECORD", "NS", "NAME_SERVER", "MX", "TXT", "SPF")}


def _render_event_scatter(combined):
    st.subheader("Cross-Domain Event View (Scatter Plot)",
                 help="Chronological overview of infrastructure changes and pDNS resolutions. Vertically aligned points across domains suggest scripted changes.")
    hover = {"Field": True, "Domain": False, "Date": False, "Value": True, "Data Source": True}
    for col, fmt in (("RRName", True), ("First Seen", "|%Y-%m-%d %H:%M"), ("Last Seen", "|%Y-%m-%d %H:%M"), ("Count", True)):
        if col in combined.columns:
            hover[col] = fmt
    fig = px.scatter(combined, x="Date", y="Field", color="Domain", symbol="Data Source",
                     hover_name="RRName" if "RRName" in combined.columns else "Domain", hover_data=hover,
                     title="Change Event Distribution")
    fig.update_traces(marker=dict(size=10, opacity=0.8, line=dict(width=1, color="white")))
    chart(fig, height=450)

    st.subheader("Record Type Density (Temporal Heatmap)",
                 help="Concentration of changes across record types over time, revealing operational phases.")
    fig = px.density_heatmap(combined, x="Date", y="Field", z="Count" if "Count" in combined.columns else None,
                             histfunc="sum", title="Density of Domain Alterations & Queries over Time", color_continuous_scale="Reds")
    chart(fig, height=400)


def _render_gantt(ds):
    st.subheader("Domain Lifespans (Gantt Chart)",
                 help="Active lifespans of DNS records and servers: rapidly rotated records vs long-standing infrastructure.")
    frames = []
    if not ds.pdns_norm.empty:
        frames.append(ds.pdns_norm[["Domain", "Field", "Domain_Field", "Value", "Start", "End", "Lifespan Days"]])
    if not ds.dh_norm.empty:
        frames.append(calculate_lifespans_for_dh(ds.dh_norm))
    frames = [f for f in frames if not f.empty]
    if not frames:
        return
    gantt = pd.concat(frames, ignore_index=True)
    hover = {"Domain": True, "Field": True, "Start": "|%Y-%m-%d %H:%M", "End": "|%Y-%m-%d %H:%M", "Lifespan Days": True, "Domain_Field": False}
    fig = px.timeline(gantt, x_start="Start", x_end="End", y="Domain_Field", color="Domain", hover_name="Value",
                      hover_data=hover, title="Infrastructure Utilization Lifespan")
    fig.update_yaxes(autorange="reversed", title="Domain | Field")
    chart(fig, height=max(400, gantt["Domain_Field"].nunique() * 25))


def _render_velocity(combined, pdns_norm):
    st.subheader("Event Delta Analysis (Time Between Changes)",
                 help="Elapsed time between consecutive events per domain. Large values indicate dormancy; values near zero expose rapid automated updates.")
    velocity = combined.dropna(subset=["Date"]).sort_values("Date").copy()
    velocity["Filtered Time Gap (Days)"] = (velocity.groupby("Domain")["Date"].diff().dt.total_seconds() / 86400.0).fillna(0).round(2)
    grouped = velocity.groupby(["Domain", "Date"]).agg({
        "Field": lambda x: ", ".join(x.unique()), "Filtered Time Gap (Days)": "max", "Data Source": "first",
    }).reset_index()
    fig = px.scatter(grouped, x="Date", y="Filtered Time Gap (Days)", color="Domain", symbol="Data Source", hover_name="Field",
                     hover_data={"Domain": True, "Field": True, "Filtered Time Gap (Days)": True, "Date": "|%Y-%m-%d %H:%M", "Data Source": True},
                     title="Time Gap Between Filtered Events")
    fig.update_traces(marker=dict(size=10, opacity=0.8, line=dict(width=1, color="white")))
    fig.update_layout(xaxis_title="Event Timestamp", yaxis_title="Days Since Previous Event")
    chart(fig, height=380)

    if not pdns_norm.empty and "Count" in pdns_norm.columns:
        st.subheader("Query Volume Burst Topography (Area Chart)",
                     help="Passive DNS resolution volume over time: campaign launches, botnet activity, or scanner probes.")
        area = pdns_norm.dropna(subset=["Date"]).assign(Date_Day=lambda d: d["Date"].dt.date)
        area = area.groupby(["Date_Day", "Domain"])["Count"].sum().reset_index()
        fig = px.area(area, x="Date_Day", y="Count", color="Domain", title="Passive DNS Query Volume Over Time")
        fig.update_layout(xaxis_title="Date", yaxis_title="Total Queries")
        chart(fig, height=380)


def _render_tempo(combined, timezone):
    st.subheader("Operational Tempo (Day-of-Week & Hourly Profiling)",
                 help="Activity histograms in the selected timezone: operator schedules, cron jobs, and off-hour deployments.")
    col1, col2 = st.columns(2)
    with col1:
        dow = combined.groupby(["Day Index", "Day of Week", "Domain"]).size().reset_index(name="Event Count")
        fig = px.bar(dow.sort_values("Day Index"), x="Day of Week", y="Event Count", color="Domain",
                     title="Activity by Day of the Week", category_orders={"Day of Week": DAYS_ORDER})
        fig.update_layout(barmode="stack")
        chart(fig, height=380)
    with col2:
        hours = combined.groupby(["Hour of Day", "Domain"]).size().reset_index(name="Event Count")
        fig = px.bar(hours, x="Hour of Day", y="Event Count", color="Domain", title=f"Activity by Hour of the Day ({timezone})")
        fig.update_layout(barmode="stack")
        fig.update_xaxes(tickmode="linear", tick0=0, dtick=2)
        chart(fig, height=380)


def _subdomain_tree(target_dom, rrnames):
    nodes = {target_dom: {"label": target_dom, "parent": ""}}
    for rrname in rrnames:
        rrname = str(rrname).strip(".").lower()
        if not rrname.endswith("." + target_dom):
            continue
        curr_id = target_dom
        for part in reversed([p for p in rrname[:-(len(target_dom) + 1)].split(".") if p]):
            parent_id, curr_id = curr_id, f"{part}.{curr_id}"
            nodes.setdefault(curr_id, {"label": part, "parent": parent_id})
    return nodes


def _render_subdomains(ds):
    st.subheader("Subdomain Hierarchy Map (Sunburst)",
                 help="Radial breakdown of nested subdomains from passive DNS and certificate hostnames.")
    frames = []
    if not ds.pdns_norm.empty and "RRName" in ds.pdns_norm.columns:
        frames.append(ds.pdns_norm[["Domain", "RRName"]])
    if not ds.cert_hostnames.empty and "RRName" in ds.cert_hostnames.columns:
        frames.append(ds.cert_hostnames[["Domain", "RRName"]])
    if not frames:
        st.info("No subdomains found in Passive DNS or Certificate logs.")
        return
    sub_df = pd.concat(frames, ignore_index=True).drop_duplicates()
    sub_df = sub_df[sub_df["RRName"].astype(str) != sub_df["Domain"].astype(str)]
    domains_with_subs = list(sub_df["Domain"].unique())
    if not domains_with_subs:
        st.info("No subdomains found in dataset.")
        return
    for tab, target_dom in zip(st.tabs([f"Subdomains: {d}" for d in domains_with_subs]), domains_with_subs):
        with tab:
            nodes = _subdomain_tree(target_dom, sub_df.loc[sub_df["Domain"] == target_dom, "RRName"].unique())
            if len(nodes) <= 1:
                st.info(f"No nested subdomains to display for {target_dom}.")
                continue
            fig = go.Figure(go.Sunburst(ids=list(nodes), labels=[n["label"] for n in nodes.values()],
                                        parents=[n["parent"] for n in nodes.values()]))
            fig.update_layout(margin=dict(t=20, l=0, r=0, b=0), title=f"Subdomain Architecture ({target_dom})")
            chart(fig, key=f"sb_tab_{target_dom}", height=500)


def _render_ip_clusters(combined):
    st.subheader("Infrastructure Clustering & IP Migration",
                 help="Groups resolved IPs into /24 (IPv4) or /48 (IPv6) clusters and plots migration timelines.")
    df_ips = combined[combined["Field"].isin(IP_FIELDS)].copy()
    if df_ips.empty:
        st.info("No IP-related records found.")
        return
    df_ips["Extracted_IP"] = df_ips["Value"].astype(str).map(extract_ip_addresses)
    df_ips = df_ips.explode("Extracted_IP").dropna(subset=["Extracted_IP"])
    if df_ips.empty:
        st.info("No IP addresses could be parsed.")
        return
    df_ips["Network"] = df_ips["Extracted_IP"].map(ip_network_bucket)
    clusters = df_ips.groupby(["Domain", "Network", "Extracted_IP"]).size().reset_index(name="Observation Count")
    fig = px.treemap(clusters, path=[px.Constant("Infrastructure"), "Domain", "Network", "Extracted_IP"],
                     values="Observation Count", title="Hierarchical Infrastructure Map (Domain ➔ Network ➔ IP)", color="Network")
    fig.update_traces(root_color="lightgrey")
    fig.update_layout(margin=dict(t=50, l=25, r=25, b=25))
    chart(fig, height=450)

    chron = df_ips.dropna(subset=["Date"]).sort_values(["Date", "Extracted_IP"])
    if chron.empty:
        st.info("IP addresses found, but lack valid timestamps.")
        return
    chron = chron.assign(Hover_Record=chron["Value"].astype(str).str.replace("\n", " | "))
    fig = px.line(chron, x="Date", y="Extracted_IP", color="Domain", markers=True, hover_name="Extracted_IP",
                  hover_data={"Network": True, "Hover_Record": True, "Data Source": True, "Date": "|%Y-%m-%d %H:%M"},
                  title="Chronological IP Migration Path")
    fig.update_yaxes(type="category", title="Assigned IP Address")
    chart(fig, height=400)


def _render_nexus(combined):
    st.subheader("The 'Nexus' Matrix (Shared Infrastructure Overlap)",
                 help="Shared IPs, name servers, MX servers, or TXT values across two or more analyzed domains.")
    if combined["Domain"].nunique() < 2:
        st.info("The Nexus Matrix requires at least 2 domains to detect overlap.")
        return
    nexus = combined.loc[combined["Field"].isin(NEXUS_FIELDS), ["Domain", "Field", "Value", "Date", "Data Source"]].dropna(subset=["Value"])
    nexus = nexus.assign(Extracted_Val=nexus["Value"].astype(str).str.split("\n")).explode("Extracted_Val")
    nexus["Extracted_Val"] = nexus["Extracted_Val"].str.strip()
    nexus = nexus[nexus["Extracted_Val"] != ""]
    shared_counts = nexus.groupby("Extracted_Val")["Domain"].nunique()
    shared_vals = shared_counts[shared_counts > 1].index
    if shared_vals.empty:
        st.success("Clean: No shared infrastructure found among selected domains.")
        return
    overlap = nexus[nexus["Extracted_Val"].isin(shared_vals)]
    grouped = overlap.groupby(["Domain", "Field", "Extracted_Val", "Data Source"]).size().reset_index(name="Observations")
    grouped["Display_Val"] = grouped["Extracted_Val"].where(grouped["Extracted_Val"].str.len() <= 40, grouped["Extracted_Val"].str[:40] + "...")
    fig = px.scatter(grouped, y="Domain", x="Display_Val", color="Field", symbol="Data Source", size="Observations",
                     hover_name="Extracted_Val",
                     hover_data={"Observations": True, "Domain": False, "Field": True, "Data Source": True, "Display_Val": False},
                     title="Shared Infrastructure Artifacts (Attribution Map)")
    fig.update_traces(marker=dict(line=dict(width=1, color="white"), opacity=0.9))
    fig.update_xaxes(tickangle=-45, title="Shared Artifact (IP, NS, MX, TXT)")
    chart(fig, height=max(380, grouped["Domain"].nunique() * 50 + 150))

    st.markdown("#### Confirmed Overlap Summary", help="Exact infrastructure artifacts shared between analyzed domains.")
    summary = overlap.groupby(["Field", "Extracted_Val"])["Domain"].apply(lambda x: ", ".join(sorted(set(x)))).reset_index()
    table(summary.rename(columns={"Extracted_Val": "Shared Artifact", "Domain": "Linked Domains"}))


def _render_trackers(enrichment):
    if not enrichment:
        return
    st.subheader("Web Analytics & Tracker Matrix",
                 help="Client-side analytics and marketing codes (GA4, GTM, Yandex Metrica, Facebook Pixel, etc.) for attribution.")
    rows = [{"Domain": dom, **t} for dom, obj in enrichment.items() for t in extract_web_trackers(obj)]
    trackers = pd.DataFrame(rows)
    if trackers.empty:
        st.info("No web tracking identifiers found in Iris Investigate data.")
        return
    col1, col2 = st.columns([1.5, 1])
    with col1:
        fig = px.strip(trackers, x="Code", y="Domain", color="Platform", title="Observed Tracking Identifiers")
        fig.update_traces(marker=dict(size=12, opacity=0.9))
        chart(fig, height=380)
    with col2:
        st.markdown("#### Tracker Overlap Detection", help="Tracking codes shared across domains suggest common management or cloned templates.")
        shared = trackers.groupby(["Platform", "Code"])["Domain"].apply(lambda x: sorted(set(x))).reset_index()
        shared = shared[shared["Domain"].map(len) > 1]
        if shared.empty:
            st.success("Clean: No shared web tracker IDs detected.")
        else:
            st.error(f"**Attribution Alert:** Found {len(shared)} shared web tracking ID(s).")
            for _, row in shared.iterrows():
                st.markdown(f"* **{md_escape(row['Platform'])}** (`{row['Code']}`): Shared by {md_escape(', '.join(row['Domain']))}")
    st.markdown("#### Detailed Extracted Tracker Inventory", help="All unique website tracking codes extracted for investigated domains.")
    table(trackers)


def _render_txt_fingerprints(app_df, pdns_norm):
    st.subheader("Infrastructure Fingerprinting",
                 help="TXT records mapped to SaaS integrations, plus Base64/Base32 strings typical of DNS tunneling and C2.")
    supplemental = 0
    if not pdns_norm.empty and "Collection" in pdns_norm.columns:
        supplemental = int(pdns_norm["Collection"].isin(["TXT lookup", "TXT supplement"]).sum())
    if app_df.empty:
        st.info("No TXT records found in Passive DNS or Domain History. Enable *Settings → Collection options → TXT "
                "lookup* to query TXT records separately from the main pDNS result limit.")
        return
    if supplemental:
        st.caption(f"Includes {supplemental} TXT record(s) from the TXT lookup (latest records per domain).")
    suspicious = app_df[app_df["Category"] == "Potential Tunneling / C2"]
    if not suspicious.empty:
        st.error(f"**Action Required:** {len(suspicious)} suspicious encoded TXT payloads detected.")
    col1, col2 = st.columns([1, 1.5])
    with col1:
        cat_counts = app_df["Category"].value_counts().reset_index()
        cat_counts.columns = ["Category", "Count"]
        fig = px.pie(cat_counts, names="Category", values="Count", title="TXT Record Categories", hole=0.4, color="Category",
                     color_discrete_map={"Known SaaS / Infrastructure": DT_GREEN, "Uncategorized": DT_SLATE, "Potential Tunneling / C2": DT_ORANGE})
        chart(fig, height=350)
    with col2:
        app_counts = app_df["Application / Tag"].value_counts().reset_index()
        app_counts.columns = ["Application", "Count"]
        fig = px.bar(app_counts, x="Count", y="Application", orientation="h", title="Identified Infrastructure Fingerprints", color="Application")
        fig.update_layout(showlegend=False)
        fig.update_yaxes(categoryorder="total ascending")
        chart(fig, height=350)


def render_infra_lens(ds):
    if ds.combined.empty:
        st.info("No Domain History or Passive DNS events available for the selected filters.")
        st.divider()
        return
    _render_event_scatter(ds.combined)
    _render_gantt(ds)
    _render_velocity(ds.combined, ds.pdns_norm)
    _render_tempo(ds.combined, ds.timezone)
    _render_subdomains(ds)
    _render_ip_clusters(ds.combined)
    _render_nexus(ds.combined)
    _render_trackers(ds.enrichment)
    _render_txt_fingerprints(ds.txt_apps, ds.pdns_norm)
    st.divider()
