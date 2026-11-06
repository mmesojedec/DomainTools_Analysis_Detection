"""Lens: Campaign & Hosting Intel - domain timelines, infrastructure graph, clusters, hosting footprint, origin exposure, hopping."""
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from config import DT_ORANGE
from core.correlation import ip_domain_timeline
from core.helpers import md_escape
from core.intel_data import ISO2_TO_ISO3
from core.network_intel import cdn_for_ip, cdn_fronting, find_origin_candidates, watchlisted_hosting
from core.timeline import LANE_ORDER, build_domain_timeline
from integrations.enrichment import extract_iris_profile
from views.common import chart, table
from visualizations.network_graph import NODE_STYLE, build_graph_elements, graph_figure


def _render_domain_timeline(ds, alerts):
    st.subheader("Domain Story Timeline",
                 help="Registration, DNS changes, Domain History, and certificate events for one domain on a single swimlane chart. "
                      "The dashed orange line marks the registration date; use Previous / Next to step through events in order.")
    domains = list(ds.selected_domains)
    if not domains:
        return
    domain = st.selectbox("Domain", domains, key="timeline_domain")
    timeline = build_domain_timeline(ds, domain)
    if timeline.empty:
        st.info(f"No timestamped events available for {domain}.")
        return
    _timeline_navigator(timeline, domain, ds.timezone)

    dom_alerts = alerts[alerts["Domain"] == domain] if not alerts.empty else alerts
    if not dom_alerts.empty:
        st.caption(f"{len(dom_alerts)} active detection(s) for {domain}: " + ", ".join(sorted(set(dom_alerts["Threat Type"]))))


@st.fragment
def _timeline_navigator(timeline, domain, timezone):
    """Event stepper + chart in a fragment, so Previous / Next only rerun this section."""
    n_events = len(timeline)
    pos_key = f"timeline_pos_{domain}"
    if st.session_state.get(pos_key, 0) >= n_events:
        st.session_state[pos_key] = 0
    position = st.session_state.get(pos_key, 0)

    def step(delta):
        st.session_state[pos_key] = min(max(st.session_state.get(pos_key, 0) + delta, 0), n_events - 1)

    col_prev, col_next, col_slider = st.columns([1, 1, 6])
    col_prev.button("◀ Previous", key=f"tl_prev_{domain}", on_click=step, args=(-1,), disabled=position <= 0, width="stretch")
    col_next.button("Next ▶", key=f"tl_next_{domain}", on_click=step, args=(1,), disabled=position >= n_events - 1, width="stretch")
    with col_slider:
        position = st.select_slider(
            "Event", options=list(range(n_events)), key=pos_key, label_visibility="collapsed",
            format_func=lambda i: f"{i + 1}/{n_events} · {timeline.loc[i, 'Time']:%Y-%m-%d %H:%M} · {timeline.loc[i, 'Event'][:50]}",
        )
    current = timeline.loc[position]

    lanes = [lane for lane in LANE_ORDER if lane in set(timeline["Lane"])]
    fig = px.scatter(timeline, x="Time", y="Lane", color="Lane", symbol="Lane", hover_name="Event",
                     hover_data={"Detail": True, "Lane": False, "Time": "|%Y-%m-%d %H:%M"},
                     category_orders={"Lane": lanes}, title=f"Timeline for {domain} ({timezone})")
    fig.update_traces(marker=dict(size=11, opacity=0.55, line=dict(width=1, color="white")))
    fig.add_scatter(x=[current["Time"]], y=[current["Lane"]], mode="markers", hoverinfo="skip", showlegend=False,
                    marker=dict(size=22, color="rgba(0,0,0,0)", line=dict(width=3, color="#FFFFFF")))
    fig.add_vline(x=current["Time"], line_width=1, line_color="rgba(255,255,255,0.5)")

    created = timeline[(timeline["Lane"] == "Registration") & (timeline["Event"] == "Registered")]
    if not created.empty:
        reg_time = created["Time"].iloc[0]
        fig.add_vline(x=reg_time, line_dash="dash", line_color=DT_ORANGE)
        fig.add_annotation(x=reg_time, y=1.0, yref="paper", text=f"Registered {reg_time:%Y-%m-%d}", showarrow=False,
                           font=dict(color=DT_ORANGE, size=11), xanchor="left", yanchor="bottom")
    fig.update_layout(showlegend=False, yaxis_title="", xaxis_title="", margin=dict(t=70))
    chart(fig, key=f"domain_timeline_{domain}", height=max(340, len(lanes) * 48 + 160))

    st.markdown(f"**Event {position + 1} of {n_events}** — {current['Lane']} · {current['Time']:%Y-%m-%d %H:%M} ({timezone})  \n"
                f"{md_escape(current['Event'])}" + (f"  \n{md_escape(current['Detail'])}" if current["Detail"] else ""))


def _render_graph(correlation):
    st.subheader("Infrastructure Graph",
                 help="Domains linked to the IPs, name servers, certificates, public keys, and trackers they share. CDN IPs and "
                      "large managed DNS providers are excluded. Click or lasso nodes to list their connections.")
    artifacts = correlation.artifacts
    if artifacts.empty:
        st.info("No infrastructure artifacts available to build a graph.")
        return
    col1, col2 = st.columns([1, 3])
    shared_only = col1.toggle("Shared artifacts only", value=True, key="graph_shared_only",
                              help="Hide artifacts used by a single domain to focus on overlaps.")
    available = [t for t in NODE_STYLE if t != "Domain" and t in set(artifacts["Type"])]
    types = col2.multiselect("Artifact types", available, default=available, key="graph_types")
    nodes, edges = build_graph_elements(artifacts, shared_only=shared_only, artifact_types=types, domain_cluster=correlation.domain_cluster)
    if nodes.empty:
        st.info("No shared infrastructure between the selected domains. Turn off 'Shared artifacts only' to see each domain's footprint.")
        return
    points = chart(graph_figure(nodes, edges, title=f"Infrastructure Graph ({len(nodes)} nodes, {len(edges)} links)"),
                   key="infra_graph", selectable=True)
    selected_ids = {p.get("customdata") if isinstance(p, dict) else getattr(p, "customdata", None) for p in points}
    selected_ids = {s if isinstance(s, str) else (s[0] if s else None) for s in selected_ids} - {None}
    if selected_ids:
        linked = edges[edges["source"].isin(selected_ids) | edges["target"].isin(selected_ids)].copy()
        linked["Domain"] = linked["source"].str.split("|", n=1).str[1]
        linked["Artifact"] = linked["target"].str.split("|", n=1).str[1]
        st.markdown(f"##### Connections of {len(selected_ids)} selected node(s)")
        table(linked[["Domain", "type", "Artifact"]].rename(columns={"type": "Artifact Type"}))


def _render_clusters(correlation):
    st.subheader("Infrastructure Clusters",
                 help="Domains linked by a strong artifact (certificate, public key, tracker) or two weak ones (IP + name server).")
    if not correlation.clusters:
        st.success("No multi-domain infrastructure clusters detected among the selected domains.")
    else:
        rows = [{
            "Cluster": c["Cluster"], "Strength": c["Strength"], "Size": c["Size"], "Domains": ", ".join(c["Domains"]),
            "Shared Artifacts": "; ".join(f"{kind} ({len(values)}): {', '.join(values[:3])}{' ...' if len(values) > 3 else ''}"
                                          for kind, values in c["Shared Artifacts"].items()),
        } for c in correlation.clusters]
        table(pd.DataFrame(rows))
    if not correlation.pairs.empty:
        with st.expander(f"Domain pair overlaps ({len(correlation.pairs)})", expanded=False):
            table(correlation.pairs.sort_values(["Linked", "Shared Artifacts"], ascending=False))


def _hosting_rows(ds):
    rows = []
    for domain, obj in ds.enrichment.items():
        for entry in extract_iris_profile(obj)["ips"]:
            rows.append({
                "Domain": domain, "IP": entry["ip"], "ASN": f"AS{entry['asn']}" if entry["asn"] else "Unknown ASN",
                "ISP": entry["isp"] or "Unknown", "Country": entry["country"] or "??",
                "CDN": cdn_for_ip(entry["ip"], ds.ip_intel) or "", "Watchlist": watchlisted_hosting(entry["isp"]) or "",
            })
    return pd.DataFrame(rows)


def _render_hosting(ds):
    st.subheader("Hosting Footprint",
                 help="Current hosting from Iris Investigate: countries, ASNs, ISPs, CDN fronting, and high-abuse hosting watchlist hits.")
    hosting = _hosting_rows(ds)
    if hosting.empty:
        st.info("No Iris Investigate IP data available (requires ~/.dtapi credentials).")
        return
    col1, col2 = st.columns([1.2, 1])
    with col1:
        geo = hosting.groupby("Country").agg(IPs=("IP", "nunique"), Domains=("Domain", "nunique")).reset_index()
        geo["ISO3"] = geo["Country"].map(ISO2_TO_ISO3)
        geo = geo.dropna(subset=["ISO3"])
        if geo.empty:
            st.info("No country information available for hosting IPs.")
        else:
            fig = px.choropleth(geo, locations="ISO3", color="IPs", hover_name="Country", hover_data={"Domains": True, "ISO3": False},
                                color_continuous_scale="Reds", title="Hosting IPs by Country")
            fig.update_geos(showframe=False, showcoastlines=True, projection_type="natural earth", bgcolor="rgba(0,0,0,0)")
            fig.update_layout(margin=dict(t=40, l=0, r=0, b=0))
            chart(fig, key="hosting_map", height=380)
    with col2:
        labels, index = [], {}

        def node(name):
            if name not in index:
                index[name] = len(labels)
                labels.append(name)
            return index[name]

        links = {}
        for _, row in hosting.iterrows():
            asn_label = f"{row['ASN']} · {row['ISP'][:28]}"
            for a, b in ((row["Domain"], asn_label), (asn_label, f"IP: {row['IP']}")):
                key = (node(a), node(b))
                links[key] = links.get(key, 0) + 1
        fig = go.Figure(go.Sankey(node=dict(label=labels, pad=12, thickness=16),
                                  link=dict(source=[k[0] for k in links], target=[k[1] for k in links], value=list(links.values()),
                                            color="rgba(116, 133, 144, 0.35)")))
        fig.update_layout(title_text="Domain ➔ ASN / ISP ➔ IP", font_size=11, margin=dict(t=40, l=5, r=5, b=5))
        chart(fig, key="asn_sankey", height=max(380, hosting["IP"].nunique() * 18 + 100))
    flagged = hosting[(hosting["Watchlist"] != "") | (hosting["CDN"] != "")]
    if not hosting[hosting["Watchlist"] != ""].empty:
        st.warning(f"**Hosting Watchlist:** {hosting.loc[hosting['Watchlist'] != '', 'IP'].nunique()} IP(s) on high-abuse / offshore providers.")
    summary = hosting.groupby(["IP", "ASN", "ISP", "Country", "CDN", "Watchlist"])["Domain"].apply(lambda x: ", ".join(sorted(set(x)))).reset_index()
    table(summary.rename(columns={"Domain": "Domains"}))
    if flagged.empty:
        st.caption("No CDN-fronted or watchlisted hosting detected.")


def _render_origin_exposure(ds):
    st.subheader("CDN Origin Exposure",
                 help="For CDN-fronted domains, public non-CDN IPs seen in DNS history or certificate hostname events - possible origin servers.")
    rows = []
    for domain in ds.selected_domains:
        events = ds.events_utc[ds.events_utc["Domain"] == domain] if not ds.events_utc.empty else pd.DataFrame()
        profile = extract_iris_profile(ds.enrichment.get(domain))
        cdn = cdn_fronting(domain, events, profile, ds.ip_intel)
        if not cdn:
            continue
        cert_events = ds.cert_hostnames[ds.cert_hostnames["Domain"] == domain] if not ds.cert_hostnames.empty else pd.DataFrame()
        candidates = find_origin_candidates(domain, events, cert_events, ds.ip_intel)
        for _, row in candidates.iterrows():
            rows.append({"Domain": domain, "Fronted By": cdn, **row.to_dict()})
        if candidates.empty:
            rows.append({"Domain": domain, "Fronted By": cdn, "IP": "", "Hostnames": "No non-CDN IPs observed", "Sources": ""})
    if not rows:
        st.info("None of the selected domains appear to be fronted by a CDN.")
        return
    table(pd.DataFrame(rows))


def _render_domain_hopping(ds, hops):
    st.subheader("Domain Hopping on Shared IPs",
                 help="Which registrable domains used each IP over time. New domains appearing right after earlier ones go dark suggest takedown evasion.")
    observations = ds.ip_observations
    if observations.empty:
        st.info("No IP observation data. Analyze IP targets, or enable *Settings → Collection options → Pivot on hosting IPs* "
                "(DNSDB Scout) to fetch reverse-IP history for the selected domains.")
        return
    ips = sorted(observations["IP"].unique(), key=lambda ip: (-(hops["IP"] == ip).sum() if not hops.empty else 0, ip))
    ip = st.selectbox("IP address", ips, key="hop_ip",
                      format_func=lambda v: f"{v} ({int((hops['IP'] == v).sum())} hop(s))" if not hops.empty else v)
    timeline = ip_domain_timeline(observations, ip)
    if timeline.empty:
        st.info("No hostnames observed for this IP.")
    else:
        shown = timeline.tail(60)
        fig = px.timeline(shown, x_start="First Seen", x_end="Last Seen", y="Registrable Domain", color="Registrable Domain",
                          hover_data={"Hostnames": True}, title=f"Domains observed on {ip} (latest {len(shown)})")
        fig.update_yaxes(autorange="reversed", title="")
        fig.update_layout(showlegend=False)
        chart(fig, key="hop_timeline", height=max(300, len(shown) * 22 + 120))
    if not hops.empty:
        table(hops[hops["IP"] == ip] if ip in set(hops["IP"]) else hops)


def render_campaign_lens(ds, threats, alerts):
    _render_domain_timeline(ds, alerts)
    _render_graph(threats.correlation)
    _render_clusters(threats.correlation)
    _render_hosting(ds)
    _render_origin_exposure(ds)
    _render_domain_hopping(ds, threats.hops)
    st.divider()
