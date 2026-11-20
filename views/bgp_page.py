"""
BGP page (BGPDB): who announces the run's hosting IPs, since when, whether the registries allow it, through which
networks, and what else is announced next to them. Tabs: Overview (findings and the IP table), Routing map (domain →
prefix → origin → upstream, and the AS paths of a prefix), Origin timeline (who announced each prefix when), Networks
(the origin and upstream ASes), Neighbouring prefixes (leads), VPNDB match and Responses (as received, as curl).
"""
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from core import bgp
from integrations.bgpdb import curl_command
from views import navigation
from views.alert_tools import THREAT_TYPE_KEY
from views.common import chart, selected_rows, selection_key

PAGE_TAB_KEY = "bgp_tab"
TAGLINE = "Who announces the hosting IPs on the internet, since when, and whether the registries allow it."
TABS = ["Overview", "Routing map", "Origin timeline", "Networks", "Neighbouring prefixes", "VPNDB match", "Responses"]
RULES = [*bgp.FINDINGS, bgp.EXIT_ON_UNSTABLE, bgp.TOR_ORIGIN, bgp.MOVED]
SEVERITY_BADGES = {"Critical": "red", "High": "red", "Medium-High": "orange", "Medium": "violet", "Low": "blue"}
STATUS_BADGES = {bgp.VALID: "green", bgp.UNAUTHORIZED: "red", bgp.UNVERIFIED: "gray", bgp.LOCAL_LEAK: "orange"}
# worst first: a link or prefix node takes the colour of the worst origin behind it
STATUS_RANK = (bgp.UNAUTHORIZED, bgp.LOCAL_LEAK, bgp.UNVERIFIED, bgp.VALID)


def _worse(a, b):
    return min(a, b, key=lambda s: STATUS_RANK.index(s) if s in STATUS_RANK else len(STATUS_RANK))
HOW_TO_READ = {
    "Overview": (
        "Every public hosting IP of the run (no CDN addresses) was looked up in BGPDB, the routing table history of "
        "about the last 30 days.",
        "**Prefix** = the block of addresses the IP is announced in; **origin** = the network (AS) that announces it.",
        "**Valid** = RPKI (or IRR) authorizes that origin; **Unauthorized** = a registry names another origin; "
        "**Not in RPKI / IRR** = nobody registered it (common, not a finding on its own).",
        "Findings: an origin conflict (two networks claim the block, one without authorization), an unauthorized "
        "origin, a newly announced prefix, a young network, a barely visible route. Each one is also an alert.",
        "Select an IP to see every origin, path and network BGPDB knows for it.",
    ),
    "Routing map": (
        "Left to right: your domain → the prefix of its IP → the network that announces it → the upstream network "
        "that carries it (from the most-seen AS path). A flow takes the colour of its usual origin: **green** = "
        "authorized, **red** = without authorization, **grey** = not in RPKI / IRR.",
        "A **prefix box** takes the colour of the worst origin ever seen for it, so a thin red link to another network "
        "behind a green flow still shows. **Orange** = a private AS number (64512–65534, 65535, …) seen by one route "
        "collector: that collector's peer leaking its internal AS, not a hijack and not a finding.",
        "Below: every AS path seen towards one prefix. The thicker the arrow, the more route collectors saw it; the "
        "origin is the last network on the right.",
    ),
    "Origin timeline": (
        "One row per prefix and network that announced it, from the first to the last time BGPDB saw it (a "
        "single announcement is drawn 8 hours wide so it shows; hover for the exact times).",
        "**Green** = authorized origin, **red** = unauthorized, **orange** = a private AS at one collector. A short "
        "red bar on top of a long green one is what a "
        "hijack or route leak looks like.",
        "Bars starting on the first day of the data only mean *at least that old*.",
    ),
    "Networks": (
        "The origin networks of the run's prefixes and the upstreams that carry them.",
        "**Registered** = when the RIR registered the AS: young networks (under a year) host a large share of "
        "malicious infrastructure. **Collectors** = how widely the network is seen; **Upstreams / Downstreams** = "
        "neighbour networks it buys transit from / sells it to.",
        "A network with one upstream and no downstreams is a stub: normal for small companies, and for bulletproof "
        "hosters behind a single provider.",
    ),
    "Neighbouring prefixes": (
        "The other prefixes announced in the range around each of the run's prefixes (the /20; IPv6 the /40), and "
        "by whom. Prefixes of /20 or larger (a carrier's aggregate) have no neighbourhood here.",
        "**Same origin** = announced by a network that also hosts your domains: the operator's other address space, a "
        "lead to check (VPNDB, passive DNS).",
    ),
    "VPNDB match": (
        "The run's VPN / proxy / Tor exits (VPNDB) with their routing (BGPDB).",
        "An exit on a newly announced or unauthorized prefix is unusual for a mainstream VPN: it raises *Anonymizer "
        "Exit on Unstable Routing*.",
        "Below, the origin networks that carry exits: a young or single-homed network full of exits is often the "
        "provider's own.",
    ),
    "Responses": (
        "Every BGPDB lookup of the run as received (NDJSON), with the URL. Select one to get it as a curl command.",
    ),
}


def _empty(frame):
    return frame is None or frame.empty


def render_bgp_page(ds):
    st.header("BGP", help="BGP routing of the run's hosting IPs from BGPDB (an internal DomainTools service): announced "
                          "prefixes and their origin networks, RPKI / IRR validity, RIR allocations, AS paths, the "
                          "networks involved and the prefixes around them. BGPDB keeps about the last 30 days.")
    st.caption(TAGLINE)
    if _empty(ds.bgp_origins):
        st.info("No BGP routing in this run. Enter the BGPDB host under Settings → API credentials (or set up the "
                "bgpdbq tool's ~/.bgpdbq.conf), keep *Look up BGP routing of the hosting IPs (BGPDB)* on (Settings → "
                "Collection options), then analyze again. BGPDB is reachable on the DomainTools network or VPN.",
                icon=":material/info:")
        if not _empty(ds.bgp_raw):
            _responses(ds)
        return
    found = bgp.findings(ds.bgp_origins, ds.bgp_asns, ds.bgp_routes)
    ips = bgp.ip_table(ds.bgp_origins, ds.bgp_routes, found, ds.enrichment)
    tabs = st.tabs(TABS, key=PAGE_TAB_KEY, on_change="rerun")
    navigation.scroll_to_tab()
    renders = (_overview, _routing_map, _timeline, _networks, _neighbours, _vpndb, _responses)
    for tab, name, render in zip(tabs, TABS, renders):
        if tab.open is not False:
            with tab:
                with st.expander("How to read this", icon=":material/help:"):
                    st.markdown("\n".join(f"- {point}" for point in HOW_TO_READ[name]))
                if name in ("Overview", "VPNDB match"):
                    render(ds, found, ips)
                else:
                    render(ds)


def brief(ds, found=None, limit=3):
    """
    The run's routing in a few plain sentences (Summary, DNS & Hosting): who announces the hosting, and the worst
    findings. [] without BGPDB data.
    """
    origins = ds.bgp_origins
    if _empty(origins):
        return []
    found = bgp.findings(origins, ds.bgp_asns, ds.bgp_routes) if found is None else found
    usual = bgp.main_origins(origins)
    networks = usual.groupby(["Origin", "AS Name"])["IP"].nunique().sort_values(ascending=False)
    top = ", ".join(f"{asn} {name}".strip() + f" ({count} IP{'s' if count != 1 else ''})"
                    for (asn, name), count in networks.head(3).items())
    lines = [f"The hosting IPs are announced in {origins['Prefix'].nunique()} prefix(es) by "
             f"{usual['Origin'].nunique()} network(s): {top}" + (" and others" if len(networks) > 3 else "") + "."]
    valid = int((usual["Status"] == bgp.VALID).sum())
    lines.append(f"{valid} of {len(usual)} usual announcement(s) are authorized by RPKI or IRR"
                 + ("; the rest are not registered (common, not a finding on its own)." if valid < len(usual) else "."))
    if _empty(found):
        lines.append("No routing finding: no origin conflict, unauthorized origin, new prefix or young network.")
    else:
        order = {name: i for i, name in enumerate(bgp.FINDINGS)}
        ranked = found.assign(_o=found["Finding"].map(order)).sort_values("_o")
        lines += [f"**{row['Finding']}** ({row['Domains']}): {row['Detail']}." for _, row in ranked.head(limit).iterrows()]
        if len(found) > limit:
            lines.append(f"{len(found) - limit} more finding(s) on the BGP page.")
    return lines


def render_bgp_line(ds):
    """DNS & Hosting: one line on the BGP routing, with a link to the BGP page."""
    if _empty(ds.bgp_origins):
        return
    found = bgp.findings(ds.bgp_origins, ds.bgp_asns, ds.bgp_routes)
    stats = bgp.summary(ds.bgp_origins, ds.bgp_asns, ds.bgp_routes, found)
    c_text, c_link = st.columns([4, 1.3], vertical_alignment="center")
    c_text.markdown(f":material/hub: **BGP:** {stats['ips']:,} IP(s) in {stats['prefixes']:,} prefix(es), "
                    f"{stats['origins']:,} origin network(s) " + badges(found))
    navigation.link("bgp", label="BGP page", container=c_link)
    st.divider()


def alerts_button(key, container=None, label="BGP routing alerts with their evidence"):
    navigation.jump_button("alerts", label, {THREAT_TYPE_KEY: list(RULES)}, button_key=f"{key}::alerts",
                           container=container, type="tertiary", icon=":material/warning:")


def badges(found):
    """`:red-badge[1 BGP Origin Conflict]` … for the findings, worst first."""
    if _empty(found):
        return ":green-badge[no routing finding]"
    order = {name: i for i, name in enumerate(bgp.FINDINGS)}
    parts = []
    for finding, group in sorted(found.groupby("Finding"), key=lambda kv: order.get(kv[0], 99)):
        worst = min(group["Severity"], key=lambda s: list(SEVERITY_BADGES).index(s) if s in SEVERITY_BADGES else 9)
        parts.append(f":{SEVERITY_BADGES.get(worst, 'gray')}-badge[{len(group)} {finding}]")
    return " ".join(parts)


# ---- Overview -------------------------------------------------------------------------------------------------------

def _overview(ds, found, ips):
    stats = bgp.summary(ds.bgp_origins, ds.bgp_asns, ds.bgp_routes, found)
    row = st.columns(5)
    row[0].metric("IPs routed", f"{stats['ips']:,}", help="Hosting IPs BGPDB knows an announcement for")
    row[1].metric("Prefixes", f"{stats['prefixes']:,}")
    row[2].metric("Origin networks", f"{stats['origins']:,}")
    row[3].metric("Upstream networks", f"{stats['upstreams']:,}", help="From the most-seen AS path of each prefix")
    row[4].metric("Unauthorized announcements", f"{stats['unauthorized']:,}",
                  help="Origins RPKI or IRR names as invalid for the prefix")
    st.markdown(badges(found))
    if not _empty(found):
        st.dataframe(found.drop(columns=["AS Name"]), hide_index=True, width="stretch",
                     column_config={"Detail": st.column_config.TextColumn(width="large"),
                                    "First Seen": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm"),
                                    "Last Seen": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm")})
        alerts_button("bgp_overview")
    st.markdown("**Hosting IPs**", help="One row per IP: its most specific announced prefix and usual origin. "
                                         "Origins > 1: other networks announced it too (see Origin timeline).")
    event = st.dataframe(ips, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
                         key=selection_key("bgp_ips", ips["IP"]),
                         column_config={"Announced Since": st.column_config.DatetimeColumn(format="YYYY-MM-DD"),
                                        "Findings": st.column_config.TextColumn(width="medium")})
    rows = selected_rows(event, ips)
    if rows:
        _ip_card(ds, ips.iloc[rows[0]]["IP"])
    else:
        st.caption("Select an IP to see every origin, AS path and network BGPDB knows for it.")
    iris_pivot(ds, "bgp_overview")


def iris_pivot(ds, key):
    """Opens IrisQL with the domains Iris sees on one of the run's origin networks or announced prefixes."""
    from core.irisql import network_query
    from views.irisql_view import QUERY_KEY as IRISQL_KEY  # the IrisQL page imports view helpers
    from views.query_editor import set_query
    usual = bgp.main_origins(ds.bgp_origins)
    if usual.empty:
        return
    networks = usual.drop_duplicates("Origin")
    options = {row["Origin"]: f"{row['Origin']} {row['AS Name']} (network)".replace("  ", " ")
               for _, row in networks.iterrows()}
    options.update({p.rstrip("+"): f"{p.rstrip('+')} (prefix)" for p in usual["Prefix"].astype(str)})
    c_pick, c_go = st.columns([3, 1.4], vertical_alignment="bottom")
    picked = c_pick.selectbox("Other domains in Iris on", list(options), format_func=options.get, key=f"{key}::iris",
                              help="Opens IrisQL with the domains Iris Investigate sees on this origin network (ASN) "
                                   "or on this prefix's addresses; edit the query, then Search (one Iris Investigate "
                                   "query). Large networks (a CDN, a cloud) match more than Iris returns: narrow the "
                                   "query, e.g. with CREATE_DATE or RISK_SCORE")
    if c_go.button("Open in IrisQL", key=f"{key}::iris_go", icon=":material/manage_search:", type="tertiary"):
        query = network_query(picked)
        if query:
            set_query(IRISQL_KEY, query)
            navigation.go("irisql")


def _ip_card(ds, ip):
    origins = ds.bgp_origins[ds.bgp_origins["IP"] == ip]
    with st.container(border=True):
        main = bgp.main_origins(origins).iloc[0]
        st.markdown(f"**{ip}** · {main['Prefix']} · {main['Origin']} {main['AS Name']} "
                    f":{STATUS_BADGES.get(main['Status'], 'gray')}-badge[{main['Status']}]")
        st.dataframe(origins.drop(columns=["IP", "Domains"]), hide_index=True, width="stretch",
                     column_config={"First Seen": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm"),
                                    "Last Seen": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm"),
                                    "RIR Date": st.column_config.DateColumn(format="YYYY-MM-DD")})
        routes = ds.bgp_routes[ds.bgp_routes["Prefix"].isin(set(origins["Prefix"]))] if not _empty(ds.bgp_routes) \
            else pd.DataFrame()
        if not routes.empty:
            st.caption(f"{len(routes)} AS path(s) towards {', '.join(sorted(set(routes['Prefix'])))}")
            st.dataframe(routes.sort_values("Collectors", ascending=False).head(15), hide_index=True, width="stretch")
        nets = ds.bgp_asns[ds.bgp_asns["ASN"].isin(set(origins["Origin"]))] if not _empty(ds.bgp_asns) else pd.DataFrame()
        if not nets.empty:
            st.dataframe(nets.drop(columns=["Domains"]), hide_index=True, width="stretch",
                         column_config={"Registered": st.column_config.DateColumn(format="YYYY-MM-DD")})
        st.code("\n".join([curl_command("ip", ip), curl_command("route", main["Prefix"], 50),
                           curl_command("asn", main["Origin"])]), language="bash")


# ---- Routing map ------------------------------------------------------------------------------------------------------

def sankey_figure(origins, routes):
    """
    Domain → prefix (its usual origin's colour) → every origin AS seen → upstream AS; unauthorized origins in red,
    collector-local private-AS leaks in orange. A prefix node takes the colour of the worst origin seen for it, so a
    thin red or orange link behind a green flow still shows. A "/24+" prefix stands for more-specific announcements
    inside the /24.
    """
    usual = bgp.main_origins(origins)
    upstream = bgp.main_upstreams(routes)
    labels, index, links = [], {}, {}

    def node(label):
        if label not in index:
            index[label] = len(labels)
            labels.append(label)
        return index[label]

    def link(a, b, status):
        key = (node(a), node(b))
        count, worst = links.get(key, (0, bgp.VALID))
        links[key] = (count + 1, _worse(worst, status) if count else status)

    for _, row in usual.iterrows():   # domain → prefix: one per IP, coloured by the usual origin
        for domain in str(row["Domains"]).split(","):
            if domain.strip():
                link(domain.strip(), row["Prefix"], row["Status"])
    for _, row in origins.drop_duplicates(["Prefix", "Origin"]).iterrows():   # prefix → every origin seen
        link(row["Prefix"], f"{row['Origin']} {row['AS Name']}".strip(), row["Status"])
    for _, row in usual.iterrows():
        if upstream.get(row["Prefix"]):
            link(f"{row['Origin']} {row['AS Name']}".strip(), f"via {upstream[row['Prefix']]}", row["Status"])
    colors = {bgp.VALID: "rgba(67,160,71,0.45)", bgp.UNAUTHORIZED: "rgba(229,57,53,0.7)",
              bgp.UNVERIFIED: "rgba(158,158,158,0.45)", bgp.LOCAL_LEAK: "rgba(251,140,0,0.7)"}
    prefix_status = {}
    for _, row in origins.iterrows():
        prefix = row["Prefix"]
        prefix_status[prefix] = _worse(prefix_status.get(prefix, row["Status"]), row["Status"])
    node_colors = [bgp.STATUS_COLORS.get(prefix_status[label], "#9e9e9e") if label in prefix_status else "#78909c"
                   for label in labels]
    sources, targets, values, link_colors = [], [], [], []
    for (a, b), (count, status) in links.items():
        sources.append(a)
        targets.append(b)
        values.append(count)
        link_colors.append(colors.get(status, colors[bgp.UNVERIFIED]))
    fig = go.Figure(go.Sankey(node={"label": labels, "pad": 12, "thickness": 14, "color": node_colors},
                              link={"source": sources, "target": targets, "value": values, "color": link_colors}))
    fig.update_layout(margin={"l": 10, "r": 10, "t": 10, "b": 10})
    return fig, len(labels)


def path_graph(routes, origins, asns, limit=25):
    """DOT: the AS paths towards one prefix, edges as thick as their collectors, origins coloured by status."""
    names = dict(zip(asns["ASN"], asns["AS Name"])) if not _empty(asns) else {}
    status = dict(zip(origins["Origin"], origins["Status"])) if not _empty(origins) else {}
    edges = {}
    for _, row in routes.sort_values("Collectors", ascending=False).head(limit).iterrows():
        hops = [h.strip() for h in str(row["Path"]).split("→") if h.strip()]
        for a, b in zip(hops, hops[1:]):
            edges[(a, b)] = edges.get((a, b), 0) + max(1, int(row["Collectors"]))
    nodes = {n for edge in edges for n in edge}
    fill = {bgp.VALID: "#2e7d32", bgp.UNAUTHORIZED: "#c62828", bgp.UNVERIFIED: "#616161", bgp.LOCAL_LEAK: "#ef6c00"}
    lines = ['digraph { graph [rankdir=LR, bgcolor="transparent", nodesep=0.2, ranksep=0.5]; '
             'node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=10, fontcolor="white", '
             'color="#555555", fillcolor="#2f2f2f"]; edge [color="#9e9e9e", arrowsize=0.5];']
    top = max(edges.values()) if edges else 1
    for name in sorted(nodes):
        label = f"{name}\\n{names.get(name, '')[:28]}".strip().replace('"', "'")
        color = fill.get(status.get(name), "#2f2f2f")
        lines.append(f'"{name}" [label="{label}", fillcolor="{color}"];')
    for (a, b), weight in edges.items():
        lines.append(f'"{a}" -> "{b}" [penwidth={0.6 + 3.4 * weight / top:.2f}, tooltip="{weight} collector(s)"];')
    return "\n".join(lines) + "}"


def _routing_map(ds):
    fig, count = sankey_figure(ds.bgp_origins, ds.bgp_routes)
    st.markdown("**Domain → prefix → origin network → upstream**")
    chart(fig, key="bgp_sankey", height=max(360, min(1400, 22 * count)))
    if _empty(ds.bgp_routes):
        st.caption("No AS paths in this run.")
        return
    def flagged(status):
        return set(ds.bgp_origins.loc[ds.bgp_origins["Status"] == status, "Prefix"].astype(str).str.rstrip("+"))

    contested, leaked = flagged(bgp.UNAUTHORIZED), flagged(bgp.LOCAL_LEAK)
    seen = ds.bgp_routes.groupby("Prefix")["Collectors"].sum()
    prefixes = sorted(seen.index, key=lambda p: (p not in contested, -seen[p]))
    prefix = st.selectbox("AS paths towards", prefixes, key="bgp_path_prefix",
                          format_func=lambda p: p + ("  ⚠ unauthorized origin seen" if p in contested
                                                     else "  · private-AS leak at one collector" if p in leaked else ""),
                          help="The prefixes of the run's IPs: those with an unauthorized origin first, then the most "
                               "widely seen. A private-AS leak is a route collector's peer leaking its internal AS "
                               "number: shown, but not a finding")
    routes = ds.bgp_routes[ds.bgp_routes["Prefix"] == prefix]
    st.graphviz_chart(path_graph(routes, ds.bgp_origins[ds.bgp_origins["Prefix"] == prefix], ds.bgp_asns),
                      width="content")
    st.caption(f"{len(routes)} path(s); the 25 most widely seen are drawn. Green: authorized origin, red: "
               "unauthorized, grey: not in RPKI / IRR, orange: a private AS seen at one route collector.")


# ---- Origin timeline --------------------------------------------------------------------------------------------------

MIN_BAR = pd.Timedelta(hours=8)   # a one-update announcement still shows as a bar


def timeline_figure(origins):
    """One row per (prefix, origin): when each network announced each prefix, coloured by authorization."""
    frame = origins.drop_duplicates(["Prefix", "Origin"]).copy()
    frame["Network"] = (frame["Origin"] + " " + frame["AS Name"].fillna("")).str.strip()
    frame["Row"] = frame["Prefix"] + "  " + frame["Origin"]
    frame["Seen Until"] = frame["Last Seen"]
    frame["Last Seen"] = frame[["Last Seen"]].join(frame["First Seen"] + MIN_BAR).max(axis=1)
    frame = frame.sort_values(["Prefix", "Updates"], ascending=[True, False])
    fig = px.timeline(frame, x_start="First Seen", x_end="Last Seen", y="Row", color="Status",
                      color_discrete_map=bgp.STATUS_COLORS, hover_name="Network",
                      hover_data={"Seen Until": True, "Collectors": True, "Updates": True, "RPKI": True, "IRR": True,
                                  "Row": False, "Last Seen": False},
                      category_orders={"Row": list(frame["Row"])})
    fig.update_yaxes(title=None)
    fig.update_layout(legend_title_text="", margin={"l": 10, "r": 10, "t": 10, "b": 10})
    return fig


def _timeline(ds):
    origins = ds.bgp_origins
    rows = len(origins.drop_duplicates(["Prefix", "Origin"]))
    chart(timeline_figure(origins), key="bgp_timeline", height=max(260, 28 * rows + 120))
    multi = origins.groupby("Prefix")["Origin"].nunique()
    contested = multi[multi > 1]
    if contested.empty:
        st.caption("Every prefix had one origin in BGPDB's window.")
    else:
        st.caption(f"{len(contested)} prefix(es) announced by more than one network: "
                   + ", ".join(f"{p} ({n})" for p, n in contested.items()))


# ---- Networks ---------------------------------------------------------------------------------------------------------

def _networks(ds):
    nets = ds.bgp_asns
    if _empty(nets):
        st.caption("No network lookups in this run.")
        return
    now = pd.Timestamp.now(tz="UTC").tz_localize(None)
    frame = nets.assign(**{"Age (days)": (now - pd.to_datetime(nets["Registered"])).dt.days})
    young = frame[frame["Age (days)"] <= bgp.NEW_ASN_DAYS]
    row = st.columns(3)
    row[0].metric("Networks", f"{len(frame):,}")
    row[1].metric("Registered in the last year", f"{len(young):,}")
    row[2].metric("Single-upstream stubs", f"{int(((frame['Upstreams'] == 1) & (frame['Downstreams'] == 0)).sum()):,}")
    plot = frame.dropna(subset=["Registered"]).copy()
    if not plot.empty:
        plot["Label"] = (plot["ASN"] + " " + plot["AS Name"]).str.strip()
        plot["Size"] = plot["Updates"].clip(lower=1).map(lambda v: max(6, min(40, v ** 0.3)))
        fig = px.scatter(plot, x="Registered", y="Collectors", color="Role", size="Size", hover_name="Label",
                         hover_data={"Upstreams": True, "Downstreams": True, "RIR Country": True, "Size": False},
                         color_discrete_map={"origin": "#42a5f5", "upstream": "#ab47bc"})
        fig.add_vrect(x0=now - pd.Timedelta(days=bgp.NEW_ASN_DAYS), x1=now, fillcolor="#e53935", opacity=0.08,
                      line_width=0, annotation_text="registered in the last year", annotation_position="top left")
        fig.update_layout(margin={"l": 10, "r": 10, "t": 30, "b": 10})
        st.markdown("**Network age and visibility**", help="Each dot is a network: when its RIR registered it (x) and "
                                                          "how many route collectors see it (y).")
        chart(fig, key="bgp_networks", height=380)
    st.dataframe(frame, hide_index=True, width="stretch",
                 column_config={"Registered": st.column_config.DateColumn(format="YYYY-MM-DD"),
                                "First Seen": st.column_config.DatetimeColumn(format="YYYY-MM-DD"),
                                "Last Seen": st.column_config.DatetimeColumn(format="YYYY-MM-DD")})


# ---- Neighbouring prefixes --------------------------------------------------------------------------------------------

def _neighbours(ds):
    near = ds.bgp_neighbours
    if _empty(near):
        st.caption("No neighbouring prefixes in this run (*BGPDB neighbouring prefixes* is off, or none were found).")
        return
    same = near[near["Same Origin"].astype(bool)]
    row = st.columns(3)
    row[0].metric("Neighbouring prefixes", f"{len(near):,}")
    row[1].metric("Announced by the run's own networks", f"{len(same):,}", help="Leads: the operator's other space")
    row[2].metric("Unauthorized", f"{int((near['Status'] == bgp.UNAUTHORIZED).sum()):,}")
    group = near.apply(lambda r: "Same origin as the run" if r["Same Origin"] else
                       "Unauthorized" if r["Status"] == bgp.UNAUTHORIZED else "Other networks", axis=1)
    counts = near.assign(Group=group).groupby(["Covering Range", "Group"]).size().reset_index(name="Prefixes")
    fig = px.bar(counts, x="Prefixes", y="Covering Range", color="Group", orientation="h",
                 color_discrete_map={"Same origin as the run": "#42a5f5", "Other networks": "#757575",
                                     "Unauthorized": "#e53935"})
    fig.update_layout(margin={"l": 10, "r": 10, "t": 10, "b": 10}, legend_title_text="")
    chart(fig, key="bgp_neighbours", height=max(220, 40 * counts["Covering Range"].nunique() + 120))
    st.dataframe(near.sort_values(["Same Origin", "Covering Range", "Prefix"], ascending=[False, True, True]),
                 hide_index=True, width="stretch",
                 column_config={"First Seen": st.column_config.DatetimeColumn(format="YYYY-MM-DD"),
                                "Last Seen": st.column_config.DatetimeColumn(format="YYYY-MM-DD"),
                                "RIR Date": st.column_config.DateColumn(format="YYYY-MM-DD")})
    if not same.empty:
        st.caption("Prefixes of the same origin are worth checking in VPNDB (CIDR targets) and passive DNS.")
        st.code("\n".join(sorted(set(same["Prefix"]))), language="text")


# ---- VPNDB match ------------------------------------------------------------------------------------------------------

def _vpndb(ds, found, ips):
    if _empty(ds.anonymizers):
        st.info("No VPNDB verdicts in this run: with a VPNDB key and *Check hosting IPs for VPN, residential proxy "
                "and Tor* on, the exits are matched with their routing here.", icon=":material/info:")
        return
    exits = bgp.vpndb_ip_match(ips, ds.anonymizers)
    st.markdown("**Anonymizer exits and their routing**")
    if exits.empty:
        st.caption("None of the run's VPN / proxy / Tor exits has a BGP record in this run.")
    else:
        unstable = exits["Findings"].astype(str).map(lambda f: any(u in f for u in bgp.UNSTABLE))
        if unstable.any():
            st.warning(f"{int(unstable.sum())} exit(s) on newly announced or unauthorized prefixes "
                       f"(*{bgp.EXIT_ON_UNSTABLE}*).", icon=":material/warning:")
        st.dataframe(exits, hide_index=True, width="stretch",
                     column_config={"Announced Since": st.column_config.DatetimeColumn(format="YYYY-MM-DD")})
    networks = bgp.vpndb_asn_match(ds.bgp_asns, ds.anonymizers, ds.hosting_asns)
    st.markdown("**Origin networks that carry exits**")
    if networks.empty:
        st.caption("No origin network of the run carries a known exit.")
    else:
        st.dataframe(networks, hide_index=True, width="stretch",
                     column_config={"Registered": st.column_config.DateColumn(format="YYYY-MM-DD")})
    navigation.link("vpndb", label="VPNDB page", icon=":material/vpn_lock:")


# ---- Responses --------------------------------------------------------------------------------------------------------

def _responses(ds):
    raw = ds.bgp_raw
    if _empty(raw):
        st.caption("No BGPDB lookups recorded.")
        return
    shown = raw.drop(columns=["Response"])
    event = st.dataframe(shown, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
                         key=selection_key("bgp_raw", shown["URL"]))
    rows = selected_rows(event, shown)
    if rows:
        row = raw.iloc[rows[0]]
        limit = None
        if "limit=" in str(row["URL"]):
            limit = str(row["URL"]).split("limit=")[-1]
        st.code(curl_command(row["Command"], row["Argument"], limit), language="bash")
        st.code(str(row["Response"])[:20000], language="json")
