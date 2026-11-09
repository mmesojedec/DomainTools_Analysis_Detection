"""
VPNDB page: which VPN or proxy provider operates behind an IP, prefix or ASN. Which of the run's hosting IPs are VPN, residential proxy or Tor exits, drawn as a flow,
a heatmap, providers and countries, an exposure timeline against VPNDB's weekly history, the Iris Investigate cross-check,
the ranges and networks around the hosting, the other domains on dedicated exits (DNSDB) and the CIDR targets.
"""
import ipaddress

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from core.anonymizers import (
    ANONYMIZER_CATEGORIES,
    anonymizer_rows,
    crosscheck,
    dedicated_exit,
    exit_during_use,
    shared_exit,
    use_intervals,
)
from core.intel_data import ISO2_TO_ISO3
from integrations.enrichment import extract_iris_profile
from views import navigation
from views.anonymizer_view import (
    CATEGORY_BADGES,
    COLUMN_CONFIG,
    RANGE_SETS,
    SHOWN_COLUMNS,
    _empty,
    alerts_button,
    export_button,
    range_ip_table,
    render_networks,
    selectable_table,
)
from views.common import chart
from views.hunt_actions import analyze_button

PAGE_TAB_KEY = "vpndb_tab"
VPNDB_TAGLINE = "Which VPN or proxy provider operates behind an IP, prefix or ASN."
TABS = ["Overview", "Exposure timeline", "Iris cross-check", "Neighbourhood", "Leads", "CIDR ranges"]
# "How to read this" per tab: plain-language points, shown collapsed above each tab
HOW_TO_READ = {
    "Overview": (
        "Every hosting IP of your domains was checked in VPNDB. The numbers at the top count what VPNDB found.",
        "**Exit** = an IP where VPN, proxy or Tor users come out onto the internet. If a domain is hosted on an exit, "
        "its owner is probably hiding behind that service.",
        "**Shared exit** = used by many customers of the service at once. It tells you *which service*, not *who*: "
        "don't block or report it on its own.",
        "The flow chart reads left to right: your domain → the VPN / proxy company → the exit IP.",
        "Click a row in the table to see everything about that IP.",
    ),
    "Exposure timeline": (
        "One line per domain and exit IP. The question it answers: **was the IP already a VPN / proxy exit while the "
        "domain was using it?**",
        "**Bar** = the time the domain pointed to that IP (from passive DNS, whole history).",
        "**Yellow diamonds** = the weeks VPNDB saw that IP working as an exit.",
        "**Red bar** = yes, the domain used the IP while it was an exit. This is what the exit alerts are based on.",
        "**Green bar** = no: the IP became an exit before or after the domain used it (the address was simply reused). "
        "No exit alert for it.",
        "**Grey bar** = unknown: VPNDB's weekly history was not fetched for that IP.",
        "IPs you entered as targets are not drawn, because they are the exit themselves.",
    ),
    "Iris cross-check": (
        "The IPs your domains use **today** (Iris Investigate) that VPNDB also knows.",
        "**Iris domains** = how many domains share that IP. **Few** domains on an exit → it is probably used by one "
        "owner, so its other domains are worth checking (**Strong pivot**). **Thousands** → a busy shared VPN exit, "
        "its other domains belong to strangers (**Noise**).",
        "**Disagreement** = Iris and VPNDB put the same IP in a different network or country. Usually harmless: the "
        "VPN shows a fake location, or the IP changed owner. Just don't trust the IP's country without checking.",
    ),
    "Neighbourhood": (
        "Looks at the IPs **next to** your domains' servers, not the servers themselves.",
        "**/24 ranges**: the 256 addresses around each hosting IP. Known exits there mean the domain sits right beside "
        "a VPN or proxy company's servers.",
        "**Hosting networks**: the whole network (ASN) the domain is hosted on. **Single tenant** = one VPN / proxy "
        "company owns almost all exits there; with many exits, the network is effectively theirs.",
    ),
    "Leads": (
        "Only for **dedicated** exits (used by one or few customers, not shared).",
        "Lists other domains that pointed to the same dedicated exit (DNSDB). They probably belong to the same "
        "customer, so they are leads: click **Analyze** to look into one.",
        "Shared exits are skipped on purpose: their other domains belong to unrelated people.",
    ),
    "CIDR ranges": (
        "Only for IP ranges you entered as targets (e.g. `104.21.59.0/24`).",
        "Each square is one address: **red** = measured exit, **gold** = VPNDB expects an exit there (interpolated), "
        "**grey** = no exit.",
    ),
}
CATEGORY_COLORS = {"Tor": "#d62728", "Residential proxy": "#ff7f0e", "VPN": "#9467bd", "Proxy": "#8c6bb1",
                   "Relay": "#1f77b4", "Hosting": "#7f7f7f", "Not anonymous": "#2ca02c", "Not observed": "#bcbcbc",
                   "Not checked": "#999999"}


def render_vpndb_page(ds):
    st.header("VPNDB", help="The run's hosting IPs checked in VPNDB (VPN, residential proxy and Tor exits), how the "
                            "domains use them, what Iris Investigate and passive DNS add, and the CIDR targets. "
                            "The Tor network overview has its own page: Infrastructure → Tor network. Not observed is not an all-clear: VPNDB only knows the exits it measured or that "
                            "public lists name.")
    st.caption(VPNDB_TAGLINE)
    navigation.link("tor", label="Tor network statistics (also from VPNDB) are on their own page",
                    icon=":material/travel_explore:")
    table = ds.anonymizers
    if _empty(table) and _empty(ds.prefixes):
        st.info("No VPNDB verdicts in this run. Add a VPNDB key under Settings → API credentials and keep *Check "
                "hosting IPs for VPN, residential proxy and Tor* on (Settings → Collection options), then analyze "
                "again.")
        return
    tabs = st.tabs(TABS, key=PAGE_TAB_KEY, on_change="rerun")
    navigation.scroll_to_tab()
    for tab, name, render in zip(tabs, TABS, (_overview, _timeline, _crosscheck, _neighbourhood, _leads, _cidr)):
        with tab:
            how_to_read(name)
            render(ds)


def how_to_read(tab):
    with st.expander("How to read this", icon=":material/help:"):
        st.markdown("\n".join(f"- {point}" for point in HOW_TO_READ[tab]))


# ---- Overview -------------------------------------------------------------------------------------------------------

def _overview(ds):
    table = ds.anonymizers
    if _empty(table):
        st.caption("No hosting IPs were checked (CIDR targets only): see *CIDR ranges*.")
        return
    flagged = anonymizer_rows(table)
    columns = st.columns(len(ANONYMIZER_CATEGORIES) + 2)
    columns[0].metric("IPs checked", f"{len(table):,}")
    for column, name in zip(columns[1:], ANONYMIZER_CATEGORIES):
        column.metric(name if name != "Relay" else "Relays", int((flagged["Category"] == name).sum()))
    columns[-1].metric("Shared exits", int(flagged.apply(shared_exit, axis=1).sum()) if not flagged.empty else 0,
                       help="IOC value LOW or sharing HIGH: they identify the service, not the actor")
    if flagged.empty:
        st.success("VPNDB attributes none of the checked IPs to a VPN, proxy or Tor.")
    else:
        c_flow, c_heat = st.columns(2)
        with c_flow:
            st.markdown("**Domain → provider → exit**", help="Each analyzed domain, the VPN / proxy / Tor operator "
                                                            "of its exits, and the exit IPs. An IP fed by several "
                                                            "domains is a shared exit or one operator's.")
            chart(flow_figure(flagged), key="vpndb_flow", height=max(320, 26 * len(flagged) + 120))
        with c_heat:
            st.markdown("**Checked IPs by domain and category**", help="How many of each domain's checked IPs VPNDB "
                                                                       "puts in each category")
            chart(category_heatmap(table), key="vpndb_heatmap", height=max(320, 40 * table["Domains"].nunique() + 160))
        c_prov, c_geo = st.columns(2)
        with c_prov:
            st.markdown("**Exits per provider**")
            chart(provider_bars(flagged), key="vpndb_providers", height=320)
        with c_geo:
            st.markdown("**Exit countries**", help="Where VPNDB locates the exits; a location mismatch (the provider "
                                                  "advertises another country) is listed in the verdict")
            geo = exit_countries(flagged)
            if geo.empty:
                st.caption("No country information.")
            else:
                fig = px.choropleth(geo, locations="ISO3", color="Exits", hover_name="Country",
                                    hover_data={"ISO3": False, "Providers": True}, color_continuous_scale="Oranges")
                fig.update_geos(showframe=False, showcoastlines=True, projection_type="natural earth",
                                bgcolor="rgba(0,0,0,0)", fitbounds=False, showcountries=True, showland=True,
                                landcolor="#2a2a3a", countrycolor="#555")   # the whole world, not one country
                fig.update_layout(margin=dict(t=10, l=0, r=0, b=0))
                chart(fig, key="vpndb_geo", height=320)
        st.markdown("**VPN, proxy and Tor exits**")
        selectable_table(flagged[SHOWN_COLUMNS], "vpndb_exits", table, ds=ds)
    c_alerts, c_export = st.columns(2)
    alerts_button("vpndb_page", c_alerts)
    export_button("vpndb_page", ("vpndb_verdicts",) + (RANGE_SETS if not _empty(ds.prefixes) else ()),
                  "Download the verdicts (Data Export → VPN / proxy / Tor)", c_export)
    if st.toggle(f"Show every checked IP ({len(table):,})", key="vpndb_every_ip"):
        selectable_table(table[SHOWN_COLUMNS + ["Note"]], "vpndb_all", table, ds=ds)


def _domain_rows(flagged):
    """One row per (domain, exit IP)."""
    rows = []
    for row in flagged.to_dict("records"):
        for domain in [d.strip() for d in str(row["Domains"]).split(",") if d.strip()]:
            rows.append({**row, "Domain": domain})
    return pd.DataFrame(rows)


def flow_figure(flagged):
    """Sankey: domain → provider (or category) → exit IP."""
    pairs = _domain_rows(flagged)
    pairs["Operator"] = pairs["Provider"].where(pairs["Provider"].astype(bool), pairs["Category"])
    # nodes are keyed by kind: an IP target is both a "domain" and its own exit
    nodes = list(dict.fromkeys([("domain", d) for d in pairs["Domain"]] + [("operator", o) for o in pairs["Operator"]]
                               + [("ip", ip) for ip in pairs.loc[pairs["IP"] != pairs["Domain"], "IP"]]))
    index = {node: i for i, node in enumerate(nodes)}
    first = pairs.groupby(["Domain", "Operator"]).size().reset_index(name="n")
    exits = pairs[pairs["IP"] != pairs["Domain"]].drop_duplicates(["Operator", "IP"])
    second = exits.assign(n=1)
    colors = [CATEGORY_COLORS.get(c, "#9467bd") for c in exits["Category"]]
    fig = go.Figure(go.Sankey(
        node=dict(label=[label for _, label in nodes], pad=12, thickness=14),
        link=dict(source=[index[("domain", d)] for d in first["Domain"]]
                  + [index[("operator", o)] for o in second["Operator"]],
                  target=[index[("operator", o)] for o in first["Operator"]] + [index[("ip", ip)] for ip in second["IP"]],
                  value=list(first["n"]) + list(second["n"]),
                  color=["rgba(150,150,150,0.35)"] * len(first) + [c + "99" for c in colors]),
    ))
    fig.update_layout(margin=dict(t=10, l=10, r=10, b=10))
    return fig


def category_heatmap(table):
    pairs = _domain_rows(table)
    counts = pairs.pivot_table(index="Domain", columns="Category", values="IP", aggfunc="nunique", fill_value=0)
    order = [c for c in list(ANONYMIZER_CATEGORIES) + ["Hosting", "Not anonymous", "Not observed", "Not checked"]
             if c in counts.columns]
    counts = counts[order]
    fig = px.imshow(counts, text_auto=True, aspect="auto", color_continuous_scale=[[0, "#262636"], [1, "#7b4fc9"]],
                    labels=dict(x="", y="", color="IPs"))
    fig.update_layout(margin=dict(t=10, l=10, r=10, b=10), coloraxis_showscale=False)
    return fig


def provider_bars(flagged):
    counts = flagged.assign(Provider=flagged["Provider"].where(flagged["Provider"].astype(bool), "unknown")) \
        .groupby(["Provider", "Category"]).size().reset_index(name="Exits").sort_values("Exits")
    fig = px.bar(counts, x="Exits", y="Provider", color="Category", orientation="h",
                 color_discrete_map=CATEGORY_COLORS)
    fig.update_layout(margin=dict(t=10, l=10, r=10, b=10), legend_title_text="", yaxis_title="", xaxis_title="")
    return fig


def exit_countries(flagged):
    geo = flagged[flagged["Country"].astype(bool)].assign(Country=lambda f: f["Country"].str.upper()) \
        .groupby("Country").agg(Exits=("IP", "nunique"),
                                Providers=("Provider", lambda p: ", ".join(sorted({x for x in p if x})[:5]))) \
        .reset_index()
    geo["ISO3"] = geo["Country"].map(ISO2_TO_ISO3)
    return geo.dropna(subset=["ISO3"])


# ---- Exposure timeline ------------------------------------------------------------------------------------------------

def exposure_frame(ds):
    """One row per (domain, exit IP, use interval) with whether VPNDB's history shows it an exit at the time."""
    flagged = anonymizer_rows(ds.anonymizers)
    if flagged.empty:
        return pd.DataFrame()
    weeks = {ip: list(g["Week"]) for ip, g in ds.exit_weeks.groupby("IP")} if not _empty(ds.exit_weeks) else {}
    current = {(e["ip"], d) for d, obj in (ds.enrichment or {}).items() for e in extract_iris_profile(obj)["ips"]}
    rows = []
    history = ds.events_all_utc   # full history: the use of an exit before the window is part of the story
    for row in _domain_rows(flagged).to_dict("records"):
        if row["Domain"] == row["IP"]:   # an IP target is the exit itself
            continue
        events = history[history["Domain"] == row["Domain"]] if not history.empty else pd.DataFrame()
        spans = use_intervals(events, row["IP"], current=(row["IP"], row["Domain"]) in current)
        known = row["IP"] in weeks and bool(weeks[row["IP"]])
        for start, end in spans:
            hit = bool(exit_during_use([(start, end)], weeks.get(row["IP"], [])))
            rows.append({"Domain": row["Domain"], "IP": row["IP"], "Row": f"{row['Domain']} · {row['IP']}",
                         "Start": start, "End": max(end, start + pd.Timedelta(days=1)), "Category": row["Category"],
                         "Provider": row["Provider"],
                         "Exit Then": "yes" if hit else "no" if known else "unknown (no weekly history)"})
    return pd.DataFrame(rows)


def _timeline(ds):
    st.markdown("**When the domains resolved to each exit, and when VPNDB saw it exit**",
                help="Bar: when the domain used the IP. Diamonds: weeks the IP was an exit. Red bar: used while it "
                     "was an exit. Green bar: the IP was an exit at another time only. Details: *How to read this*.")
    frame = exposure_frame(ds)
    if frame.empty:
        st.caption("No domain resolved to an anonymizer exit (IP targets are not drawn: they are the exit).")
        return
    fig = px.timeline(frame, x_start="Start", x_end="End", y="Row", color="Exit Then", hover_data=["Category", "Provider"],
                      color_discrete_map={"yes": "#d62728", "no": "#2ca02c", "unknown (no weekly history)": "#9e9e9e"})
    if not _empty(ds.exit_weeks):
        marks = ds.exit_weeks.merge(frame[["IP", "Row"]].drop_duplicates(), on="IP")
        fig.add_trace(go.Scatter(x=marks["Week"], y=marks["Row"], mode="markers", name="VPNDB exit week",
                                 marker=dict(symbol="diamond", size=7, color="#ffbf00"),
                                 text=marks["Status"] + " · " + marks["Provider"], hoverinfo="x+text"))
    fig.update_yaxes(autorange="reversed", title="")
    fig.update_layout(margin=dict(t=10, l=10, r=10, b=10), legend_title_text="Exit while the domain used it")
    chart(fig, key="vpndb_timeline", height=max(260, 34 * frame["Row"].nunique() + 140))
    summary = frame.groupby(["Domain", "IP", "Category", "Provider"])["Exit Then"].agg(
        lambda v: "yes" if "yes" in set(v) else v.iloc[0]).reset_index()
    st.dataframe(summary, hide_index=True, width="stretch")
    if _empty(ds.exit_weeks):
        st.caption("VPNDB's weekly history was not fetched for these exits (no VPNDB key, or a run from before this "
                   "check): the exit alerts use the current verdict only.")


# ---- Iris cross-check ---------------------------------------------------------------------------------------------------

PIVOT_BADGES = {"Strong pivot": "green", "Noise: shared exit": "gray", "Check": "blue"}


def _crosscheck(ds):
    st.markdown("**Iris Investigate and VPNDB on the same IPs**",
                help="Iris domains: few = a good pivot, thousands = a shared exit (noise). Disagreement: a different "
                     "network or country in Iris and VPNDB. Details: *How to read this*.")
    frame = crosscheck(ds.anonymizers, ds.enrichment)
    if frame.empty:
        st.caption("None of the checked IPs is a current Iris IP of the run's domains.")
        return
    exits = frame[frame["Pivot Value"].astype(bool)]
    c1, c2, c3 = st.columns(3)
    c1.metric("Current Iris IPs checked", f"{len(frame):,}")
    c2.metric("Strong pivots", int((frame["Pivot Value"] == "Strong pivot").sum()),
              help="Exits VPNDB rates dedicated, or with 50 domains or fewer in Iris")
    c3.metric("Iris / VPNDB disagree", int(frame["Disagreement"].astype(bool).sum()))
    for row in exits.to_dict("records"):
        st.markdown(f":{PIVOT_BADGES.get(row['Pivot Value'], 'gray')}-badge[{row['Pivot Value']}] `{row['IP']}` "
                    f"{row['Category']} {row['Provider']} · "
                    + (f"{int(row['Iris Domains']):,} domains in Iris" if pd.notna(row["Iris Domains"]) else
                       "domain count unknown") + (f" · {row['Disagreement']}" if row["Disagreement"] else ""))
    st.dataframe(frame, hide_index=True, width="stretch", column_config={
        **COLUMN_CONFIG, "Iris Domains": st.column_config.NumberColumn("Iris domains", help="Domains on the IP in "
                                                                                           "Iris Investigate"),
        "Iris ASN": st.column_config.NumberColumn("Iris ASN", format="%d"),
        "VPNDB ASN": st.column_config.NumberColumn("VPNDB ASN", format="%d")})


# ---- Neighbourhood ------------------------------------------------------------------------------------------------------

def _neighbourhood(ds):
    st.markdown("**/24 ranges around the hosting IPs**",
                help="The /24 of each checked IP that is not itself an exit, looked up in VPNDB: known exits next to "
                     "the domain's server mean it is hosted on, or beside, a VPN or proxy operator's servers. Raises "
                     "*Hosted Among Anonymizer Exits*.")
    ranges = ds.neighbour_ranges
    if _empty(ranges):
        st.caption("No neighbouring ranges were looked up.")
    else:
        with_exits = ranges[ranges["Known Exits"] > 0]
        st.caption(f"{len(with_exits)} of {len(ranges)} range(s) hold known exits.")
        st.dataframe(ranges, hide_index=True, width="stretch", column_config={
            "Known Exits": st.column_config.NumberColumn("Known exits"),
            "Single Tenant": st.column_config.CheckboxColumn("Single tenant"),
            "ASN": st.column_config.NumberColumn("ASN", format="%d")})
    st.markdown("**Hosting networks (Iris ASNs) in VPNDB**",
                help="The VPN and proxy providers VPNDB knows on each network the domains are hosted on now. Single "
                     "tenant: one provider holds 95 % of the network's exits; with 25 or more known exits the network "
                     "is taken as that provider's (*Hosted Among Anonymizer Exits*). A single tenant with a handful of "
                     "exits is a hoster where one proxy customer runs a few servers.")
    asns = ds.hosting_asns
    if _empty(asns):
        st.caption("No hosting networks were looked up.")
        return
    shown = asns[asns["Known Exits"] > 0]
    if not shown.empty:
        fig = px.bar(shown.assign(Network=lambda f: "AS" + f["ASN"].astype(str) + " " + f["AS Organization"]),
                     x="Known Exits", y="Network", orientation="h", color="Single Tenant", hover_data=["Providers"])
        fig.update_layout(margin=dict(t=10, l=10, r=10, b=10), yaxis_title="", xaxis_title="Known exits")
        chart(fig, key="vpndb_asns", height=max(220, 32 * len(shown) + 100))
    st.dataframe(asns, hide_index=True, width="stretch", column_config={
        "ASN": st.column_config.NumberColumn("ASN", format="%d"),
        "Single Tenant": st.column_config.CheckboxColumn("Single tenant"),
        "Known Exits": st.column_config.NumberColumn("Known exits")})


# ---- Leads --------------------------------------------------------------------------------------------------------------

def _leads(ds):
    st.markdown("**Other domains on dedicated exits (DNSDB)**",
                help="Every name DNSDB saw resolving to an exit VPNDB rates dedicated (few users): unlike a shared "
                     "exit, the other domains on it are probably the same customer's. Shared exits are not looked up.")
    names = ds.exit_neighbours
    if _empty(names):
        flagged = anonymizer_rows(ds.anonymizers)
        dedicated = int(flagged.apply(dedicated_exit, axis=1).sum()) if not flagged.empty else 0
        st.caption("No exit in this run is dedicated (VPNDB sharing LOW or IOC value HIGH): shared exits are not looked "
                   "up, their other domains belong to unrelated customers." if not dedicated else
                   f"{dedicated} dedicated exit(s), but DNSDB returned no other names for them (or there is no DNSDB "
                   "key: Settings → API credentials).")
        return
    new = names[~names["Analyzed"]]
    domains = new.groupby("Domain").agg(Names=("Name", "nunique"), Exits=("IP", lambda ips: ", ".join(sorted(set(ips)))),
                                        Last=("Last Seen", "max")).reset_index().sort_values("Last", ascending=False)
    st.caption(f"{names['Domain'].nunique():,} domain(s) on {names['IP'].nunique()} dedicated exit(s), "
               f"{len(domains):,} not analyzed yet.")
    for i, lead in enumerate(domains.head(10).to_dict("records")):
        c_text, c_button = st.columns([5, 1.3], vertical_alignment="center")
        c_text.markdown(f"`{lead['Domain']}` · {lead['Names']} name(s) · on {lead['Exits']}"
                        + (f" · last seen {lead['Last']:%Y-%m-%d}" if pd.notna(lead["Last"]) else ""))
        analyze_button([lead["Domain"]], f"Exit neighbour {lead['Domain']}", key=f"vpndb_lead::{i}",
                       container=c_button, label="Analyze", width="stretch")
    with st.expander(f"Every name ({len(names):,})"):
        st.dataframe(names, hide_index=True, width="stretch", column_config={
            "Analyzed": st.column_config.CheckboxColumn("Analyzed", help="Already one of this run's domains")})


# ---- CIDR ranges --------------------------------------------------------------------------------------------------------

def address_grid(ips, cidr):
    """A 16 × 16 grid per /24 of the range (rows: third octet blocks of 16 addresses): exit kind of each address."""
    network = ipaddress.ip_network(cidr, strict=False)
    if network.version != 4 or network.num_addresses > 1024 or ips.empty:
        return None
    kind = {row["IP"]: (2 if row["Method"] != "interpolated" else 1) if row["Category"] in ANONYMIZER_CATEGORIES else 0
            for row in ips.to_dict("records")}
    cells = [(int(address) - int(network.network_address), kind.get(str(address), 0), str(address))
             for address in network]
    rows = (len(cells) + 15) // 16
    z = [[None] * 16 for _ in range(rows)]
    text = [[""] * 16 for _ in range(rows)]
    for offset, value, address in cells:
        z[offset // 16][offset % 16] = value
        text[offset // 16][offset % 16] = address
    fig = go.Figure(go.Heatmap(z=z, text=text, hovertemplate="%{text}<extra></extra>", zmin=0, zmax=2, xgap=1, ygap=1,
                               colorscale=[[0, "#3a3a3a"], [0.5, "#c9a227"], [1, "#d62728"]], showscale=False))
    fig.update_yaxes(autorange="reversed", showticklabels=False)
    fig.update_xaxes(showticklabels=False)
    fig.update_layout(margin=dict(t=10, l=10, r=10, b=10))
    return fig


def _cidr(ds):
    if _empty(ds.prefixes):
        st.caption("No CIDR targets in this run. Enter a range (e.g. `104.21.59.0/24`) as a target to see the "
                   "providers in it and every address.")
        return
    for row in ds.prefixes.to_dict("records"):
        ips = range_ip_table(ds.range_ips, ds.prefix_addresses, row["CIDR"])
        fig = address_grid(ips, row["CIDR"]) if not ips.empty else None
        if fig is not None:
            st.markdown(f"**{row['CIDR']}** :{CATEGORY_BADGES.get(row['Category'], 'violet')}-badge[{row['Category']}]"
                        " — red: measured exit, gold: interpolated, gray: no exit", help="One cell per address, 16 "
                        "per row; hover for the address")
            chart(fig, key=f"vpndb_grid::{row['CIDR']}", height=max(160, 18 * len(fig.data[0].z) + 40))
    render_networks(ds)
