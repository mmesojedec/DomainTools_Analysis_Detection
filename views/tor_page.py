"""
Tor network page (Infrastructure): the whole Tor network today, from VPNDB's /tor overview: relays and exits, which
networks and countries carry Tor exit traffic, and whether the run's hosting networks are among them. Statistics only:
the run's own IPs are checked for Tor on the VPNDB page and each IP card.
"""
import pandas as pd
import plotly.express as px
import streamlit as st

from core import bgp
from core.anonymizers import tor_tables
from views.anonymizer_view import _empty
from views.common import chart

HOW_TO_READ = (
    "A picture of the whole Tor network today: how many relays and exits there are, and which networks and countries "
    "carry Tor exit traffic. These are network-wide statistics, not verdicts on your domains.",
    "A warning appears if one of **your** domains is hosted on a network that also carries Tor exit traffic: it "
    "shares that network with anonymized traffic (alert *Hosted Among Tor Exits*).",
    "Every network the run saw is matched against the Tor exit networks: the hosting networks (VPNDB, Iris) and, with "
    "BGPDB, each network that announced the run's prefixes (with or without authorization), the upstreams on their "
    "AS paths and the origins of more-specific prefixes announced inside them. *Seen as* tells which. A Tor exit network that announced one "
    "of the run's prefixes without authorization raises *Unauthorized Origin Is a Tor Exit Network*.",
    "Whether a hosting IP **is** a Tor relay or exit is on the **VPNDB** page and each IP card (*Tor network* tab).",
    "The data comes from **VPNDB** (`/tor`): the Tor Project's relay list placed with VPNDB's routing and country "
    "tables. It is fetched once per run with the VPNDB check and does not count against the VPNDB quota.",
)


def render_tor_page(ds):
    st.header("Tor network", help="Network-wide Tor statistics from VPNDB's /tor overview: relays, exits, and the "
                                  "networks and countries that carry Tor exit traffic.")
    st.caption("Tor network statistics provided through **VPNDB** (the Tor Project's relay list with VPNDB's routing "
               "and country data). Whether one of your IPs is a Tor exit is on the VPNDB page.")
    with st.expander("How to read this", icon=":material/help:"):
        st.markdown("\n".join(f"- {point}" for point in HOW_TO_READ))
    _tor_network(ds)


def _domains(value):
    return {d.strip() for d in str(value).split(",") if d.strip()}


def run_network_roles(ds):
    """
    {AS number: ({roles}, {domains})}: every network the run saw, with how: hosting (VPNDB / Iris ASN), and from
    BGPDB the usual origin of a prefix, an unauthorized origin, an upstream on the AS paths and the origin of a
    more-specific prefix announced inside one.
    """
    seen = {}

    def add(asn, role, domains=()):
        number = bgp.asn_number(asn) if not isinstance(asn, int) else asn
        if number is not None:
            roles, names = seen.setdefault(number, (set(), set()))
            roles.add(role)
            names.update(domains)

    for row in (ds.anonymizers.to_dict("records") if not _empty(ds.anonymizers) else []):
        if pd.notna(row.get("ASN")):
            add(int(row["ASN"]), "Hosting (VPNDB)", _domains(row["Domains"]))
    for intel in (ds.ip_intel or {}).values():
        if intel.get("asn"):
            add(int(intel["asn"]), "Hosting (Iris)", intel.get("domains") or ())
    origins = getattr(ds, "bgp_origins", None)
    if not _empty(origins):
        usual = bgp.main_origins(origins)
        for _, row in usual.iterrows():
            add(row["Origin"], "BGP origin", _domains(row["Domains"]))
        for _, row in origins[origins["Status"] == bgp.UNAUTHORIZED].iterrows():
            add(row["Origin"], "BGP unauthorized origin", _domains(row["Domains"]))
    routes = getattr(ds, "bgp_routes", None)
    if not _empty(routes):
        for path in routes["Path"].astype(str):
            for hop in [h.strip() for h in path.split("→") if h.strip()][:-1]:
                add(hop, "BGP upstream / transit")
    neighbours = getattr(ds, "bgp_neighbours", None)
    if not _empty(neighbours):
        for asn in neighbours["Origin"]:
            add(asn, "BGP more-specific prefix")
    return seen


def run_tor_networks(ds, networks):
    """
    The networks the run saw (hosting ASNs from VPNDB and Iris, and every AS BGPDB showed: origins, unauthorized
    origins, upstreams, neighbours) that are among the Tor exit networks, with how the run saw them and its domains.
    """
    if networks.empty or "asn" not in networks:
        return pd.DataFrame()
    seen = run_network_roles(ds)
    hits = networks[networks["asn"].isin(set(seen))].copy()
    hits.insert(0, "Seen as", hits["asn"].map(lambda a: ", ".join(sorted(seen[a][0]))))
    hits["Run domains"] = hits["asn"].map(lambda a: ", ".join(sorted(seen[a][1])[:10]))
    return hits


def _tor_network(ds):
    overview = ds.tor_overview
    st.markdown("**The Tor network at a glance**",
                help="The Tor Project's relay list placed with VPNDB's routing and country tables: where Tor traffic "
                     "leaves the internet and who runs it. One call per run, not counted against the VPNDB quota. "
                     "A domain hosted on a network that carries a large share of Tor exit traffic shares it with "
                     "anonymized traffic.")
    if not overview:
        st.caption("No Tor overview in this run: it is fetched with the VPNDB check (VPNDB key needed).")
        return
    counts = overview.get("counts") or {}
    columns = st.columns(5)
    for column, (label, key) in zip(columns, (("Relays", "relays"), ("Exit relays", "exitRelays"),
                                              ("Exit addresses", "exitAddresses"), ("Exit networks", "exitNetworks"),
                                              ("New exits (30 d)", "newExitRelays30d"))):
        column.metric(label, f"{counts.get(key, 0):,}")
    concentration = overview.get("concentration") or {}
    if concentration:
        st.caption(f"The 5 largest networks carry {concentration.get('top5Networks', 0):.0%} of all Tor exit traffic, "
                   f"the 10 largest {concentration.get('top10Networks', 0):.0%}. Relay list published "
                   f"{overview.get('relaysPublished', '?')}.")
    tables = tor_tables(overview)
    hits = run_tor_networks(ds, tables["Networks"])
    if not hits.empty:
        hosting = hits["Seen as"].str.contains("Hosting|BGP origin|unauthorized", regex=True)
        st.warning(f"{len(hits)} network(s) the run saw carry Tor exit traffic"
                   + (f", {int(hosting.sum())} of them hosting (or announcing) the run's IPs." if hosting.any() else
                      ": all of them only as transit or inside the hosting prefixes, not as the hosting network."))
        st.dataframe(hits, hide_index=True, width="stretch", column_config={
            "Seen as": st.column_config.Column("Seen as", help="How the run saw the network: hosting its IPs (VPNDB / "
                                               "Iris ASN), announcing them (BGP origin), announcing them without "
                                               "authorization, carrying the routes (upstream / transit) or announcing a "
                                               "more-specific prefix inside them (more-specific prefix)")})
    c_net, c_country = st.columns(2)
    for column, name, label in ((c_net, "Networks", "organization"), (c_country, "Countries", "country")):
        frame = tables[name]
        with column:
            st.markdown(f"**Exit traffic by {name.lower()[:-1] if name != 'Countries' else 'country'}**")
            if frame.empty:
                st.caption("No data.")
                continue
            top = frame.head(15).copy()
            top["Label"] = (("AS" + top["asn"].astype(str) + " ") if "asn" in top else "") + top[label].astype(str)
            fig = px.bar(top.iloc[::-1], x="Exit share %", y="Label", orientation="h",
                         hover_data=[c for c in ("exitAddresses", "exitRelays") if c in top])
            fig.update_layout(margin=dict(t=10, l=10, r=10, b=10), yaxis_title="", xaxis_title="% of Tor exit traffic")
            chart(fig, key=f"vpndb_tor_{name}", height=420)
    with st.expander(f"Exit prefixes ({len(tables['Prefixes']):,})"):
        st.dataframe(tables["Prefixes"].astype(str), hide_index=True, width="stretch")
