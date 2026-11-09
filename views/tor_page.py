"""
Tor network page (Infrastructure): the whole Tor network today, from VPNDB's /tor overview: relays and exits, which
networks and countries carry Tor exit traffic, and whether the run's hosting networks are among them. Statistics only:
the run's own IPs are checked for Tor on the VPNDB page and each IP card.
"""
import pandas as pd
import plotly.express as px
import streamlit as st

from core.anonymizers import tor_tables
from views.anonymizer_view import _empty
from views.common import chart

HOW_TO_READ = (
    "A picture of the whole Tor network today: how many relays and exits there are, and which networks and countries "
    "carry Tor exit traffic. These are network-wide statistics, not verdicts on your domains.",
    "A warning appears if one of **your** domains is hosted on a network that also carries Tor exit traffic: it "
    "shares that network with anonymized traffic (alert *Hosted Among Tor Exits*).",
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


def run_tor_networks(ds, networks):
    """The run's hosting networks (VPNDB and Iris ASNs) among the Tor exit networks, with the domains on them."""
    if networks.empty or "asn" not in networks:
        return pd.DataFrame()
    used = {}
    table = ds.anonymizers
    for row in (table.to_dict("records") if not _empty(table) else []):
        if pd.notna(row["ASN"]):
            used.setdefault(int(row["ASN"]), set()).update(d.strip() for d in str(row["Domains"]).split(",") if d.strip())
    for intel in (ds.ip_intel or {}).values():
        if intel.get("asn"):
            used.setdefault(int(intel["asn"]), set()).update(intel.get("domains") or ())
    hits = networks[networks["asn"].isin(set(used))].copy()
    hits["Run domains"] = hits["asn"].map(lambda a: ", ".join(sorted(used[a])[:10]))
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
        st.warning(f"{len(hits)} of the run's hosting network(s) carry Tor exit traffic.")
        st.dataframe(hits, hide_index=True, width="stretch")
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
