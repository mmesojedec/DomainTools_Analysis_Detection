"""
Summary → IP and range targets: per address or range entered as a target, what passive DNS, Iris, the certificates,
BGPDB and VPNDB returned for it, the names and domains seen on it, and Analyze for those domains.
"""
import streamlit as st

from core.address_targets import address_targets, names_on, related_domains, target_table
from views import navigation
from views.hunt_actions import analyze_button

HELP = ("Each IP address or CIDR range you entered, looked up in every source that takes addresses: passive DNS "
        "(DNSDB: every name that resolved to it or into the range), Iris Investigate (the domains whose current IPs "
        "are on it), the certificates naming it (a SAN IP in the range), its BGP routing (BGPDB: the announcement "
        "covering it and, for a range, every prefix announced inside it) and VPNDB. Pick a target for its names and "
        "domains, and analyze them as a new run.")


def render_address_targets(ds, targets, high_risk=70):
    """Nothing when the run has no IP or CIDR target."""
    if not address_targets(targets):
        return
    st.subheader("IP and range targets", help=HELP)
    table = target_table(ds, targets, high_risk)
    picked = st.dataframe(table, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
                          key="address_targets_table", column_config={
                              "Last Seen": st.column_config.DatetimeColumn(format="YYYY-MM-DD"),
                              "High-risk in Iris": st.column_config.NumberColumn(
                                  help=f"Iris risk score {high_risk} or more")})
    rows = picked.selection.rows if picked and picked.selection else []
    target = table.iloc[rows[0]]["Target"] if rows else table.iloc[0]["Target"]
    st.caption(f"**{target}**" + ("" if rows else " (select a row for another target)"))
    names, iris = st.columns(2)
    with names:
        found = names_on(ds.pdns, target)
        st.markdown(f"**Names in passive DNS** · {found['Name'].nunique():,}")
        st.dataframe(found.drop_duplicates("Name").head(500), hide_index=True, width="stretch", height=260)
    with iris:
        on = ds.target_domains[ds.target_domains["Target"] == target] if not ds.target_domains.empty else None
        st.markdown(f"**Domains in Iris** · {0 if on is None else len(on):,}")
        if on is None or on.empty:
            st.caption("None found, or not looked up (DomainTools API key needed).")
        else:
            st.dataframe(on.drop(columns=["Target"]), hide_index=True, width="stretch", height=260)
    domains = related_domains(ds, target, high_risk)
    row = st.container(horizontal=True, vertical_alignment="center")
    if domains:
        analyze_button(domains, target, key=f"address_analyze::{target}", label=f"Analyze {len(domains)} domain(s)",
                       container=row, help="Analyzes the riskiest Iris domains and the passive DNS names on this "
                                           f"target ({', '.join(domains[:3])}{', …' if len(domains) > 3 else ''}) "
                                           "as a new run linked to this one.")
    from views.ip_profile_view import open_button
    open_button(target, label="Open in IP profile", key=f"address_profile::{target}", container=row)
    if table.loc[table["Target"] == target, "Prefix"].iloc[0]:
        navigation.link("bgp", "Its routing on the BGP page", icon=":material/hub:", container=row)
