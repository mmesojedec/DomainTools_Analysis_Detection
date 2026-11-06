"""VPNDB building blocks shared by the VPNDB page, the Summary, the Domain profile and DNS & Hosting: tables, verdict cards, links and the CIDR range cards."""
import pandas as pd
import streamlit as st

from core.anonymizers import ANONYMIZER_CATEGORIES, anonymizer_rows, for_domains
from core.threat_detection.anonymizer_rules import THREAT_TYPES
from views import navigation
from views.alert_tools import THREAT_TYPE_KEY
from views.common import selected_rows, selection_key
from views.ip_card import render_ip_card

SHOWN_COLUMNS = ["IP", "Domains", "Category", "Provider", "Confidence", "Tor", "Sharing", "IOC Value", "Infrastructure",
                 "ASN", "AS Organization", "Country", "Last Seen", "Method", "Feeds", "Basis"]
COLUMN_CONFIG = {
    "Category": st.column_config.Column("Category", help="Tor, residential proxy, VPN, proxy or relay, by VPNDB"),
    "Confidence": st.column_config.Column("Confidence", help="VPNDB's confidence in the attribution (High, Medium, "
                                                             "Low, Very low); Basis says how it was reached"),
    "Sharing": st.column_config.Column("Sharing", help="How many users share the exit (VPNDB): HIGH means many"),
    "IOC Value": st.column_config.Column("IOC value", help="What the IP is worth as an actor indicator (VPNDB): LOW "
                                                          "means it identifies the service, not the actor"),
    "ASN": st.column_config.NumberColumn("ASN", format="%d"),
}


def render_anonymizer_summary(ds):
    """DNS & Hosting: one line on the VPNDB verdicts, with a link to the VPNDB page."""
    table = ds.anonymizers
    if _empty(table) and _empty(ds.prefixes):
        return
    flagged = anonymizer_rows(table)
    c_text, c_link = st.columns([4, 1.3], vertical_alignment="center")
    counts = " ".join(f":{CATEGORY_BADGES.get(name, 'violet')}-badge[{count} {name}]"
                      for name, count in flagged["Category"].value_counts().items()) if not flagged.empty else \
        ":green-badge[no VPN, proxy or Tor exit]"
    c_text.markdown(f":material/vpn_lock: **VPNDB:** {len(table) if not _empty(table) else 0:,} hosting IP(s) checked "
                    + counts + (f" · {len(ds.prefixes)} CIDR range(s)" if not _empty(ds.prefixes) else ""))
    navigation.link("vpndb", label="VPNDB page", container=c_link)
    st.divider()


def alerts_button(key, container=None, label="VPNDB alerts with their evidence"):
    """Opens the Alerts page filtered to the VPNDB rules."""
    navigation.jump_button("alerts", label, {THREAT_TYPE_KEY: list(THREAT_TYPES)}, button_key=f"{key}::alerts",
                           container=container, type="tertiary", icon=":material/warning:")


def export_button(key, sets, label, container=None):
    """Opens Data Export with the VPNDB tables `sets` ticked."""
    navigation.jump_button("export", label, {f"export_{s}": True for s in sets}, button_key=f"{key}::export",
                           container=container, type="tertiary", icon=":material/download:")


def selectable_table(frame, key, table, column_config=None, ds=None):
    """A table of VPNDB rows: selecting one shows everything the run knows about the IP below (views.ip_card)."""
    event = st.dataframe(frame, hide_index=True, width="stretch", column_config={**COLUMN_CONFIG, **(column_config or {})},
                         on_select="rerun",
                         selection_mode="single-row", key=selection_key(key, frame["IP"]))
    rows = selected_rows(event, frame)
    if not rows:
        st.caption("Select a row to see the IP in full: VPNDB's verdict and whole answer, its weekly history, where "
                   "the run saw it, and its place in the Tor network.")
        return
    ip = frame.iloc[rows[0]]["IP"]
    row = table[table["IP"] == ip].iloc[0].to_dict()
    with st.container(border=True):
        st.markdown(f"**{ip}**  :{CATEGORY_BADGES.get(row['Category'], 'gray')}-badge[{row['Category'] or 'No verdict'}]"
                    + (f"  {row['Provider']}" if row["Provider"] else ""))
        render_ip_card(row, key, ds)


def domain_verdict_text(table, domain):
    """'2 of 5 IPs: VPN nordvpn, Residential proxy rayobyte' for one domain; '' when VPNDB checked none of its IPs."""
    rows = for_domains(table, [domain])
    if rows.empty:
        return ""
    flagged = anonymizer_rows(rows)
    if flagged.empty:
        return f"0 of {len(rows)} IPs"
    kinds = flagged.groupby("Category")["Provider"].agg(lambda p: ", ".join(sorted({x for x in p if x})[:3]))
    return f"{len(flagged)} of {len(rows)} IPs: " + "; ".join(f"{name} {prov}".strip() for name, prov in kinds.items())


CATEGORY_BADGES = {"Tor": "red", "Residential proxy": "orange", "VPN": "violet", "Proxy": "violet", "Relay": "blue",
                   "Hosting": "gray", "Not anonymous": "green", "Not observed": "gray", "Not checked": "gray", "No known exits": "green",
                   "VPN / proxy exits": "violet"}


def _empty(frame):
    return frame is None or frame.empty


def ip_check_only(ds):
    """True for an IP check run: VPNDB verdicts (IPs or CIDR ranges) and no other data."""
    return ((not _empty(ds.anonymizers) or not _empty(ds.prefixes)) and ds.combined.empty and ds.ssl.empty
            and not ds.enrichment)


PREFIX_CONFIG = {
    "Providers": st.column_config.Column("Providers", width="large",
                                         help="Every provider with known exits in the range and its share of them"),
    "Known Exits": st.column_config.NumberColumn("Known exits", help="Exit addresses VPNDB knows inside the range"),
    "Coverage": st.column_config.Column("Coverage", help="Known exits as a share of the range's addresses"),
    "Single Tenant": st.column_config.CheckboxColumn("Single tenant", help="One provider holds 95 % or more"),
    "Announced": st.column_config.CheckboxColumn("Announced", help="The routing table announces exactly this range"),
    "ASN": st.column_config.NumberColumn("ASN", format="%d"),
}


RANGE_SETS = ("vpndb_ranges", "vpndb_range_addresses", "vpndb_range_ips")   # Data Export sets of CIDR targets
RANGE_IP_COLUMNS = ["IP", "Category", "Provider", "Confidence", "Method", "Pool", "Tunnel", "Probes (30 d)",
                    "Last Seen", "Infrastructure", "ASN", "AS Organization", "Country", "Feeds", "Basis", "Note"]


def range_ip_table(range_ips, addresses, cidr):
    """One row per address of `cidr` (VPNDB bulk), with the pool, tunnel and probes of the ones probing exited through;
    measured exits first, then the ones VPNDB interpolates from the range, then the rest."""
    rows = range_ips[range_ips["CIDR"] == cidr] if not _empty(range_ips) else pd.DataFrame(columns=RANGE_IP_COLUMNS)
    if rows.empty:
        return rows
    seen = addresses[addresses["CIDR"] == cidr] if not _empty(addresses) else pd.DataFrame(columns=["IP"])
    probed = seen.set_index("IP")[["Pool", "Methods", "Observations"]] if not seen.empty else pd.DataFrame(
        columns=["Pool", "Methods", "Observations"])
    table = rows.join(probed.rename(columns={"Methods": "Tunnel", "Observations": "Probes (30 d)"}), on="IP")
    exit_ = table["Category"].isin(ANONYMIZER_CATEGORIES)
    order = (~exit_).astype(int) * 2 + (exit_ & (table["Method"] == "interpolated")).astype(int)   # measured first
    table[["Pool", "Tunnel"]] = table[["Pool", "Tunnel"]].astype(object).where(table[["Pool", "Tunnel"]].notna(), "")
    return table.assign(_order=order).sort_values("_order", kind="stable")[RANGE_IP_COLUMNS]


def render_networks(ds):
    """CIDR targets: the providers inside each range (VPNDB /prefix), and every address of it, one row per IP."""
    ranges, addresses = ds.prefixes, ds.prefix_addresses
    st.markdown("#### CIDR ranges", help="Each CIDR target looked up in VPNDB as a range: which VPN or proxy providers "
                                         "have exits inside it and in what share, and how much of it VPNDB knows. "
                                         "Ranges VPNDB knows exits in (IPv4, up to 1,024 addresses) are also checked "
                                         "address by address. CIDR ranges are looked up in VPNDB only.")
    st.dataframe(ranges, hide_index=True, width="stretch", column_config=PREFIX_CONFIG)
    for row in ranges.to_dict("records"):
        ips = range_ip_table(ds.range_ips, addresses, row["CIDR"])
        exits = ips[ips["Category"].isin(ANONYMIZER_CATEGORIES)] if not ips.empty else ips
        inferred = int((exits["Method"] == "interpolated").sum()) if not exits.empty else 0
        label = f"{row['CIDR']}  :{CATEGORY_BADGES.get(row['Category'], 'violet')}-badge[{row['Category']}]" + \
            (f"  {row['Top Provider']}" if row["Top Provider"] else "") + \
            (f" · {len(ips):,} IPs: {len(exits) - inferred} measured exits, {inferred} interpolated"
             if not ips.empty else "")
        with st.expander(label, expanded=len(ranges) == 1):
            facts = [{"Field": name, "Value": str(row[name])} for name in ranges.columns
                     if name != "CIDR" and row.get(name) is not None and str(row[name]) not in ("", "nan", "<NA>")]
            st.dataframe(facts, hide_index=True, width="stretch")
            if not ips.empty:
                st.caption(f"Every address of the range checked in VPNDB ({len(ips):,} IPs, one query each). "
                           "**Measured** exits first (method probe or scan: VPNDB saw traffic leave through the "
                           "address), then **interpolated** ones (method interpolated: not seen themselves, attributed "
                           "from the range's measured share, with the confidence that share gives), then the rest. "
                           "Pool, tunnel and probes are filled in for the addresses VPNDB's probing exited through in "
                           "the last 30 days.")
                st.dataframe(ips, hide_index=True, width="stretch", column_config=COLUMN_CONFIG)
            elif row["Known Exits"]:
                st.caption("Not checked address by address: IPv6, or larger than 1,024 addresses (see Data sources).")
            else:
                st.caption("Not checked address by address: VPNDB knows no exit in this range.")


def render_ip_check(ds, alerts):
    """Summary of an IP check run: one card per IP and per CIDR range with VPNDB's verdict and evidence."""
    table = ds.anonymizers
    if _empty(table):
        st.subheader("IP check (VPNDB)")
        render_networks(ds)
        export_button("ip_check_ranges", RANGE_SETS, "Download the verdicts (Data Export → CIDR ranges)")
        return
    st.subheader("IP check (VPNDB)", help="Who is behind each IP target: VPN, residential proxy, Tor or hosting, with "
                                         "VPNDB's confidence and evidence. Not observed is not an all-clear: VPNDB "
                                         "only knows the exits it measured or that public lists name, and it does not "
                                         "collect IPv6.")
    flagged = anonymizer_rows(table)
    c_all, c_flagged, c_alerts = st.columns(3)
    c_all.metric("IPs checked", f"{len(table):,}")
    c_flagged.metric("VPN, proxy or Tor", f"{len(flagged):,}")
    c_alerts.metric("Alerts", f"{len(alerts):,}")
    st.dataframe(table[["IP", "Category", "Provider", "Confidence", "Tor", "IOC Value", "ASN", "AS Organization",
                        "Country", "Note"]], hide_index=True, width="stretch", column_config=COLUMN_CONFIG)
    for row in table.to_dict("records"):
        color = CATEGORY_BADGES.get(row["Category"], "gray")
        label = f"{row['IP']}  :{color}-badge[{row['Category'] or 'No verdict'}]" + \
            (f"  {row['Provider']}" if row["Provider"] else "")
        with st.expander(label, expanded=row["Category"] in ANONYMIZER_CATEGORIES and len(table) <= 5):
            render_ip_card(row, f"ip_check::{row['IP']}", ds)
    if not _empty(ds.prefixes):
        render_networks(ds)
    if not alerts.empty:
        alerts_button("ip_check", label=f"{len(alerts)} alert(s) with their evidence")
    export_button("ip_check", ("vpndb_verdicts",) + (RANGE_SETS if not _empty(ds.prefixes) else ()),
                  "Download the verdicts (Data Export → VPN / proxy / Tor)")
