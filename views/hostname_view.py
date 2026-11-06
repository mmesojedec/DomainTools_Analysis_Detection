"""Hostname Inventory lens: every hostname a run's certificates and passive DNS mention, with lifecycle flags."""
import pandas as pd
import streamlit as st

from config import HOSTNAME_NEW_DAYS
from core.helpers import md_escape
from core.hostnames import FLAG_HELP
from views.common import capped_table, selected_rows, selection_key

DATE_COLUMNS = ["First Certificate", "Latest Certificate", "Certificate Expires", "pDNS First Seen", "pDNS Last Seen"]
LINK_DATE_COLUMNS = ["Not Before", "Not After"]
COLUMN_HELP = {
    "Focus": "In the current hostname focus (Global View Filters)",
    "Flags": "; ".join(f"{flag}: {text}" for flag, text in FLAG_HELP.items()),
    "Certificates": "Collected certificates naming this hostname exactly",
    "First Certificate": "Earliest Not Before of those certificates",
    "Latest Certificate": "Most recent Not Before of those certificates",
    "Latest Certificate Hash": "Hash of that newest certificate (SHA-256 from the Certificate API, SHA-1 from Domain "
                               "History); every certificate is listed in the table below",
    "Certificate Expires": "Latest Not After of those certificates",
    "pDNS First Seen": "First time passive DNS saw this exact name",
    "pDNS Last Seen": "Last time passive DNS saw this exact name",
    "pDNS Records": "Passive DNS records for this exact name (all record types)",
    "Current Values": "A / AAAA / CNAME values seen within a day of the name's latest resolution",
    "Cert Events": "Certificate Events observations of this hostname",
}


def _shift(frame, timezone, columns=DATE_COLUMNS):
    out = frame.copy()
    for col in columns:
        values = pd.to_datetime(out[col], errors="coerce")
        out[col] = values.dt.tz_localize("UTC").dt.tz_convert(timezone).dt.tz_localize(None)
    return out


def render_hostname_lens(ds):
    st.header("Hostname Inventory", help="Every hostname under the selected domains that the run's certificates, passive "
                                         "DNS or certificate events mention, over the full collected history (not only "
                                         "the analysis window). Service names such as _dmarc are left out.")
    inventory = ds.hostname_inventory
    if inventory is None or inventory.empty:
        st.info("No hostnames found for the selected domains.")
        return
    flags = inventory["Flags"].fillna("")
    metrics = [("Hostnames", len(inventory)), ("With certificates", int((inventory["Certificates"] > 0).sum())),
               ("Certificate, never resolved", int(flags.str.contains("never resolved").sum())),
               ("Resolves, no certificate", int(flags.str.contains("no certificate").sum())),
               (f"New ({HOSTNAME_NEW_DAYS} days)", int(flags.str.contains("New").sum())),
               ("Sensitive name", int(flags.str.contains("Sensitive").sum()))]
    for col, (label, value) in zip(st.columns(len(metrics)), metrics):
        col.metric(label, value, help=FLAG_HELP.get(label.split(" (")[0]))
    _render_inventory_table(ds, inventory, flags)


@st.fragment
def _render_inventory_table(ds, inventory, flags):
    """A fragment: filtering and selecting hostnames reruns only the tables, not the whole app."""
    c_flags, c_search, c_focus = st.columns([3, 2, 1])
    wanted = c_flags.multiselect("Show hostnames flagged", list(FLAG_HELP), placeholder="Any (no flag filter)",
                                 key="inventory_flags")
    search = c_search.text_input("Hostname contains", key="inventory_search").strip().lower()
    only_focus = c_focus.toggle("Focus only", value=False, key="inventory_focus_only", disabled=not ds.host_focus,
                                help="Only hostnames in the current hostname focus")
    shown = inventory
    if wanted:
        shown = shown[flags.loc[shown.index].map(lambda f: any(flag in f for flag in wanted))]
    if search:
        shown = shown[shown["Hostname"].str.contains(search, regex=False)]
    if only_focus:
        shown = shown[shown["Focus"]]
    capped = [d for d, c in ds.pdns_coverage.items() if c.get("truncated") and d in set(shown["Apex"])]
    st.caption(f"{len(shown):,} of {len(inventory):,} hostname(s). Sorted by domain and name; click a column to sort."
               + (f" Passive DNS hit its result limit for {md_escape(', '.join(capped))}, so 'Certificate, never "
                  "resolved' is not flagged there." if capped else ""))
    column_config = {col: st.column_config.Column(col, help=text) for col, text in COLUMN_HELP.items()}
    column_config.update({col: st.column_config.DatetimeColumn(col, help=COLUMN_HELP[col], format="YYYY-MM-DD HH:mm")
                          for col in DATE_COLUMNS})
    event = capped_table(_shift(shown, ds.timezone), label="hostnames", column_config=column_config,
                         on_select="rerun", selection_mode="multi-row",
                         key=selection_key("inventory_table", shown["Hostname"]))
    rows = selected_rows(event, shown)
    _render_certificate_links(ds, shown.iloc[rows]["Hostname"] if rows else shown["Hostname"], bool(rows))


def _render_certificate_links(ds, hostnames, selected):
    """Certificates of the selected hostnames (or of every hostname shown), with their hashes for a later lookup."""
    links = ds.hostname_certificates
    st.subheader("Certificates by hostname", help="Each certificate that names a hostname, or carries the wildcard one "
                                                   "level above it, with its hash for a lookup in another tool")
    if links is None or links.empty:
        st.info("No collected certificate with a hash names these hostnames.")
        return
    links = links[links["Hostname"].isin(set(hostnames))]
    st.caption((f"{len(links):,} certificate link(s) for the {len(set(hostnames)):,} selected hostname(s)." if selected else
                f"{len(links):,} certificate link(s) for the hostnames above. Select rows in the inventory to narrow "
                "this to those hostnames.") + " *Named*: the certificate lists the hostname; *Wildcard*: it covers the "
               "hostname through a wildcard.")
    if links.empty:
        return
    capped_table(_shift(links, ds.timezone, LINK_DATE_COLUMNS), label="certificate links", column_config={
        col: st.column_config.DatetimeColumn(col, format="YYYY-MM-DD HH:mm") for col in LINK_DATE_COLUMNS})
    hashes = "\n".join(dict.fromkeys(links["Certificate Hash"]))
    with st.expander(f"Copy the {hashes.count(chr(10)) + 1:,} certificate hash(es)"):
        st.code(hashes, language=None)
