"""Subdomain Triage lens: the Hostname Inventory's subdomains ranked by phishing, brand and lifecycle signals."""
import pandas as pd
import streamlit as st

from config import HOSTNAME_NEW_DAYS
from core.subdomain_triage import LEVELS, STRONG_SIGNALS, TRIAGE_SIGNALS, build_subdomain_triage
from views.common import selected_rows, selection_key
from views.sidebar import focus_on_hostnames, rerun_app_if_requested

COLUMN_HELP = {
    "Score": "Sum of the signal weights: " + "; ".join(f"{name} {weight}" for name, (weight, _) in TRIAGE_SIGNALS.items()),
    "Level": f"High: score 6+ with a strong name signal ({', '.join(STRONG_SIGNALS)}); Medium: a strong name signal "
             "or score 4+; Low: any other signal",
    "Signals": "; ".join(f"{name}: {text}" for name, (_, text) in TRIAGE_SIGNALS.items()).replace(
        "the last N days", f"the last {HOSTNAME_NEW_DAYS} days"),
    "Matched": "The phishing words, brands and embedded domains found in the name",
    "First Seen": "Earliest certificate Not Before or passive DNS first seen",
    "Certificates": "Collected certificates naming this hostname exactly",
    "pDNS Records": "Passive DNS records for this exact name",
    "Current Values": "A / AAAA / CNAME values seen within a day of the name's latest resolution",
    "Latest Certificate Hash": "Hash of the newest certificate naming it, for a lookup in another tool",
    "Platform": "The shared platform the domain belongs to (free hosting, serverless, free subdomains), if any",
}


def dataset_triage(ds):
    if "subdomain_triage" not in ds.derived:
        ds.derived["subdomain_triage"] = build_subdomain_triage(ds.hostname_inventory)
    return ds.derived["subdomain_triage"]


def render_triage_lens(ds):
    st.header("Subdomain Triage", help="The subdomains of the Hostname Inventory ranked by signals that phishing and "
                                       "malware subdomains tend to show. Most useful on shared platforms (pages.dev, "
                                       "workers.dev, free subdomain services), where the domain's own risk says nothing "
                                       "about its subdomains. Full collected history, like the Hostname Inventory.")
    triage = dataset_triage(ds)
    if triage.empty:
        st.info("No subdomains found for the selected domains.")
        return
    level = triage["Level"]
    metrics = [("High", int((level == "High").sum())), ("Medium", int((level == "Medium").sum())),
               ("Low", int((level == "Low").sum())), ("Subdomains", len(triage))]
    for col, (label, value) in zip(st.columns(len(metrics)), metrics):
        col.metric(label, f"{value:,}", help=COLUMN_HELP["Level"] if label != "Subdomains" else
                   "Hostnames below the selected domains (the domains themselves and wildcard names are left out)")
    platforms = sorted(p for p in triage["Platform"].unique() if p)
    if platforms:
        st.info(f"**Shared platforms:** {', '.join(platforms)} give out subdomains to anyone, so judge each subdomain "
                "on its own signals, not on the domain's risk score.")
    _render_triage_table(ds, triage)


@st.fragment
def _render_triage_table(ds, triage):
    """A fragment: filters and selection rerun only this part."""
    c_level, c_signal, c_domain, c_search = st.columns([2, 2, 2, 2])
    levels = c_level.multiselect("Level", LEVELS, default=["High", "Medium"], key="triage_levels",
                                 placeholder="Any level (including no signal)")
    signals = c_signal.multiselect("Has signal", list(TRIAGE_SIGNALS), key="triage_signals", placeholder="Any signal",
                                   help="Only hostnames with all of these signals")
    domains = c_domain.multiselect("Domain", sorted(triage["Apex"].unique()), key="triage_domains",
                                   placeholder="All domains")
    search = c_search.text_input("Hostname or match contains", key="triage_search").strip().lower()
    shown = triage
    if levels:
        shown = shown[shown["Level"].isin(levels)]
    for name in signals:
        shown = shown[shown["Signals"].str.split(", ").map(lambda found, n=name: n in found)]
    if domains:
        shown = shown[shown["Apex"].isin(domains)]
    if search:
        shown = shown[shown["Hostname"].str.contains(search, regex=False)
                      | shown["Matched"].str.contains(search, regex=False)]
    st.caption(f"{len(shown):,} of {len(triage):,} subdomain(s), highest score first, then newest. Select rows to focus "
               "the other lenses on them or to copy them.")
    if shown.empty:
        return
    shown = shown.reset_index(drop=True)
    view = shown.copy()
    view["First Seen"] = pd.to_datetime(view["First Seen"], errors="coerce").dt.tz_localize("UTC") \
        .dt.tz_convert(ds.timezone).dt.tz_localize(None)
    column_config = {col: st.column_config.Column(col, help=text) for col, text in COLUMN_HELP.items()}
    column_config["First Seen"] = st.column_config.DatetimeColumn("First Seen", help=COLUMN_HELP["First Seen"],
                                                                  format="YYYY-MM-DD HH:mm")
    column_config["Score"] = st.column_config.ProgressColumn("Score", help=COLUMN_HELP["Score"], min_value=0,
                                                             max_value=int(triage["Score"].max()) or 1, format="%d")
    event = st.dataframe(view, hide_index=True, column_config=column_config, on_select="rerun",
                         selection_mode="multi-row", key=selection_key("triage_table", shown["Hostname"]))
    rows = selected_rows(event, shown)
    picked = shown.iloc[rows] if rows else shown
    hostnames = list(picked["Hostname"])
    c_focus, c_copy = st.columns([1, 3])
    c_focus.button(f"Focus on {len(rows):,} hostname(s)" if rows else "Focus on hostnames", disabled=not rows,
                   on_click=focus_on_hostnames, args=(hostnames,), key="triage_focus", icon=":material/filter_alt:",
                   help="Adds the selected hostnames to Focus on hostnames in the sidebar: every lens then shows only "
                        "their passive DNS, certificates and certificate events. No new lookups.")
    with c_copy.expander(f"Copy {len(hostnames):,} hostname(s)" + (" (selected)" if rows else " (every row shown)")):
        st.code("\n".join(hostnames), language=None)
    rerun_app_if_requested()
