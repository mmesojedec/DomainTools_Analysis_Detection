"""Indicator Sightings page: every saved run and offline dataset where one indicator was observed."""
import pandas as pd
import streamlit as st

from core.helpers import md_escape
from core.seen import MIN_PARTIAL, RUN, normalize, search, summary
from views import navigation
from views.history_view import RECENT_PICK_KEY
from views.sidebar import request_offline_load, start_hunt

ANALYZABLE = {"Target", "IP", "Hostname", "Name Server", "MX"}   # kinds that make a sensible new run on their own
SHOWN = ["Found in", "When", "Name", "Target list", "Domain", "Kind", "Value", "Alerts on domain"]


def _render_summary(frame):
    stats = summary(frame)
    columns = st.columns(4)
    columns[0].metric("Runs", f"{stats['runs']:,}", help="Saved runs (dt_runs/) where it appears")
    columns[1].metric("Datasets", f"{stats['datasets']:,}", help="Saved offline datasets where it appears")
    columns[2].metric("Target lists", f"{stats['target_lists']:,}", help="Different investigations (target lists)")
    columns[3].metric("Domains", f"{stats['domains']:,}", help="Analyzed domains it was seen with")
    if stats["first"] is not None and not pd.isna(stats["first"]):
        st.caption(f"First seen {stats['first']:%Y-%m-%d %H:%M} UTC · last seen {stats['last']:%Y-%m-%d %H:%M} UTC "
                   "(the oldest and newest run or dataset it appears in)")


def _render_actions(row):
    """What can be done with the picked match: open its run, load its dataset, analyze the indicator itself."""
    with st.container(horizontal=True, vertical_alignment="center"):
        if row["Found in"] == RUN:
            navigation.jump_button("history", "Open in Runs & Diffs", button_key="seen_open",
                                   state={RECENT_PICK_KEY: row["key"], f"hist_detail_{row['key']}": row["id"]},
                                   icon=":material/history:", help="Opens this run: its details, comparisons and trends")
        else:
            st.button("Load offline dataset", key="seen_load", icon=":material/upload_file:",
                      on_click=request_offline_load, args=(row["id"],),
                      help="Loads this dataset and re-analyzes it with no API calls")
        if row["Kind"] in ANALYZABLE:
            st.button(f"Analyze {row['Value']} as a new run", key="seen_analyze", icon=":material/play_arrow:",
                      on_click=start_hunt, args=([row["Value"]], f"Sightings: {row['Value']}"),
                      help="A new live run on this indicator with the current collection options (makes API queries)")


def render_seen_page():
    st.header("Indicator Sightings", help="Every saved run (dt_runs/) and offline dataset (dt_offline/) where an "
                                          "indicator was observed. Local files only: no API query.")
    st.caption("Where was this indicator observed before, in which investigation and with which domains? Enter an IP, domain or hostname, name server, MX host, certificate SHA-256, web tracker code (e.g. "
               "G-…, UA-…, GTM-…) or email address. Defanged input (`a[.]com`, `hxxps://…`) is fine.")
    with st.container(horizontal=True, vertical_alignment="bottom"):
        query = st.text_input("Indicator", key="seen_query", placeholder="e.g. 198.51.100.7, ns1.example.net, "
                                                                         "hostmaster@example.com", width="stretch")
        partial = st.checkbox("Partial match", key="seen_partial",
                              help=f"Also values that contain it (at least {MIN_PARTIAL} characters), e.g. "
                                   "`dynect.net` finds every name server there")
        datasets = st.checkbox("Offline datasets", key="seen_datasets", value=True,
                               help="Also search the offline datasets (the first search reads each one, a second "
                                    "or two; later searches are instant)")
    if not normalize(query):
        st.caption("Emails are recorded with runs from now on; older runs match emails through their offline "
                   "datasets.")
        return
    with st.spinner("Searching the saved runs and offline datasets..."):
        frame = search(query, partial, datasets)
    if frame.empty:
        st.warning(f"**{md_escape(normalize(query))}** is not in any saved run"
                   + (" or offline dataset." if datasets else ".") + " Runs are kept per target list (Runs & Diffs → "
                   "Manage Runs sets how many), so older ones may have been deleted.", icon=":material/search_off:")
        return
    _render_summary(frame)
    st.caption("Each row is one sighting: the indicator observed in a run or dataset, with the domain it was seen with.")
    picked = st.dataframe(
        frame[SHOWN], hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
        key="seen_table",
        column_config={"When": st.column_config.DatetimeColumn("When (UTC)", format="YYYY-MM-DD HH:mm"),
                       "Value": st.column_config.TextColumn(width="medium"),
                       "Alerts on domain": st.column_config.NumberColumn(
                           help="Alerts the run raised on that domain (runs only)")})
    rows = picked.selection.rows if picked and picked.selection else []
    row = frame.iloc[rows[0] if rows else 0]
    when = f"{row['When']:%Y-%m-%d %H:%M} UTC" if not pd.isna(row["When"]) else "date unknown"
    st.caption(f"Picked: {row['Found in'].lower()} of {md_escape(row['Target list'])} ({when})"
               + ("" if rows else ", the newest. Click a row to pick another."))
    _render_actions(row)
