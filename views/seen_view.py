"""
Indicator Sightings (a tab of the Recent runs page): every saved run and offline dataset where one indicator was
observed, when, and with which domains; with no indicator yet, the indicators your runs share across target lists.
"""
import pandas as pd
import plotly.express as px
import streamlit as st

from core.helpers import md_escape
from core.persistence import load_all_runs
from core.run_views import top_shared
from core.seen import MIN_PARTIAL, RUN, normalize, search, summary
from views import navigation
from views.common import chart
from views.history_view import RECENT_PICK_KEY, _list_labels
from views.sidebar import request_offline_load, start_hunt

QUERY_KEY = "seen_query"
SUGGESTIONS_KEY = "seen_suggestions"

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


def _set_query(value):
    st.session_state[QUERY_KEY] = value


def _render_suggestions():
    """With no indicator typed: the indicators that link two or more of your target lists, to search with a click."""
    all_runs = load_all_runs()
    rows = top_shared(all_runs, _list_labels(all_runs))
    if not rows:
        st.caption("Emails are recorded with runs from now on; older runs match emails through their offline "
                   "datasets.")
        return
    st.markdown("**Shared across your target lists**",
                help="Indicators that runs of two or more different target lists found, on different domains (CDN "
                     "IPs, large DNS providers and values in many lists left out). The same links as the cards' "
                     "*Shares* and the Hunting graph's dashed lines.")
    picked = st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", on_select="rerun",
                          selection_mode="single-row", key=SUGGESTIONS_KEY,
                          column_config={"Lists": st.column_config.NumberColumn("Target lists", width="small"),
                                         "Target lists": st.column_config.TextColumn("Seen in", width="large")})
    chosen = picked.selection.rows if picked and picked.selection else []
    row = rows[chosen[0] if chosen else 0]
    st.button(f"Show sightings of {row['Indicator']}", key="seen_suggest", type="primary",
              icon=":material/visibility:", on_click=_set_query, args=(row["Indicator"],),
              help="Searches it below" + ("" if chosen else ". Click a row to pick another indicator."))


def _render_timeline(frame):
    """Each sighting as a dot over time, one lane per target list (color: kind, symbol: run or dataset)."""
    data = frame.dropna(subset=["When"]).copy()
    if data["id"].nunique() < 2:
        return
    data["When"] = data["When"].dt.tz_convert(None)
    fig = px.scatter(data, x="When", y="Target list", color="Kind", symbol="Found in",
                     hover_data={"Domain": True, "Value": True, "Name": True})
    fig.update_traces(marker={"size": 12, "line": {"width": 1, "color": "white"}})
    fig.update_layout(height=max(200, 80 + 40 * data["Target list"].nunique()),
                      margin={"l": 10, "r": 10, "t": 10, "b": 10}, xaxis_title="UTC", yaxis_title=None,
                      legend={"orientation": "h", "y": -0.3})
    chart(fig)


def _render_actions(row, pick_run=None):
    """What can be done with the picked match: open its run, load its dataset, analyze the indicator itself."""
    with st.container(horizontal=True, vertical_alignment="center"):
        if row["Found in"] == RUN:
            if pick_run is not None:
                st.button("Pick in Recent runs", key="seen_pick", icon=":material/schedule:", on_click=pick_run,
                          args=(row["id"],), help="Shows this run in the Recent runs tab, with its run actions and "
                                                  "the other indicators it shares")
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


def render_sightings(pick_run=None):
    st.caption("Where was this indicator observed before, in which investigation and with which domains? Enter an IP, domain or hostname, name server, MX host, certificate SHA-256, web tracker code (e.g. "
               "G-…, UA-…, GTM-…) or email address. Defanged input (`a[.]com`, `hxxps://…`) is fine.")
    with st.container(horizontal=True, vertical_alignment="bottom"):
        query = st.text_input("Indicator", key=QUERY_KEY, placeholder="e.g. 198.51.100.7, ns1.example.net, "
                                                                         "hostmaster@example.com", width="stretch")
        partial = st.checkbox("Partial match", key="seen_partial",
                              help=f"Also values that contain it (at least {MIN_PARTIAL} characters), e.g. "
                                   "`dynect.net` finds every name server there")
        datasets = st.checkbox("Offline datasets", key="seen_datasets", value=True,
                               help="Also search the offline datasets (the first search reads each one, a second "
                                    "or two; later searches are instant)")
    if not normalize(query):
        _render_suggestions()
        return
    with st.spinner("Searching the saved runs and offline datasets..."):
        frame = search(query, partial, datasets)
    if frame.empty:
        st.warning(f"**{md_escape(normalize(query))}** is not in any saved run"
                   + (" or offline dataset." if datasets else ".") + " Runs are kept per target list (Runs & Diffs → "
                   "Manage Runs sets how many), so older ones may have been deleted.", icon=":material/search_off:")
        return
    _render_summary(frame)
    _render_timeline(frame)
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
    _render_actions(row, pick_run)
