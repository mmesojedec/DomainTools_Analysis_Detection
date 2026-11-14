"""
Recent runs page (top menu): the newest saved runs as a timeline, cards or a table, with what changed, the risk trend
and the indicators each run shares with other target lists; and Indicator Sightings, where any of those indicators
(or one you type) was observed before. Local files only (dt_runs/, dt_offline/): no API query.
"""
import pandas as pd
import streamlit as st

from core.helpers import md_escape
from core.offline import list_offline_datasets
from core.persistence import load_all_runs, load_settings
from core.run_history import format_created, run_summary
from core.run_views import filter_overview, recent_overview, run_indicators, shared_indicators, top_severity
from core.use_cases import PROFILES_SETTING
from views import navigation
from views.history_view import (
    _list_labels,
    _offline_by_run,
    _recent_row,
    _targets_label,
    _use_case_title,
    render_run_actions,
)
from views.run_visuals import CARDS_PER_ROW, recent_timeline, run_card, runs_calendar
from views.seen_view import QUERY_KEY, render_sightings

TAB_KEY = "recent_tab"
RUNS_TAB, SIGHTINGS_TAB = "Recent runs", "Indicator Sightings"
VIEW_KEY = "recent_view"           # Timeline / Cards / Table
SELECTED_KEY = "recent_selected"   # the run id picked in Recent runs (any view)
LIMIT_KEY = "recent_limit"
FILTER_KEY, ALERTS_KEY, NEW_KEY = "recent_filter", "recent_only_alerts", "recent_only_new"
VIEWS = ("Timeline", "Cards", "Table")
LIMITS = (10, 25, 50, 100)
SHARED_TABLE_KEY = "recent_shared_table"
INDICATOR_KEY = "recent_indicator"


def select_run(run_id):
    st.session_state[SELECTED_KEY] = run_id


def find_sightings(value):
    """Callback: show the Indicator Sightings tab searching `value`."""
    st.session_state[QUERY_KEY] = str(value)
    st.session_state[TAB_KEY] = SIGHTINGS_TAB


def pick_run(run_id):
    """Callback (Indicator Sightings): pick a saved run in the Recent runs tab, clearing filters that hide it."""
    st.session_state[SELECTED_KEY] = run_id
    st.session_state[TAB_KEY] = RUNS_TAB
    for key, value in ((FILTER_KEY, ""), (ALERTS_KEY, False), (NEW_KEY, False)):
        st.session_state[key] = value


def open_sightings(value):
    """From another page: open Recent runs → Indicator Sightings searching `value`."""
    navigation.go("recent", **{QUERY_KEY: str(value), TAB_KEY: SIGHTINGS_TAB})


def _controls():
    with st.container(horizontal=True, vertical_alignment="bottom"):
        view = st.segmented_control(
            "View", VIEWS, key=VIEW_KEY, default=VIEWS[0],
            help="Timeline: one lane per target list, a dot per run (size: alerts, color: highest severity). Cards: "
                 "each run with its change since the previous run of the same list, its risk trend and the indicators "
                 "it shares with other lists. Table: the plain list.") or VIEWS[0]
        text = st.text_input("Filter", key=FILTER_KEY, placeholder="target or run name", width=220,
                             help="Only runs whose targets, seeds or name contain this text")
        limit = st.selectbox("Runs", LIMITS, key=LIMIT_KEY, width=90, help="How many of the newest matching runs")
        only_alerts = st.toggle("With alerts", key=ALERTS_KEY, help="Only runs that raised alerts")
        only_new = st.toggle("New alerts", key=NEW_KEY,
                             help="Only runs with alerts that the previous run of the same targets did not have "
                                  "(a first run counts when it has alerts)")
    return view, text, int(limit), only_alerts, only_new


def _shown(all_runs, text, limit, only_alerts, only_new):
    """The matching runs, newest first; the picked run stays in view even when it is older than the limit."""
    rows = filter_overview(recent_overview(all_runs, len(all_runs)), text, only_alerts, only_new)
    ids = [row["id"] for row in rows]
    picked = st.session_state.get(SELECTED_KEY)
    if picked in ids and ids.index(picked) >= limit:
        limit = ids.index(picked) + 1
    return rows[:limit]


def _render_view(view, runs, labels, timezone, use_cases, offline, profiles, selected):
    ids = [run["id"] for run in runs]
    if view == "Timeline":
        clicked = recent_timeline(runs, labels, timezone, use_cases, selected)
        if clicked and clicked != selected:
            select_run(clicked)
            st.rerun()
        st.caption("Click a run to pick it. Cards show what changed since each list's previous run and what it shares.")
    elif view == "Cards":
        for start_at in range(0, len(runs), CARDS_PER_ROW):
            for column, run in zip(st.columns(CARDS_PER_ROW, gap="small"), runs[start_at:start_at + CARDS_PER_ROW]):
                with column:
                    run_card(run, labels[run["key"]], timezone, use_cases.get(run["id"]), labels,
                             run["id"] == selected, select_run, find_sightings)
    else:
        frame = pd.DataFrame([_recent_row(run, timezone, offline.get(run["id"]), profiles) for run in runs])
        frame["Shares"] = [len(shared_indicators(run)) for run in runs]
        picked = st.dataframe(
            frame, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
            key="recent_runs_table",
            column_config={"Run": st.column_config.TextColumn(width="medium"),
                           "Targets": st.column_config.TextColumn(width="medium"),
                           "Offline copy": st.column_config.CheckboxColumn(
                               width="small", help="An offline copy was saved from this run"),
                           "Shares": st.column_config.NumberColumn(
                               width="small", help="Indicators also seen in other target lists, on other domains")})
        rows = picked.selection.rows if picked and picked.selection else []
        if rows and ids[rows[0]] != selected:
            select_run(ids[rows[0]])
            st.rerun()


def _render_shared(run, labels):
    """The picked run's indicators shared with other lists, and any of its indicators, linked to their sightings."""
    indicators = shared_indicators(run, labels)
    if indicators:
        st.markdown(f"**Shared with other target lists ({len(indicators)})**",
                    help="Indicators this run found that runs of other target lists also found, on other domains. "
                         "CDN IPs, large DNS providers and values in many lists are left out.")
        frame = pd.DataFrame(indicators)
        picked = st.dataframe(frame, hide_index=True, width="stretch", on_select="rerun",
                              selection_mode="single-row", key=f"{SHARED_TABLE_KEY}::{run['id']}",
                              column_config={"Lists": st.column_config.NumberColumn(
                                  "Other lists", width="small", help="Other target lists that found it"),
                                  "Also in": st.column_config.TextColumn(width="large")})
        rows = picked.selection.rows if picked and picked.selection else []
        row = indicators[rows[0] if rows else 0]
        st.button(f"Where else was {row['Indicator']} seen?", key="recent_shared_find", type="primary",
                  icon=":material/visibility:", on_click=find_sightings, args=(row["Indicator"],),
                  help="Opens Indicator Sightings: every saved run and offline dataset where it was observed. "
                       + ("" if rows else "Click a row to pick another indicator."))
    snapshot = next((s for _, s in load_all_runs() if s.get("id") == run["id"]), None)
    values = run_indicators(snapshot)
    with st.expander(f"Any indicator of this run ({len(values)})", icon=":material/search:"):
        if not values:
            st.caption("This run recorded no indicators.")
            return
        kinds = sorted({kind for kind, _ in values})
        c_kind, c_value = st.columns([1, 3], vertical_alignment="bottom")
        kind = c_kind.selectbox("Kind", kinds, key=f"{INDICATOR_KEY}_kind::{run['id']}")
        value = c_value.selectbox("Indicator", [v for k, v in values if k == kind],
                                  key=f"{INDICATOR_KEY}::{run['id']}::{kind}")
        st.button("Show its sightings", key="recent_indicator_find", icon=":material/visibility:",
                  on_click=find_sightings, args=(value,), disabled=not value)


def _render_runs(timezone):
    st.caption("Pick up a previous analysis: run it again with the same use case and options, load the offline copy "
               "saved from it (no API calls), open it in Runs & Diffs, or follow an indicator it shares with other "
               "investigations to every place it was seen.")
    all_runs = load_all_runs()
    if not all_runs:
        st.info("No saved runs yet. Each live Analyze is saved automatically and shows here.")
        return
    view, text, limit, only_alerts, only_new = _controls()
    runs = _shown(all_runs, text, limit, only_alerts, only_new)
    if not runs:
        st.info("No saved run matches these filters.")
        return
    offline, profiles = _offline_by_run(list_offline_datasets()), load_settings().get(PROFILES_SETTING)
    labels = _list_labels(all_runs)
    use_cases = {run["id"]: _use_case_title((run.get("options") or {}).get("use_case"), profiles) for run in runs}
    ids = [run["id"] for run in runs]
    if st.session_state.get(SELECTED_KEY) not in ids:
        st.session_state[SELECTED_KEY] = ids[0]
    selected = st.session_state[SELECTED_KEY]
    st.caption(f"{len(runs)} of {len(all_runs)} saved run(s)" + (" match the filters." if
                                                                  text or only_alerts or only_new else "."))
    _render_view(view, runs, labels, timezone, use_cases, offline, profiles, selected)
    run = next(run for run in runs if run["id"] == selected)
    st.markdown(f"##### {md_escape(_targets_label(run['targets'], 3, run.get('seeds')))}")
    st.caption(f"Picked: {format_created(run['created'], timezone)}" + (", the newest." if run["id"] == ids[0] else "."))
    render_run_actions(run, offline.get(run["id"]))
    _render_shared(run, labels)
    with st.expander("Runs per day", icon=":material/calendar_month:"):
        runs_calendar(all_runs)
    with st.container(horizontal=True):
        navigation.link("history", label="See every run on Runs & Diffs")
        navigation.link("hunt_graph", label="See how runs connect on the Hunting graph")


def render_recent_page(timezone="UTC"):
    st.header("Recent runs", help="Saved runs (dt_runs/, saved after each live Analyze) and offline datasets "
                                  "(dt_offline/). Local files only: no API query.")
    st.session_state.setdefault(TAB_KEY, RUNS_TAB)
    tabs = st.tabs([RUNS_TAB, SIGHTINGS_TAB], key=TAB_KEY, on_change="rerun")
    # only the open tab is drawn, so a sightings search does not run while the runs are shown
    with tabs[0]:
        if tabs[0].open is not False:
            _render_runs(timezone)
    with tabs[1]:
        if tabs[1].open is not False:
            render_sightings(pick_run=pick_run)


def render_recent_teaser(timezone="UTC"):
    """Start page: the newest run in one line (the link to Recent runs sits with the IrisQL and CertsQL links)."""
    all_runs = load_all_runs()
    if not all_runs:
        return
    newest = max(all_runs, key=lambda item: str(item[1].get("id") or item[1].get("created")))[1]
    summary = run_summary(newest)   # only this run's own summary: no change or shared-indicator work on the Start page
    count = int(summary.get("alerts") or 0)
    alerts = f"{count} alert(s), highest {top_severity(summary).lower()}" if count else "no alerts"
    st.caption(f"Last run: **{md_escape(_targets_label(newest['targets'], 3, newest.get('seeds')))}** · "
               f"{format_created(newest['created'], timezone)} · {alerts} · {len(all_runs)} saved run(s)")
