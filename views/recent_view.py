"""
Recent runs page (top menu): the newest saved runs as a timeline, cards or a table, with what changed, the risk trend
and the indicators each run shares with other target lists; and Indicator Sightings, where any of those indicators
(or one you type) was observed before. Local files only (dt_runs/, dt_offline/): no API query.
"""
import pandas as pd
import streamlit as st

from core.helpers import md_escape
from core.intel_data import SEVERITY_ORDER
from core.offline import list_offline_datasets
from core.persistence import load_all_runs, load_settings
from core.run_history import format_created, run_summary
from core.run_views import (
    filter_overview,
    group_by_list,
    recent_overview,
    run_indicators,
    shared_indicators,
    top_severity,
)
from core.use_cases import PROFILES_SETTING
from views import navigation
from views.history_view import (
    _list_labels,
    _offline_by_run,
    _targets_label,
    _use_case_title,
    render_run_actions,
)
from views.run_visuals import CARDS_PER_ROW, recent_timeline, run_card, runs_activity
from views.seen_view import QUERY_KEY, render_sightings

TAB_KEY = "recent_tab"
RUNS_TAB, COMPARE_TAB, SIGHTINGS_TAB = "Recent runs", "Compare & trends", "Indicator Sightings"
VIEW_KEY = "recent_view"           # Timeline / Cards / Table
SELECTED_KEY = "recent_selected"   # the run id picked in Recent runs (any view)
LIMIT_KEY = "recent_limit"
FILTER_KEY, ALERTS_KEY, NEW_KEY = "recent_filter", "recent_only_alerts", "recent_only_new"
LIST_KEY = "recent_list"   # Table: only the runs of this target list (a card's *Show all runs*)
ALL_RUNS_KEY = "recent_all_runs"   # Table: every run (on) or one row per target list (off, the default)
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


def show_list_runs(key):
    """Card *Show all runs* callback: the Table view with every run of that target list."""
    st.session_state[VIEW_KEY] = "Table"
    st.session_state[LIST_KEY] = key
    st.session_state[ALL_RUNS_KEY] = True


def _all_runs_changed():
    """Turning *Show all runs* off leaves a card's single list too (it would be one row)."""
    if not st.session_state.get(ALL_RUNS_KEY):
        st.session_state.pop(LIST_KEY, None)


def _controls():
    if ALL_RUNS_KEY in st.session_state:   # keep the Table's choice while another view is shown
        st.session_state[ALL_RUNS_KEY] = st.session_state[ALL_RUNS_KEY]
    st.session_state.setdefault(VIEW_KEY, VIEWS[0])   # not default=: a card's Show all runs sets the view
    with st.container(horizontal=True, vertical_alignment="bottom"):
        view = st.segmented_control(
            "View", VIEWS, key=VIEW_KEY,
            help="Timeline: one lane per target list, a dot per run (size: alerts, color: highest severity). Cards: "
                 "one card per target list, its newest run with the number of runs, the change since the previous "
                 "run, the risk trend and the indicators it shares with other lists. Table: one row per target "
                 "list, or every run newest first with Show all runs.") or VIEWS[0]
        text = st.text_input("Filter", key=FILTER_KEY, placeholder="target or run name", width=220,
                             help="Only runs whose targets, seeds or name contain this text")
        limit = st.selectbox("Runs", LIMITS, key=LIMIT_KEY, width=90,
                             help="How many of the newest matching runs (Cards, and the Table without Show all "
                                  "runs: how many target lists)")
        all_runs = view == "Table" and st.toggle(
            "Show all runs", key=ALL_RUNS_KEY, on_change=_all_runs_changed,
            help="Off: one row per target list, its newest run with the number of runs. On: every run, newest first.")
        only_alerts = st.toggle("With alerts", key=ALERTS_KEY, help="Only runs that raised alerts")
        only_new = st.toggle("New alerts", key=NEW_KEY,
                             help="Only runs with alerts that the previous run of the same targets did not have "
                                  "(a first run counts when it has alerts)")
    return view, text, int(limit), only_alerts, only_new, bool(all_runs)


def _shown(all_runs, text, limit, only_alerts, only_new, view, every_run=False):
    """
    The matching runs, newest first: every run (Timeline; the Table with Show all runs, only of the list a card asked
    for), or one row per target list (Cards, and the Table without Show all runs: its newest run, with "repeats",
    every run of the list). The limit counts the rows; the picked run stays in view even when it is older.
    """
    rows = filter_overview(recent_overview(all_runs, len(all_runs)), text, only_alerts, only_new)
    if view == "Table" and not every_run:
        st.session_state.pop(LIST_KEY, None)
    if view == "Cards" or (view == "Table" and not every_run):
        rows = group_by_list(rows)
        picked_id = st.session_state.get(SELECTED_KEY)   # a picked older run is shown as its list's card
        st.session_state[SELECTED_KEY] = next(
            (row["id"] for row in rows if any(r["id"] == picked_id for r in row["repeats"])), picked_id)
    if view != "Table":   # a card's Show all runs narrows the Table only until another view is picked
        st.session_state.pop(LIST_KEY, None)
    elif st.session_state.get(LIST_KEY):
        rows = [row for row in rows if row["key"] == st.session_state[LIST_KEY]]
    ids = [row["id"] for row in rows]
    picked = st.session_state.get(SELECTED_KEY)
    if picked in ids and ids.index(picked) >= limit:
        limit = ids.index(picked) + 1
    return rows[:limit]


SEVERITY_SHORT = {"Critical": "Crit", "High": "High", "Medium-High": "Med-H", "Medium": "Med", "Low": "Low"}


def _all_runs_frame(runs, timezone, use_cases, offline, compact=False):
    """The Table view: one row per run with all its details (compact: per target list, its newest run)."""
    rows = []
    for run in runs:
        by_severity = (run["summary"] or {}).get("by_severity") or {}
        change = run["change"]
        rows.append({
            "Newest run" if compact else "Run": format_created(run["created"], timezone),
            "Targets": _targets_label(run["targets"], 3, run.get("seeds")) + (f" — {run['name']}" if run.get("name")
                                                                              else ""),
            **{SEVERITY_SHORT[s]: int(by_severity.get(s) or 0) for s in SEVERITY_ORDER},
            "Alerts": run["alerts"],
            "New": "—" if change is None else f"+{change['new']}",
            "Resolved": "—" if change is None else f"−{change['resolved']}",
            "Change": "first run" if change is None else "repeat" if not change["new"] and not change["resolved"]
            else "changed",
            "Max risk": "—" if run.get("max_risk") is None else f"{run['max_risk']:g}",
            "Use case": use_cases.get(run["id"]) or ("—" if run.get("options") else "not recorded"),
            "Window": run.get("window") or "—",
            "Queries": "—" if run.get("queries") is None else f"{int(run['queries']):,}",
            "Started by": run.get("via") or ("—" if not run.get("parent") else "a lead"),
            "Offline copy": offline.get(run["id"]) is not None,
            "Shares": len(shared_indicators(run)),
            "Runs of list": run["runs_of_list"],
        })
    return pd.DataFrame(rows)


def _render_view(view, runs, labels, timezone, use_cases, offline, selected, every_run=False):
    ids = [run["id"] for run in runs]
    if view == "Timeline":
        clicked = recent_timeline(runs, labels, timezone, use_cases, selected)
        if clicked and clicked != selected:
            select_run(clicked)
            st.rerun()
        st.caption("Click a run to pick it. Cards show each target list once, with its runs and what changed.")
    elif view == "Cards":
        for start_at in range(0, len(runs), CARDS_PER_ROW):
            for column, run in zip(st.columns(CARDS_PER_ROW, gap="small"), runs[start_at:start_at + CARDS_PER_ROW]):
                with column:
                    run_card(run, labels[run["key"]], timezone, use_cases.get(run["id"]), labels,
                             run["id"] == selected, select_run, find_sightings, show_list_runs)
    else:
        listed = st.session_state.get(LIST_KEY)
        if listed:
            with st.container(horizontal=True, vertical_alignment="center"):
                st.caption(f"Every run of **{md_escape(labels.get(listed, listed))}**.")
                st.button("Show every list", key="recent_list_clear", type="tertiary", icon=":material/close:",
                          on_click=st.session_state.pop, args=(LIST_KEY, None))
        frame = _all_runs_frame(runs, timezone, use_cases, offline, compact=not every_run)
        picked = st.dataframe(
            frame, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
            key=f"recent_runs_table::{'all' if every_run else 'lists'}",
            column_config={"Targets": st.column_config.TextColumn(width="medium"),
                           "Offline copy": st.column_config.CheckboxColumn(
                               width="small", help="An offline copy was saved from this run"),
                           "New": st.column_config.TextColumn(help="Alerts the previous run of the list did not have"),
                           "Resolved": st.column_config.TextColumn(
                               help="Alerts of the previous run of the list that this run no longer has"),
                           "Change": st.column_config.TextColumn(
                               help="Against the previous run of the same target list: repeat (the same alerts), "
                                    "changed (new or resolved alerts) or first run"),
                           "Started by": st.column_config.TextColumn(
                               help="What led to the run: Run again, Same targets again, a lead or step of another "
                                    "run (Hunt map), or — for a run started from the Start page"),
                           "Shares": st.column_config.NumberColumn(
                               width="small", help="Indicators also seen in other target lists, on other domains"),
                           "Runs of list": st.column_config.NumberColumn(
                               width="small", help="Saved runs of this target list")})
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
               "saved from it (no API calls), compare it with other runs, or follow an indicator it shares with other "
               "investigations to every place it was seen.")
    all_runs = load_all_runs()
    if not all_runs:
        st.info("No saved runs yet. Each live Analyze is saved automatically and shows here.")
        return
    view, text, limit, only_alerts, only_new, every_run = _controls()
    runs = _shown(all_runs, text, limit, only_alerts, only_new, view, every_run)
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
    if "repeats" in runs[0]:
        total = sum(len(run["repeats"]) for run in runs)
        st.caption(f"{len(runs)} target list(s), {total} of {len(all_runs)} saved run(s)"
                   + (" match the filters." if text or only_alerts or only_new else "."))
    else:
        st.caption(f"{len(runs)} of {len(all_runs)} saved run(s)"
                   + (" match the filters." if text or only_alerts or only_new else "."))
    _render_view(view, runs, labels, timezone, use_cases, offline, selected, every_run)
    run = next(run for run in runs if run["id"] == selected)
    st.markdown(f"##### {md_escape(_targets_label(run['targets'], 3, run.get('seeds')))}")
    st.caption(f"Picked: {format_created(run['created'], timezone)}" + (", the newest." if run["id"] == ids[0] else "."))
    render_run_actions(run, offline.get(run["id"]))
    _render_shared(run, labels)
    with st.expander("Runs and detections per day", icon=":material/calendar_month:"):
        runs_activity(all_runs)
    with st.container(horizontal=True):
        navigation.link("history", label="Compare runs and trends")
        navigation.jump_button("hunt_tree", "See how runs connect on the Hunt map", state={"hunt_map_tab": "All investigations"},
                               button_key="recent_hunt_map", icon=":material/account_tree:", type="tertiary")


def render_recent_page(timezone="UTC", render_history=None):
    st.header("Runs", help="Saved runs (dt_runs/, saved after each live Analyze) and offline datasets "
                           "(dt_offline/). Local files only: no API query.")
    st.session_state.setdefault(TAB_KEY, RUNS_TAB)
    tabs = st.tabs([RUNS_TAB, COMPARE_TAB, SIGHTINGS_TAB], key=TAB_KEY, on_change="rerun")
    navigation.scroll_to_tab()
    # only the open tab is drawn, so a sightings search does not run while the runs are shown
    if tabs[0].open is not False:
        with tabs[0]:
            _render_runs(timezone)
    if tabs[1].open is not False and render_history is not None:
        with tabs[1]:
            render_history()
    if tabs[2].open is not False:
        with tabs[2]:
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
